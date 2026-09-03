# ================================
# SERVER.PY - Painel de Inventário
# ================================
import os
import sys
import json
import uuid
import re
import logging
import shutil
import io
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
import sqlite3
import bcrypt

# ================================
# CONFIGURAÇÃO VIA VARIÁVEIS DE AMBIENTE
# ================================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(APP_DIR, "db.sqlite3"))
DB_BACKUP_DIR = os.environ.get("DB_BACKUP_DIR", os.path.join(APP_DIR, "backups"))

# Suporte a .env (variaveis de ambiente em arquivo) - util em producao
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(APP_DIR, ".env"))
    load_dotenv(os.path.join(os.path.dirname(APP_DIR), ".env"))
except Exception:
    pass

def _load_env_fallback():
    """Parser minimo de .env (KEY=VALUE) quando python-dotenv nao esta instalado."""
    for path in (os.path.join(APP_DIR, ".env"), os.path.join(os.path.dirname(APP_DIR), ".env")):
        try:
            if not os.path.isfile(path):
                continue
            with io.open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    if key and key not in os.environ:
                        os.environ[key] = val.strip().strip('"').strip("'")
        except Exception:
            continue

_load_env_fallback()

IS_PRODUCTION = os.environ.get("FLASK_ENV", "").lower() in ("production", "prod")

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "SEU_TOKEN_SUPER_SECRETO")
# Master (admin geral): em produção PANEL_USER/PANEL_PASS são OBRIGATÓRIOS
_PANEL_USER = os.environ.get("PANEL_USER")
_PANEL_PASS = os.environ.get("PANEL_PASS")
LOGIN_USER = _PANEL_USER or ("admin" if not IS_PRODUCTION else "")
LOGIN_PASS = _PANEL_PASS or ("admin" if not IS_PRODUCTION else "")
MASTER_TENANT_ID = int(os.environ.get("PANEL_TENANT_ID", "2"))
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")  # persiste em .secret_key se ausente

# Email config (opcional)
RECOVERY_EMAIL_TO = os.environ.get("RECOVERY_EMAIL_TO", "ti@ahbb.org.br")
RECOVERY_EMAIL_FROM = os.environ.get("RECOVERY_EMAIL_FROM", "noreply@ahbb.org.br")

# Rate limiting
RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT", "200 per hour")

# ================================
# LOGGING
# ================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(APP_DIR, 'server.log'), encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

if not FLASK_SECRET_KEY:
    _key_file = os.path.join(APP_DIR, ".secret_key")
    try:
        if os.path.exists(_key_file):
            FLASK_SECRET_KEY = io.open(_key_file, encoding="utf-8").read().strip()
        if not FLASK_SECRET_KEY:
            FLASK_SECRET_KEY = os.urandom(32).hex()
            io.open(_key_file, "w", encoding="utf-8").write(FLASK_SECRET_KEY)
            logger.info("FLASK_SECRET_KEY gerada e salva em .secret_key")
    except Exception as _e:
        FLASK_SECRET_KEY = FLASK_SECRET_KEY or os.urandom(32).hex()
        logger.warning(f"Nao foi possivel persistir FLASK_SECRET_KEY: {_e}")

if IS_PRODUCTION and (not _PANEL_USER or not _PANEL_PASS):
    import secrets as _sec
    LOGIN_USER = LOGIN_USER or _sec.token_hex(6)
    LOGIN_PASS = LOGIN_PASS or _sec.token_urlsafe(12)
    logger.warning("PRODUCAO sem PANEL_USER/PANEL_PASS: credenciais do admin geral geradas (veja logs/variaveis).")

# ================================
# APP FLASK
# ================================
app = Flask(__name__, template_folder=APP_DIR)
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(IS_PRODUCTION),
)

# Rate limiting (simples, sem Redis)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[RATE_LIMIT_DEFAULT],
        storage_uri="memory://"
    )
    logger.info("Rate limiting habilitado")
except ImportError:
    limiter = None
    logger.warning("flask-limiter não instalado, rate limiting desabilitado")

# CSRF disabled for internal panel
csrf = None


# ================================
# DATABASE
# ================================
def get_db():
    """Retorna conexão SQLite com row_factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # Melhor performance
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Inicializa tabelas do banco"""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                slug TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TEXT
            );
            
            CREATE TABLE IF NOT EXISTS computers (
                agent_id TEXT PRIMARY KEY,
                device_uid TEXT,
                hostname TEXT,
                alias TEXT,
                tag_evo TEXT,
                last_seen TEXT,
                payload_json TEXT,
                unit_id INTEGER,
                location_id INTEGER,
                tenant_id INTEGER NOT NULL DEFAULT 1
            );
            
            CREATE TABLE IF NOT EXISTS units (
                unit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT,
                UNIQUE(tenant_id, name)
            );
            
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                is_unit_admin INTEGER DEFAULT 0,
                manage_scripts INTEGER DEFAULT 0,
                created_at TEXT,
                UNIQUE(tenant_id, username)
            );
            
            CREATE TABLE IF NOT EXISTS user_units (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                user_id INTEGER NOT NULL,
                unit_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (unit_id) REFERENCES units(unit_id),
                UNIQUE(user_id, unit_id)
            );
            
            CREATE TABLE IF NOT EXISTS scripts (
                script_id TEXT PRIMARY KEY,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT,
                updated_at TEXT
            );
            
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                device_uid TEXT NOT NULL,
                script_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                created_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                stdout TEXT,
                stderr TEXT,
                exit_code INTEGER,
                FOREIGN KEY (script_id) REFERENCES scripts(script_id)
            );
            
            CREATE TABLE IF NOT EXISTS password_resets (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            
            CREATE INDEX IF NOT EXISTS idx_jobs_device ON jobs(device_uid);
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
            CREATE TABLE IF NOT EXISTS locations (
                location_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                unit_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT,
                FOREIGN KEY (unit_id) REFERENCES units(unit_id) ON DELETE CASCADE
            );
            
            CREATE INDEX IF NOT EXISTS idx_locations_unit ON locations(unit_id);
            
            CREATE TABLE IF NOT EXISTS metrics_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                agent_id TEXT NOT NULL,
                cpu_percent REAL,
                ram_percent REAL,
                disk_used_gb REAL,
                disk_total_gb REAL,
                recorded_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES computers(agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_agent ON metrics_history(agent_id);
            CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics_history(recorded_at);
            
            CREATE TABLE IF NOT EXISTS tickets (
                ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                agent_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                priority TEXT NOT NULL DEFAULT 'medium',
                created_by TEXT,
                assigned_to TEXT,
                created_at TEXT,
                updated_at TEXT,
                closed_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES computers(agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_tickets_tenant ON tickets(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
            CREATE TABLE IF NOT EXISTS ticket_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                performed_by TEXT,
                created_at TEXT,
                FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_ticket_history_ticket ON ticket_history(ticket_id);
            CREATE TABLE IF NOT EXISTS ticket_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                content TEXT NOT NULL,
                is_internal INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY (ticket_id) REFERENCES tickets(ticket_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_ticket_notes_ticket ON ticket_notes(ticket_id);
            
            CREATE TABLE IF NOT EXISTS maintenance_alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                agent_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'warning',
                is_resolved INTEGER DEFAULT 0,
                created_at TEXT,
                resolved_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES computers(agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_maintenance_tenant ON maintenance_alerts(tenant_id);

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                agent_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES computers(agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(is_read);
CREATE INDEX IF NOT EXISTS idx_computers_last_seen ON computers(last_seen);
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                detail TEXT,
                created_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);

            CREATE TABLE IF NOT EXISTS notifications (
                notif_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                user_id INTEGER,
                unit_id INTEGER,
                title TEXT NOT NULL,
                message TEXT,
                link TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read);
            CREATE INDEX IF NOT EXISTS idx_notif_tenant ON notifications(tenant_id);

            CREATE TABLE IF NOT EXISTS assets (
                asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                unit_id INTEGER,
                location_id INTEGER,
                kind TEXT NOT NULL DEFAULT 'outro',
                name TEXT NOT NULL,
                brand TEXT,
                model TEXT,
                serial TEXT,
                patrimonio TEXT,
                status TEXT NOT NULL DEFAULT 'ativo',
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_assets_unit ON assets(unit_id);

            CREATE TABLE IF NOT EXISTS kb_articles (
                article_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                unit_id INTEGER,
                category TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                is_public INTEGER DEFAULT 1,
                created_by TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_kb_tenant ON kb_articles(tenant_id);

            CREATE TABLE IF NOT EXISTS computer_changes (
                change_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                agent_id TEXT NOT NULL,
                summary TEXT,
                detail TEXT,
                created_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_changes_agent ON computer_changes(agent_id);

            CREATE TABLE IF NOT EXISTS report_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                period TEXT NOT NULL,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                sent_at TEXT,
                UNIQUE(period, tenant_id)
            );
        """)
        conn.commit()
    
    # Auto-migration: add missing columns
    with get_db() as conn:
        cursor = conn.execute("PRAGMA table_info(computers)")
        cols = [row[1] for row in cursor.fetchall()]
        if "unit_id" not in cols:
            conn.execute("ALTER TABLE computers ADD COLUMN unit_id INTEGER")
            conn.commit()
            logger.info("Migration: added unit_id to computers")
        if "location_id" not in cols:
            conn.execute("ALTER TABLE computers ADD COLUMN location_id INTEGER")
            conn.commit()
            logger.info("Migration: added location_id to computers")
        
        # Tenant migrations
        tables_need_tenant = ["computers", "units", "users", "scripts", "jobs", "locations", "user_units"]
        for table in tables_need_tenant:
            cursor = conn.execute(f"PRAGMA table_info({table})")
            cols = [row[1] for row in cursor.fetchall()]
            if "tenant_id" not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1")
                conn.commit()
                logger.info(f"Migration: added tenant_id to {table}")
        
        # Insert default tenant if none exists
        count = conn.execute("SELECT COUNT(*) as cnt FROM tenants").fetchone()["cnt"]
        if count == 0:
            conn.execute("INSERT INTO tenants (name, slug, created_at) VALUES (?, ?, ?)",
                ("Default", "default", utc_now_iso()))
            conn.commit()
            logger.info("Default tenant created")
    logger.info("Banco de dados inicializado")


def migrate_db():
    """Adiciona colunas novas que podem nao existir"""
    try:
        with get_db() as conn:
            for stmt in [
                'ALTER TABLE tickets ADD COLUMN resolution_notes TEXT',
                'ALTER TABLE tickets ADD COLUMN category TEXT DEFAULT ' + chr(39) + 'other' + chr(39),
                'ALTER TABLE tickets ADD COLUMN first_response_at TEXT',
                'ALTER TABLE tickets ADD COLUMN resolved_at TEXT',
                'ALTER TABLE tickets ADD COLUMN sla_due TEXT',
                'ALTER TABLE tickets ADD COLUMN unit_id INTEGER',
                'ALTER TABLE tickets ADD COLUMN location_id INTEGER',
                'ALTER TABLE users ADD COLUMN is_unit_admin INTEGER DEFAULT 0',
                'ALTER TABLE users ADD COLUMN manage_scripts INTEGER DEFAULT 0',
                'ALTER TABLE tickets ADD COLUMN rating INTEGER',
                'ALTER TABLE tickets ADD COLUMN rating_comment TEXT',
            ]:
                try:
                    conn.execute(stmt)
                except:
                    pass
            conn.commit()
    except:
        pass


def backup_db():
    """Cria backup do banco antes de modificações importantes"""
    try:
        os.makedirs(DB_BACKUP_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(DB_BACKUP_DIR, f"db_backup_{timestamp}.sqlite3")
        shutil.copy2(DB_PATH, backup_path)
        
        # Manter apenas os últimos 10 backups
        backups = sorted([f for f in os.listdir(DB_BACKUP_DIR) if f.endswith('.sqlite3')])
        while len(backups) > 10:
            old = backups.pop(0)
            os.remove(os.path.join(DB_BACKUP_DIR, old))
            logger.info(f"Backup antigo removido: {old}")
        
        logger.info(f"Backup criado: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Erro ao criar backup: {e}")
        return None


# ================================
# HELPERS
# ================================
def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match((email or "").strip()))


def norm_tag(tag: str) -> str:
    tag = (tag or "").strip().upper().replace(" ", "")
    if tag and not tag.startswith("EVO"):
        tag = f"EVO-{tag}"
    if tag.startswith("EVO") and "-" not in tag and len(tag) > 3:
        tag = "EVO-" + tag[3:]
    return tag


def is_valid_tag(tag: str) -> bool:
    return bool(re.fullmatch(r"EVO-\w{2,20}", tag or ""))


def get_current_tenant():
    """Retorna o tenant_id da sessao atual"""
    return session.get("tenant_id", 1)


def require_agent_token(f):
    """Decorator para autenticação do agente"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-AGENT-TOKEN")
        if token != AGENT_TOKEN:
            logger.warning(f"Tentativa de acesso não autorizado de {request.remote_addr}")
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def require_login(f):
    """Decorator para login obrigatório com timeout de sessão"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        # Session timeout: 30 minutes
        from time import time
        last_activity = session.get("last_activity", 0)
        if time() - last_activity > 1800:  # 30 min
            session.clear()
            return redirect(url_for("login_page"))
        session["last_activity"] = time()
        return f(*args, **kwargs)
    return decorated


def current_user_access():
    """Retorna (role, unit_ids) do usuário logado.
    role: 'master' (admin da empresa - vê tudo) | 'unit_admin' | 'tech'
    unit_ids: unidades permitidas (None = todas as unidades da empresa p/ master)
    """
    user_id = session.get("user_id")
    if not user_id:
        # Login master (admin/admin via env) -> vê toda a empresa
        return "master", None
    with get_db() as conn:
        row = conn.execute("SELECT is_admin, is_unit_admin FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if row is None:
        return "master", None
    if row["is_admin"]:
        return "master", None
    with get_db() as conn:
        rows = conn.execute("SELECT unit_id FROM user_units WHERE user_id = ?", (user_id,)).fetchall()
    unit_ids = [r["unit_id"] for r in rows]
    if row["is_unit_admin"]:
        return "unit_admin", unit_ids
    return "tech", unit_ids


def unit_scope_clause(alias, agent_alias=None):
    """Retorna (fragmento_sql, params) filtrando por unidades permitidas.
    alias: alias da tabela que possui unit_id (ex: 'c').
    Para master -> sem filtro. Para os demais -> unit_id IN (...).
    """
    role, unit_ids = current_user_access()
    if role == "master":
        return "", []
    if not unit_ids:
        return f" AND 1=0", []
    ph = ",".join("?" * len(unit_ids))
    return f" AND {alias}.unit_id IN ({ph})", unit_ids


def computer_in_scope(agent_id):
    """Verifica se o usuário pode acessar um computador específico."""
    role, unit_ids = current_user_access()
    if role == "master":
        return True
    with get_db() as conn:
        row = conn.execute("SELECT unit_id FROM computers WHERE agent_id = ?", (agent_id,)).fetchone()
    if not row:
        return False
    return row["unit_id"] in (unit_ids or [])


def ticket_in_scope(ticket_id):
    """Verifica se o usuário pode acessar um chamado específico."""
    role, unit_ids = current_user_access()
    if role == "master":
        return True
    with get_db() as conn:
        row = conn.execute("SELECT unit_id FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if not row:
        return False
    return row["unit_id"] in (unit_ids or [])


SLA_HOURS = {"critical": 4, "high": 8, "medium": 24, "low": 72}


def sla_due_from(created_iso, priority="medium"):
    """Calcula sla_due (ISO) a partir de created_iso + horas por prioridade."""
    try:
        from datetime import timedelta
        base = datetime.fromisoformat(str(created_iso))
        hours = SLA_HOURS.get(priority, 24)
        return (base + timedelta(hours=hours)).isoformat()
    except Exception:
        return None


def user_can_manage_scripts():
    """master / unit_admin sempre podem; tech precisa da flag manage_scripts."""
    role, _ = current_user_access()
    if role in ("master", "unit_admin"):
        return True
    uid = session.get("user_id")
    if not uid:
        return True  # env master
    with get_db() as conn:
        row = conn.execute("SELECT manage_scripts FROM users WHERE user_id = ?", (uid,)).fetchone()
    return bool(row and row["manage_scripts"])


def _users_to_notify(tenant_id, unit_ids):
    """Usuarios que devem receber notificacao: admins da empresa + usuarios das unidades."""
    ids = set()
    with get_db() as conn:
        for r in conn.execute("SELECT user_id FROM users WHERE tenant_id = ? AND is_admin = 1", (tenant_id,)):
            ids.add(r["user_id"])
        if unit_ids:
            ph = ",".join("?" * len(unit_ids))
            for r in conn.execute(
                "SELECT DISTINCT u.user_id FROM user_units u WHERE u.unit_id IN (" + ph + ")",
                unit_ids,
            ):
                ids.add(r["user_id"])
    return list(ids)


def create_notification(tenant_id, title, message, link=None, unit_id=None, user_ids=None):
    """Cria notificacoes. user_ids None -> todos os afetados da empresa/unidade."""
    try:
        if user_ids is None:
            user_ids = _users_to_notify(tenant_id, [unit_id] if unit_id else None)
        now = utc_now_iso()
        with get_db() as conn:
            for uid in user_ids or []:
                conn.execute(
                    "INSERT INTO notifications (tenant_id, user_id, unit_id, title, message, link, is_read, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                    (tenant_id, uid, unit_id, title, message, link, now),
                )
            conn.commit()
    except Exception as e:
        logger.warning(f"Falha ao criar notificacao: {e}")


def notify_ticket_event(ticket_id, title, message, link=None, only_assigned_user=None):
    """Notifica afetados de um chamado (admins + usuarios da unidade ou o atribuido)."""
    try:
        with get_db() as conn:
            t = conn.execute("SELECT tenant_id, unit_id FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            if not t:
                return
            tid, unit_id = t["tenant_id"], t["unit_id"]
        if only_assigned_user:
            create_notification(tid, title, message, link=link, user_ids=[only_assigned_user])
        else:
            create_notification(tid, title, message, link=link, unit_id=unit_id)
    except Exception as e:
        logger.warning(f"Falha notify_ticket_event: {e}")


def log_computer_change(agent_id, summary, detail=None):
    """Registra mudanca no ciclo de vida do ativo (PC)."""
    try:
        with get_db() as conn:
            row = conn.execute("SELECT tenant_id FROM computers WHERE agent_id = ?", (agent_id,)).fetchone()
            tid = row["tenant_id"] if row else 1
            conn.execute(
                "INSERT INTO computer_changes (tenant_id, agent_id, summary, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (tid, agent_id, summary, detail, utc_now_iso()),
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"Falha log_computer_change: {e}")


def serialize_computer(row, unit_name=None, location_name=None):
    """Serializa dados do computador"""
    payload = {}
    if row["payload_json"]:
        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {}

    result = {
        "agent_id": row["agent_id"],
        "device_uid": row["device_uid"],
        "hostname": row["hostname"],
        "alias": row["alias"],
        "tag_evo": row["tag_evo"],
        "last_seen": row["last_seen"],
        "payload_json": row["payload_json"],
        "unit_id": row["unit_id"] if "unit_id" in row.keys() else None,
        "unit_name": unit_name,
        "location_id": row["location_id"] if "location_id" in row.keys() else None,
        "location_name": row["location_name"] if "location_name" in row.keys() else None,
        "_device_uid": row["device_uid"],
        "_tag_evo": row["tag_evo"],
        "_agent_id": row["agent_id"],
        "_alias": row["alias"],
        "_last_seen": row["last_seen"],
        "_unit_id": row["unit_id"] if "unit_id" in row.keys() else None,
        "_unit_name": unit_name,
        "_location_id": row["location_id"] if "location_id" in row.keys() else None,
        "_location_name": row["location_name"] if "location_name" in row.keys() else None,
        "payload": payload,
        **payload
    }
    return result


# ================================
# ROTAS PÚBLICAS
# ================================
# ================================
# AUDITORIA
# ================================
_AUDIT_EXCLUDE_EXACT = {"/api/alerts/check-offline", "/api/alerts/check_maintenance"}
_AUDIT_EXCLUDE_PREFIX = ("/api/agent/",)

@app.before_request
def audit_request():
    """Registra toda alteracao feita por usuario logado nas APIs."""
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return None
    if not request.path.startswith("/api/"):
        return None
    if request.path in _AUDIT_EXCLUDE_EXACT or request.path.startswith(_AUDIT_EXCLUDE_PREFIX):
        return None
    if not session.get("logged_in"):
        return None
    body = request.get_json(silent=True) or {}
    detail = {}
    for k, v in body.items():
        low = str(k).lower()
        if any(w in low for w in ("pass", "senha", "hash", "secret", "token")):
            detail[str(k)] = "***"
        elif isinstance(v, (dict, list)):
            detail[str(k)] = "<complexo>"
        else:
            detail[str(k)] = v
    snippet = json.dumps(detail, ensure_ascii=False)[:400]
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (tenant_id, user_id, username, action, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (session.get("tenant_id", 1), session.get("user_id"), session.get("user") or "master",
                 request.method + " " + request.path, snippet, utc_now_iso())
            )
            conn.commit()
    except Exception:
        pass
    return None


@app.route("/api/audit", methods=["GET"])
@require_login
def api_audit_list():
    role, _ = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    try:
        limit = min(max(int(request.args.get("limit", 150)), 1), 500)
    except Exception:
        limit = 150
    tid = get_current_tenant()
    with get_db() as conn:
        if not session.get("user_id"):
            rows = conn.execute("SELECT * FROM audit_log ORDER BY log_id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY log_id DESC LIMIT ?", (tid, limit)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/auditoria")
@require_login
def auditoria_page():
    role, _ = current_user_access()
    if role == "tech":
        return redirect(url_for("index"))
    return render_template("auditoria.html")


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"ok": True, "timestamp": utc_now_iso()})


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"]) if limiter else lambda f: f
def login_page():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        if username == LOGIN_USER and password == LOGIN_PASS:
            session.clear()
            session["logged_in"] = True
            session["user"] = username
            session["tenant_id"] = MASTER_TENANT_ID
            from time import time
            session["last_activity"] = time()
            logger.info(f"Login bem-sucedido: {username}")
            return redirect(url_for("index"))
        
        # Check tenant users
        with get_db() as conn:
            user = conn.execute(
                "SELECT user_id, tenant_id, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            if user:
                import hashlib
                try:
                    is_valid = bcrypt.checkpw(password.encode(), user["password_hash"].encode())
                except Exception:
                    # Fallback: old SHA256 hash
                    import hashlib
                    is_valid = hashlib.sha256(password.encode()).hexdigest() == user["password_hash"]
                if is_valid:
                    session.clear()
                    session["logged_in"] = True
                    session["user"] = username
                    session["user_id"] = user["user_id"]
                    session["tenant_id"] = user["tenant_id"]
                    from time import time
                    session["last_activity"] = time()
                    # Migrate old SHA256 hash to bcrypt
                    if not user["password_hash"].startswith("$2"):
                        new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                        with get_db() as migrate_conn:
                            migrate_conn.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (new_hash, user["user_id"]))
                            migrate_conn.commit()
                    logger.info(f"Login bem-sucedido: {username} (tenant {user['tenant_id']})")
                    return redirect(url_for("index"))
        logger.warning(f"Tentativa de login falhou: {username}")
        return render_template("login.html", error="Usuário ou senha inválidos")
    if session.get("logged_in"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    user = session.get("user", "unknown")
    session.clear()
    logger.info(f"Logout: {user}")
    return redirect(url_for("login_page"))


# ================================
# RECUPERAÇÃO DE SENHA
# ================================
def _send_reset_email(to_email, reset_url, username):
    """Envia e-mail com link de redefinição de senha"""
    subject = "[AtivoFix] Redefinição de senha"
    body = f"""<div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto">
    <div style="background:linear-gradient(135deg,#38bdf8,#818cf8);padding:20px;border-radius:12px 12px 0 0;text-align:center">
        <h1 style="color:white;margin:0">AtivoFix</h1>
        <p style="color:rgba(255,255,255,.8);margin:4px 0 0">Redefinição de Senha</p>
    </div>
    <div style="background:#1e293b;padding:24px;border-radius:0 0 12px 12px;color:#e2e8f0">
        <h2 style="margin:0 0 16px">Olá, {username}!</h2>
        <p>Recebemos uma solicitação para redefinir a senha da sua conta no <strong>AtivoFix</strong>.</p>
        <div style="background:rgba(51,65,85,.3);padding:12px;border-radius:8px;margin:16px 0">
            <p style="margin:0;font-size:13px;color:#94a3b8">Clique no botão abaixo para criar uma nova senha. O link expira em <strong>30 minutos</strong>.</p>
        </div>
        <div style="text-align:center;margin:24px 0">
            <a href="{reset_url}" style="background:linear-gradient(135deg,#38bdf8,#818cf8);color:white;text-decoration:none;padding:12px 28px;border-radius:10px;font-weight:bold;display:inline-block">Redefinir minha senha</a>
        </div>
        <p style="font-size:13px;color:#94a3b8">Se o botão não funcionar, copie e cole este link no navegador:</p>
        <p style="font-size:12px;color:#64748b;word-break:break-all">{reset_url}</p>
        <p style="font-size:12px;color:#64748b;margin-top:16px">Se você não solicitou esta redefinição, ignore este e-mail — sua senha permanece segura.</p>
    </div>
</div>"""
    return send_email(to_email, subject, body)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    """Tela que pede o e-mail cadastrado e envia link de redefinição"""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            return render_template("forgot_password.html", error="Informe seu e-mail cadastrado.")
        with get_db() as conn:
            user = conn.execute(
                "SELECT user_id, username, email FROM users WHERE lower(email) = lower(?)",
                (email,)
            ).fetchone()
        # Sempre mostra mensagem genérica (não revela se o e-mail existe)
        if user:
            import secrets
            token = secrets.token_urlsafe(48)
            expires_at = utc_now_iso()
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO password_resets (token, email, created_at, used) VALUES (?, ?, ?, 0)",
                    (token, email, expires_at)
                )
                conn.commit()
            reset_url = url_for("reset_password_page", token=token, _external=True)
            sent = _send_reset_email(email, reset_url, user["username"])
            logger.info(f"Link de redefinição enviado para {email} (sent={sent})")
            if not sent:
                # Sem SMTP configurado: loga o link para o admin conseguir testar
                logger.warning(f"SMTP não configurado. Link de redefinição: {reset_url}")
                return render_template(
                    "forgot_password.html",
                    error="Não foi possível enviar o e-mail: servidor SMTP não configurado. Fale com o administrador.",
                    dev_link=reset_url,
                )
        return render_template("forgot_password.html",
                               success="Se o e-mail estiver cadastrado, você receberá um link de redefinição em instantes.")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_page(token):
    """Tela que valida o token e define a nova senha"""
    from time import time as _time
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM password_resets WHERE token = ? AND used = 0",
            (token,)
        ).fetchone()
    if not row:
        return render_template("reset_password.html", error="Link inválido ou já utilizado. Solicite um novo link de redefinição.")
    # Expira em 30 minutos
    try:
        from datetime import datetime as _dt
        created = _dt.fromisoformat(row["created_at"])
        age_seconds = (_dt.now().timestamp() - created.timestamp())
        if age_seconds > 1800:
            return render_template("reset_password.html", error="Este link expirou. Solicite um novo link de redefinição.")
    except Exception:
        pass

    if request.method == "POST":
        password = (request.form.get("password") or "")
        confirm = (request.form.get("confirm") or "")
        if len(password) < 6:
            return render_template("reset_password.html", token=token, error="A senha deve ter pelo menos 6 caracteres.")
        if password != confirm:
            return render_template("reset_password.html", token=token, error="As senhas não coincidem.")
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE lower(email) = lower(?)",
                (bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), row["email"])
            )
            conn.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (token,))
            conn.commit()
        logger.info(f"Senha redefinida para {row['email']}")
        return render_template("reset_password.html",
                               success="Senha redefinida com sucesso! Você já pode entrar com a nova senha.")
    return render_template("reset_password.html", token=token)


# ================================
# ROTAS PRINCIPAIS (PROTEGIDAS)
# ================================
@app.route("/")
@require_login
def index():
    return render_template("index.html")


@app.route("/scripts")
@require_login
def scripts_page():
    return render_template("scripts.html")


@app.route("/detalhe/<agent_id>")
@require_login
def detalhe(agent_id):
    return render_template("detalhe.html", agent_id=agent_id)


@app.route("/pc/<agent_id>")
@require_login
def pc_detail(agent_id):
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso a este computador"}), 403
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM computers WHERE agent_id = ?", (agent_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return render_template("detalhe.html", pc=serialize_computer(row))


@app.route("/pc/<agent_id>/delete", methods=["POST"])
@require_login
def pc_delete(agent_id):
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso a este computador"}), 403
    with get_db() as conn:
        row = conn.execute(
            "SELECT device_uid FROM computers WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        device_uid = row["device_uid"]
        conn.execute("DELETE FROM jobs WHERE device_uid = ?", (device_uid,))
        conn.execute("DELETE FROM computers WHERE agent_id = ?", (agent_id,))
        conn.commit()
    logger.info(f"Computador excluído: {agent_id}")
    return jsonify({"ok": True})


# ================================
# API - COMPUTERS
# ================================
@app.route("/api/computers", methods=["GET"])
@require_login
def api_computers():
    tid = get_current_tenant()
    extra, extra_params = unit_scope_clause("c")
    with get_db() as conn:
        rows = conn.execute(
            """SELECT c.*, u.name as unit_name, l.name as location_name
               FROM computers c 
               LEFT JOIN units u ON c.unit_id = u.unit_id 
               LEFT JOIN locations l ON c.location_id = l.location_id
               WHERE c.tenant_id = ?""" + extra + """
               ORDER BY c.last_seen DESC, c.hostname ASC""",
            [tid] + extra_params
        ).fetchall()
    return jsonify({"computers": [serialize_computer(r, r["unit_name"]) for r in rows]})


@app.route("/dados")
@require_login
def dados():
    tid = get_current_tenant()
    extra, extra_params = unit_scope_clause("c")
    with get_db() as conn:
        rows = conn.execute(
            """SELECT c.*, u.name as unit_name, l.name as location_name
               FROM computers c 
               LEFT JOIN units u ON c.unit_id = u.unit_id 
               LEFT JOIN locations l ON c.location_id = l.location_id
               WHERE c.tenant_id = ?""" + extra + """
               ORDER BY c.last_seen DESC, c.hostname ASC""",
            [tid] + extra_params
        ).fetchall()
    return jsonify([serialize_computer(r, r["unit_name"]) for r in rows])


@app.route("/api/alias", methods=["POST"])
def api_alias():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    alias = (data.get("alias") or "").strip()
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso a este computador"}), 403
    with get_db() as conn:
        conn.execute("UPDATE computers SET alias = ? WHERE agent_id = ?", (alias, agent_id))
        conn.commit()
    log_computer_change(agent_id, "Apelido alterado", f"Novo apelido: {alias or '(vazio)'}")
    return jsonify({"ok": True})


# ================================
# API - SCRIPTS (CRUD COMPLETO)
# ================================
@app.route("/api/scripts", methods=["GET"])
@require_login
def api_scripts_list():
    tid = get_current_tenant()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT script_id, name, created_at, updated_at FROM scripts WHERE tenant_id = ? ORDER BY name",
            (tid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scripts/<script_id>", methods=["GET"])
@require_login
def api_scripts_get(script_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scripts WHERE script_id = ?", (script_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/scripts", methods=["POST"])
@require_login
def api_scripts_create():
    if not user_can_manage_scripts():
        return jsonify({"error": "sem permissão para gerenciar scripts"}), 403
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    content = data.get("content") or ""
    if not name or not content.strip():
        return jsonify({"error": "name and content are required"}), 400
    script_id = uuid.uuid4().hex
    now = utc_now_iso()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scripts (script_id, name, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (script_id, name, content, now, now)
        )
        conn.commit()
    logger.info(f"Script criado: {name} ({script_id})")
    return jsonify({"ok": True, "script_id": script_id})


@app.route("/api/scripts/<script_id>", methods=["POST"])
@require_login
def api_scripts_update(script_id):
    if not user_can_manage_scripts():
        return jsonify({"error": "sem permissão para gerenciar scripts"}), 403
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    content = data.get("content") or ""
    if not name or not content.strip():
        return jsonify({"error": "name and content are required"}), 400
    now = utc_now_iso()
    with get_db() as conn:
        result = conn.execute(
            "UPDATE scripts SET name = ?, content = ?, updated_at = ? WHERE script_id = ?",
            (name, content, now, script_id)
        )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    logger.info(f"Script atualizado: {name} ({script_id})")
    return jsonify({"ok": True})


@app.route("/api/scripts/<script_id>", methods=["DELETE"])
@require_login
def api_scripts_delete(script_id):
    if not user_can_manage_scripts():
        return jsonify({"error": "sem permissão para gerenciar scripts"}), 403
    with get_db() as conn:
        jobs = conn.execute(
            "SELECT COUNT(*) as cnt FROM jobs WHERE script_id = ? AND status IN ('queued', 'pending')",
            (script_id,)
        ).fetchone()
        if jobs["cnt"] > 0:
            return jsonify({"error": "script has pending jobs"}), 400
        conn.execute("DELETE FROM scripts WHERE script_id = ?", (script_id,))
        conn.commit()
    logger.info(f"Script excluído: {script_id}")
    return jsonify({"ok": True})


# ================================
# API - JOBS
# ================================
@app.route("/api/jobs", methods=["GET"])
@require_login
def api_jobs_list():
    device_uid = request.args.get("device_uid")
    with get_db() as conn:
        if device_uid:
            rows = conn.execute(
                """SELECT j.*, s.name as script_name 
                   FROM jobs j LEFT JOIN scripts s ON s.script_id = j.script_id 
                   WHERE j.device_uid = ? ORDER BY j.created_at DESC""",
                (device_uid,)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT j.*, s.name as script_name 
                   FROM jobs j LEFT JOIN scripts s ON s.script_id = j.script_id 
                   ORDER BY j.created_at DESC LIMIT 100"""
            ).fetchall()
    return jsonify({"jobs": [dict(r) for r in rows]})


@app.route("/api/jobs/create", methods=["POST"])
@require_login
def api_jobs_create():
    if not user_can_manage_scripts():
        return jsonify({"error": "sem permissão para gerenciar jobs"}), 403
    data = request.get_json(silent=True) or {}
    device_uid = data.get("device_uid")
    script_id = data.get("script_id")
    if not device_uid or not script_id:
        return jsonify({"error": "device_uid and script_id are required"}), 400
    with get_db() as conn:
        script = conn.execute("SELECT name FROM scripts WHERE script_id = ?", (script_id,)).fetchone()
        if not script:
            return jsonify({"error": "script not found"}), 404
        job_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO jobs (job_id, device_uid, script_id, status, created_at) VALUES (?, ?, ?, 'queued', ?)",
            (job_id, device_uid, script_id, utc_now_iso())
        )
        conn.commit()
    logger.info(f"Job criado: {job_id} para {device_uid}")
    return jsonify({"ok": True, "job_id": job_id})


# ================================
# API - AGENTE
# ================================
@app.route("/api/agent", methods=["POST"])
@require_agent_token
def api_agent():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    device_uid = data.get("device_uid")
    hostname = data.get("hostname") or "sem-nome"
    payload_json = json.dumps(data, ensure_ascii=False, indent=2)
    now = utc_now_iso()
    # Dedupe: mesmo device_uid com outro agent_id (reinstalacao) -> reaproveita o registro antigo
    with get_db() as conn:
        dup = conn.execute(
            "SELECT agent_id FROM computers WHERE device_uid = ? AND agent_id != ? LIMIT 1",
            (device_uid, agent_id),
        ).fetchone()
        if dup:
            agent_id = dup["agent_id"] if dup else agent_id
        # mesmas intenções: mesmo hostname, mesmo device_uid vazio -> usa o primeiro registro
        if not device_uid and not dup:
            dup2 = conn.execute(
                "SELECT agent_id FROM computers WHERE hostname = ? AND agent_id != ? LIMIT 1",
                (hostname, agent_id),
            ).fetchone()
            if dup2:
                agent_id = dup2["agent_id"] if dup2 else agent_id
        existing = conn.execute("SELECT alias, tag_evo, payload_json FROM computers WHERE agent_id = ?", (agent_id,)).fetchone()
        alias = existing["alias"] if existing else None
        tag_evo = existing["tag_evo"] if existing else None
        if existing and existing["payload_json"]:
            try:
                old_p = json.loads(existing["payload_json"])
                new_p = data
                diffs = []
                for key in ("hostname", "os_caption", "cpu", "ram_total_gb", "windows_user"):
                    ov = str(old_p.get(key, "")).strip()
                    nv = str(new_p.get(key, "")).strip()
                    if ov != nv and (ov or nv):
                        diffs.append(f"{key}: {ov or 'vazio'} -> {nv or 'vazio'}")
                if diffs:
                    log_computer_change(agent_id, "Inventario atualizado", "; ".join(diffs[:8]))
            except Exception:
                pass
        conn.execute("INSERT INTO computers (agent_id, device_uid, hostname, alias, tag_evo, last_seen, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(agent_id) DO UPDATE SET device_uid=excluded.device_uid, hostname=excluded.hostname, alias=coalesce(excluded.alias, computers.alias), tag_evo=computers.tag_evo, last_seen=excluded.last_seen, payload_json=excluded.payload_json", (agent_id, device_uid, hostname, alias, tag_evo, now, payload_json))
        conn.commit()
    status = "need_tag" if not tag_evo else "ok"
    return jsonify({"status": status, "device_uid": device_uid, "agent_id": agent_id})

@app.route("/api/agent/bind", methods=["POST"])
@require_agent_token
def api_agent_bind():
    data = request.get_json(silent=True) or {}
    device_uid = data.get("device_uid")
    tag_evo = norm_tag(data.get("tag_evo"))
    if not device_uid or not tag_evo:
        return jsonify({"error": "device_uid and tag_evo are required"}), 400
    if not is_valid_tag(tag_evo):
        return jsonify({"error": "invalid tag format"}), 400
    with get_db() as conn:
        conn.execute("UPDATE computers SET tag_evo = ? WHERE device_uid = ? OR agent_id = ?", (tag_evo, device_uid, device_uid))
        conn.commit()
    return jsonify({"status": "ok", "tag_evo": tag_evo})

@app.route("/api/agent/jobs", methods=["GET"])
@require_agent_token
def api_agent_jobs():
    device_uid = request.args.get("device_uid")
    if not device_uid:
        return jsonify({"jobs": []})
    with get_db() as conn:
        rows = conn.execute("SELECT j.*, s.name as script_name, s.content FROM jobs j LEFT JOIN scripts s ON s.script_id = j.script_id WHERE j.device_uid = ? AND j.status IN ('queued', 'pending') ORDER BY j.created_at ASC", (device_uid,)).fetchall()
    jobs = [{"job_id": r["job_id"], "device_uid": r["device_uid"], "script_id": r["script_id"], "script_name": r["script_name"] or r["script_id"], "content": r["content"] or "", "status": r["status"]} for r in rows]
    return jsonify({"jobs": jobs})

@app.route("/api/agent/jobs/<job_id>/result", methods=["POST"])
@require_agent_token
def api_agent_job_result(job_id):
    data = request.get_json(silent=True) or {}
    now = utc_now_iso()
    with get_db() as conn:
        conn.execute("UPDATE jobs SET status = ?, stdout = ?, stderr = ?, exit_code = ?, finished_at = ? WHERE job_id = ?", (data.get("status") or "done", data.get("stdout") or "", data.get("stderr") or "", data.get("exit_code"), now, job_id))
        conn.commit()
    return jsonify({"status": "ok"})


# ================================
# API - UNIDADES
# ================================
@app.route("/api/units", methods=["GET"])
@require_login
def api_units_list():
    # Support tenant_id from query param (for public portal) or session
    tid_param = request.args.get("tenant_id")
    if tid_param and not session.get("user_id"):
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM units WHERE tenant_id = ? ORDER BY name", (tid_param,)).fetchall()
        return jsonify([dict(r) for r in rows])
    # env master (admin/admin sem user_id) -> visão plataforma (todas as empresas)
    # DB is_admin=1 -> somente a própria empresa; unit admin/tech -> só vinculadas
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    with get_db() as conn:
        if role == "master" and not session.get("user_id"):
            rows = conn.execute("""SELECT u.*, t.name as tenant_name FROM units u
                LEFT JOIN tenants t ON u.tenant_id = t.tenant_id
                ORDER BY t.name, u.name""").fetchall()
        elif role == "master":
            rows = conn.execute("""SELECT u.*, t.name as tenant_name FROM units u
                LEFT JOIN tenants t ON u.tenant_id = t.tenant_id
                WHERE u.tenant_id = ?
                ORDER BY t.name, u.name""", (tid,)).fetchall()
        elif unit_ids:
            ph = ",".join("?" * len(unit_ids))
            rows = conn.execute(f"""SELECT u.*, t.name as tenant_name FROM units u
                LEFT JOIN tenants t ON u.tenant_id = t.tenant_id
                WHERE u.unit_id IN ({ph})
                ORDER BY u.name""", unit_ids).fetchall()
        else:
            rows = []
    return jsonify([dict(r) for r in rows])


@app.route("/api/units", methods=["POST"])
@require_login
def api_units_create():
    data = request.get_json(silent=True) or {}
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar unidades"}), 403

    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    now = utc_now_iso()
    # env master pode atribuir unidade a qualquer empresa; admin de empresa fica na própria
    if data.get("tenant_id"):
        if session.get("user_id"):
            return jsonify({"error": "você só pode criar unidades na sua própria empresa"}), 403
        tid = int(data["tenant_id"])
    else:
        tid = get_current_tenant()
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO units (tenant_id, name, description, created_at) VALUES (?, ?, ?, ?)",
                (tid, name, description, now)
            )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                return jsonify({"error": "unit already exists"}), 400
            raise
    logger.info(f"Unidade criada: {name}")
    return jsonify({"ok": True})


@app.route("/api/units/<int:unit_id>", methods=["POST"])
@require_login
def api_units_update(unit_id):
    data = request.get_json(silent=True) or {}
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar unidades"}), 403

    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    with get_db() as conn:
        result = conn.execute(
            "UPDATE units SET name = ?, description = ? WHERE unit_id = ?",
            (name, description, unit_id)
        )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    logger.info(f"Unidade atualizada: {name}")
    return jsonify({"ok": True})


@app.route("/api/units/<int:unit_id>", methods=["DELETE"])
@require_login
def api_units_delete(unit_id):
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar unidades"}), 403
    with get_db() as conn:
        conn.execute("DELETE FROM user_units WHERE unit_id = ?", (unit_id,))
        conn.execute("UPDATE computers SET location_id = NULL WHERE location_id IN (SELECT location_id FROM locations WHERE unit_id = ?)", (unit_id,))
        conn.execute("DELETE FROM locations WHERE unit_id = ?", (unit_id,))
        conn.execute("UPDATE computers SET unit_id = NULL, location_id = NULL WHERE unit_id = ?", (unit_id,))
        conn.execute("DELETE FROM units WHERE unit_id = ?", (unit_id,))
        conn.commit()
    logger.info(f"Unidade excluida: {unit_id}")
    return jsonify({"ok": True})


# ================================
# API - LOCAIS (LOCATIONS)
# ================================
@app.route("/api/locations", methods=["GET"])
@require_login
def api_locations_list():
    unit_id = request.args.get("unit_id")
    tid = get_current_tenant()
    role, my_unit_ids = current_user_access()
    # when listing from tenant pages, restrict per user scope
    with get_db() as conn:
        if unit_id:
            # unit admin/tech só acessa locais das próprias unidades
            if role != "master":
                int_uid = int(unit_id)
                if int_uid not in (my_unit_ids or []):
                    return jsonify([])
            rows = conn.execute(
                "SELECT l.*, u.name as unit_name FROM locations l LEFT JOIN units u ON l.unit_id = u.unit_id WHERE l.unit_id = ? ORDER BY l.name",
                (unit_id,)
            ).fetchall()
        else:
            if role == "master":
                rows = conn.execute(
                    "SELECT l.*, u.name as unit_name FROM locations l LEFT JOIN units u ON l.unit_id = u.unit_id WHERE u.tenant_id = ? ORDER BY u.name, l.name",
                    (tid,)
                ).fetchall()
            elif my_unit_ids:
                ph = ",".join("?" * len(my_unit_ids))
                rows = conn.execute(
                    "SELECT l.*, u.name as unit_name FROM locations l LEFT JOIN units u ON l.unit_id = u.unit_id WHERE l.unit_id IN (" + ph + ") ORDER BY u.name, l.name",
                    my_unit_ids
                ).fetchall()
            else:
                rows = []
    return jsonify([dict(r) for r in rows])


@app.route("/api/locations", methods=["POST"])
@require_login
def api_locations_create():
    data = request.get_json(silent=True) or {}
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar locais"}), 403

    unit_id = data.get("unit_id")
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    if not unit_id or not name:
        return jsonify({"error": "unit_id and name are required"}), 400
    now = utc_now_iso()
    with get_db() as conn:
        unit = conn.execute("SELECT name FROM units WHERE unit_id = ?", (unit_id,)).fetchone()
        if not unit:
            return jsonify({"error": "unit not found"}), 404
        tid = get_current_tenant()
        try:
            conn.execute(
                "INSERT INTO locations (tenant_id, unit_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
                (tid, unit_id, name, description, now)
            )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                return jsonify({"error": "location already exists in this unit"}), 400
            raise
    logger.info(f"Local criado: {name} na unidade {unit['name']}")
    return jsonify({"ok": True})


@app.route("/api/locations/<int:location_id>", methods=["POST"])
@require_login
def api_locations_update(location_id):
    data = request.get_json(silent=True) or {}
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar locais"}), 403

    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    with get_db() as conn:
        result = conn.execute(
            "UPDATE locations SET name = ?, description = ? WHERE location_id = ?",
            (name, description, location_id)
        )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    logger.info(f"Local atualizado: {name}")
    return jsonify({"ok": True})


@app.route("/api/locations/<int:location_id>", methods=["DELETE"])
@require_login
def api_locations_delete(location_id):
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar locais"}), 403
    with get_db() as conn:
        conn.execute("UPDATE computers SET location_id = NULL WHERE location_id = ?", (location_id,))
        conn.execute("DELETE FROM locations WHERE location_id = ?", (location_id,))
        conn.commit()
    logger.info(f"Local excluido: {location_id}")
    return jsonify({"ok": True})


@app.route("/api/computers/<agent_id>/location", methods=["POST"])
@require_login
def api_computer_set_location(agent_id):
    role, _ = current_user_access()
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso a este computador"}), 403
    if role == "tech":
        return jsonify({"error": "somente admins podem alterar local"}), 403
    data = request.get_json(silent=True) or {}
    location_id = data.get("location_id")
    with get_db() as conn:
        if location_id:
            result = conn.execute(
                "UPDATE computers SET location_id = ? WHERE agent_id = ?",
                (location_id, agent_id)
            )
        else:
            result = conn.execute(
                "UPDATE computers SET location_id = NULL WHERE agent_id = ?",
                (agent_id,)
            )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    log_computer_change(agent_id, "Local alterado", f"location_id={location_id}")
    logger.info(f"PC {agent_id} vinculado a local {location_id}")
    return jsonify({"ok": True})


@app.route("/locais")
@require_login
def locais_page():
    return redirect("/unidades")


# ================================
# API - USUARIOS
# ================================
@app.route("/api/me", methods=["GET"])
@require_login
def api_me():
    role, unit_ids = current_user_access()
    tid = get_current_tenant()
    with get_db() as conn:
        units = []
        if unit_ids is None:
            if role == "master" and not session.get("user_id"):
                rows = conn.execute("SELECT unit_id, name FROM units ORDER BY name").fetchall()
            else:
                rows = conn.execute("SELECT unit_id, name FROM units WHERE tenant_id = ? ORDER BY name", (tid,)).fetchall()
            units = [{"unit_id": r["unit_id"], "name": r["name"]} for r in rows]
        elif unit_ids:
            ph = ",".join("?" * len(unit_ids))
            rows = conn.execute(f"SELECT unit_id, name FROM units WHERE unit_id IN ({ph}) ORDER BY name", unit_ids).fetchall()
            units = [{"unit_id": r["unit_id"], "name": r["name"]} for r in rows]
        tenant = conn.execute("SELECT name FROM tenants WHERE tenant_id = ?", (tid,)).fetchone()
    return jsonify({
        "user": session.get("user"),
        "user_id": session.get("user_id"),
        "tenant_id": tid,
        "tenant_name": tenant["name"] if tenant else "",
        "role": role,
        "unit_ids": unit_ids,
        "units": units,
        "is_master": role == "master",
        "is_unit_admin": role == "unit_admin",
        "can_manage_scripts": user_can_manage_scripts(),
    })


@app.route("/api/users", methods=["GET"])
@require_login
def api_users_list():
    role, unit_ids = current_user_access()
    tid = get_current_tenant()
    with get_db() as conn:
        if role == "master" and not session.get("user_id"):
            # env master (admin/admin): vê usuários de todas as empresas
            rows = conn.execute(
                """SELECT u.user_id, u.username, u.email, u.is_admin, u.is_unit_admin,
                          u.manage_scripts, u.tenant_id, u.created_at, t.name AS tenant_name
                   FROM users u LEFT JOIN tenants t ON u.tenant_id = t.tenant_id
                   ORDER BY t.name, u.username"""
            ).fetchall()
        elif role == "master":
            # admin da empresa: somente usuários da própria empresa
            rows = conn.execute(
                "SELECT user_id, username, email, is_admin, is_unit_admin, manage_scripts, tenant_id, created_at, '' AS tenant_name FROM users WHERE tenant_id = ? ORDER BY username",
                (tid,)
            ).fetchall()
        else:
            # unit_admin/tech: só usuários vinculados às unidades permitidas
            if not unit_ids:
                return jsonify([])
            ph = ",".join("?" * len(unit_ids))
            rows = conn.execute(
                f"""SELECT DISTINCT u.user_id, u.username, u.email, u.is_admin, u.is_unit_admin,
                           u.manage_scripts, u.tenant_id, u.created_at, '' AS tenant_name
                    FROM users u
                    JOIN user_units uu ON uu.user_id = u.user_id
                    WHERE u.tenant_id = ? AND uu.unit_id IN ({ph})
                    ORDER BY u.username""",
                [tid] + unit_ids
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users", methods=["POST"])
@require_login
def api_users_create():
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão para criar usuários"}), 403
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    is_admin = 1 if data.get("is_admin") else 0
    is_unit_admin = 1 if data.get("is_unit_admin") else 0
    manage_scripts = 1 if data.get("manage_scripts") else 0
    unit_ids = data.get("unit_ids") or []
    # Empresa do novo usuário: env master escolhe; admin de empresa/unidade fica na própria
    if not session.get("user_id"):
        try:
            tid = int(data.get("tenant_id") or get_current_tenant())
        except (TypeError, ValueError):
            return jsonify({"error": "empresa inválida"}), 400
        with get_db() as conn:
            _t = conn.execute("SELECT tenant_id FROM tenants WHERE tenant_id = ?", (tid,)).fetchone()
        if not _t:
            return jsonify({"error": "empresa inválida"}), 400
    else:
        tid = get_current_tenant()
        if data.get("tenant_id"):
            try:
                if int(data.get("tenant_id")) != tid:
                    return jsonify({"error": "você só pode criar usuários na sua própria empresa"}), 403
            except (TypeError, ValueError):
                return jsonify({"error": "empresa inválida"}), 400
    # unit_admin só pode criar usuários dentro das próprias unidades e nunca master
    if role == "unit_admin":
        if is_admin:
            return jsonify({"error": "admin da unidade não pode criar admin master"}), 403
        if not my_unit_ids:
            return jsonify({"error": "sua conta não está vinculada a nenhuma unidade"}), 403
        allowed = set(my_unit_ids)
        if unit_ids and not set(unit_ids).issubset(allowed):
            return jsonify({"error": "você só pode vincular usuários às suas unidades"}), 403
        if not unit_ids:
            unit_ids = list(allowed)
    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "e-mail inválido"}), 400
    # valida que as unidades pertencem à empresa escolhida
    unit_ids = [int(x) for x in (unit_ids or [])]
    if unit_ids:
        with get_db() as conn:
            _ph = ",".join("?" * len(unit_ids))
            _c = conn.execute(
                f"SELECT COUNT(*) AS c FROM units WHERE unit_id IN ({_ph}) AND tenant_id = ?",
                unit_ids + [tid]
            ).fetchone()["c"]
        if _c != len(set(unit_ids)):
            return jsonify({"error": "unidade pertence a outra empresa"}), 400
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    now = utc_now_iso()
    user_id = None
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin, is_unit_admin, manage_scripts, tenant_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, email, password_hash, is_admin, is_unit_admin, manage_scripts, tid, now)
            )
            conn.commit()
            user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            for u in (unit_ids or []):
                conn.execute(
                    "INSERT INTO user_units (user_id, unit_id, tenant_id) VALUES (?, ?, ?)",
                    (user_id, int(u), tid)
                )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                return jsonify({"error": "username already exists"}), 400
            raise
    logger.info(f"Usuario criado: {username}")
    return jsonify({"ok": True, "user_id": user_id})


@app.route("/api/users/<int:user_id>", methods=["POST"])
@require_login
def api_users_update(user_id):
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão para editar usuários"}), 403
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    is_admin = 1 if data.get("is_admin") else 0
    is_unit_admin = 1 if data.get("is_unit_admin") else 0
    manage_scripts = 1 if data.get("manage_scripts") else 0
    # env master pode mover o usuário para outra empresa; demais ficam na própria
    new_tid = None
    if not session.get("user_id") and data.get("tenant_id"):
        try:
            new_tid = int(data["tenant_id"])
        except (TypeError, ValueError):
            return jsonify({"error": "empresa inválida"}), 400
        with get_db() as conn:
            _t = conn.execute("SELECT tenant_id FROM tenants WHERE tenant_id = ?", (new_tid,)).fetchone()
        if not _t:
            return jsonify({"error": "empresa inválida"}), 400
    if not username or not email:
        return jsonify({"error": "username and email are required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "e-mail inválido"}), 400
    with get_db() as conn:
        # confere acesso: unit_admin só gerencia usuários das próprias unidades
        if role == "unit_admin":
            _ph = ",".join("?" * len(my_unit_ids))
            row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM user_units WHERE user_id = ? AND unit_id IN ({_ph})",
                [user_id] + list(my_unit_ids)
            ).fetchone()
            if not row or row["cnt"] == 0:
                return jsonify({"error": "sem acesso a este usuário"}), 403
            if is_admin:
                return jsonify({"error": "admin da unidade não pode promover admin master"}), 403
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() if password else None
        cols = ["username = ?", "email = ?", "is_admin = ?", "is_unit_admin = ?", "manage_scripts = ?"]
        params = [username, email, is_admin, is_unit_admin, manage_scripts]
        if password_hash:
            cols.append("password_hash = ?")
            params.append(password_hash)
        if new_tid is not None:
            cols.append("tenant_id = ?")
            params.append(new_tid)
        params.append(user_id)
        result = conn.execute("UPDATE users SET " + ", ".join(cols) + " WHERE user_id = ?", params)
        if new_tid is not None:
            # mudou de empresa: limpa vínculos antigos (a tela re-vincula depois)
            conn.execute("DELETE FROM user_units WHERE user_id = ?", (user_id,))
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    logger.info(f"Usuario atualizado: {username}")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_login
def api_users_delete(user_id):
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão para excluir usuários"}), 403
    if session.get("user_id") == user_id:
        return jsonify({"error": "você não pode excluir a própria conta"}), 400
    with get_db() as conn:
        if role == "unit_admin":
            row = conn.execute(
                """SELECT COUNT(*) as cnt FROM user_units
                   WHERE user_id = ? AND unit_id IN (%s)""" % (",".join("?" * len(my_unit_ids))),
                [user_id] + list(my_unit_ids)
            ).fetchone()
            if not row or row["cnt"] == 0:
                return jsonify({"error": "sem acesso a este usuário"}), 403
        conn.execute("DELETE FROM user_units WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
    logger.info(f"Usuario excluido: {user_id}")
    return jsonify({"ok": True})


# ================================
# API - VINCULAR PC A UNIDADE
# ================================
@app.route("/api/computers/<agent_id>/unit", methods=["POST"])
@require_login
def api_computer_set_unit(agent_id):
    role, unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "somente admins podem alterar unidade"}), 403
    data = request.get_json(silent=True) or {}
    unit_id = data.get("unit_id")
    # unit_admin só pode vincular a computador de unidade que administra
    if role == "unit_admin":
        target = unit_id
        if target is not None and target not in (unit_ids or []):
            return jsonify({"error": "sem acesso a esta unidade"}), 403
    with get_db() as conn:
        if unit_id:
            result = conn.execute(
                "UPDATE computers SET unit_id = ? WHERE agent_id = ?",
                (unit_id, agent_id)
            )
        else:
            result = conn.execute(
                "UPDATE computers SET unit_id = NULL WHERE agent_id = ?",
                (agent_id,)
            )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    log_computer_change(agent_id, "Unidade alterada", f"unit_id={unit_id}")
    logger.info(f"PC {agent_id} vinculado a unidade {unit_id}")
    return jsonify({"ok": True})


# ================================
# API - VINCULAR USUARIO A UNIDADE
# ================================
@app.route("/api/users/<int:user_id>/units", methods=["GET"])
@require_login
def api_user_units_list(user_id):
    role, my_unit_ids = current_user_access()
    with get_db() as conn:
        if role != "master":
            if not my_unit_ids:
                return jsonify([])
            ph = ",".join("?" * len(my_unit_ids))
            row = conn.execute(
                f"""SELECT COUNT(*) as cnt FROM user_units
                    WHERE user_id = ? AND unit_id IN ({ph})""",
                [user_id] + list(my_unit_ids)
            ).fetchone()
            if not row or row["cnt"] == 0:
                return jsonify([])
        rows = conn.execute(
            "SELECT u.unit_id, u.name, u.description FROM user_units uu JOIN units u ON u.unit_id = uu.unit_id WHERE uu.user_id = ? ORDER BY u.name",
            (user_id,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users/<int:user_id>/units", methods=["POST"])
@require_login
def api_user_units_set(user_id):
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão para editar usuários"}), 403
    data = request.get_json(silent=True) or {}
    unit_ids = [int(x) for x in (data.get("unit_ids") or [])]
    # env master pode vincular unidades de qualquer empresa; demais ficam na própria
    if not session.get("user_id") and data.get("tenant_id"):
        try:
            tid = int(data["tenant_id"])
        except (TypeError, ValueError):
            return jsonify({"error": "empresa inválida"}), 400
    else:
        tid = get_current_tenant()
    with get_db() as conn:
        if role == "unit_admin":
            allowed = set(my_unit_ids)
            if not set(unit_ids).issubset(allowed):
                return jsonify({"error": "você só pode vincular usuários às suas unidades"}), 403
            ph = ",".join("?" * len(my_unit_ids))
            trow = conn.execute(
                f"SELECT COUNT(*) as cnt FROM user_units WHERE user_id = ? AND unit_id IN ({ph})",
                [user_id] + list(my_unit_ids)
            ).fetchone()
            if not trow or trow["cnt"] == 0:
                return jsonify({"error": "sem acesso a este usuário"}), 403
        # confere que as unidades pertencem à empresa
        if unit_ids:
            ph = ",".join("?" * len(unit_ids))
            cnt = conn.execute(f"SELECT COUNT(*) as cnt FROM units WHERE unit_id IN ({ph}) AND tenant_id = ?", unit_ids + [tid]).fetchone()["cnt"]
            if cnt != len(set(unit_ids)):
                return jsonify({"error": "unidade inválida"}), 400
        conn.execute("DELETE FROM user_units WHERE user_id = ?", (user_id,))
        for unit_id in unit_ids:
            conn.execute(
                "INSERT INTO user_units (user_id, unit_id, tenant_id) VALUES (?, ?, ?) ON CONFLICT(user_id, unit_id) DO NOTHING",
                (user_id, unit_id, tid)
            )
        # mantém o usuário na mesma empresa das unidades vinculadas
        conn.execute("UPDATE users SET tenant_id = ? WHERE user_id = ?", (tid, user_id))
        conn.commit()
    logger.info(f"Unidades do usuario {user_id} atualizadas")
    return jsonify({"ok": True})


@app.route("/unidades")
@require_login
def unidades_page():
    return render_template("unidades.html")


@app.route("/usuarios")
@require_login
def usuarios_page():
    return render_template("usuarios.html")



# ================================
# API - TENANTS (EMPRESAS)
# ================================
@app.route("/api/tenants", methods=["GET"])
@require_login
def api_tenants_list():
    role, _ = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    with get_db() as conn:
        if not session.get("user_id"):
            rows = conn.execute("SELECT * FROM tenants ORDER BY name").fetchall()
        else:
            rows = conn.execute("SELECT * FROM tenants WHERE tenant_id = ? ORDER BY name", (get_current_tenant(),)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tenants", methods=["POST"])
@require_login
def api_tenants_create():
    if session.get("user_id"):
        return jsonify({"error": "somente o administrador geral pode gerenciar empresas"}), 403
    data = request.get_json(silent=True) or {}
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar empresas"}), 403

    name = (data.get("name") or "").strip()
    slug = (data.get("slug") or "").strip().lower().replace(" ", "-")
    description = (data.get("description") or "").strip()
    if not name or not slug:
        return jsonify({"error": "name and slug are required"}), 400
    now = utc_now_iso()
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO tenants (name, slug, description, created_at) VALUES (?, ?, ?, ?)",
                (name, slug, description, now)
            )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                return jsonify({"error": "tenant already exists"}), 400
            raise
    logger.info(f"Tenant criado: {name}")
    return jsonify({"ok": True})


@app.route("/api/tenants/<int:tenant_id>", methods=["POST"])
@require_login
def api_tenants_update(tenant_id):
    if session.get("user_id"):
        return jsonify({"error": "somente o administrador geral pode gerenciar empresas"}), 403
    data = request.get_json(silent=True) or {}
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar empresas"}), 403

    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    with get_db() as conn:
        result = conn.execute(
            "UPDATE tenants SET name = ?, description = ? WHERE tenant_id = ?",
            (name, description, tenant_id)
        )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/tenants/<int:tenant_id>", methods=["DELETE"])
@require_login
def api_tenants_delete(tenant_id):
    if session.get("user_id"):
        return jsonify({"error": "somente o administrador geral pode gerenciar empresas"}), 403
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master pode gerenciar empresas"}), 403
    if tenant_id == 1:
        return jsonify({"error": "cannot delete default tenant"}), 400
    with get_db() as conn:
        conn.execute("UPDATE computers SET tenant_id = 1 WHERE tenant_id = ?", (tenant_id,))
        conn.execute("UPDATE units SET tenant_id = 1 WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM users WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM scripts WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM jobs WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM locations WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM user_units WHERE tenant_id = ?", (tenant_id,))
        conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
        conn.commit()
    return jsonify({"ok": True})


@app.route("/empresas")
@require_login
def empresas_page():
    return render_template("empresas.html")


@app.route("/estrutura")
@require_login
def estrutura_page():
    return render_template("estrutura.html")


@app.route("/estrutura.js")
def estrutura_js():
    return send_file(os.path.join(APP_DIR, "estrutura.js"), mimetype="application/javascript")


# ================================
# API - DASHBOARD STATS
# ================================
@app.route("/api/dashboard", methods=["GET"])
@require_login
def api_dashboard():
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    extra, extra_params = unit_scope_clause("c")
    unit_ph = ""
    unit_params = []
    if role != "master" and unit_ids:
        unit_ph = ",".join("?" * len(unit_ids))
        unit_params = unit_ids
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) as cnt FROM computers c WHERE c.tenant_id = ?" + extra, [tid] + extra_params).fetchone()["cnt"]
        if role == "master":
            units = conn.execute("SELECT COUNT(*) as cnt FROM units WHERE tenant_id = ?", (tid,)).fetchone()["cnt"]
            users_count = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE tenant_id = ?", (tid,)).fetchone()["cnt"]
        elif unit_ids:
            ph = ",".join("?" * len(unit_ids))
            units = conn.execute("SELECT COUNT(*) as cnt FROM units WHERE tenant_id = ? AND unit_id IN (" + ph + ")", [tid] + unit_ids).fetchone()["cnt"]
            users_count = conn.execute("SELECT COUNT(DISTINCT u.user_id) as cnt FROM users u JOIN user_units uu ON uu.user_id = u.user_id WHERE u.tenant_id = ? AND uu.unit_id IN (" + ph + ")", [tid] + unit_ids).fetchone()["cnt"]
        else:
            units = 0
            users_count = 0
        scripts_count = conn.execute("SELECT COUNT(*) as cnt FROM scripts WHERE tenant_id = ?", (tid,)).fetchone()["cnt"]
        
        # PCs per unit
        if role == "master":
            per_unit = conn.execute("""
                SELECT COALESCE(u.name, 'Sem unidade') as unit_name, COUNT(*) as cnt
                FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
                WHERE c.tenant_id = ?
                GROUP BY c.unit_id ORDER BY cnt DESC
            """, (tid,)).fetchall()
        elif unit_ids:
            per_unit = conn.execute("""
                SELECT COALESCE(u.name, 'Sem unidade') as unit_name, COUNT(*) as cnt
                FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
                WHERE c.tenant_id = ? AND c.unit_id IN (""" + unit_ph + """)
                GROUP BY c.unit_id ORDER BY cnt DESC
            """, [tid] + unit_params).fetchall()
        else:
            per_unit = []
        
        # Recent jobs
        if role == "master":
            recent_jobs = conn.execute("""
                SELECT j.job_id, j.status, j.created_at, s.name as script_name, c.hostname
                FROM jobs j 
                LEFT JOIN scripts s ON s.script_id = j.script_id
                LEFT JOIN computers c ON c.device_uid = j.device_uid
                WHERE c.tenant_id = ?
                ORDER BY j.created_at DESC LIMIT 10
            """, (tid,)).fetchall()
        elif unit_ids:
            recent_jobs = conn.execute("""
                SELECT j.job_id, j.status, j.created_at, s.name as script_name, c.hostname
                FROM jobs j 
                LEFT JOIN scripts s ON s.script_id = j.script_id
                LEFT JOIN computers c ON c.device_uid = j.device_uid
                WHERE c.tenant_id = ? AND c.unit_id IN (""" + unit_ph + """)
                ORDER BY j.created_at DESC LIMIT 10
            """, [tid] + unit_params).fetchall()
        else:
            recent_jobs = []
        
        # Agent stats from payload
        if role == "master":
            computers_data = conn.execute("SELECT payload_json, last_seen, unit_id FROM computers WHERE tenant_id = ?", (tid,)).fetchall()
        elif unit_ids:
            computers_data = conn.execute("SELECT payload_json, last_seen, unit_id FROM computers WHERE tenant_id = ? AND unit_id IN (" + unit_ph + ")", [tid] + unit_params).fetchall()
        else:
            computers_data = []
        cpu_avg = 0
        ram_avg = 0
        disk_total = 0
        disk_used = 0
        os_stats = {}
        total_with_payload = 0
        
        for comp in computers_data:
            if not comp["payload_json"]:
                continue
            try:
                p = json.loads(comp["payload_json"])
                total_with_payload += 1
                # CPU: use cpu_percent if available, else 0
                if "cpu_percent" in p:
                    cpu_avg += float(p["cpu_percent"])
                # RAM: use ram_percent if available, else 0
                if "ram_percent" in p:
                    ram_avg += float(p["ram_percent"])
                # Disks: check 'disks' (bytes), 'volumes' (GB), 'physical_disks' (GB)
                disk_list = p.get("disks") or p.get("volumes") or []
                for d in disk_list:
                    if isinstance(d, dict):
                        if "total" in d and "used" in d:
                            disk_total += d["total"]
                            disk_used += d["used"]
                        elif "total_gb" in d:
                            disk_total += d["total_gb"] * (1024**3)
                            disk_used += (d.get("total_gb", 0) - d.get("free_gb", 0)) * (1024**3)
                        elif "size" in d:
                            disk_total += d["size"]
                            disk_used += d.get("used", 0)
                # OS: check 'os', 'os_caption', 'os_version'
                os_name = p.get("os") or p.get("os_caption") or p.get("os_version") or "Desconhecido"
                os_stats[os_name] = os_stats.get(os_name, 0) + 1
            except:
                pass
        
        if total_with_payload > 0:
            cpu_avg = round(cpu_avg / total_with_payload, 1)
            ram_avg = round(ram_avg / total_with_payload, 1)

        # KPIs por unidade (item 13): chamados abertos, PCs offline, tempo medio de resolucao
        from datetime import timedelta
        t_extra, t_params = unit_scope_clause("t")
        open_tickets = conn.execute("SELECT COUNT(*) as c FROM tickets t WHERE t.tenant_id = ? AND t.status IN ('open','in_progress')" + t_extra, [tid] + t_params).fetchone()["c"]
        off_extra, off_params = unit_scope_clause("c")
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        offline_pcs = conn.execute("SELECT COUNT(*) as c FROM computers c WHERE c.tenant_id = ? AND (c.last_seen IS NULL OR c.last_seen < ?)" + off_extra, [tid, cutoff] + off_params).fetchone()["c"]
        avg_hours = conn.execute("SELECT AVG((julianday(t.resolved_at) - julianday(t.created_at)) * 24) as a FROM tickets t WHERE t.tenant_id = ? AND t.resolved_at IS NOT NULL" + t_extra, [tid] + t_params).fetchone()["a"] or 0

        return jsonify({
            "open_tickets": open_tickets,
            "offline_pcs": offline_pcs,
            "avg_resolution_hours": round(avg_hours, 1),
            "total_computers": total,
            "total_units": units,
            "total_users": users_count,
            "total_scripts": scripts_count,
            "computers_per_unit": [{"unit": r["unit_name"], "count": r["cnt"]} for r in per_unit],
            "recent_jobs": [{"job_id": r["job_id"], "status": r["status"], "created_at": r["created_at"], "script_name": r["script_name"], "hostname": r["hostname"]} for r in recent_jobs],
            "cpu_average": cpu_avg,
            "ram_average": ram_avg,
            "disk_total_gb": round(disk_total / (1024**3), 1) if disk_total else 0,
            "disk_used_gb": round(disk_used / (1024**3), 1) if disk_used else 0,
            "os_distribution": os_stats,
            "scope": "unit" if role != "master" else "company"
        })




# ================================
# API - OFFLINE ALERTS
# ================================
@app.route("/api/alerts", methods=["GET"])
@require_login
def api_alerts_list():
    tid = get_current_tenant()
    extra, extra_params = unit_scope_clause("c")
    with get_db() as conn:
        rows = conn.execute(
            """SELECT a.*, c.hostname, c.tag_evo 
               FROM alerts a 
               LEFT JOIN computers c ON a.agent_id = c.agent_id
               WHERE a.tenant_id = ?""" + extra + """
               ORDER BY a.created_at DESC LIMIT 50""",
            [tid] + extra_params
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts/unread-count", methods=["GET"])
@require_login
def api_alerts_unread_count():
    tid = get_current_tenant()
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) as cnt FROM alerts WHERE tenant_id = ? AND is_read = 0",
            (tid,)
        ).fetchone()["cnt"]
    return jsonify({"count": count})


@app.route("/api/alerts/mark-read", methods=["POST"])
@require_login
def api_alerts_mark_read():
    tid = get_current_tenant()
    with get_db() as conn:
        conn.execute(
            "UPDATE alerts SET is_read = 1 WHERE tenant_id = ? AND is_read = 0",
            (tid,)
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/alerts/check-offline", methods=["POST"])
@require_login
def api_alerts_check_offline():
    """Check for offline PCs and create alerts"""
    from datetime import timedelta
    tid = get_current_tenant()
    threshold_minutes = int(request.json.get("threshold_minutes", 60)) if request.is_json else 60
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=threshold_minutes)).isoformat()
    
    with get_db() as conn:
        # Find PCs not seen within threshold
        offline_pcs = conn.execute(
            """SELECT agent_id, hostname, tag_evo, last_seen 
               FROM computers 
               WHERE tenant_id = ? AND (last_seen IS NULL OR last_seen < ?)""",
            (tid, cutoff)
        ).fetchall()
        
        alerts_created = 0
        for pc in offline_pcs:
            # Check if alert already exists for this PC
            existing = conn.execute(
                """SELECT alert_id FROM alerts 
                   WHERE agent_id = ? AND is_read = 0 AND alert_type = 'offline'""",
                (pc["agent_id"],)
            ).fetchone()
            
            if not existing:
                conn.execute(
                    """INSERT INTO alerts (tenant_id, agent_id, alert_type, message, created_at) 
                       VALUES (?, ?, 'offline', ?, ?)""",
                    (tid, pc["agent_id"], 
                     f"PC {pc['hostname'] or pc['agent_id']} está offline desde {pc['last_seen'] or 'desconhecido'}",
                     now.isoformat())
                )
                alerts_created += 1
        
        conn.commit()
    
    return jsonify({"ok": True, "alerts_created": alerts_created, "offline_count": len(offline_pcs)})

# ================================
# API - EXPORT CSV
# ================================
@app.route("/api/export/csv", methods=["GET"])
@require_login
def api_export_csv():
    import io, csv
    unit_name = request.args.get("unit_name", "").strip()
    extra, extra_params = unit_scope_clause("c")
    with get_db() as conn:
        if unit_name:
            rows = conn.execute("""
                SELECT c.hostname, c.alias, c.tag_evo, c.last_seen, c.unit_id,
                       u.name as unit_name, c.payload_json
                FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
                WHERE u.name = ?""" + extra + " ORDER BY c.hostname",
                [unit_name] + extra_params).fetchall()
        else:
            rows = conn.execute("""
                SELECT c.hostname, c.alias, c.tag_evo, c.last_seen, c.unit_id,
                       u.name as unit_name, c.payload_json
                FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
                WHERE 1=1""" + extra + " ORDER BY c.hostname",
                extra_params).fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Hostname", "Alias", "Tag EVO", "Unidade", "CPU", "RAM", "OS", "IP", "Ultimo Envio"])
    
    for r in rows:
        p = {}
        if r["payload_json"]:
            try: p = json.loads(r["payload_json"])
            except: pass
        # Extract IP from network
        ip_addr = "N/A"
        net = p.get("network", {})
        if isinstance(net, dict):
            ip_addr = net.get("ip", "N/A")
        
        writer.writerow([
            r["hostname"] or "",
            r["alias"] or "",
            r["tag_evo"] or "",
            r["unit_name"] or "Sem unidade",
            p.get("cpu", "N/A"),
            str(p.get("ram_total_gb", "N/A")) + " GB" if "ram_total_gb" in p else "N/A",
            p.get("os_caption") or p.get("os") or "N/A",
            ip_addr,
            r["last_seen"] or "N/A"
        ])
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventario.csv"}
    )


# ================================
# API - EXPORT PDF (PCs POR UNIDADE)
# ================================
@app.route("/api/export/pdf", methods=["GET"])
@require_login
def api_export_pdf():
    from fpdf import FPDF
    import io
    
    extra, extra_params = unit_scope_clause("c")
    with get_db() as conn:
        # Get all units with PC counts
        units_data = conn.execute("""
            SELECT COALESCE(u.name, 'Sem unidade') as unit_name, COUNT(*) as pc_count
            FROM computers c 
            LEFT JOIN units u ON c.unit_id = u.unit_id
            WHERE 1=1""" + extra + """
            GROUP BY c.unit_id 
            ORDER BY pc_count DESC
        """, extra_params).fetchall()
        
        # Get total
        total = conn.execute("SELECT COUNT(*) as cnt FROM computers c WHERE 1=1" + extra, extra_params).fetchone()["cnt"]
        
        # Get all computers with details per unit
        all_computers = conn.execute("""
            SELECT c.hostname, c.tag_evo, c.alias, c.last_seen,
                   COALESCE(u.name, 'Sem unidade') as unit_name, c.payload_json
            FROM computers c 
            LEFT JOIN units u ON c.unit_id = u.unit_id
            WHERE 1=1""" + extra + """
            ORDER BY u.name, c.hostname
        """, extra_params).fetchall()
    
    class PDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 14)
            self.cell(0, 10, "Relatorio de Inventario por Unidade", 0, 1, "C")
            self.ln(5)
        
        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.cell(0, 10, f"Pagina {self.page_no()}/{{nb}}", 0, 0, "C")
    
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Summary section
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Resumo Geral", 0, 1, "L")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Total de PCs cadastrados: {total}", 0, 1, "L")
    pdf.cell(0, 8, f"Total de Unidades: {len(units_data)}", 0, 1, "L")
    pdf.ln(5)
    
    # PCs per unit table
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "PCs por Unidade", 0, 1, "L")
    pdf.ln(3)
    
    # Table header
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(226, 232, 240)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(100, 8, "Unidade", 1, 0, "C", True)
    pdf.cell(40, 8, "Quantidade", 1, 0, "C", True)
    pdf.cell(40, 8, "Percentual", 1, 1, "C", True)
    
    # Table rows
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)
    for row in units_data:
        pct = round((row["pc_count"] / total * 100), 1) if total > 0 else 0
        pdf.cell(100, 8, row["unit_name"], 1, 0, "L")
        pdf.cell(40, 8, str(row["pc_count"]), 1, 0, "C")
        pdf.cell(40, 8, f"{pct}%", 1, 1, "C")
    
    # Total row
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(100, 8, "TOTAL", 1, 0, "L")
    pdf.cell(40, 8, str(total), 1, 0, "C")
    pdf.cell(40, 8, "100%", 1, 1, "C")
    
    pdf.ln(10)
    
    # Detail section per unit
    current_unit = None
    for comp in all_computers:
        if comp["unit_name"] != current_unit:
            current_unit = comp["unit_name"]
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10, f"Unidade: {current_unit}", 0, 1, "L")
            pdf.ln(3)
            
            # Table header
            pdf.set_fill_color(30, 41, 59)
            pdf.set_text_color(226, 232, 240)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(40, 7, "Hostname", 1, 0, "C", True)
            pdf.cell(30, 7, "Tag EVO", 1, 0, "C", True)
            pdf.cell(40, 7, "CPU", 1, 0, "C", True)
            pdf.cell(25, 7, "RAM", 1, 0, "C", True)
            pdf.cell(45, 7, "Ultimo Envio", 1, 1, "C", True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 8)
        
        p = {}
        if comp["payload_json"]:
            try: p = json.loads(comp["payload_json"])
            except: pass
        
        hostname = (comp["hostname"] or "N/A")[:20]
        tag = comp["tag_evo"] or "N/A"
        cpu = (p.get("cpu", "N/A") or "N/A")[:25]
        ram = str(p.get("ram_total_gb", "N/A")) + " GB" if "ram_total_gb" in p else "N/A"
        last = (comp["last_seen"] or "N/A")[:16]
        
        pdf.cell(40, 7, hostname, 1, 0, "L")
        pdf.cell(30, 7, tag, 1, 0, "C")
        pdf.cell(40, 7, cpu, 1, 0, "L")
        pdf.cell(25, 7, ram, 1, 0, "C")
        pdf.cell(45, 7, last, 1, 1, "L")
    
    # Generate PDF
    pdf_output = io.BytesIO()
    pdf.output(pdf_output)
    pdf_output.seek(0)
    
    from flask import Response
    return Response(
        pdf_output.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=relatorio_inventario.pdf"}
    )




# ================================
# API - METRICS HISTORY
# ================================
@app.route("/api/metrics/history", methods=["GET"])
@require_login
def api_metrics_history():
    agent_id = request.args.get("agent_id")
    days = int(request.args.get("days", 7))
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    
    with get_db() as conn:
        if agent_id:
            if not computer_in_scope(agent_id):
                return jsonify([])
            rows = conn.execute(
                "SELECT * FROM metrics_history WHERE agent_id = ? AND recorded_at > ? ORDER BY recorded_at ASC",
                (agent_id, cutoff)
            ).fetchall()
        elif role == "master":
            rows = conn.execute(
                "SELECT mh.*, c.hostname FROM metrics_history mh LEFT JOIN computers c ON mh.agent_id = c.agent_id WHERE mh.recorded_at > ? AND mh.tenant_id = ? ORDER BY mh.recorded_at ASC",
                (cutoff, tid)
            ).fetchall()
        elif unit_ids:
            ph = ",".join("?" * len(unit_ids))
            rows = conn.execute(
                "SELECT mh.*, c.hostname FROM metrics_history mh LEFT JOIN computers c ON mh.agent_id = c.agent_id WHERE mh.recorded_at > ? AND mh.tenant_id = ? AND c.unit_id IN (" + ph + ") ORDER BY mh.recorded_at ASC",
                [cutoff, tid] + unit_ids
            ).fetchall()
        else:
            rows = []
    return jsonify([dict(r) for r in rows])


@app.route("/api/metrics/summary", methods=["GET"])
@require_login
def api_metrics_summary():
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    # join para filtrar por unidade
    unit_join = ""
    if role != "master":
        if not unit_ids:
            return jsonify({"current": {}, "this_week": {}, "last_week": {}})
        unit_join = " JOIN computers c ON mh.agent_id = c.agent_id AND c.unit_id IN (" + ",".join("?" * len(unit_ids)) + ")"
    with get_db() as conn:
        params_base = [tid]
        if role != "master":
            params_base = params_base + unit_ids
        current = conn.execute(
            "SELECT AVG(mh.cpu_percent) as cpu_avg, AVG(mh.ram_percent) as ram_avg, SUM(mh.disk_used_gb) as disk_used, SUM(mh.disk_total_gb) as disk_total FROM metrics_history mh" + unit_join + " WHERE mh.tenant_id = ? AND mh.recorded_at > datetime('now', '-1 hour')",
            params_base
        ).fetchone()
        
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        week_ago = (now - timedelta(days=7)).isoformat()
        two_weeks_ago = (now - timedelta(days=14)).isoformat()
        
        this_week = conn.execute(
            "SELECT AVG(mh.cpu_percent) as cpu, AVG(mh.ram_percent) as ram FROM metrics_history mh" + unit_join + " WHERE mh.tenant_id = ? AND mh.recorded_at > ?",
            params_base + [week_ago]
        ).fetchone()
        
        last_week = conn.execute(
            "SELECT AVG(mh.cpu_percent) as cpu, AVG(mh.ram_percent) as ram FROM metrics_history mh" + unit_join + " WHERE mh.tenant_id = ? AND mh.recorded_at > ? AND mh.recorded_at <= ?",
            params_base + [two_weeks_ago, week_ago]
        ).fetchone()
        
    return jsonify({
        "current": dict(current) if current else {},
        "this_week": dict(this_week) if this_week else {},
        "last_week": dict(last_week) if last_week else {}
    })


# ================================
# API - MAINTENANCE ALERTS
# ================================
@app.route("/api/maintenance", methods=["GET"])
@require_login
def api_maintenance_list():
    tid = get_current_tenant()
    extra, extra_params = unit_scope_clause("c")
    with get_db() as conn:
        rows = conn.execute(
            "SELECT m.*, c.hostname, c.tag_evo FROM maintenance_alerts m LEFT JOIN computers c ON m.agent_id = c.agent_id WHERE m.tenant_id = ?" + extra + " ORDER BY m.created_at DESC LIMIT 50",
            [tid] + extra_params
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/maintenance/<int:alert_id>/resolve", methods=["POST"])
@require_login
def api_maintenance_resolve(alert_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE maintenance_alerts SET is_resolved = 1, resolved_at = ? WHERE alert_id = ?",
            (utc_now_iso(), alert_id)
        )
        conn.commit()
    return jsonify({"ok": True})


# ================================
# API - TICKETS
# ================================
@app.route("/api/tickets", methods=["GET"])
@require_login
def api_tickets_list():
    tenant = get_user_tenant()
    status = request.args.get("status")
    role, unit_ids = current_user_access()
    extra, extra_params = unit_scope_clause("t")
    with get_db() as conn:
        if status:
            rows = conn.execute(
                "SELECT t.*, c.hostname FROM tickets t LEFT JOIN computers c ON t.agent_id = c.agent_id WHERE t.tenant_id = ? AND t.status = ?" + extra + " ORDER BY t.created_at DESC",
                [tenant, status] + extra_params
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT t.*, c.hostname FROM tickets t LEFT JOIN computers c ON t.agent_id = c.agent_id WHERE t.tenant_id = ?" + extra + " ORDER BY t.created_at DESC",
                [tenant] + extra_params
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tickets", methods=["POST"])
@require_login
def api_tickets_create():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    agent_id = data.get("agent_id")
    priority = data.get("priority", "medium")
    
    if not title:
        return jsonify({"error": "title is required"}), 400
    
    now = utc_now_iso()
    tid = get_current_tenant()
    user = session.get("user", "system")
    
    role, my_unit_ids = current_user_access()
    unit_id = None
    sla_due = sla_due_from(now, priority)
    with get_db() as conn:
        # define unidade do chamado a partir do computador ou da unidade do usuário
        if agent_id:
            c_row = conn.execute("SELECT unit_id FROM computers WHERE agent_id = ?", (agent_id,)).fetchone()
            if c_row and c_row["unit_id"]:
                unit_id = c_row["unit_id"]
        if unit_id is None and role != "master":
            unit_id = my_unit_ids[0] if my_unit_ids else None
        conn.execute(
            "INSERT INTO tickets (tenant_id, agent_id, title, description, status, priority, created_by, unit_id, sla_due, created_at, updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)",
            (tid, agent_id, title, description, priority, user, unit_id, sla_due, now, now)
        )
        ticket_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
    return jsonify({"ok": True, "ticket_id": ticket_id})


@app.route("/api/tickets/<int:ticket_id>", methods=["POST"])
@require_login
def api_tickets_update(ticket_id):
    data = request.get_json(silent=True) or {}
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    now = utc_now_iso()
    
    with get_db() as conn:
        updates = []
        params = []
        
        if "status" in data:
            updates.append("status = ?")
            params.append(data["status"])
            if data["status"] in ("closed", "resolved"):
                updates.append("closed_at = ?")
                params.append(now)
        
        if "priority" in data:
            updates.append("priority = ?")
            params.append(data["priority"])
            updates.append("sla_due = ?")
            params.append(sla_due_from(now, data["priority"]))
        
        if "assigned_to" in data:
            updates.append("assigned_to = ?")
            params.append(data["assigned_to"])
        
        updates.append("updated_at = ?")
        params.append(now)
        params.append(ticket_id)
        
        conn.execute("UPDATE tickets SET " + ", ".join(updates) + " WHERE ticket_id = ?", params)
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>", methods=["DELETE"])
@require_login
def api_tickets_delete(ticket_id):
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    with get_db() as conn:
        conn.execute("DELETE FROM tickets WHERE ticket_id = ?", (ticket_id,))
        conn.commit()
    return jsonify({"ok": True})


# ================================
# API - TICKETS - ENHANCED
# ================================

@app.route("/api/tickets/<int:ticket_id>/assign", methods=["POST"])
@require_login
def api_ticket_assign(ticket_id):
    data = request.get_json(silent=True) or {}
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    assigned_raw = (data.get("assigned_to") or "").strip()
    now = utc_now_iso()
    user = session.get("user", "system")
    tid = None
    with get_db() as conn:
        row = conn.execute("SELECT tenant_id, unit_id, assigned_to FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
        old_val = row["assigned_to"] if row else None
        tid = row["tenant_id"] if row else None
        assigned_to = None
        target_uid = None
        if assigned_raw:
            urow = conn.execute(
                "SELECT user_id, username FROM users WHERE tenant_id = ? AND (lower(username) = lower(?) OR CAST(user_id AS TEXT) = ?)",
                (tid, assigned_raw, assigned_raw),
            ).fetchone()
            if urow:
                assigned_to = urow["username"]
                target_uid = urow["user_id"]
            else:
                assigned_to = assigned_raw
        conn.execute("UPDATE tickets SET assigned_to = ?, updated_at = ? WHERE ticket_id = ?", (assigned_to, now, ticket_id))
        conn.execute("INSERT INTO ticket_history (ticket_id, action, old_value, new_value, performed_by, created_at) VALUES (?, 'assigned', ?, ?, ?, ?)",
            (ticket_id, old_val, assigned_to, user, now))
        conn.commit()
    if assigned_to:
        title = f"Chamado #{ticket_id} atribuido a voce"
        if target_uid:
            create_notification(tid, title, f"O chamado #{ticket_id} foi atribuido a voce.", link="/chamados", user_ids=[target_uid])
        else:
            notify_ticket_event(ticket_id, title, f"O chamado #{ticket_id} foi atribuido a {assigned_to}.", link="/chamados")
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>/start", methods=["POST"])
@require_login
def api_ticket_start(ticket_id):
    data = request.get_json(silent=True) or {}
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    notes = (data.get('notes') or '').strip()
    now = utc_now_iso()
    user = session.get("user", "system")
    with get_db() as conn:
        conn.execute("UPDATE tickets SET status = 'in_progress', first_response_at = COALESCE(first_response_at, ?), updated_at = ? WHERE ticket_id = ?",
            (now, now, ticket_id))
        conn.execute("INSERT INTO ticket_history (ticket_id, action, old_value, new_value, performed_by, created_at) VALUES (?, 'status_changed', 'open', 'in_progress', ?, ?)",
            (ticket_id, user, now))
        if notes:
            conn.execute("INSERT INTO ticket_notes (ticket_id, author, content, is_internal, created_at) VALUES (?, ?, ?, 0, ?)",
                (ticket_id, user, notes, now))
        conn.commit()
    _notify_status(ticket_id, "open", "in_progress")
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>/resolve", methods=["POST"])
@require_login
def api_ticket_resolve(ticket_id):
    data = request.get_json(silent=True) or {}
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    resolution_notes = (data.get("resolution_notes") or "").strip()
    now = utc_now_iso()
    user = session.get("user", "system")
    with get_db() as conn:
        conn.execute("UPDATE tickets SET status = 'resolved', resolution_notes = ?, resolved_at = ?, updated_at = ? WHERE ticket_id = ?",
            (resolution_notes, now, now, ticket_id))
        conn.execute("INSERT INTO ticket_history (ticket_id, action, old_value, new_value, performed_by, created_at) VALUES (?, 'resolved', 'in_progress', 'resolved', ?, ?)",
            (ticket_id, user, now))
        conn.commit()
    notify_ticket_event(ticket_id, f"Chamado #{ticket_id} resolvido", "O chamado foi resolvido. Confira a resolucao.", link="/chamados")
    _notify_status(ticket_id, "in_progress", "resolved")
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>/close", methods=["POST"])
@require_login
def api_ticket_close(ticket_id):
    data = request.get_json(silent=True) or {}
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    resolution_notes = (data.get("resolution_notes") or "").strip()
    now = utc_now_iso()
    user = session.get("user", "system")
    with get_db() as conn:
        conn.execute("UPDATE tickets SET status = 'closed', resolution_notes = COALESCE(NULLIF(?, ''), resolution_notes), closed_at = ?, updated_at = ? WHERE ticket_id = ?",
            (resolution_notes or None, now, now, ticket_id))
        conn.execute("INSERT INTO ticket_history (ticket_id, action, old_value, new_value, performed_by, created_at) VALUES (?, 'closed', 'resolved', 'closed', ?, ?)",
            (ticket_id, user, now))
        conn.commit()
    notify_ticket_event(ticket_id, f"Chamado #{ticket_id} encerrado", "O chamado foi encerrado.", link="/chamados")
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>/reopen", methods=["POST"])
@require_login
def api_ticket_reopen(ticket_id):
    now = utc_now_iso()
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    user = session.get("user", "system")
    with get_db() as conn:
        conn.execute("UPDATE tickets SET status = 'open', closed_at = NULL, resolved_at = NULL, updated_at = ? WHERE ticket_id = ?", (now, ticket_id))
        conn.execute("INSERT INTO ticket_history (ticket_id, action, old_value, new_value, performed_by, created_at) VALUES (?, 'status_changed', 'closed', 'open', ?, ?)",
            (ticket_id, user, now))
        conn.commit()
    notify_ticket_event(ticket_id, f"Chamado #{ticket_id} reaberto", "O chamado foi reaberto.", link="/chamados")
    return jsonify({"ok": True})

@app.route("/api/tickets/<int:ticket_id>/notes", methods=["GET"])
@require_login
def api_ticket_notes_list(ticket_id):
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM ticket_notes WHERE ticket_id = ? ORDER BY created_at DESC", (ticket_id,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tickets/<int:ticket_id>/notes", methods=["POST"])
@require_login
def api_ticket_notes_add(ticket_id):
    data = request.get_json(silent=True) or {}
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    content_text = (data.get("content") or "").strip()
    is_internal = data.get("is_internal", 0)
    if not content_text:
        return jsonify({"error": "content required"}), 400
    now = utc_now_iso()
    user = session.get("user", "system")
    with get_db() as conn:
        conn.execute("INSERT INTO ticket_notes (ticket_id, author, content, is_internal, created_at) VALUES (?, ?, ?, ?, ?)",
            (ticket_id, user, content_text, 1 if is_internal else 0, now))
        conn.execute("UPDATE tickets SET updated_at = ? WHERE ticket_id = ?", (now, ticket_id))
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>/history", methods=["GET"])
@require_login
def api_ticket_history(ticket_id):
    if not ticket_in_scope(ticket_id):
        return jsonify({"error": "sem acesso a este chamado"}), 403
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM ticket_history WHERE ticket_id = ? ORDER BY created_at DESC", (ticket_id,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tickets/stats", methods=["GET"])
@require_login
def api_tickets_stats():
    tid = get_current_tenant()
    extra, extra_params = unit_scope_clause("t")
    with get_db() as conn:
        stats = {}
        for st in ['open', 'in_progress', 'on_hold', 'resolved', 'closed']:
            row = conn.execute("SELECT COUNT(*) as cnt FROM tickets t WHERE t.tenant_id = ? AND t.status = ?" + extra, [tid, st] + extra_params).fetchone()
            stats[st] = row["cnt"]
        stats["total"] = sum(stats.values())
    return jsonify(stats)

@app.route("/api/tickets/report", methods=["GET"])
@require_login
def api_tickets_report():
    tid = get_current_tenant()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    status = request.args.get("status", "")
    extra, extra_params = unit_scope_clause("t")
    query = "SELECT t.*, c.hostname FROM tickets t LEFT JOIN computers c ON t.agent_id = c.agent_id WHERE t.tenant_id = ?" + extra
    params = [tid] + extra_params
    if status:
        query += " AND t.status = ?"
        params.append(status)
    if date_from:
        query += " AND t.created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND t.created_at <= ?"
        params.append(date_to + "T23:59:59")
    query += " ORDER BY t.created_at DESC"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tickets/report/pdf", methods=["GET"])
@require_login
def api_tickets_report_pdf():
    from fpdf import FPDF
    from flask import Response
    tid = get_current_tenant()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    status = request.args.get("status", "")
    extra, extra_params = unit_scope_clause("t")
    query = "SELECT t.*, c.hostname FROM tickets t LEFT JOIN computers c ON t.agent_id = c.agent_id WHERE t.tenant_id = ?" + extra
    params = [tid] + extra_params
    if status:
        query += " AND t.status = ?"
        params.append(status)
    if date_from:
        query += " AND t.created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND t.created_at <= ?"
        params.append(date_to + "T23:59:59")
    query += " ORDER BY t.created_at DESC"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        tenant = conn.execute("SELECT name FROM tenants WHERE tenant_id = ?", (tid,)).fetchone()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "AtivoFix - Relatorio de Chamados", 0, 1, "C")
    pdf.set_font("Helvetica", "", 12)
    tname = tenant["name"] if tenant else "N/A"
    pdf.cell(0, 8, "Empresa: " + tname, 0, 1)
    if date_from or date_to:
        pdf.cell(0, 8, "Periodo: " + (date_from or "Inicio") + " a " + (date_to or "Fim"), 0, 1)
    pdf.cell(0, 8, "Total: " + str(len(rows)), 0, 1)
    pdf.ln(5)
    sl = {"open": "Abertos", "in_progress": "Em Andamento", "on_hold": "Em Espera", "resolved": "Resolvidos", "closed": "Fechados"}
    sc = {}
    for r in rows:
        s = r["status"]
        sc[s] = sc.get(s, 0) + 1
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Resumo por Status", 0, 1)
    pdf.set_font("Helvetica", "", 11)
    for s, cnt in sc.items():
        pdf.cell(0, 7, sl.get(s, s) + ": " + str(cnt), 0, 1)
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(56, 189, 248)
    pdf.set_text_color(255, 255, 255)
    for hdr in ["ID", "Titulo", "Status", "Prioridade", "PC", "Criado"]:
        pdf.cell(30 if hdr == "Titulo" else 20, 8, hdr, 1, 0, "C", True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(0, 0, 0)
    fill = False
    for r in rows:
        fc = (240, 240, 240) if fill else (255, 255, 255)
        pdf.set_fill_color(*fc)
        pdf.cell(20, 7, str(r["ticket_id"]), 1, 0, "C", True)
        pdf.cell(30, 7, (r["title"] or "")[:15], 1, 0, "L", True)
        pdf.cell(20, 7, sl.get(r["status"], r["status"])[:10], 1, 0, "C", True)
        pdf.cell(20, 7, r["priority"].capitalize()[:8], 1, 0, "C", True)
        pdf.cell(20, 7, (r["hostname"] or "N/A")[:10], 1, 0, "C", True)
        pdf.cell(20, 7, (r["created_at"] or "")[:10], 1, 0, "C", True)
        pdf.ln()
        fill = not fill
    output = pdf.output()
    return Response(output, mimetype="application/pdf", headers={"Content-Disposition": "attachment; filename=relatorio_chamados.pdf"})

# ================================
# PAGES
# ================================
@app.route("/manutencao")
@require_login
def manutencao_page():
    return render_template("manutencao.html")


@app.route("/chamados")
@require_login
def chamados_page():
    return render_template("chamados.html")


# ================================
# PAGE - DASHBOARD
# ================================


# === Email Notification System ===
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "suporte@ativofix.com")
EMAIL_ENABLED = bool(SMTP_HOST and SMTP_USER)

def send_email(to, subject, body):
    """Send email notification if SMTP is configured."""
    if not EMAIL_ENABLED or not to:
        return False
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_FROM
        msg["To"] = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def notify_ticket_created(ticket_id, title, created_by, email=None):
    subject = f"[AtivoFix] Chamado #{ticket_id} criado - {title}"
    body = f"""<div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto">
    <div style="background:linear-gradient(135deg,#38bdf8,#818cf8);padding:20px;border-radius:12px 12px 0 0;text-align:center">
        <h1 style="color:white;margin:0">AtivoFix</h1>
        <p style="color:rgba(255,255,255,.8);margin:4px 0 0">Chamado Criado</p>
    </div>
    <div style="background:#1e293b;padding:24px;border-radius:0 0 12px 12px;color:#e2e8f0">
        <h2 style="margin:0 0 16px">#{ticket_id} - {title}</h2>
        <p>Seu chamado foi registrado com sucesso!</p>
        <div style="background:rgba(51,65,85,.3);padding:12px;border-radius:8px;margin:16px 0">
            <p style="margin:0"><strong>Status:</strong> Aberto</p>
            <p style="margin:4px 0 0"><strong>Prioridade:</strong> Media</p>
        </div>
        <p style="font-size:13px;color:#94a3b8">Acompanhe seu chamado em: <a href="#" style="color:#38bdf8">AtivoFix - Acompanhar Chamado</a></p>
    </div>
</div>"""
    if email:
        send_email(email, subject, body)


def _notify_status(ticket_id, old_status, new_status):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT title, created_by FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            if row:
                email = None
                if "(" in row["created_by"]:
                    email = row["created_by"].split("(")[1].rstrip(")")
                notify_status_changed(ticket_id, row["title"], old_status, new_status, email)
    except: pass

def notify_status_changed(ticket_id, title, old_status, new_status, email=None):
    SL = {"open": "Aberto", "in_progress": "Em Andamento", "resolved": "Resolvido", "closed": "Fechado"}
    subject = f"[AtivoFix] Chamado #{ticket_id} - Status alterado para {SL.get(new_status, new_status)}"
    body = f"""<div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto">
    <div style="background:linear-gradient(135deg,#38bdf8,#818cf8);padding:20px;border-radius:12px 12px 0 0;text-align:center">
        <h1 style="color:white;margin:0">AtivoFix</h1>
        <p style="color:rgba(255,255,255,.8);margin:4px 0 0">Status Atualizado</p>
    </div>
    <div style="background:#1e293b;padding:24px;border-radius:0 0 12px 12px;color:#e2e8f0">
        <h2 style="margin:0 0 16px">#{ticket_id} - {title}</h2>
        <p>O status do seu chamado foi alterado:</p>
        <div style="background:rgba(51,65,85,.3);padding:12px;border-radius:8px;margin:16px 0;text-align:center">
            <span style="color:#94a3b8">{SL.get(old_status, old_status)}</span>
            <span style="color:#38bdf8;margin:0 12px">→</span>
            <span style="color:#22c55e;font-weight:bold">{SL.get(new_status, new_status)}</span>
        </div>
    </div>
</div>"""
    if email:
        send_email(email, subject, body)


def get_user_tenant():
    """Get current user's tenant_id from session."""
    return session.get('tenant_id', 1)

def require_tenant(f):
    """Decorator to add tenant_id to function."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        kwargs['tenant_id'] = get_user_tenant()
        return f(*args, **kwargs)
    return decorated

@app.route("/dashboard")
@require_login
def dashboard_page():
    return render_template("dashboard.html")


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "internal server error"}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "rate limit exceeded"}), 429







@app.route("/suporte")
@require_login
def suporte_dashboard():
    return render_template("dashboard_chamados.html")

@app.route("/api/tickets/dashboard")
@require_login
def api_tickets_dashboard():
    tid = get_current_tenant()
    extra, extra_params = unit_scope_clause("t")
    with get_db() as conn:
        # Tickets by status
        status_counts = {}
        for row in conn.execute("SELECT t.status, COUNT(*) as cnt FROM tickets t WHERE t.tenant_id = ?" + extra + " GROUP BY t.status", [tid] + extra_params):
            status_counts[row["status"]] = row["cnt"]
        
        # Tickets by priority
        priority_counts = {}
        for row in conn.execute("SELECT t.priority, COUNT(*) as cnt FROM tickets t WHERE t.tenant_id = ?" + extra + " GROUP BY t.priority", [tid] + extra_params):
            priority_counts[row["priority"]] = row["cnt"]
        
        # Tickets created per day (last 30 days)
        daily_created = []
        for row in conn.execute("""
            SELECT DATE(t.created_at) as day, COUNT(*) as cnt 
            FROM tickets t 
            WHERE t.tenant_id = ? AND t.created_at >= datetime('now', '-30 days')""" + extra + """
            GROUP BY DATE(t.created_at) 
            ORDER BY day
        """, [tid] + extra_params):
            daily_created.append({"date": row["day"], "count": row["cnt"]})
        
        # Tickets resolved per day (last 30 days)
        daily_resolved = []
        for row in conn.execute("""
            SELECT DATE(t.resolved_at) as day, COUNT(*) as cnt 
            FROM tickets t 
            WHERE t.tenant_id = ? AND t.resolved_at IS NOT NULL AND t.resolved_at >= datetime('now', '-30 days')""" + extra + """
            GROUP BY DATE(t.resolved_at) 
            ORDER BY day
        """, [tid] + extra_params):
            daily_resolved.append({"date": row["day"], "count": row["cnt"]})
        
        # Average resolution time (in hours)
        avg_time = conn.execute("""
            SELECT AVG((julianday(t.resolved_at) - julianday(t.created_at)) * 24) as avg_hours
            FROM tickets t WHERE t.tenant_id = ? AND t.resolved_at IS NOT NULL""" + extra,
            [tid] + extra_params).fetchone()["avg_hours"] or 0
        
        # Tickets by unit
        unit_counts = []
        for row in conn.execute("""
            SELECT u.name as unit_name, COUNT(t.ticket_id) as cnt
            FROM tickets t
            LEFT JOIN computers ON t.agent_id = computers.agent_id
            LEFT JOIN units u ON computers.unit_id = u.unit_id
            WHERE t.tenant_id = ?""" + extra + """
            GROUP BY u.name
            ORDER BY cnt DESC
            LIMIT 10
        """, [tid] + extra_params):
            unit_counts.append({"unit": row["unit_name"] or "Sem unidade", "count": row["cnt"]})
        
        # Open SLAs by priority
        sla_info = []
        for row in conn.execute("""
            SELECT t.ticket_id, t.title, t.priority, t.created_at, t.status
            FROM tickets t WHERE t.tenant_id = ? AND t.status IN ('open', 'in_progress')""" + extra + """
            ORDER BY CASE t.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
        """, [tid] + extra_params):
            sla_hours = {"critical": 1, "high": 4, "medium": 8, "low": 24}.get(row["priority"], 24)
            sla_info.append({
                "ticket_id": row["ticket_id"],
                "title": row["title"],
                "priority": row["priority"],
                "created_at": row["created_at"],
                "sla_hours": sla_hours,
                "status": row["status"]
            })
        
        # Total tickets
        total = conn.execute("SELECT COUNT(*) as cnt FROM tickets t WHERE t.tenant_id = ?" + extra, [tid] + extra_params).fetchone()["cnt"]
        
    return jsonify({
        "status_counts": status_counts,
        "priority_counts": priority_counts,
        "daily_created": daily_created,
        "daily_resolved": daily_resolved,
        "avg_resolution_hours": round(avg_time, 1),
        "unit_counts": unit_counts,
        "sla_info": sla_info,
        "total": total
    })



@app.route("/acompanhar-chamado")
def acompanhar_chamado_page():
    return render_template("acompanhar_chamado.html")


@app.route("/avaliar")
def avaliar_page():
    return render_template("avaliar.html")

@app.route("/api/tickets/track", methods=["POST"])
def api_ticket_track():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email obrigatorio"}), 400
    with get_db() as conn:
        rows = conn.execute("""
            SELECT ticket_id, title, description, priority, status, rating, rating_comment,
                   created_by, created_at, resolved_at, closed_at, resolution_notes, sla_due
            FROM tickets 
            WHERE (created_by LIKE ? OR created_by LIKE ?)
            ORDER BY created_at DESC
        """, ('%' + email + '%', '%' + email.split('@')[0] + '%')).fetchall()
    tickets = []
    for r in rows:
        tickets.append({
            'ticket_id': r['ticket_id'], 'title': r['title'],
            'description': r['description'], 'priority': r['priority'],
            'status': r['status'], 'created_by': r['created_by'],
            'created_at': r['created_at'], 'resolved_at': r['resolved_at'],
            'closed_at': r['closed_at'], 'resolution_notes': r['resolution_notes'],
            'rating': r['rating'] if 'rating' in r.keys() else None,
            'rating_comment': r['rating_comment'] if 'rating_comment' in r.keys() else None,
            'sla_due': r['sla_due'] if 'sla_due' in r.keys() else None
        })
    return jsonify({"tickets": tickets, "email": email})



@app.route("/api/tickets/public", methods=["POST"])
def api_ticket_public():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    desc = (data.get("description") or "").strip()
    priority = data.get("priority", "medium")
    created_by = (data.get("created_by") or "Anonimo").strip()
    email = (data.get("email") or "").strip() or None
    if email and not is_valid_email(email):
        return jsonify({"error": "E-mail inválido"}), 400
    if not title or not desc:
        return jsonify({"error": "Titulo e descricao sao obrigatorios"}), 400
    now = utc_now_iso()
    user = session.get("user", created_by)
    tenant_id = data.get("tenant_id", get_user_tenant())
    with get_db() as conn:
        conn.execute("INSERT INTO tickets (title, description, priority, status, created_by, sla_due, created_at, updated_at, tenant_id) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)",
            (title, desc, priority, created_by, sla_due_from(now, priority), now, now, tenant_id))
        ticket_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("INSERT INTO ticket_history (ticket_id, action, old_value, new_value, performed_by, created_at) VALUES (?, 'created', NULL, 'open', ?, ?)",
            (ticket_id, created_by, now))
        if email and email not in created_by:
            conn.execute("UPDATE tickets SET created_by = ? || ' (' || ? || ')' WHERE ticket_id = ?", (created_by, email, ticket_id))
        # Store unit_id and location_id
        unit_id = data.get("unit_id")
        location_id = data.get("location_id")
        if unit_id or location_id:
            conn.execute("UPDATE tickets SET unit_id = ?, location_id = ? WHERE ticket_id = ?",
                (unit_id, location_id, ticket_id))
        conn.commit()
    notify_ticket_event(ticket_id, f"Novo chamado #{ticket_id}: {title}", "Um novo chamado foi aberto no portal.", link=f"/chamados")
    email = data.get("email") or (created_by.split("(")[1].rstrip(")") if "(" in created_by else None)
    notify_ticket_created(ticket_id, title, created_by, email)
    return jsonify({"ok": True, "ticket_id": ticket_id})

@app.route("/abrir-chamado")
def abrir_chamado_page():
    return render_template("abrir_chamado.html")


# ================================
# PUBLIC API (no login required for ticket portal)
# ================================
@app.route("/api/public/tenants", methods=["GET"])
def api_public_tenants_list():
    with get_db() as conn:
        rows = conn.execute("SELECT tenant_id, name FROM tenants ORDER BY name").fetchall()
    return jsonify([{"tenant_id": r["tenant_id"], "name": r["name"]} for r in rows])


@app.route("/api/public/units", methods=["GET"])
def api_public_units_list():
    tenant_id = request.args.get("tenant_id")
    if not tenant_id:
        return jsonify([])
    with get_db() as conn:
        rows = conn.execute("SELECT unit_id, name FROM units WHERE tenant_id = ? ORDER BY name", (tenant_id,)).fetchall()
    return jsonify([{"unit_id": r["unit_id"], "name": r["name"]} for r in rows])


@app.route("/api/public/locations", methods=["GET"])
def api_public_locations_list():
    unit_id = request.args.get("unit_id")
    if not unit_id:
        return jsonify([])
    with get_db() as conn:
        rows = conn.execute("SELECT location_id, name FROM locations WHERE unit_id = ? ORDER BY name", (unit_id,)).fetchall()
    return jsonify([{"location_id": r["location_id"], "name": r["name"]} for r in rows])



@app.route('/abrir-chamado.js')
def abrir_chamado_js():
    return send_file(os.path.join(APP_DIR, 'abrir_chamado.js'), mimetype='application/javascript')

# ================================
# FEATURE: NOTIFICAÇÕES IN-APP
# ================================
@app.route("/api/notifications", methods=["GET"])
@require_login
def api_notifications_list():
    tid = get_current_tenant()
    uid = session.get("user_id")
    role, unit_ids = current_user_access()
    limit = min(max(int(request.args.get("limit", 30)), 1), 100)
    try:
        with get_db() as conn:
            if role == "master" and not uid:
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE tenant_id = ? ORDER BY notif_id DESC LIMIT ?",
                    (tid, limit),
                ).fetchall()
            elif role == "master":
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE tenant_id = ? AND (user_id IS NULL OR user_id = ?) ORDER BY notif_id DESC LIMIT ?",
                    (tid, uid, limit),
                ).fetchall()
            elif unit_ids:
                ph = ",".join("?" * len(unit_ids))
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE tenant_id = ? AND (user_id = ? OR (user_id IS NULL AND unit_id IN (" + ph + "))) ORDER BY notif_id DESC LIMIT ?",
                    [tid, uid] + unit_ids + [limit],
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE tenant_id = ? AND user_id = ? ORDER BY notif_id DESC LIMIT ?",
                    (tid, uid, limit),
                ).fetchall()
    except Exception:
        rows = []
    return jsonify([dict(r) for r in rows])


@app.route("/api/notifications/unread-count", methods=["GET"])
@require_login
def api_notifications_unread_count():
    tid = get_current_tenant()
    uid = session.get("user_id")
    role, unit_ids = current_user_access()
    try:
        with get_db() as conn:
            if role == "master" and not uid:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM notifications WHERE tenant_id = ? AND is_read = 0", (tid,)
                ).fetchone()
            elif role == "master":
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM notifications WHERE tenant_id = ? AND is_read = 0 AND (user_id IS NULL OR user_id = ?)",
                    (tid, uid),
                ).fetchone()
            elif unit_ids:
                ph = ",".join("?" * len(unit_ids))
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM notifications WHERE tenant_id = ? AND is_read = 0 AND (user_id = ? OR (user_id IS NULL AND unit_id IN (" + ph + ")))",
                    [tid, uid] + unit_ids,
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM notifications WHERE tenant_id = ? AND is_read = 0 AND user_id = ?", (tid, uid)
                ).fetchone()
    except Exception:
        return jsonify({"count": 0})
    return jsonify({"count": row["cnt"] if row else 0})


@app.route("/api/notifications/read", methods=["POST"])
@require_login
def api_notifications_mark_read():
    data = request.get_json(silent=True) or {}
    notif_id = data.get("notif_id")
    tid = get_current_tenant()
    uid = session.get("user_id")
    role, unit_ids = current_user_access()
    try:
        with get_db() as conn:
            if notif_id:
                conn.execute("UPDATE notifications SET is_read = 1 WHERE notif_id = ? AND tenant_id = ?", (notif_id, tid))
            elif role == "master" and not uid:
                conn.execute("UPDATE notifications SET is_read = 1 WHERE tenant_id = ?", (tid,))
            elif unit_ids:
                ph = ",".join("?" * len(unit_ids))
                conn.execute(
                    "UPDATE notifications SET is_read = 1 WHERE tenant_id = ? AND (user_id = ? OR (user_id IS NULL AND unit_id IN (" + ph + ")))",
                    [tid, uid] + unit_ids,
                )
            else:
                conn.execute("UPDATE notifications SET is_read = 1 WHERE tenant_id = ? AND user_id = ?", (tid, uid))
            conn.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@app.route("/notificacoes")
@require_login
def notificacoes_page():
    return render_template("notificacoes.html")


# ================================
# FEATURE: CICLO DE VIDA - ATIVOS (EQUIPAMENTOS NÃO-PC)
# ================================
@app.route("/ativos")
@require_login
def ativos_page():
    return render_template("ativos.html")


@app.route("/api/assets", methods=["GET"])
@require_login
def api_assets_list():
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    extra, extra_params = unit_scope_clause("a")
    kind = request.args.get("kind", "").strip()
    q = request.args.get("q", "").strip()
    query = """SELECT a.*, u.name as unit_name, l.name as location_name
               FROM assets a
               LEFT JOIN units u ON a.unit_id = u.unit_id
               LEFT JOIN locations l ON a.location_id = l.location_id
               WHERE a.tenant_id = ?""" + extra
    params = [tid] + extra_params
    if kind:
        query += " AND a.kind = ?"
        params.append(kind)
    if q:
        query += " AND (a.name LIKE ? OR a.brand LIKE ? OR a.model LIKE ? OR a.serial LIKE ? OR a.patrimonio LIKE ?)"
        for _ in range(5):
            params.append("%" + q + "%")
    query += " ORDER BY a.created_at DESC"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/assets", methods=["POST"])
@require_login
def api_assets_create():
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão para cadastrar ativos"}), 403
    data = request.get_json(silent=True) or {}
    unit_id = data.get("unit_id")
    if role == "unit_admin" and unit_id not in (my_unit_ids or []):
        return jsonify({"error": "unidade fora do seu acesso"}), 403
    now = utc_now_iso()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO assets (tenant_id, unit_id, location_id, kind, name, brand, model, serial, patrimonio, status, notes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (get_current_tenant(), unit_id, data.get("location_id"), data.get("kind") or "outro",
             (data.get("name") or "").strip(), (data.get("brand") or "").strip(),
             (data.get("model") or "").strip(), (data.get("serial") or "").strip(),
             (data.get("patrimonio") or "").strip(), data.get("status") or "ativo",
             (data.get("notes") or "").strip(), now, now),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/assets/<int:asset_id>", methods=["POST"])
@require_login
def api_assets_update(asset_id):
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    data = request.get_json(silent=True) or {}
    with get_db() as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        if role == "unit_admin" and row["unit_id"] not in (my_unit_ids or []):
            return jsonify({"error": "fora do seu acesso"}), 403
        conn.execute(
            """UPDATE assets SET unit_id=?, location_id=?, kind=?, name=?, brand=?, model=?, serial=?, patrimonio=?, status=?, notes=?, updated_at=?
               WHERE asset_id=?""",
            (data.get("unit_id", row["unit_id"]), data.get("location_id", row["location_id"]),
             data.get("kind") or row["kind"], (data.get("name") or row["name"]).strip(),
             (data.get("brand", row["brand"]) or "").strip(), (data.get("model", row["model"]) or "").strip(),
             (data.get("serial", row["serial"]) or "").strip(), (data.get("patrimonio", row["patrimonio"]) or "").strip(),
             data.get("status") or row["status"], (data.get("notes", row["notes"]) or "").strip(), utc_now_iso(), asset_id),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
@require_login
def api_assets_delete(asset_id):
    role, my_unit_ids = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    with get_db() as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        if role == "unit_admin" and row["unit_id"] not in (my_unit_ids or []):
            return jsonify({"error": "fora do seu acesso"}), 403
        conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
        conn.commit()
    return jsonify({"ok": True})


# ================================
# FEATURE: HISTÓRICO DO COMPUTADOR
# ================================
@app.route("/api/computers/<agent_id>/changes", methods=["GET"])
@require_login
def api_computer_changes(agent_id):
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso"}), 403
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM computer_changes WHERE agent_id = ? ORDER BY change_id DESC LIMIT 60",
            (agent_id,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# ================================
# FEATURE: ETIQUETA QR
# ================================
@app.route("/etiqueta/<agent_id>")
@require_login
def etiqueta_page(agent_id):
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso a este computador"}), 403
    with get_db() as conn:
        row = conn.execute(
            """SELECT c.*, u.name as unit_name, l.name as location_name
               FROM computers c
               LEFT JOIN units u ON c.unit_id = u.unit_id
               LEFT JOIN locations l ON c.location_id = l.location_id
               WHERE c.agent_id = ?""",
            (agent_id,),
        ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    pc = serialize_computer(row, row["unit_name"], row["location_name"])
    return render_template("etiqueta.html", pc=pc)


@app.route("/api/qr/<agent_id>.png")
@require_login
def api_qr_png(agent_id):
    if not computer_in_scope(agent_id):
        return jsonify({"error": "sem acesso"}), 403
    try:
        import qrcode
        from flask import send_file
        url = request.url_root.rstrip("/") + f"/pc/{agent_id}"
        img = qrcode.make(url)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")
    except Exception as e:
        logger.warning(f"QR error: {e}")
        return jsonify({"error": "qrcode lib nao instalada"}), 500


# ================================
# FEATURE: BASE DE CONHECIMENTO
# ================================
@app.route("/base-conhecimento")
def kb_public_page():
    return render_template("kb.html")


@app.route("/api/public/kb", methods=["GET"])
def api_public_kb():
    tid = request.args.get("tenant_id") or 1
    cat = request.args.get("category", "").strip()
    q = request.args.get("q", "").strip()
    query = "SELECT * FROM kb_articles WHERE tenant_id = ? AND is_public = 1"
    params = [int(tid)]
    if cat:
        query += " AND category = ?"
        params.append(cat)
    if q:
        query += " AND (title LIKE ? OR content LIKE ?)"
        params += ["%" + q + "%", "%" + q + "%"]
    query += " ORDER BY created_at DESC LIMIT 100"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/public/kb/categories", methods=["GET"])
def api_public_kb_categories():
    tid = request.args.get("tenant_id") or 1
    with get_db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT category FROM kb_articles WHERE tenant_id = ? AND is_public = 1 AND category != ''",
            (int(tid),),
        ).fetchall()
    return jsonify([r["category"] for r in rows if r["category"]])


@app.route("/api/kb", methods=["GET"])
@require_login
def api_kb_list():
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    if role == "master" and not session.get("user_id"):
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM kb_articles ORDER BY created_at DESC LIMIT 200").fetchall()
        return jsonify([dict(r) for r in rows])
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM kb_articles WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 200", (tid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/kb", methods=["POST"])
@require_login
def api_kb_create():
    role, _ = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    if not title or not content:
        return jsonify({"error": "title e content são obrigatórios"}), 400
    now = utc_now_iso()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO kb_articles (tenant_id, unit_id, category, title, content, is_public, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (get_current_tenant(), data.get("unit_id"), (data.get("category") or "Geral").strip(),
             title, content, 1 if data.get("is_public", 1) else 0, session.get("user", "admin"), now, now),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/kb/<int:article_id>", methods=["POST"])
@require_login
def api_kb_update(article_id):
    role, _ = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    data = request.get_json(silent=True) or {}
    now = utc_now_iso()
    with get_db() as conn:
        row = conn.execute("SELECT tenant_id FROM kb_articles WHERE article_id = ?", (article_id,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        if session.get("user_id") and row["tenant_id"] != get_current_tenant():
            return jsonify({"error": "sem acesso"}), 403
        conn.execute(
            """UPDATE kb_articles SET unit_id=?, category=?, title=?, content=?, is_public=?, updated_at=?
               WHERE article_id=?""",
            (data.get("unit_id", row.get("unit_id")), (data.get("category") or "Geral").strip(),
             (data.get("title") or "").strip(), (data.get("content") or "").strip(),
             1 if data.get("is_public", 1) else 0, now, article_id),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/kb/<int:article_id>", methods=["DELETE"])
@require_login
def api_kb_delete(article_id):
    role, _ = current_user_access()
    if role == "tech":
        return jsonify({"error": "sem permissão"}), 403
    with get_db() as conn:
        row = conn.execute("SELECT tenant_id FROM kb_articles WHERE article_id = ?", (article_id,)).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        if session.get("user_id") and row["tenant_id"] != get_current_tenant():
            return jsonify({"error": "sem acesso"}), 403
        conn.execute("DELETE FROM kb_articles WHERE article_id = ?", (article_id,))
        conn.commit()
    return jsonify({"ok": True})


# ================================
# FEATURE: CSAT (avaliação do chamado no portal)
# ================================
@app.route("/api/tickets/rate", methods=["POST"])
def api_ticket_rate():
    data = request.get_json(silent=True) or {}
    ticket_id = data.get("ticket_id")
    email = (data.get("email") or "").strip().lower()
    try:
        rating = int(data.get("rating"))
    except Exception:
        return jsonify({"error": "avaliação inválida"}), 400
    if rating < 1 or rating > 5:
        return jsonify({"error": "avaliação deve ser entre 1 e 5"}), 400
    comment = (data.get("comment") or "").strip()
    with get_db() as conn:
        row = conn.execute(
            "SELECT created_by, status FROM tickets WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "chamado não encontrado"}), 404
        if email and email not in str(row["created_by"] or "").lower():
            return jsonify({"error": "e-mail não confere com o chamado"}), 403
        if row["status"] not in ("resolved", "closed"):
            return jsonify({"error": "avaliação disponível somente após resolução/fechamento"}), 400
        conn.execute(
            "UPDATE tickets SET rating = ?, rating_comment = ? WHERE ticket_id = ?",
            (rating, comment, ticket_id),
        )
        conn.commit()
    return jsonify({"ok": True})


# ================================
# FEATURE: RELATÓRIO AGENDADO (mensal, por e-mail)
# ================================
def _last_month_label():
    from datetime import timedelta
    d = datetime.now(timezone.utc).replace(day=1) - timedelta(days=1)
    return d.strftime("%Y-%m")


def build_monthly_report_html(tenant_id):
    """Gera resumo mensal (fechados no mes passado) por unidade, em HTML para e-mail."""
    period = _last_month_label()
    month_start = period + "-01"
    with get_db() as conn:
        unit_rows = conn.execute(
            """SELECT COALESCE(u.name, 'Sem unidade') as unit_name,
                      COUNT(t.ticket_id) as total,
                      SUM(CASE WHEN t.status IN ('resolved','closed') THEN 1 ELSE 0 END) as done
               FROM tickets t LEFT JOIN units u ON t.unit_id = u.unit_id
               WHERE t.tenant_id = ? AND t.created_at >= ?
               GROUP BY t.unit_id ORDER BY total DESC""",
            (tenant_id, month_start),
        ).fetchall()
        totals = conn.execute(
            "SELECT COUNT(*) as c FROM tickets WHERE tenant_id = ? AND created_at >= ?",
            (tenant_id, month_start),
        ).fetchone()
    lines = "".join(
        f"<tr><td>{r['unit_name']}</td><td>{r['total']}</td><td>{r['done'] or 0}</td></tr>" for r in unit_rows
    )
    return f"""<h2 style="color:#1e293b">Resumo mensal — {period}</h2>
    <table border="1" cellpadding="8" style="border-collapse:collapse;width:100%">
      <tr style="background:#38bdf8;color:#fff"><th>Unidade</th><th>Chamados</th><th>Resolvidos/Encerrados</th></tr>
      {lines or '<tr><td colspan="3">Nenhum chamado no período</td></tr>'}
    </table>
    <p>Total no período: <b>{totals['c'] if totals else 0}</b></p>"""


def run_scheduled_reports():
    """Envia por e-mail o relatório mensal aos admins de cada empresa (uma vez por período)."""
    try:
        if not EMAIL_ENABLED:
            return
        period = _last_month_label()
        with get_db() as conn:
            tenants = conn.execute("SELECT tenant_id FROM tenants").fetchall()
        for t in tenants:
            tid = t["tenant_id"]
            with get_db() as conn:
                done = conn.execute(
                    "SELECT 1 FROM report_log WHERE period = ? AND tenant_id = ?", (period, tid)
                ).fetchone()
            if done:
                continue
            with get_db() as conn:
                admins = conn.execute(
                    "SELECT email FROM users WHERE tenant_id = ? AND is_admin = 1 AND email != ''", (tid,)
                ).fetchall()
            if not admins:
                continue
            body = build_monthly_report_html(tid)
            ok = False
            for a in admins:
                ok = send_email(a["email"], f"[AtivoFix] Relatório mensal de chamados — {period}", body) or ok
            with get_db() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO report_log (period, tenant_id, sent_at) VALUES (?, ?, ?)",
                    (period, tid, utc_now_iso()),
                )
                conn.commit()
            logger.info(f"Relatorio mensal {period} enviado para tenant {tid} (ok={ok})")
    except Exception as e:
        logger.warning(f"run_scheduled_reports falhou: {e}")


import threading as _threading


def _report_scheduler_loop():
    while True:
        try:
            now = datetime.now()
            if now.hour == 8 and now.minute < 5:
                run_scheduled_reports()
        except Exception:
            pass
        try:
            _threading.Event().wait(3600)
        except Exception:
            break


@app.route("/api/reports/run", methods=["POST"])
@require_login
def api_reports_run_now():
    role, _ = current_user_access()
    if role != "master":
        return jsonify({"error": "somente admin master"}), 403
    run_scheduled_reports()
    return jsonify({"ok": True, "period": _last_month_label()})

# ================================
# FEATURE: TÉCNICOS POR UNIDADE (atribuição de chamados)
# ================================
@app.route("/api/ticket-assignees", methods=["GET"])
@require_login
def api_ticket_assignees():
    tid = get_current_tenant()
    role, unit_ids = current_user_access()
    with get_db() as conn:
        if role == "master" and not session.get("user_id"):
            rows = conn.execute(
                """SELECT DISTINCT u.user_id, u.username, u.email FROM users u ORDER BY u.username"""
            ).fetchall()
        elif role == "master":
            rows = conn.execute(
                "SELECT user_id, username, email FROM users WHERE tenant_id = ? AND is_admin = 1 ORDER BY username",
                (tid,),
            ).fetchall()
        elif unit_ids:
            ph = ",".join("?" * len(unit_ids))
            rows = conn.execute(
                "SELECT DISTINCT u.user_id, u.username, u.email FROM users u JOIN user_units uu ON uu.user_id = u.user_id WHERE u.tenant_id = ? AND uu.unit_id IN (" + ph + ") ORDER BY u.username",
                [tid] + unit_ids,
            ).fetchall()
        else:
            rows = []
    return jsonify([dict(r) for r in rows])


# Garante schema/backup mesmo quando o app e importado (gunicorn, testes)
if os.environ.get("SKIP_DB_INIT", "").lower() not in ("1", "true", "yes"):
    try:
        if os.path.exists(DB_PATH):
            backup_db()
        init_db()
        migrate_db()
    except Exception as _e:
        logger.error(f"Falha ao inicializar banco no import: {_e}")

if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        backup_db()
    init_db()
    migrate_db()
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Server starting on {host}:{port} debug={debug}")
    if not debug:
        try:
            t = _threading.Thread(target=_report_scheduler_loop, daemon=True)
            t.start()
        except Exception as e:
            logger.warning(f"Falha ao iniciar scheduler de relatorios: {e}")
    app.run(host=host, port=port, debug=debug)

