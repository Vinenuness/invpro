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
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3

# ================================
# CONFIGURAÇÃO VIA VARIÁVEIS DE AMBIENTE
# ================================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(APP_DIR, "db.sqlite3"))
DB_BACKUP_DIR = os.environ.get("DB_BACKUP_DIR", os.path.join(APP_DIR, "backups"))

AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "SEU_TOKEN_SUPER_SECRETO")
LOGIN_USER = os.environ.get("PANEL_USER", "admin")
LOGIN_PASS = os.environ.get("PANEL_PASS", "admin")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())

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

# ================================
# APP FLASK
# ================================
app = Flask(__name__, template_folder=APP_DIR)
app.secret_key = FLASK_SECRET_KEY

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
@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"ok": True, "timestamp": utc_now_iso()})


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute") if limiter else lambda f: f
def login_page():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        if username == LOGIN_USER and password == LOGIN_PASS:
            session["logged_in"] = True
            session["user"] = username
            session["tenant_id"] = 1  # Default tenant
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
    session.pop("logged_in", None)
    session.pop("user", None)
    logger.info(f"Logout: {user}")
    return redirect(url_for("login_page"))


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
    with get_db() as conn:
        rows = conn.execute(
            """SELECT c.*, u.name as unit_name, l.name as location_name
               FROM computers c 
               LEFT JOIN units u ON c.unit_id = u.unit_id 
               LEFT JOIN locations l ON c.location_id = l.location_id
               WHERE c.tenant_id = ?
               ORDER BY c.last_seen DESC, c.hostname ASC""",
            (tid,)
        ).fetchall()
    return jsonify({"computers": [serialize_computer(r, r["unit_name"]) for r in rows]})


@app.route("/dados")
def dados():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT c.*, u.name as unit_name, l.name as location_name
               FROM computers c 
               LEFT JOIN units u ON c.unit_id = u.unit_id 
               LEFT JOIN locations l ON c.location_id = l.location_id
               ORDER BY c.last_seen DESC, c.hostname ASC"""
        ).fetchall()
    return jsonify([serialize_computer(r, r["unit_name"]) for r in rows])


@app.route("/api/alias", methods=["POST"])
def api_alias():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    alias = (data.get("alias") or "").strip()
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400
    with get_db() as conn:
        conn.execute("UPDATE computers SET alias = ? WHERE agent_id = ?", (alias, agent_id))
        conn.commit()
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
    with get_db() as conn:
        existing = conn.execute("SELECT alias, tag_evo FROM computers WHERE agent_id = ?", (agent_id,)).fetchone()
        alias = existing["alias"] if existing else None
        tag_evo = existing["tag_evo"] if existing else None
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
    tid = get_current_tenant()
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM units WHERE tenant_id = ? ORDER BY name", (tid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/units", methods=["POST"])
@require_login
def api_units_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    now = utc_now_iso()
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
    with get_db() as conn:
        if unit_id:
            rows = conn.execute(
                "SELECT l.*, u.name as unit_name FROM locations l LEFT JOIN units u ON l.unit_id = u.unit_id WHERE l.unit_id = ? ORDER BY l.name",
                (unit_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT l.*, u.name as unit_name FROM locations l LEFT JOIN units u ON l.unit_id = u.unit_id ORDER BY u.name, l.name"
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/locations", methods=["POST"])
@require_login
def api_locations_create():
    data = request.get_json(silent=True) or {}
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
    with get_db() as conn:
        conn.execute("UPDATE computers SET location_id = NULL WHERE location_id = ?", (location_id,))
        conn.execute("DELETE FROM locations WHERE location_id = ?", (location_id,))
        conn.commit()
    logger.info(f"Local excluido: {location_id}")
    return jsonify({"ok": True})


@app.route("/api/computers/<agent_id>/location", methods=["POST"])
@require_login
def api_computer_set_location(agent_id):
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
    logger.info(f"PC {agent_id} vinculado a local {location_id}")
    return jsonify({"ok": True})


@app.route("/locais")
@require_login
def locais_page():
    return redirect("/unidades")


# ================================
# API - USUARIOS
# ================================
@app.route("/api/users", methods=["GET"])
@require_login
def api_users_list():
    tid = get_current_tenant()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT user_id, username, email, is_admin, created_at FROM users WHERE tenant_id = ? ORDER BY username",
            (tid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users", methods=["POST"])
@require_login
def api_users_create():
    import hashlib
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    is_admin = 1 if data.get("is_admin") else 0
    if not username or not email or not password:
        return jsonify({"error": "username, email and password are required"}), 400
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    now = utc_now_iso()
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, email, password_hash, is_admin, now)
            )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                return jsonify({"error": "username already exists"}), 400
            raise
    logger.info(f"Usuario criado: {username}")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>", methods=["POST"])
@require_login
def api_users_update(user_id):
    import hashlib
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    is_admin = 1 if data.get("is_admin") else 0
    if not username or not email:
        return jsonify({"error": "username and email are required"}), 400
    with get_db() as conn:
        if password:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            result = conn.execute(
                "UPDATE users SET username = ?, email = ?, password_hash = ?, is_admin = ? WHERE user_id = ?",
                (username, email, password_hash, is_admin, user_id)
            )
        else:
            result = conn.execute(
                "UPDATE users SET username = ?, email = ?, is_admin = ? WHERE user_id = ?",
                (username, email, is_admin, user_id)
            )
        conn.commit()
    if result.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    logger.info(f"Usuario atualizado: {username}")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_login
def api_users_delete(user_id):
    with get_db() as conn:
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
    data = request.get_json(silent=True) or {}
    unit_id = data.get("unit_id")
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
    logger.info(f"PC {agent_id} vinculado a unidade {unit_id}")
    return jsonify({"ok": True})


# ================================
# API - VINCULAR USUARIO A UNIDADE
# ================================
@app.route("/api/users/<int:user_id>/units", methods=["GET"])
@require_login
def api_user_units_list(user_id):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT u.unit_id, u.name, u.description FROM user_units uu JOIN units u ON u.unit_id = uu.unit_id WHERE uu.user_id = ? ORDER BY u.name",
            (user_id,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users/<int:user_id>/units", methods=["POST"])
@require_login
def api_user_units_set(user_id):
    data = request.get_json(silent=True) or {}
    unit_ids = data.get("unit_ids") or []
    with get_db() as conn:
        conn.execute("DELETE FROM user_units WHERE user_id = ?", (user_id,))
        for unit_id in unit_ids:
            conn.execute(
                "INSERT INTO user_units (user_id, unit_id) VALUES (?, ?)",
                (user_id, unit_id)
            )
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
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM tenants ORDER BY name").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tenants", methods=["POST"])
@require_login
def api_tenants_create():
    data = request.get_json(silent=True) or {}
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
    data = request.get_json(silent=True) or {}
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


# ================================
# API - DASHBOARD STATS
# ================================
@app.route("/api/dashboard", methods=["GET"])
@require_login
def api_dashboard():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) as cnt FROM computers").fetchone()["cnt"]
        units = conn.execute("SELECT COUNT(*) as cnt FROM units").fetchone()["cnt"]
        users_count = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
        scripts_count = conn.execute("SELECT COUNT(*) as cnt FROM scripts").fetchone()["cnt"]
        
        # PCs per unit
        per_unit = conn.execute("""
            SELECT COALESCE(u.name, 'Sem unidade') as unit_name, COUNT(*) as cnt
            FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
            GROUP BY c.unit_id ORDER BY cnt DESC
        """).fetchall()
        
        # Recent jobs
        recent_jobs = conn.execute("""
            SELECT j.job_id, j.status, j.created_at, s.name as script_name, c.hostname
            FROM jobs j 
            LEFT JOIN scripts s ON s.script_id = j.script_id
            LEFT JOIN computers c ON c.device_uid = j.device_uid
            ORDER BY j.created_at DESC LIMIT 10
        """).fetchall()
        
        # Agent stats from payload
        computers_data = conn.execute("SELECT payload_json, last_seen, unit_id FROM computers").fetchall()
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
        
        return jsonify({
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
            "os_distribution": os_stats
        })




# ================================
# API - OFFLINE ALERTS
# ================================
@app.route("/api/alerts", methods=["GET"])
@require_login
def api_alerts_list():
    tid = get_current_tenant()
    with get_db() as conn:
        rows = conn.execute(
            """SELECT a.*, c.hostname, c.tag_evo 
               FROM alerts a 
               LEFT JOIN computers c ON a.agent_id = c.agent_id
               WHERE a.tenant_id = ? 
               ORDER BY a.created_at DESC LIMIT 50""",
            (tid,)
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
    with get_db() as conn:
        if unit_name:
            rows = conn.execute("""
                SELECT c.hostname, c.alias, c.tag_evo, c.last_seen, c.unit_id,
                       u.name as unit_name, c.payload_json
                FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
                WHERE u.name = ? ORDER BY c.hostname
            """, (unit_name,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT c.hostname, c.alias, c.tag_evo, c.last_seen, c.unit_id,
                       u.name as unit_name, c.payload_json
                FROM computers c LEFT JOIN units u ON c.unit_id = u.unit_id
                ORDER BY c.hostname
            """).fetchall()
    
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
    
    with get_db() as conn:
        # Get all units with PC counts
        units_data = conn.execute("""
            SELECT COALESCE(u.name, 'Sem unidade') as unit_name, COUNT(*) as pc_count
            FROM computers c 
            LEFT JOIN units u ON c.unit_id = u.unit_id
            GROUP BY c.unit_id 
            ORDER BY pc_count DESC
        """).fetchall()
        
        # Get total
        total = conn.execute("SELECT COUNT(*) as cnt FROM computers").fetchone()["cnt"]
        
        # Get all computers with details per unit
        all_computers = conn.execute("""
            SELECT c.hostname, c.tag_evo, c.alias, c.last_seen,
                   COALESCE(u.name, 'Sem unidade') as unit_name, c.payload_json
            FROM computers c 
            LEFT JOIN units u ON c.unit_id = u.unit_id
            ORDER BY u.name, c.hostname
        """).fetchall()
    
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
    
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    
    with get_db() as conn:
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM metrics_history WHERE agent_id = ? AND recorded_at > ? ORDER BY recorded_at ASC",
                (agent_id, cutoff)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT mh.*, c.hostname FROM metrics_history mh LEFT JOIN computers c ON mh.agent_id = c.agent_id WHERE mh.recorded_at > ? AND mh.tenant_id = ? ORDER BY mh.recorded_at ASC",
                (cutoff, tid)
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/metrics/summary", methods=["GET"])
@require_login
def api_metrics_summary():
    tid = get_current_tenant()
    with get_db() as conn:
        current = conn.execute(
            "SELECT AVG(cpu_percent) as cpu_avg, AVG(ram_percent) as ram_avg, SUM(disk_used_gb) as disk_used, SUM(disk_total_gb) as disk_total FROM metrics_history WHERE tenant_id = ? AND recorded_at > datetime('now', '-1 hour')",
            (tid,)
        ).fetchone()
        
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        week_ago = (now - timedelta(days=7)).isoformat()
        two_weeks_ago = (now - timedelta(days=14)).isoformat()
        
        this_week = conn.execute(
            "SELECT AVG(cpu_percent) as cpu, AVG(ram_percent) as ram FROM metrics_history WHERE tenant_id = ? AND recorded_at > ?",
            (tid, week_ago)
        ).fetchone()
        
        last_week = conn.execute(
            "SELECT AVG(cpu_percent) as cpu, AVG(ram_percent) as ram FROM metrics_history WHERE tenant_id = ? AND recorded_at > ? AND recorded_at <= ?",
            (tid, two_weeks_ago, week_ago)
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
    with get_db() as conn:
        rows = conn.execute(
            "SELECT m.*, c.hostname, c.tag_evo FROM maintenance_alerts m LEFT JOIN computers c ON m.agent_id = c.agent_id WHERE m.tenant_id = ? ORDER BY m.created_at DESC LIMIT 50",
            (tid,)
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
    tid = get_current_tenant()
    status = request.args.get("status")
    with get_db() as conn:
        if status:
            rows = conn.execute(
                "SELECT t.*, c.hostname FROM tickets t LEFT JOIN computers c ON t.agent_id = c.agent_id WHERE t.tenant_id = ? AND t.status = ? ORDER BY t.created_at DESC",
                (tid, status)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT t.*, c.hostname FROM tickets t LEFT JOIN computers c ON t.agent_id = c.agent_id WHERE t.tenant_id = ? ORDER BY t.created_at DESC",
                (tid,)
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
    
    with get_db() as conn:
        conn.execute(
            "INSERT INTO tickets (tenant_id, agent_id, title, description, status, priority, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)",
            (tid, agent_id, title, description, priority, user, now, now)
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/tickets/<int:ticket_id>", methods=["POST"])
@require_login
def api_tickets_update(ticket_id):
    data = request.get_json(silent=True) or {}
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
    with get_db() as conn:
        conn.execute("DELETE FROM tickets WHERE ticket_id = ?", (ticket_id,))
        conn.commit()
    return jsonify({"ok": True})


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

if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        backup_db()
    init_db()
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Server starting on {host}:{port} debug={debug}")
    app.run(host=host, port=port, debug=debug)

