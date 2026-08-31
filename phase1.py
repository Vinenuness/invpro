import os

with open('templates/server.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add metrics history table to init_db
metrics_table = """            CREATE TABLE IF NOT EXISTS metrics_history (
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
"""

old_alerts = "            CREATE TABLE IF NOT EXISTS alerts ("
content = content.replace(old_alerts, metrics_table + chr(10) + old_alerts)

with open('templates/server.py', 'w', encoding='utf-8') as f:
    f.write(content)

print('Phase 1 done: tables added')
