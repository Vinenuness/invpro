

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

