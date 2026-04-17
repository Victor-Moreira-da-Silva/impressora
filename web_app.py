#!/usr/bin/env python3
from __future__ import annotations
import json
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

_data_lock = threading.Lock()

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from printer_monitor import descobrir_impressoras

DATA_DIR = Path("data")
DB_FILE = DATA_DIR / "app.db"
INTERVAL_SECONDS = 300  # 5 minutos
NETWORK_CIDR = "192.168.0.0/24"
SNMP_COMMUNITY = "public"
MAX_SNAPSHOTS = 576  # aprox. 2 dias com coleta de 5 em 5 minutos

app = Flask(__name__)
app.secret_key = "trocar-em-producao-" + secrets.token_hex(16)
_db_lock = threading.Lock()
_collector_started = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _connect_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                collected_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )

        admin = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if admin is None:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, is_admin, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    "admin",
                    generate_password_hash("admin123"),
                    1,
                    _utc_now_iso(),
                ),
            )


def _insert_snapshot(snapshot: dict) -> None:
    with _connect_db() as conn:
        conn.execute(
            "INSERT INTO snapshots (collected_at, payload_json) VALUES (?, ?)",
            (snapshot["collected_at"], json.dumps(snapshot, ensure_ascii=False)),
        )
        conn.execute(
            """
            DELETE FROM snapshots
            WHERE id NOT IN (
                SELECT id FROM snapshots
                ORDER BY collected_at DESC
                LIMIT ?
            )
            """,
            (MAX_SNAPSHOTS,),
        )


def _load_snapshots() -> list[dict]:
    with _connect_db() as conn:
        rows = conn.execute(
            "SELECT payload_json FROM snapshots ORDER BY collected_at ASC"
        ).fetchall()

    snapshots: list[dict] = []
    for row in rows:
        try:
            snapshots.append(json.loads(row["payload_json"]))
        except json.JSONDecodeError:
            continue
    return snapshots


def _collect_once() -> dict:
    printers = descobrir_impressoras(NETWORK_CIDR, SNMP_COMMUNITY)
    serialized = [asdict(p) for p in printers]
    return {"collected_at": _utc_now_iso(), "printers": serialized}


def _collector_loop() -> None:
    while True:
        snapshot = _collect_once()
        with _db_lock:
            _insert_snapshot(snapshot)
        time.sleep(INTERVAL_SECONDS)


def _start_collector_once() -> None:
    global _collector_started
    with _data_lock:
        if _collector_started:
            return
        _collector_started = True

    thread = threading.Thread(target=_collector_loop, daemon=True)
    thread.start()


def _latest_snapshot(snapshots: list[dict]) -> dict:
    if snapshots:
        return snapshots[-1]
    return {"collected_at": None, "printers": []}


def _compute_daily_prints(snapshots: list[dict]) -> dict[str, int]:
    day_start = datetime.now(timezone.utc).date()

    first_by_printer: dict[str, int] = {}
    last_by_printer: dict[str, int] = {}

    for snap in snapshots:
        ts_text = snap.get("collected_at")
        if not ts_text:
            continue

        try:
            ts = datetime.fromisoformat(ts_text)
        except Exception:
            continue

        if ts.date() != day_start:
            continue

        for printer in snap.get("printers", []):
            ip = printer.get("ip") or "desconhecida"
            count = printer.get("folhas_impressas")
            if not isinstance(count, int):
                continue

            if ip not in first_by_printer:
                first_by_printer[ip] = count
            last_by_printer[ip] = count

    totals: dict[str, int] = {}
    for ip, last in last_by_printer.items():
        first = first_by_printer.get(ip, last)
        totals[ip] = max(last - first, 0)

    return totals


def _compute_problem_history(snapshots: list[dict]) -> list[dict]:
    events: list[dict] = []

    for snap in snapshots[-120:]:  # últimas 10h
        collected_at = snap.get("collected_at", "")
        for printer in snap.get("printers", []):
            problems: list[str] = []

            status = (printer.get("status") or "").lower()
            if status and status not in {"idle", "imprimindo"}:
                problems.append(f"Status: {status}")

            for alert in printer.get("alertas") or []:
                if alert:
                    problems.append(f"Alerta: {alert}")

            erro = printer.get("erro")
            if erro:
                problems.append(f"Erro SNMP: {erro}")

            if problems:
                events.append(
                    {
                        "timestamp": collected_at,
                        "ip": printer.get("ip") or "N/A",
                        "nome": printer.get("nome") or "N/A",
                        "problems": problems,
                    }
                )

    return list(reversed(events))


def _status_distribution(latest: dict) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for printer in latest.get("printers", []):
        status = printer.get("status") or "desconhecido"
        counts[status] += 1
    return dict(counts)

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user["is_admin"]:
            flash("Apenas administradores podem acessar esta página.", "error")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)

    return wrapped

@app.before_request
def bootstrap_and_load_user() -> None:
    _init_db()
    _start_collector_once()
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        with _connect_db() as conn:
            g.user = conn.execute(
                "SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)
            ).fetchone()


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with _connect_db() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Login realizado com sucesso.", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))

        flash("Usuário ou senha inválidos.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão encerrada.", "success")
    return redirect(url_for("login"))



@app.route("/")
@login_required
def dashboard() -> str:
    with _db_lock:
        snapshots = _load_snapshots()

    latest = _latest_snapshot(snapshots)
    daily_totals = _compute_daily_prints(snapshots)

    printers = latest.get("printers", [])
    total_printers = len(printers)
    printers_ok = sum(1 for p in printers if not p.get("erro"))
    daily_total_count = sum(daily_totals.values())

    return render_template(
        "dashboard.html",
        collected_at=latest.get("collected_at"),
        printers=printers,
        total_printers=total_printers,
        printers_ok=printers_ok,
        daily_total_count=daily_total_count,
    )


@app.route("/relatorios")
@login_required
def relatorios() -> str:
    with _db_lock:
        snapshots = _load_snapshots()

    latest = _latest_snapshot(snapshots)
    daily_totals = _compute_daily_prints(snapshots)
    history = _compute_problem_history(snapshots)
    status_dist = _status_distribution(latest)

    return render_template(
        "relatorios.html",
        collected_at=latest.get("collected_at"),
        daily_totals=daily_totals,
        daily_total_count=sum(daily_totals.values()),
        status_dist=status_dist,
        problem_history=history,
    )

@app.route("/usuarios", methods=["GET", "POST"])
@login_required
@admin_required
def usuarios() -> str:
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        is_admin = 1 if request.form.get("is_admin") == "on" else 0

        if not username or len(password) < 6:
            flash("Preencha usuário e senha (mínimo 6 caracteres).", "error")
            return redirect(url_for("usuarios"))

        try:
            with _connect_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, is_admin, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, generate_password_hash(password), is_admin, _utc_now_iso()),
                )
            flash("Usuário criado com sucesso.", "success")
        except sqlite3.IntegrityError:
            flash("Este usuário já existe.", "error")

        return redirect(url_for("usuarios"))

    with _connect_db() as conn:
        users = conn.execute(
            "SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()

    return render_template("usuarios.html", users=users)

if __name__ == "__main__":
    _init_db()
    _start_collector_once()
    app.run(host="0.0.0.0", port=5000, debug=False)
