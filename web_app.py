#!/usr/bin/env python3
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template

from printer_monitor import descobrir_impressoras

DATA_DIR = Path("data")
SNAPSHOT_FILE = DATA_DIR / "snapshots.json"
INTERVAL_SECONDS = 300  # 5 minutos
NETWORK_CIDR = "192.168.0.0/24"
SNMP_COMMUNITY = "public"

app = Flask(__name__)
_data_lock = threading.Lock()
_collector_started = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_snapshots() -> list[dict]:
    if not SNAPSHOT_FILE.exists():
        return []
    try:
        return json.loads(SNAPSHOT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_snapshots(snapshots: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_FILE.write_text(
        json.dumps(snapshots, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _collect_once() -> dict:
    printers = descobrir_impressoras(NETWORK_CIDR, SNMP_COMMUNITY)
    serialized = [asdict(p) for p in printers]
    return {"collected_at": _utc_now_iso(), "printers": serialized}


def _collector_loop() -> None:
    while True:
        snapshot = _collect_once()
        with _data_lock:
            snapshots = _load_snapshots()
            snapshots.append(snapshot)
            snapshots = snapshots[-576:]  # aprox. 2 dias com coleta de 5 em 5 minutos
            _save_snapshots(snapshots)
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


@app.before_request
def ensure_collector_started() -> None:
    _start_collector_once()


@app.route("/")
def dashboard() -> str:
    with _data_lock:
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
def relatorios() -> str:
    with _data_lock:
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


if __name__ == "__main__":
    _start_collector_once()
    app.run(host="0.0.0.0", port=5000, debug=False)
