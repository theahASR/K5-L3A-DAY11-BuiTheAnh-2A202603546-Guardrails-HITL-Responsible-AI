"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import time
import uuid
import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        request_id = request_id or uuid.uuid4().hex
        self._open[request_id] = {
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_monotonic": time.monotonic(),
        }
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        request_id = request_id or (
            next(reversed(self._open), None) if self._open else None
        )
        entry = self._open.pop(request_id, {}) if request_id else {}
        started = entry.get("started_monotonic")
        latency_ms = (
            (time.monotonic() - started) * 1000 if started is not None else 0.0
        )

        self.logs.append({
            "request_id": request_id,
            "user_id": entry.get("user_id", user_id),
            "input": entry.get("input", ""),
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "started_at": entry.get("started_at", utc_now_iso()),
            "finished_at": utc_now_iso(),
            "latency_ms": round(latency_ms, 2),
        })
        return request_id

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
