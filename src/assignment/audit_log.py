"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input text + start timestamp keyed by request_id for latency tracking."""
        import uuid
        rid = request_id or str(uuid.uuid4())[:8]
        self._open[rid] = {
            "user_id": user_id,
            "input_text": text,
            "timestamp": utc_now_iso(),
            "start_time": __import__("time").time(),
        }
        return rid

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        import time as _time

        start_info = self._open.pop(request_id, None) if request_id else None
        latency_ms = None
        if start_info:
            latency_ms = round((_time.time() - start_info["start_time"]) * 1000, 1)

        entry = {
            "request_id": request_id,
            "user_id": user_id,
            "input_text": start_info["input_text"] if start_info else None,
            "output_text": text[:500],
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
            "timestamp": utc_now_iso(),
        }
        self.logs.append(entry)

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        from pathlib import Path
        p = Path(filepath)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
