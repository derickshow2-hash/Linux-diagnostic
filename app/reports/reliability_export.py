from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from app.reliability.investigation import investigate
from app.reliability.store import ReliabilityStore, utc_now


def reliability_payload(store: ReliabilityStore) -> dict[str, Any]:
    incidents = store.incidents(2000)
    changes = store.changes(2000)
    samples = store.samples(10000)
    return {
        "schema_version": 1,
        "exported_at": utc_now(),
        "incidents": incidents,
        "groups_and_correlations": investigate(incidents, changes),
        "changes": changes,
        "performance_samples": samples,
        "notes": [
            "Временная связь не доказывает причинность.",
            "Полные дампы памяти не экспортируются.",
        ],
    }


def export_reliability_json(store: ReliabilityStore, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(reliability_payload(store), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def export_reliability_html(store: ReliabilityStore, path: str | Path) -> None:
    payload = reliability_payload(store)
    escaped = html.escape(json.dumps(payload, ensure_ascii=False, indent=2))
    Path(path).write_text(
        "<!doctype html><html lang='ru'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Fedora Doctor — надёжность</title>"
        "<style>body{font:14px system-ui;margin:2rem;background:#111;color:#eee}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1b1b1b;padding:1rem;border-radius:.5rem}</style>"
        f"<h1>Fedora Doctor — мониторинг надёжности</h1><pre>{escaped}</pre></html>",
        encoding="utf-8",
    )
