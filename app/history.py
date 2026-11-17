from __future__ import annotations

import json
from pathlib import Path
from platformdirs import user_data_dir


def history_dir() -> Path:
    p=Path(user_data_dir("fedora-doctor")); p.mkdir(parents=True, exist_ok=True); return p


def save(report: dict) -> Path:
    p=history_dir()/"history.jsonl"
    with p.open("a", encoding="utf-8") as f: f.write(json.dumps(report,ensure_ascii=False)+"\n")
    return p


def recent(limit: int = 30) -> list[dict]:
    p=history_dir()/"history.jsonl"
    if not p.exists(): return []
    rows=[]
    lines=p.read_text(encoding="utf-8").splitlines()[-limit:]
    for index, line in enumerate(lines):
        try: rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            rows.append({"_error":f"Повреждённая запись истории #{index+1}: {exc.msg}"})
    return list(reversed(rows))
