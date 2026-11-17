from __future__ import annotations

import html
import json
from pathlib import Path
from app.models import DiagnosticReport


def export_json(report: DiagnosticReport, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def export_html(report: DiagnosticReport, path: str | Path) -> None:
    cards=[]
    for f in report.findings:
        evidence="".join(f"<li>{html.escape(x)}</li>" for x in f.evidence)
        rec="".join(f"<li>{html.escape(x)}</li>" for x in f.recommendations)
        commands="".join(f"<li><code>{html.escape(x)}</code></li>" for x in f.commands)
        cards.append(f"<article class='{html.escape(f.severity)}'><h2>{html.escape(f.title)}</h2><p><b>{html.escape(f.severity.upper())} · {html.escape(f.status)} · уверенность {f.confidence:.0%}</b></p><p>{html.escape(f.explanation)}</p><h3>Доказательства</h3><ul>{evidence}</ul><h3>Рекомендации</h3><ul>{rec}</ul><h3>Команды</h3><ul>{commands}</ul></article>")
    host=" · ".join(html.escape(str(v)) for v in report.host.values())
    doc=f"""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Отчёт Fedora Doctor</title><style>body{{font:16px system-ui;max-width:1000px;margin:32px auto;padding:0 16px;color:#20242a;background:#f5f7fa}}article{{background:white;border-left:5px solid #728096;padding:16px 22px;margin:16px 0;border-radius:8px}}.critical{{border-color:#c62828}}.warning{{border-color:#ed9d00}}.info{{border-color:#4778bf}}code{{overflow-wrap:anywhere}}small{{color:#667}}</style><h1>Отчёт Fedora Doctor</h1><p>{html.escape(report.created_at)} · {report.duration_seconds:.1f} с</p><p>{host}</p>{''.join(cards) if cards else '<p>Найденных проблем нет по проверенным правилам.</p>'}<details><summary>Сырые данные</summary><pre>{html.escape(json.dumps(report.data,ensure_ascii=False,indent=2))}</pre></details></html>"""
    Path(path).write_text(doc, encoding="utf-8")
