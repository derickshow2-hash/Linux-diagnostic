from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .incidents import group_incidents


def investigate(
    incidents: list[dict[str, Any]],
    changes: list[dict[str, Any]],
    change_window_hours: int = 24,
) -> dict[str, Any]:
    """Return cautious temporal correlations with explicit non-causal wording."""
    groups = group_incidents(incidents)
    correlations = []
    for incident in incidents:
        at = _time(incident.get("occurred_at"))
        if at is None:
            continue
        nearby = []
        for change in changes:
            change_at = _time(change.get("occurred_at"))
            if change_at is None:
                continue
            delta = (at - change_at).total_seconds()
            if 0 <= delta <= change_window_hours * 3600:
                nearby.append({"change": change, "seconds_before": int(delta)})
        if nearby:
            nearest = min(nearby, key=lambda item: item["seconds_before"])
            correlations.append(
                {
                    "incident": incident,
                    **nearest,
                    "status": "temporal-correlation",
                    "confidence": 0.35,
                    "assessment": "Изменение произошло раньше события; одной временной близости недостаточно, чтобы считать его причиной.",
                }
            )
    components: dict[str, int] = {}
    for group in groups:
        for component in group["components"]:
            components[component] = components.get(component, 0) + group["count"]
    candidates = [
        {
            "component": name,
            "related_events": count,
            "confidence": min(0.6, 0.25 + count * 0.05),
            "assessment": "Повторяемость делает компонент кандидатом для проверки, но не доказывает первопричину.",
        }
        for name, count in sorted(
            components.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    return {
        "groups": groups,
        "change_correlations": correlations,
        "possible_causes": candidates,
        "causality_established": False,
    }


def _time(value: Any) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
