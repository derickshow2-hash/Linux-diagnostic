from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

CRASH_SIGNALS = {
    "SIGSEGV",
    "SIGABRT",
    "SIGBUS",
    "SIGILL",
    "SIGFPE",
    "SIGSYS",
    "SIGTRAP",
}
CRASH_RE = re.compile(
    r"(?:segfault|segmentation fault|core dumped|dumped core|signal (?:11|6|7|4)|SIG(?:SEGV|ABRT|BUS|ILL|FPE)|ANOM_ABEND|application .{0,100} crashed|process .{0,100} crashed)",
    re.I,
)
HANG_RE = re.compile(r"not responding|unresponsive process|process .* hung", re.I)
OOM_RE = re.compile(
    r"Out of memory|oom-kill|Killed process|Memory cgroup out of memory", re.I
)
KERNEL_RE = re.compile(
    r"Kernel panic|Oops:|soft lockup|hard LOCKUP|watchdog:.*lockup|GPU HANG|GPU reset|NVRM: Xid|GPU has fallen off the bus",
    re.I,
)
SESSION_RE = re.compile(
    r"kwin_wayland|plasmashell|Xwayland|wayland|pipewire|nvidia_drm|drm atomic", re.I
)


def _decode_time(entry: dict[str, Any]) -> str:
    raw = entry.get("__REALTIME_TIMESTAMP") or entry.get("_SOURCE_REALTIME_TIMESTAMP")
    if raw:
        try:
            return datetime.fromtimestamp(int(raw) / 1_000_000, timezone.utc).isoformat(
                timespec="milliseconds"
            )
        except (TypeError, ValueError, OSError, OverflowError):
            pass
    return str(entry.get("_BOOT_ID") or "unknown-time")


def _text(value: Any) -> str:
    if isinstance(value, list):
        value = "\n".join(str(x) for x in value)
    return str(value or "")


def parse_journal_json(raw: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(entry, dict):
            continue
        msg = _text(entry.get("MESSAGE"))
        comm = _text(
            entry.get("COREDUMP_COMM")
            or entry.get("_COMM")
            or entry.get("SYSLOG_IDENTIFIER")
        )
        exe = _text(entry.get("COREDUMP_EXE") or entry.get("_EXE"))
        pid = _int(entry.get("COREDUMP_PID") or entry.get("_PID"))
        signal = _signal(entry.get("COREDUMP_SIGNAL"), msg)
        if OOM_RE.search(msg):
            category, summary, confidence = "oom", "OOM killer завершил процесс", 0.95
            match = re.search(r"Killed process\s+(\d+)\s+\(([^)]+)\)", msg, re.I)
            if match:
                pid, comm = int(match.group(1)), match.group(2)
        elif signal in CRASH_SIGNALS or CRASH_RE.search(msg):
            category, summary, confidence = (
                "crash",
                "Обнаружено аварийное завершение процесса",
                0.9,
            )
        elif HANG_RE.search(msg):
            category, summary, confidence = (
                "hang",
                "Журнал сообщает о неотвечающем процессе",
                0.35,
            )
        elif KERNEL_RE.search(msg):
            category, summary, confidence = (
                "kernel",
                "Обнаружена ошибка ядра или GPU",
                0.8,
            )
        elif SESSION_RE.search(msg) and re.search(
            r"error|failed|crash|segfault|hung|reset|timeout", msg, re.I
        ):
            category, summary, confidence = (
                "desktop",
                "Обнаружена ошибка графической сессии или мультимедиа",
                0.65,
            )
        elif _service_failure(msg):
            category, summary, confidence = (
                "service",
                "Сбой или перезапуск systemd-службы",
                0.65,
            )
        else:
            continue
        unit = _text(entry.get("_SYSTEMD_UNIT") or entry.get("_SYSTEMD_USER_UNIT"))
        process_name = unit if category == "service" and unit else comm or exe or None
        exit_code = _text(entry.get("COREDUMP_EXIT_CODE") or entry.get("EXIT_CODE"))
        exit_status = _text(
            entry.get("COREDUMP_EXIT_STATUS") or entry.get("EXIT_STATUS")
        )
        if exit_status:
            exit_code = f"{exit_code} {exit_status}".strip()
        detail = msg[:1500]
        stack = _text(entry.get("COREDUMP_STACKTRACE"))[:12000]
        if not stack and "stacktrace" in entry:
            stack = _text(entry.get("stacktrace"))[:12000]
        key_text = "\0".join(
            [
                category,
                str(entry.get("_BOOT_ID", "")),
                str(entry.get("__MONOTONIC_TIMESTAMP", "")),
                str(pid or ""),
                signal or "",
                detail,
            ]
        )
        events.append(
            {
                "fingerprint": hashlib.sha256(
                    key_text.encode("utf-8", "replace")
                ).hexdigest(),
                "occurred_at": _decode_time(entry),
                "category": category,
                "process": process_name,
                "pid": pid,
                "signal": signal,
                "exit_code": exit_code or None,
                "app_version": _package_version(entry),
                "stack_trace": stack or None,
                "source": "journal",
                "summary": summary,
                "evidence": [
                    detail,
                    *([f"unit={unit}"] if unit else []),
                    *([f"exe={exe}"] if exe else []),
                ],
                "group_key": _group_key(category, process_name or unit or "system"),
                "confidence": confidence,
                "boot_id": _text(entry.get("_BOOT_ID")) or None,
                "related_component": _component(comm, exe, unit, msg),
            }
        )
    return events


def parse_coredumpctl_json(raw: str) -> list[dict[str, Any]]:
    """Parse systemd-coredump JSON without fetching or retaining core memory files."""
    entries: list[Any] = []
    try:
        decoded = json.loads(raw)
        entries = decoded if isinstance(decoded, list) else [decoded]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out = []
    for row in entries:
        if not isinstance(row, dict):
            continue
        pid = _int(_first(row, "COREDUMP_PID", "PID", "pid"))
        comm = _text(_first(row, "COREDUMP_COMM", "COMM", "comm"))
        exe = _text(_first(row, "COREDUMP_EXE", "EXE", "exe"))
        signal = _signal(
            _first(row, "COREDUMP_SIGNAL", "SIGNAL", "signal", "SIG", "sig"), ""
        )
        stamp = _first(
            row, "COREDUMP_TIMESTAMP", "TIMESTAMP", "timestamp", "TIME", "time"
        )
        occurred = _timestamp(stamp)
        process_name = comm or (Path(exe).name if exe else None)
        identity = "\0".join([occurred, str(pid or ""), exe, signal or ""])
        out.append(
            {
                "fingerprint": hashlib.sha256(
                    identity.encode("utf-8", "replace")
                ).hexdigest(),
                "occurred_at": occurred,
                "category": "crash",
                "process": process_name,
                "pid": pid,
                "signal": signal,
                "exit_code": _text(_first(row, "COREDUMP_EXIT_CODE", "EXIT_CODE"))
                or None,
                "app_version": _package_version(row),
                "stack_trace": None,
                "source": "systemd-coredump",
                "summary": "systemd-coredump сохранил дамп аварии",
                "evidence": [
                    f"executable={exe}" if exe else "Core dump metadata available"
                ],
                "group_key": _group_key("crash", process_name or "process"),
                "confidence": 0.95,
                "related_component": _component(comm, exe, "", ""),
            }
        )
    return out


def group_incidents(
    events: list[dict[str, Any]], window_seconds: int = 300
) -> list[dict[str, Any]]:
    """Build temporal groups; group membership indicates correlation, not causality."""
    rows = sorted(events, key=lambda x: str(x.get("occurred_at", "")))
    groups: list[dict[str, Any]] = []
    related_categories = {
        "oom",
        "kernel",
        "desktop",
        "crash",
        "hang",
        "service",
        "reboot",
    }
    for event in rows:
        at = _parse_timestamp(event.get("occurred_at"))
        target = None
        for group in reversed(groups):
            last_at = _parse_timestamp(group["events"][-1].get("occurred_at"))
            close = (
                at and last_at and 0 <= (at - last_at).total_seconds() <= window_seconds
            )
            same_signature = event.get("group_key") == group.get("signature")
            event_component = event.get("related_component")
            same_component = bool(
                event_component and event_component in group["components"]
            )
            cross_system = event.get("category") in related_categories and any(
                old.get("category") in related_categories for old in group["events"]
            )
            if close and (same_signature or same_component or cross_system):
                target = group
                break
        if target is None:
            groups.append(
                {
                    "group_key": f"temporal:{event.get('group_key', 'system')}",
                    "signature": event.get("group_key", "system"),
                    "events": [event],
                    "components": set(_components(event)),
                }
            )
        else:
            target["events"].append(event)
            target["components"].update(_components(event))
    result = []
    for group in groups:
        evs = group["events"]
        result.append(
            {
                "group_key": group["group_key"],
                "start": evs[0].get("occurred_at"),
                "end": evs[-1].get("occurred_at"),
                "count": len(evs),
                "components": sorted(group["components"]),
                "events": evs,
                "assessment": "Повторяющиеся события сгруппированы по времени и компоненту; причинность не установлена.",
            }
        )
    return result


def _components(event: dict[str, Any]) -> set[str]:
    component = event.get("related_component")
    return {component} if component else set()


def _component(*values: str) -> str | None:
    text = " ".join(values).lower()
    for match, component in (
        ("chatgpt", "ChatGPT"),
        ("kwin", "KWin"),
        ("plasmashell", "Plasma"),
        ("xwayland", "XWayland"),
        ("pipewire", "PipeWire"),
        ("nvidia", "NVIDIA"),
        ("systemd", "systemd"),
        ("code", "VS Code"),
    ):
        if match in text:
            return component
    return None


def _group_key(category: str, process: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", process.lower()).strip("-")[:60]
    return f"{category}:{normalized or 'system'}"


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first(row: dict[str, Any], *keys: str) -> Any:
    return next((row[k] for k in keys if row.get(k) not in (None, "")), None)


def _package_version(row: dict[str, Any]) -> str | None:
    value = _first(row, "COREDUMP_PACKAGE_VERSION", "PACKAGE_VERSION")
    if value:
        return _text(value)
    package = _first(row, "COREDUMP_PACKAGE_JSON", "PACKAGE_JSON")
    if isinstance(package, dict):
        return _text(package.get("version")) or None
    if package:
        try:
            decoded = json.loads(package)
            if isinstance(decoded, dict):
                return _text(decoded.get("version")) or None
        except (TypeError, json.JSONDecodeError):
            pass
    return None


def _signal(value: Any, message: str) -> str | None:
    text = _text(value).strip()
    if text:
        text = text.upper()
        numeric = {
            "4": "SIGILL",
            "5": "SIGTRAP",
            "6": "SIGABRT",
            "7": "SIGBUS",
            "8": "SIGFPE",
            "11": "SIGSEGV",
            "31": "SIGSYS",
        }
        if text in numeric:
            return numeric[text]
        return text if text.startswith("SIG") else f"SIG{text}"
    found = re.search(r"SIG(?:SEGV|ABRT|BUS|ILL|FPE|SYS|TRAP)", message, re.I)
    return found.group(0).upper() if found else None


def _service_failure(message: str) -> bool:
    lowered = message.lower()
    if "failed with result" in lowered or "scheduled restart job" in lowered:
        return True
    if "main process exited" not in lowered:
        return False
    code = re.search(r"\bcode=([a-z_-]+)", lowered)
    status = re.search(r"\bstatus=(\d+)", lowered)
    return bool(
        (code and code.group(1) not in {"exited", "success"})
        or (status and int(status.group(1)) != 0)
    )


def _timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        try:
            # systemd JSON timestamps are commonly microseconds since epoch.
            return datetime.fromtimestamp(
                float(value) / (1_000_000 if value > 10**12 else 1), timezone.utc
            ).isoformat(timespec="milliseconds")
        except (ValueError, OSError, OverflowError):
            pass
    if isinstance(value, str):
        text = value.strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except ValueError:
            pass
        text = re.sub(r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+", "", text)
        zone_match = re.search(r"\s+([A-Z]{2,6})$", text)
        zone_name = {"MSK": "Europe/Moscow", "UTC": "UTC", "GMT": "GMT"}.get(
            zone_match.group(1) if zone_match else ""
        )
        text = re.sub(r"\s+[A-Z]{2,6}$", "", text)
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
            parsed = (
                parsed.replace(tzinfo=ZoneInfo(zone_name))
                if zone_name
                else parsed.astimezone()
            )
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except ValueError:
            pass
    return str(value or "unknown-time")


def _parse_timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (TypeError, ValueError):
        return None
