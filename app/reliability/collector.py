from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from app.collectors.commands import run

from .incidents import parse_coredumpctl_json, parse_journal_json
from .store import ReliabilityStore, utc_now

EVENT_PATTERN = r"segfault|core dumped|dumped core|ANOM_ABEND|SIGSEGV|SIGABRT|crashed|not responding|unresponsive|drkonqi|Out of memory|oom-kill|Killed process|Kernel panic|Oops:|soft lockup|hard LOCKUP|GPU HANG|NVRM: Xid|fallen off the bus|Scheduled restart job|Main process exited|Failed with result|kwin_wayland|plasmashell|Xwayland|pipewire"


def collect_events(
    store: ReliabilityStore, since: str = "10 minutes ago"
) -> dict[str, Any]:
    """Read bounded journal/coredump metadata; never request raw core data."""
    journal = run(
        [
            "journalctl",
            "--since",
            since,
            "--output=json",
            "--no-pager",
            "--all",
            "-g",
            EVENT_PATTERN,
            "-n",
            "1200",
        ],
        timeout=12,
        max_chars=2_000_000,
    )
    coredumps = run(
        [
            "coredumpctl",
            "list",
            "--since",
            "24 hours ago",
            "--json=short",
            "--no-pager",
        ],
        timeout=8,
        max_chars=512_000,
    )
    journal_events = (
        parse_journal_json(journal.stdout)
        if journal.available and journal.returncode == 0
        else []
    )
    dump_events = (
        parse_coredumpctl_json(coredumps.stdout)
        if coredumps.available and coredumps.returncode == 0
        else []
    )
    events = _merge_duplicate_sources(journal_events + dump_events)
    journal_status = _command_status(journal)
    coredump_status = _command_status(coredumps)
    if dump_events and coredump_status.get("error"):
        coredump_status["warning"] = coredump_status.pop("error")
    inserted = 0
    for event in events:
        inserted += int(store.add_incident(event))
    inserted += int(detect_new_boot(store))
    store.rotate()
    return {
        "new_events": inserted,
        "parsed_events": len(events),
        "journal_status": journal_status,
        "coredump_status": coredump_status,
    }


def detect_new_boot(store: ReliabilityStore) -> bool:
    """Record a boot-ID change across monitor sessions without assuming it was unexpected."""
    boot_id = _current_boot_id()
    if not boot_id:
        return False
    previous = store.get_setting("last_boot_id")
    store.set_setting("last_boot_id", boot_id)
    if not previous or previous == boot_id:
        return False
    boot_time = datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(
        timespec="milliseconds"
    )
    identity = hashlib.sha256(
        f"boot-change\0{previous}\0{boot_id}".encode()
    ).hexdigest()
    return store.add_incident(
        {
            "fingerprint": identity,
            "occurred_at": boot_time,
            "category": "reboot",
            "process": "system",
            "source": "boot-id",
            "summary": "С момента последней проверки началась новая загрузка системы",
            "evidence": [f"previous boot ID={previous}", f"current boot ID={boot_id}"],
            "group_key": "reboot:system",
            "confidence": 0.3,
        }
    )


def _current_boot_id() -> str | None:
    try:
        return (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except OSError:
        return None


def sample_performance() -> dict[str, Any]:
    vm, swap = psutil.virtual_memory(), psutil.swap_memory()
    cpu_values = psutil.cpu_percent(interval=None, percpu=True)
    disk = psutil.disk_io_counters(perdisk=True) or {}
    net = psutil.net_io_counters(pernic=True) or {}
    temps: dict[str, list[dict[str, Any]]] = {}
    try:
        for name, rows in (psutil.sensors_temperatures(fahrenheit=False) or {}).items():
            temps[name] = [
                {
                    "label": t.label,
                    "current": t.current,
                    "high": t.high,
                    "critical": t.critical,
                }
                for t in rows
            ]
    except (AttributeError, OSError, psutil.Error):
        pass
    gpu_percent = vram_used = vram_total = None
    gpu = run(
        [
            "nvidia-smi",
            "--query-gpu=utilization.gpu,memory.used,memory.total",
            "--format=csv,noheader,nounits",
        ],
        timeout=2,
        max_chars=4096,
    )
    if gpu.available and gpu.returncode == 0:
        try:
            pieces = [x.strip() for x in gpu.stdout.splitlines()[0].split(",")]
            gpu_percent, vram_used, vram_total = (
                float(pieces[0]),
                int(pieces[1]) * 1024**2,
                int(pieces[2]) * 1024**2,
            )
        except (IndexError, ValueError):
            pass
    if gpu_percent is None:
        for device in sorted(Path("/sys/class/drm").glob("card[0-9]/device")):
            gpu_percent = _read_number(device / "gpu_busy_percent")
            vram_used = _read_number(device / "mem_info_vram_used")
            vram_total = _read_number(device / "mem_info_vram_total")
            if (
                gpu_percent is not None
                or vram_used is not None
                or vram_total is not None
            ):
                break
    return {
        "captured_at": utc_now(),
        "cpu_percent": round(sum(cpu_values) / len(cpu_values), 2)
        if cpu_values
        else None,
        "ram_percent": vm.percent,
        "ram_available": vm.available,
        "swap_percent": swap.percent,
        "gpu_percent": gpu_percent,
        "vram_used": vram_used,
        "vram_total": vram_total,
        "temperatures": temps,
        "disk_io": {
            n: {"read_bytes": x.read_bytes, "write_bytes": x.write_bytes}
            for n, x in disk.items()
        },
        "network": {
            n: {"bytes_sent": x.bytes_sent, "bytes_recv": x.bytes_recv}
            for n, x in net.items()
        },
        "load": list(os.getloadavg()) if hasattr(os, "getloadavg") else [],
    }


TRACKED_PACKAGE_RE = re.compile(
    r"^(?:kernel(?:-core|-modules|-modules-core|-modules-extra)?|nvidia(?:-.*)?|akmod-nvidia|xorg-x11-drv-nvidia(?:-.*)?|mesa(?:-.*)?|kwin(?:-.*)?|plasma-workspace(?:-.*)?|pipewire(?:-.*)?)$"
)
TRACKED_CONFIGS = (
    "/etc/default/grub",
    "/etc/environment",
    "/etc/modprobe.d",
    "/etc/systemd/system",
    "/etc/udev/rules.d",
    "/etc/X11/xorg.conf.d",
)


def collect_system_changes(store: ReliabilityStore) -> int:
    """Track selected RPM versions and system configuration metadata, not file contents."""
    old_state = store.get_setting("change_snapshot") or {}
    old_digest = store.get_setting("change_snapshot_digest")
    rpm = run(
        [
            "rpm",
            "-qa",
            "--qf",
            "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME}\n",
        ],
        timeout=10,
        max_chars=1_000_000,
    )
    state: dict[str, Any] = {"packages": {}, "configs": {}, "display": {}}
    if rpm.available and rpm.returncode == 0:
        for line in rpm.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3 or not TRACKED_PACKAGE_RE.match(parts[0]):
                continue
            state["packages"][parts[0]] = {"nevra": parts[1], "installed": parts[2]}
    else:
        state["packages"] = old_state.get("packages", {})
    for raw_path in TRACKED_CONFIGS:
        path = Path(raw_path)
        if path.is_file():
            state["configs"][raw_path] = _stat_signature(path)
        elif path.is_dir():
            try:
                for child in sorted(path.iterdir()):
                    if child.is_file() and (
                        raw_path != "/etc/systemd/system" or _relevant_unit(child.name)
                    ):
                        state["configs"][str(child)] = _stat_signature(child)
            except OSError:
                continue
    display = run(["kscreen-doctor", "-o"], timeout=5, max_chars=32_000)
    if display.available and display.returncode == 0:
        state["display"] = parse_display_snapshot(display.stdout)
    else:
        state["display"] = old_state.get("display", {})
    serialized = json.dumps(state, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode()).hexdigest()
    inserted = 0
    if old_digest and old_state and old_digest != digest:
        old_packages, new_packages = old_state.get("packages", {}), state["packages"]
        for name in sorted(set(old_packages) | set(new_packages)):
            before, after = old_packages.get(name), new_packages.get(name)
            if before != after:
                kind = (
                    "package-update"
                    if before and after
                    else "package-install"
                    if after
                    else "package-remove"
                )
                change = {
                    "fingerprint": hashlib.sha256(
                        f"{kind}\0{name}\0{before}\0{after}".encode()
                    ).hexdigest(),
                    "kind": kind,
                    "subject": name,
                    "details": {"before": before, "after": after},
                    "source": "rpm metadata",
                    "occurred_at": _rpm_change_time(after or before),
                }
                inserted += int(store.add_change(change))
        old_configs, new_configs = old_state.get("configs", {}), state["configs"]
        for path in sorted(set(old_configs) | set(new_configs)):
            before, after = old_configs.get(path), new_configs.get(path)
            if before != after:
                kind = (
                    "config-change"
                    if before and after
                    else "config-add"
                    if after
                    else "config-remove"
                )
                change = {
                    "fingerprint": hashlib.sha256(
                        f"{kind}\0{path}\0{before}\0{after}".encode()
                    ).hexdigest(),
                    "kind": kind,
                    "subject": path,
                    "details": {"metadata_before": before, "metadata_after": after},
                    "source": "file metadata",
                    "occurred_at": _metadata_change_time(after or before),
                }
                inserted += int(store.add_change(change))
        if old_state.get("display") != state["display"] and state["display"]:
            change = {
                "fingerprint": hashlib.sha256(
                    f"display-layout\0{old_state.get('display')}\0{state['display']}".encode()
                ).hexdigest(),
                "kind": "display-layout-change",
                "subject": "KDE monitor outputs / geometry / scale",
                "details": {
                    "before": old_state.get("display"),
                    "after": state["display"],
                },
                "source": "kscreen-doctor metadata",
            }
            inserted += int(store.add_change(change))
    store.set_setting("change_snapshot", state)
    store.set_setting("change_snapshot_digest", digest)
    return inserted


def _stat_signature(path: Path) -> dict[str, int]:
    st = path.stat()
    return {"mtime_ns": st.st_mtime_ns, "size": st.st_size, "inode": st.st_ino}


def _read_number(path: Path) -> float | int | None:
    try:
        value = int(path.read_text(encoding="ascii").strip())
        return value if "busy_percent" not in path.name else float(value)
    except (OSError, ValueError):
        return None


def _rpm_change_time(package_state: Any) -> str | None:
    try:
        installed = int(package_state.get("installed"))
        return datetime.fromtimestamp(installed, timezone.utc).isoformat(
            timespec="milliseconds"
        )
    except (AttributeError, TypeError, ValueError, OSError, OverflowError):
        return None


def _metadata_change_time(signature: Any) -> str | None:
    try:
        stamp = int(signature.get("mtime_ns")) / 1_000_000_000
        return datetime.fromtimestamp(stamp, timezone.utc).isoformat(
            timespec="milliseconds"
        )
    except (AttributeError, TypeError, ValueError, OSError, OverflowError):
        return None


def _relevant_unit(name: str) -> bool:
    return bool(
        re.search(r"kwin|plasma|nvidia|drm|pipewire|wayland|display|gpu", name, re.I)
    )


def parse_display_snapshot(raw: str) -> list[str]:
    """Keep monitor layout metadata, excluding EDID and serial-like fields."""
    selected = []
    for line in raw.splitlines():
        stripped = line.strip()
        if re.match(
            r"(?:Output:|Geometry:|Scale:|Rotation:|Mode:|Position:)", stripped, re.I
        ):
            selected.append(stripped[:500])
    return selected


def _merge_duplicate_sources(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    for event in sorted(
        events,
        key=lambda x: (x.get("occurred_at", ""), x.get("source") != "systemd-coredump"),
    ):
        duplicate = next(
            (
                old
                for old in kept
                if event.get("pid")
                and event.get("pid") == old.get("pid")
                and event.get("signal") == old.get("signal")
                and event.get("category") == old.get("category")
                and event.get("process") == old.get("process")
                and _nearby(
                    event.get("occurred_at", ""), old.get("occurred_at", ""), 20
                )
            ),
            None,
        )
        if duplicate:
            if event.get("source") == "systemd-coredump":
                duplicate.update(event)
            else:
                duplicate["evidence"] = list(
                    dict.fromkeys(
                        duplicate.get("evidence", []) + event.get("evidence", [])
                    )
                )
        else:
            kept.append(event)
    return kept


def _nearby(left: str, right: str, seconds: int) -> bool:
    try:
        a = datetime.fromisoformat(left.replace("Z", "+00:00"))
        b = datetime.fromisoformat(right.replace("Z", "+00:00"))
        return abs((a - b).total_seconds()) <= seconds
    except (TypeError, ValueError):
        return left == right


def _command_status(result: Any) -> dict[str, Any]:
    stderr = result.stderr[-1000:]
    error = result.error
    if not error and result.returncode not in (0, None):
        error = stderr or f"command exited with status {result.returncode}"
    if not error and re.search(
        r"failed to acquire bus|operation not permitted|permission denied|access denied",
        stderr,
        re.I,
    ):
        error = stderr
    return {
        "available": result.available,
        "returncode": result.returncode,
        "error": error,
        "stderr": stderr,
    }
