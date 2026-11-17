from __future__ import annotations

import os
import platform
import time
from pathlib import Path
from typing import Any

import psutil

from .commands import run, output


def _record(value: Any) -> dict[str, Any]:
    """Convert psutil named tuples and regular records into JSON-safe mappings."""
    if hasattr(value, "_asdict"):
        return value._asdict()
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    raise TypeError(f"Unsupported system record type: {type(value).__name__}")


def _cmd(key: str, argv: list[str], timeout: float = 8) -> dict[str, Any]:
    r = run(argv, timeout)
    return {"argv": r.argv, "available": r.available, "returncode": r.returncode,
            "stdout": r.stdout.strip(), "stderr": r.stderr.strip(), "error": r.error}


def host_info() -> dict[str, Any]:
    release = {}; release_error=""
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1); release[k] = v.strip('"')
    except OSError as exc:
        release_error=str(exc)
    return {"hostname": platform.node(), "os": release.get("PRETTY_NAME", platform.platform()),
            "kernel": platform.release(), "architecture": platform.machine(), "desktop": os.getenv("XDG_CURRENT_DESKTOP", "unknown"),
            "session_type": os.getenv("XDG_SESSION_TYPE", "unknown"), "uid": os.getuid() if hasattr(os, "getuid") else None,
            "os_release_error": release_error}


def collect_system() -> dict[str, Any]:
    return {"systemd_failed": _cmd("systemd_failed", ["systemctl", "--failed", "--no-legend", "--plain"]),
            "systemd_status": _cmd("systemd_status", ["systemctl", "is-system-running"]),
            "boot_time": psutil.boot_time(), "uptime_seconds": max(0, time.time()-psutil.boot_time()),
            "dnf_history": _cmd("dnf_history", ["dnf5", "history", "list", "--reverse"], 15),
            "dnf_repolist": _cmd("dnf_repolist", ["dnf5", "repolist", "--enabled"], 15),
            # Cache-only so merely opening the dashboard never refreshes repositories or writes metadata.
            "updates_cached": _cmd("updates_cached", ["dnf5", "--cacheonly", "list", "--upgrades"], 12)}


def collect_performance() -> dict[str, Any]:
    # Short interval is bounded to avoid making diagnostics a material workload.
    per_cpu = psutil.cpu_percent(interval=0.3, percpu=True)
    freq = psutil.cpu_freq(percpu=True)
    mem, swap = psutil.virtual_memory(), psutil.swap_memory()
    sensors = {}; sensor_errors={}
    try: sensors = psutil.sensors_temperatures()
    except (AttributeError, OSError) as exc: sensor_errors["temperatures"]=str(exc)
    try: fans = psutil.sensors_fans()
    except (AttributeError, OSError) as exc: fans = {}; sensor_errors["fans"]=str(exc)
    try: power = psutil.sensors_battery()
    except (AttributeError, OSError) as exc: power = None; sensor_errors["battery"]=str(exc)
    return {"cpu_percent_per_core": per_cpu, "cpu_frequency_mhz": [f.current if f else None for f in (freq or [])],
            "cpu_count_logical": psutil.cpu_count(), "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [],
            "memory": {"total": mem.total, "available": mem.available, "used": mem.used, "percent": mem.percent,
                       "cached": getattr(mem, "cached", 0), "buffers": getattr(mem, "buffers", 0)},
            "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
            "cpu_governor": _read_glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"),
            "cpu_epp": _read_glob("/sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference"),
            "temperatures": {k: [{"label": x.label, "current": x.current, "high": x.high, "critical": x.critical} for x in v] for k,v in (sensors or {}).items()},
            "sensor_errors": sensor_errors,
            "fans": fans, "battery": str(power) if power else None,
            "disk_io": {k: _record(v) for k,v in (psutil.disk_io_counters(perdisk=True) or {}).items()},
            "processes": _top_processes(), "oom_recent": _cmd("oom_recent", ["journalctl", "-k", "-b", "--no-pager", "-g", "Out of memory|oom-kill|Killed process", "-n", "60"], 10)}


def _read_glob(pattern: str) -> list[str]:
    import glob
    out=[]
    for p in glob.glob(pattern):
        try: out.append(f"{p}: {Path(p).read_text().strip()}")
        except OSError as exc: out.append(f"{p}: <недоступно: {exc}>")
    return out


def _top_processes() -> list[dict[str, Any]]:
    rows=[]; tracked=[]; started=time.monotonic()
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            before=p.cpu_times(); tracked.append((p, before.user+before.system, p.info))
        except (psutil.Error, OSError): continue
    time.sleep(0.15)
    elapsed=max(time.monotonic()-started, .01); cores=psutil.cpu_count() or 1
    for p, old, info in tracked:
        try:
            now=p.cpu_times(); pct=max(0,(now.user+now.system-old)/elapsed/cores*100)
            rows.append({"pid":info["pid"],"name":info["name"],"rss":info["memory_info"].rss if info["memory_info"] else 0,"cpu_percent":round(pct,1)})
        except (psutil.Error, OSError): continue
    return sorted(rows, key=lambda x: x["cpu_percent"], reverse=True)[:12]


def collect_gpu() -> dict[str, Any]:
    nvidia = _cmd("nvidia_smi", ["nvidia-smi", "--query-gpu=name,driver_version,utilization.gpu,temperature.gpu,memory.used,memory.total,clocks.gr,clocks.mem", "--format=csv,noheader,nounits"])
    return {"nvidia_smi": nvidia, "modules": _cmd("modules", ["lsmod"]),
            "nouveau_loaded": _cmd("nouveau", ["modinfo", "-F", "filename", "nouveau"]),
            "drm": _cmd("drm", ["cat", "/proc/cmdline"]),
            "display": _cmd("display", ["kscreen-doctor", "-o"]),
            "vulkan": _cmd("vulkan", ["vulkaninfo", "--summary"], 12),
            "opengl": _cmd("opengl", ["glxinfo", "-B"], 8),
            "gpu_journal": _cmd("gpu_journal", ["journalctl", "-b", "--no-pager", "-k", "-g", "NVIDIA|nvidia|nouveau|Xid|drm", "-n", "120"], 12),
            "kwin_journal": _cmd("kwin_journal", ["journalctl", "-b", "--no-pager", "-g", "kwin|plasmashell", "-n", "80"], 10),
            "loaded_nvidia": _module_version("nvidia")}


def _module_version(module: str) -> str:
    return output(["cat", f"/sys/module/{module}/version"])


def collect_storage() -> dict[str, Any]:
    disks = []; disk_usage_errors=[]
    for p in psutil.disk_partitions(all=False):
        try:
            u=psutil.disk_usage(p.mountpoint)
            disks.append({"device":p.device,"mountpoint":p.mountpoint,"fstype":p.fstype,"total":u.total,"used":u.used,"free":u.free,"percent":u.percent})
        except OSError as exc: disk_usage_errors.append(f"{p.mountpoint}: {exc}")
    block_devices=_cmd("block_devices", ["lsblk", "-J", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,TRAN"])
    smart_results=[]; lsblk_parse_error=""
    try:
        import json
        block_tree=json.loads(block_devices["stdout"]).get("blockdevices",[])
        candidates=[f"/dev/{d['name']}" for d in block_tree if d.get("type")=="disk" and d.get("name")]
        for device in candidates[:4]:
            smart_results.append({"device":device, **_cmd("smartctl", ["smartctl", "-a", device], 6)})
    except (ValueError, TypeError) as exc:
        lsblk_parse_error=str(exc)
    return {"partitions": disks, "disk_usage_errors":disk_usage_errors, "block_devices": block_devices,
            "smart_devices": smart_results, "smart_scan": _cmd("smart_scan", ["smartctl", "--scan-open"], 8), "lsblk_parse_error":lsblk_parse_error,
            "btrfs_usage": _cmd("btrfs_usage", ["btrfs", "filesystem", "usage", "-b", "/"]),
            "btrfs_device": _cmd("btrfs_device", ["btrfs", "device", "stats", "/"]),
            "btrfs_scrub": _cmd("btrfs_scrub", ["btrfs", "scrub", "status", "/"]),
            "io_journal": _cmd("io_journal", ["journalctl", "-b", "--no-pager", "-k", "-g", "I/O error|blk_update_request|Buffer I/O|nvme.*error|ata.*error", "-n", "100"], 10)}


def collect_network() -> dict[str, Any]:
    routes=_cmd("routes", ["ip", "-j", "route"])
    gateway=None; route_parse_error=""
    try:
        import json
        gateway=next((r.get("gateway") for r in json.loads(routes["stdout"]) if r.get("dst")=="default" and r.get("gateway")),None)
    except (ValueError, TypeError) as exc: route_parse_error=str(exc)
    # Three ICMP probes to the detected default gateway are bounded and do not alter network settings.
    gateway_ping=_cmd("gateway_ping", ["ping", "-n", "-c", "3", "-W", "1", gateway], 5) if gateway else {"available":False,"stdout":"Шлюз по умолчанию не определён","error":""}
    dns_probe=_cmd("dns_probe", ["getent", "ahosts", "fedoraproject.org"], 4)
    return {"interfaces": [{"name":n, "is_up":s.isup, "speed_mbps":s.speed, "mtu":s.mtu, "duplex":str(s.duplex), "addresses":[a.address for a in psutil.net_if_addrs().get(n,[])]} for n,s in psutil.net_if_stats().items()],
            "counters": {n:_record(c) for n,c in psutil.net_io_counters(pernic=True).items()},
            "nm": _cmd("nm", ["nmcli", "general", "status"]), "routes": routes, "route_parse_error":route_parse_error,"gateway":gateway,"gateway_ping":gateway_ping,
            "dns": _cmd("dns", ["resolvectl", "status"]), "dns_probe":dns_probe, "driver": _cmd("driver", ["lspci", "-nnk"]),
            "link": _cmd("link", ["ip", "-s", "link"])}


def collect_hardware() -> dict[str, Any]:
    return {"dmi": _cmd("dmi", ["dmidecode", "--type", "memory"], 8), "mce": _cmd("mce", ["journalctl", "-k", "-b", "--no-pager", "-g", "MCE|EDAC|hardware error|Machine Check", "-n", "100"], 10),
            "sensors": _cmd("sensors", ["sensors", "-j"]), "cpu_info": _cmd("cpu_info", ["lscpu", "-J"])}


def collect_logs() -> dict[str, Any]:
    return {"current_errors": _cmd("current_errors", ["journalctl", "-b", "-p", "err", "--no-pager", "-n", "250"], 12),
            "previous_errors": _cmd("previous_errors", ["journalctl", "-b", "-1", "-p", "err", "--no-pager", "-n", "120"], 12),
            "kernel": _cmd("kernel", ["journalctl", "-k", "-b", "--no-pager", "-p", "warning", "-n", "250"], 12),
            "boot": _cmd("boot", ["systemd-analyze", "time"]), "blame": _cmd("blame", ["systemd-analyze", "blame", "--no-pager"]),
            "critical_chain": _cmd("critical_chain", ["systemd-analyze", "critical-chain"]),
            "efi": _cmd("efi", ["findmnt", "/boot/efi"])}


COLLECTORS = {"Обзор": (collect_system,), "CPU и RAM": (collect_performance, collect_hardware),
             "GPU и графика": (collect_gpu,), "Накопители": (collect_storage,), "Сеть": (collect_network,),
             "Службы и процессы": (collect_system, collect_performance), "Системные журналы": (collect_logs,), "Загрузка": (collect_logs,)}


def collect_all() -> dict[str, Any]:
    data={}
    for group, funcs in COLLECTORS.items():
        for fn in funcs:
            key = fn.__name__.removeprefix("collect_")
            if key not in data: data[key]=fn()
    data["logs"] = collect_logs()
    return data
