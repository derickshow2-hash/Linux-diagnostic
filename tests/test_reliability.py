from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from app.collectors.commands import CommandResult
from app.main import MainWindow
from app.reliability import collector
from app.reliability.collector import (
    _merge_duplicate_sources,
    collect_events,
    collect_system_changes,
    detect_new_boot,
    parse_display_snapshot,
)
from app.reliability.incidents import (
    group_incidents,
    parse_coredumpctl_json,
    parse_journal_json,
)
from app.reliability.investigation import investigate
from app.reliability.store import ReliabilityStore
from app.reports.reliability_export import (
    export_reliability_html,
    export_reliability_json,
)


def journal_line(message: str, **extra) -> str:
    row = {
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": "1794942000000000",
        "__MONOTONIC_TIMESTAMP": "1234",
        "_BOOT_ID": "boot-1",
        "_COMM": "demo-app",
        "_PID": "4242",
    }
    row.update(extra)
    return json.dumps(row)


def test_detects_abort_and_segfault_but_not_ordinary_exit():
    lines = [
        journal_line(
            "Process 4242 (demo-app) dumped core.",
            COREDUMP_SIGNAL="6",
            COREDUMP_PID="4242",
        ),
        journal_line("segfault at 0 ip 0", _COMM="browser", _PID="90"),
        journal_line("Process terminated by signal 15", _COMM="normal-app", _PID="92"),
        journal_line("Process exited with status 0", _COMM="normal-app", _PID="91"),
        journal_line(
            "Main process exited, code=exited, status=0/SUCCESS",
            _COMM="systemd",
            _PID="1",
        ),
    ]
    events = parse_journal_json("\n".join(lines))
    assert len(events) == 2
    assert events[0]["signal"] == "SIGABRT"
    assert any(x["category"] == "crash" for x in events)


def test_parses_kernel_oom_and_process_context():
    (event,) = parse_journal_json(
        journal_line("Out of memory: Killed process 3432 (code) total-vm:1kB")
    )
    assert event["category"] == "oom"
    assert event["pid"] == 3432
    assert event["process"] == "code"


def test_coredump_record_uses_victim_process_not_logger_process():
    (event,) = parse_journal_json(
        journal_line(
            "Process 4242 (demo-app) dumped core.",
            _COMM="systemd-coredump",
            _PID="4243",
            COREDUMP_COMM="demo-app",
            COREDUMP_PID="4242",
            COREDUMP_SIGNAL="6",
        )
    )
    assert event["process"] == "demo-app"
    assert event["pid"] == 4242


def test_detects_service_kde_errors_and_journal_reported_hangs():
    rows = [
        journal_line(
            "systemd: Scheduled restart job, restart counter is at 1", _COMM="systemd"
        ),
        journal_line(
            "kwin_wayland: rendering failed after timeout", _COMM="kwin_wayland"
        ),
        journal_line("Application Firefox is not responding", _COMM="drkonqi"),
    ]
    events = parse_journal_json("\n".join(rows))
    assert {event["category"] for event in events} == {"service", "desktop", "hang"}


def test_core_dump_metadata_is_parsed_without_core_payload():
    rows = parse_coredumpctl_json(
        json.dumps(
            [
                {
                    "COREDUMP_PID": 4242,
                    "COREDUMP_COMM": "demo-app",
                    "COREDUMP_EXE": "/usr/bin/demo-app",
                    "COREDUMP_SIGNAL": 6,
                    "COREDUMP_TIMESTAMP": 1794942000000000,
                }
            ]
        )
    )
    assert rows[0]["source"] == "systemd-coredump"
    assert rows[0]["signal"] == "SIGABRT"
    assert rows[0]["stack_trace"] is None


def test_coredumpctl_local_timestamp_and_short_signal_are_normalized():
    (row,) = parse_coredumpctl_json(
        json.dumps(
            [
                {
                    "time": "Tue 2026-01-02 12:00:00 UTC",
                    "pid": 4242,
                    "sig": "ABRT",
                    "exe": "/usr/bin/demo-app",
                }
            ]
        )
    )
    assert row["occurred_at"] == "2026-01-02T12:00:00.000+00:00"
    assert row["process"] == "demo-app"
    assert row["signal"] == "SIGABRT"


def test_coredump_and_journal_copy_of_same_event_are_merged():
    core = {
        "occurred_at": "2026-01-02T12:00:00.000+00:00",
        "pid": 4242,
        "signal": "SIGABRT",
        "category": "crash",
        "process": "demo-app",
        "source": "systemd-coredump",
        "evidence": ["core"],
    }
    journal = {
        **core,
        "source": "journal",
        "fingerprint": "different",
        "evidence": ["journal"],
    }
    merged = _merge_duplicate_sources([core, journal])
    assert len(merged) == 1
    assert set(merged[0]["evidence"]) == {"core", "journal"}


def test_timestamp_conversion_uses_journal_microseconds():
    (event,) = parse_journal_json(
        journal_line("NVRM: Xid 79", _COMM="kernel", _PID="0")
    )
    parsed = datetime.fromisoformat(event["occurred_at"])
    assert parsed.tzinfo is not None
    assert parsed.year == 2026


def test_duplicate_incidents_are_counted_once_and_survive_restart(tmp_path):
    store = ReliabilityStore(tmp_path / "history.sqlite3")
    event = {
        "fingerprint": "same",
        "category": "crash",
        "process": "demo-app",
        "summary": "SIGABRT",
    }
    assert store.add_incident(event) is True
    assert store.add_incident(event) is False
    reopened = ReliabilityStore(tmp_path / "history.sqlite3")
    (row,) = reopened.incidents()
    assert row["occurrences"] == 1
    assert row["process"] == "demo-app"


def test_groups_related_events_and_keeps_causality_unproven():
    start = datetime(2026, 11, 17, 18, tzinfo=timezone.utc)
    events = [
        {
            "occurred_at": start.isoformat(),
            "group_key": "crash:chatgpt",
            "category": "crash",
            "related_component": "demo-app",
        },
        {
            "occurred_at": (start + timedelta(seconds=90)).isoformat(),
            "group_key": "crash:chatgpt",
            "category": "crash",
            "related_component": "demo-app",
        },
    ]
    groups = group_incidents(events)
    assert groups[0]["count"] == 2
    result = investigate(events, [])
    assert result["causality_established"] is False
    assert result["possible_causes"][0]["component"] == "demo-app"


def test_change_is_only_temporal_correlation_not_cause():
    at = datetime(2026, 11, 17, 18, tzinfo=timezone.utc)
    result = investigate(
        [
            {
                "occurred_at": at.isoformat(),
                "group_key": "crash:chatgpt",
                "category": "crash",
            }
        ],
        [
            {
                "occurred_at": (at - timedelta(minutes=5)).isoformat(),
                "kind": "package-update",
                "subject": "mesa",
            }
        ],
    )
    assert result["change_correlations"][0]["status"] == "temporal-correlation"
    assert "недостаточно" in result["change_correlations"][0]["assessment"]


def test_sqlite_sample_and_change_storage_and_retention_rotation(tmp_path):
    store = ReliabilityStore(tmp_path / "history.sqlite3")
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    store.add_sample(
        {"captured_at": old, "cpu_percent": 42, "disk_io": {"nvme0": {"read_bytes": 5}}}
    )
    store.add_sample(
        {"captured_at": datetime.now(timezone.utc).isoformat(), "cpu_percent": 10}
    )
    store.add_change(
        {
            "fingerprint": "change-1",
            "kind": "config-change",
            "subject": "/etc/environment",
        }
    )
    assert store.rotate()["samples"] == 1
    assert len(store.samples()) == 1
    assert store.changes()[0]["subject"] == "/etc/environment"


def test_rotation_honors_configured_sample_limit(tmp_path):
    store = ReliabilityStore(tmp_path / "bounded.sqlite3")
    store.set_setting("max_sample_rows", 100)
    base = datetime.now(timezone.utc)
    for index in range(102):
        store.add_sample(
            {
                "captured_at": (base + timedelta(seconds=index)).isoformat(),
                "cpu_percent": index,
            }
        )
    assert store.rotate()["samples"] == 2
    assert len(store.samples(200)) == 100


def test_schema_migration_is_versioned_and_repeatable(tmp_path):
    dbpath = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(dbpath) as db:
        db.execute("PRAGMA user_version=0")
    ReliabilityStore(dbpath)
    with sqlite3.connect(dbpath) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert ReliabilityStore(dbpath).get_setting("interval_seconds") == 30


def test_boot_change_is_reported_without_claiming_unexpected_restart(
    monkeypatch, tmp_path
):
    store = ReliabilityStore(tmp_path / "boot.sqlite3")
    store.set_setting("last_boot_id", "old-boot")
    monkeypatch.setattr(collector, "_current_boot_id", lambda: "new-boot")
    monkeypatch.setattr(collector.psutil, "boot_time", lambda: 1794942000)
    assert detect_new_boot(store)
    (row,) = store.incidents()
    assert row["category"] == "reboot"
    assert "новая загрузка" in row["summary"]


def test_display_snapshot_excludes_unrelated_monitor_metadata():
    snapshot = parse_display_snapshot(
        """Output: 1 HDMI-A-1 enabled connected
Geometry: 1920x1080+0+0
Scale: 1.25
EDID: private monitor data
Serial: 12345
Mode: 1920x1080@60
"""
    )
    assert len(snapshot) == 4
    assert all("EDID" not in line and "Serial" not in line for line in snapshot)


def test_unavailable_journal_and_coredump_tools_are_reported(monkeypatch, tmp_path):
    def absent(argv, **kwargs):
        return CommandResult(argv, False, None, error="missing")

    monkeypatch.setattr(collector, "run", absent)
    status = collect_events(ReliabilityStore(tmp_path / "events.sqlite3"))
    assert status["journal_status"]["available"] is False
    assert status["coredump_status"]["available"] is False
    assert status["parsed_events"] == 0


def test_permission_error_is_not_reported_as_clean_source():
    blocked = CommandResult(
        ["coredumpctl"],
        True,
        0,
        stderr="Failed to acquire bus: Operation not permitted",
    )
    result = collector._command_status(blocked)
    assert "Operation not permitted" in result["error"]


def test_rpm_snapshot_is_idempotent_and_tracks_selected_versions(monkeypatch, tmp_path):
    rows = ["kernel-core\t0:7.3.3-1.fc44.x86_64\t1", "random-app\t0:1-1.fc44.x86_64\t2"]
    monkeypatch.setattr(
        collector,
        "run",
        lambda argv, **kwargs: CommandResult(argv, True, 0, "\n".join(rows)),
    )
    monkeypatch.setattr(collector, "TRACKED_CONFIGS", ())
    store = ReliabilityStore(tmp_path / "changes.sqlite3")
    assert collect_system_changes(store) == 0  # First run establishes the baseline.
    assert collect_system_changes(store) == 0  # Unchanged state creates no event.
    rows[0] = "kernel-core\t0:7.3.4-1.fc44.x86_64\t3"
    assert collect_system_changes(store) == 1
    assert store.changes()[0]["subject"] == "kernel-core"


def test_performance_sample_contains_series_fields(monkeypatch):
    class Mem:
        percent = 50
        available = 1000

    class Swap:
        percent = 10

    monkeypatch.setattr(collector.psutil, "virtual_memory", lambda: Mem())
    monkeypatch.setattr(collector.psutil, "swap_memory", lambda: Swap())
    monkeypatch.setattr(collector.psutil, "cpu_percent", lambda **kwargs: [20, 40])
    monkeypatch.setattr(collector.psutil, "disk_io_counters", lambda **kwargs: {})
    monkeypatch.setattr(collector.psutil, "net_io_counters", lambda **kwargs: {})
    monkeypatch.setattr(collector.psutil, "sensors_temperatures", lambda **kwargs: {})
    monkeypatch.setattr(
        collector, "run", lambda argv, **kwargs: CommandResult(argv, False, None)
    )
    sample = collector.sample_performance()
    assert sample["cpu_percent"] == 30
    assert sample["ram_percent"] == 50
    assert sample["swap_percent"] == 10
    assert {"disk_io", "network", "temperatures", "load"} <= sample.keys()


def test_reliability_exports_include_history_and_escape_html(tmp_path):
    store = ReliabilityStore(tmp_path / "export.sqlite3")
    store.add_incident(
        {
            "fingerprint": "one",
            "occurred_at": "2026-11-17T00:00:00+00:00",
            "category": "crash",
            "summary": "<script>bad</script>",
            "process": "app",
        }
    )
    json_path, html_path = tmp_path / "reliability.json", tmp_path / "reliability.html"
    export_reliability_json(store, json_path)
    export_reliability_html(store, html_path)
    assert (
        json.loads(json_path.read_text())["incidents"][0]["summary"]
        == "<script>bad</script>"
    )
    html = html_path.read_text()
    assert "&lt;script&gt;" in html
    assert "<script>bad" not in html


def test_gui_reliability_scan_runs_asynchronously_and_persists(
    qtbot, monkeypatch, tmp_path
):
    from app import main

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(main, "collect_events", lambda store, since: {"new_events": 0})
    monkeypatch.setattr(main, "collect_system_changes", lambda store: 0)
    monkeypatch.setattr(
        main, "sample_performance", lambda: {"cpu_percent": 12, "ram_percent": 40}
    )
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    assert "Надёжность" in [window.tabs.tabText(i) for i in range(window.tabs.count())]
    window.start_reliability(False)
    qtbot.waitUntil(lambda: window.reliability_thread is None, timeout=5000)
    assert len(ReliabilityStore().samples()) == 1
    assert window.performance_history.rowCount() == 1


def test_monitor_can_be_stopped_without_blocking_gui(qtbot, monkeypatch, tmp_path):
    from app import main

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(main, "collect_events", lambda store, since: {"new_events": 0})
    monkeypatch.setattr(main, "collect_system_changes", lambda store: 0)
    monkeypatch.setattr(main, "sample_performance", lambda: {"cpu_percent": 1})
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    ticks = []
    from PySide6.QtCore import QTimer

    timer = QTimer(window)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start(10)
    window.start_reliability(True)
    qtbot.waitUntil(
        lambda: (
            window.reliability_thread is not None
            and window.reliability_thread.isRunning()
        ),
        timeout=1000,
    )
    window.stop_reliability()
    qtbot.waitUntil(lambda: window.reliability_thread is None, timeout=5000)
    assert ticks
