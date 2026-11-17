from __future__ import annotations

import json
import subprocess
import time
from collections import namedtuple
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFileDialog, QMessageBox, QApplication
from PySide6.QtGui import QPalette

from app import history
from app.analyzers.rules import analyze
from app.collectors import system
from app.collectors.commands import run
from app.main import MainWindow
from app.models import DiagnosticReport, Finding
from app.reports.export import export_html, export_json
from app.ui.theme import BLACK, LIGHT, apply_theme, load_theme, save_theme


def test_record_serializes_psutil_named_tuples():
    Disk = namedtuple("Disk", "read_count read_bytes")
    Network = namedtuple("Network", "bytes_sent bytes_recv")
    assert system._record(Disk(2, 4096)) == {"read_count": 2, "read_bytes": 4096}
    assert system._record(Network(100, 200)) == {"bytes_sent": 100, "bytes_recv": 200}
    with pytest.raises(TypeError, match="Unsupported system record"):
        system._record(object())


def test_performance_collector_handles_realistic_counter_types(monkeypatch):
    Disk = namedtuple("sdiskio", "read_count write_count read_bytes write_bytes read_time write_time")
    monkeypatch.setattr(system.psutil, "cpu_percent", lambda **kwargs: [10.0, 20.0])
    monkeypatch.setattr(system.psutil, "cpu_freq", lambda **kwargs: [SimpleNamespace(current=2300)])
    monkeypatch.setattr(system.psutil, "virtual_memory", lambda: SimpleNamespace(total=1000, available=600, used=400, percent=40, cached=100, buffers=20))
    monkeypatch.setattr(system.psutil, "swap_memory", lambda: SimpleNamespace(total=500, used=0, percent=0))
    monkeypatch.setattr(system.psutil, "sensors_temperatures", lambda: {})
    monkeypatch.setattr(system.psutil, "sensors_fans", lambda: {})
    monkeypatch.setattr(system.psutil, "sensors_battery", lambda: None)
    monkeypatch.setattr(system.psutil, "disk_io_counters", lambda perdisk=True: {"nvme0n1": Disk(1, 2, 4096, 8192, 3, 4)})
    monkeypatch.setattr(system.psutil, "cpu_count", lambda: 2)
    monkeypatch.setattr(system, "_top_processes", lambda: [])
    monkeypatch.setattr(system, "_read_glob", lambda pattern: [])
    monkeypatch.setattr(system, "_cmd", lambda *args, **kwargs: {"stdout": "", "available": False})
    result = system.collect_performance()
    assert result["disk_io"]["nvme0n1"]["read_bytes"] == 4096


def test_network_collector_uses_bounded_fixture_probes(monkeypatch):
    Interface = namedtuple("snetio", "bytes_sent bytes_recv packets_sent packets_recv errin errout dropin dropout")
    calls = []
    def fake_cmd(key, argv, timeout=8):
        calls.append((key, argv, timeout))
        stdout = json.dumps([{"dst": "default", "gateway": "192.0.2.1"}]) if key == "routes" else "ok"
        return {"argv": argv, "available": True, "returncode": 0, "stdout": stdout, "stderr": "", "error": ""}
    monkeypatch.setattr(system, "_cmd", fake_cmd)
    monkeypatch.setattr(system.psutil, "net_if_stats", lambda: {"enp1s0": SimpleNamespace(isup=True, speed=1000, mtu=1500, duplex="full")})
    monkeypatch.setattr(system.psutil, "net_if_addrs", lambda: {"enp1s0": []})
    monkeypatch.setattr(system.psutil, "net_io_counters", lambda pernic=True: {"enp1s0": Interface(1, 2, 3, 4, 0, 0, 0, 0)})
    result = system.collect_network()
    assert result["gateway"] == "192.0.2.1"
    assert result["counters"]["enp1s0"]["bytes_recv"] == 2
    assert next(c for c in calls if c[0] == "gateway_ping")[1][-1] == "192.0.2.1"
    assert next(c for c in calls if c[0] == "gateway_ping")[2] <= 5
    assert any(c[0] == "dns_probe" for c in calls)


def test_storage_collector_parses_lsblk_and_limits_smart_probes(monkeypatch):
    calls = []
    def fake_cmd(key, argv, timeout=8):
        calls.append((key, argv))
        stdout = json.dumps({"blockdevices": [{"name": f"sd{x}", "type": "disk"} for x in "abcde"]}) if key == "block_devices" else ""
        return {"argv": argv, "available": True, "returncode": 0, "stdout": stdout, "stderr": "", "error": ""}
    monkeypatch.setattr(system, "_cmd", fake_cmd)
    monkeypatch.setattr(system.psutil, "disk_partitions", lambda all=False: [])
    result = system.collect_storage()
    smart = [argv[-1] for key, argv in calls if key == "smartctl"]
    assert smart == ["/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd"]
    assert len(result["smart_devices"]) == 4


def test_command_runner_reports_timeout_and_missing_executable(monkeypatch):
    monkeypatch.setattr("app.collectors.commands.shutil.which", lambda _: "/usr/bin/fake")
    def timeout(*args, **kwargs): raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr("app.collectors.commands.subprocess.run", timeout)
    timed = run(["fake"], timeout=0.01)
    assert timed.available and timed.returncode is None and "таймаут" in timed.error
    monkeypatch.setattr("app.collectors.commands.shutil.which", lambda _: None)
    absent = run(["absent"])
    assert not absent.available and absent.returncode is None


def test_system_gpu_hardware_and_log_collectors_are_structured(monkeypatch):
    calls=[]
    monkeypatch.setattr(system, "_cmd", lambda key, argv, timeout=8: calls.append(key) or {"argv":argv,"available":False,"returncode":None,"stdout":"","stderr":"","error":"missing"})
    monkeypatch.setattr(system, "_module_version", lambda _: "550.1")
    monkeypatch.setattr(system.psutil, "boot_time", lambda: 1000.0)
    info=system.collect_system(); gpu=system.collect_gpu(); hardware=system.collect_hardware(); logs=system.collect_logs()
    assert info["boot_time"]==1000.0 and "updates_cached" in info
    assert gpu["loaded_nvidia"]=="550.1" and "nvidia_smi" in gpu
    assert {"dmi","mce","sensors","cpu_info"} <= hardware.keys()
    assert {"current_errors","previous_errors","boot","blame","critical_chain","efi"} <= logs.keys()
    assert "systemd_failed" in calls and "kwin_journal" in calls and "current_errors" in calls


@pytest.mark.parametrize("data", [None, [], {"storage": None}, {"storage": {"partitions": [None], "smart_devices": [None]}}, {"performance": {"memory": {"percent": "broken"}, "temperatures": {"cpu": ["invalid"]}}}])
def test_analyzer_handles_empty_and_malformed_structures(data):
    result = analyze(data)
    assert isinstance(result, list)
    assert all(isinstance(item, Finding) for item in result)


def test_analyzer_correlates_gpu_and_kwin_as_probable_not_proven():
    data = {"gpu": {"gpu_journal": {"stdout": "NVRM: Xid 79 NVIDIA"}, "kwin_journal": {"stdout": "kwin: error while rendering"}}}
    finding = next(x for x in analyze(data) if "совпадают" in x.title)
    assert finding.status == "probable"
    assert "не устанавливают" in finding.explanation


def test_json_and_html_exports_escape_untrusted_text(tmp_path):
    report = DiagnosticReport.create({"hostname": "host"}, {"x": "<script>alert(1)</script>"},
        [Finding("<bad>", "warning", "confirmed", ["<img src=x>"])], .2)
    json_path = tmp_path / "report.json"; html_path = tmp_path / "report.html"
    export_json(report, json_path); export_html(report, html_path)
    assert json.loads(json_path.read_text())["findings"][0]["title"] == "<bad>"
    html = html_path.read_text()
    assert "&lt;script&gt;" in html and "&lt;img" in html
    assert "<script>alert" not in html


def test_history_corrupt_line_is_visible_and_valid_entries_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "user_data_dir", lambda _: str(tmp_path))
    history.save({"created_at": "valid", "host": {}, "findings": []})
    with (tmp_path / "history.jsonl").open("a") as f: f.write("{broken json\n")
    entries = history.recent()
    assert entries[0]["_error"].startswith("Повреждённая запись")
    assert entries[1]["created_at"] == "valid"


def test_theme_qsettings_persistence_and_palette(qtbot, tmp_path):
    app = QApplication.instance()
    config_file = tmp_path / "settings.ini"
    settings = QSettings(str(config_file), QSettings.Format.IniFormat)
    assert save_theme(BLACK, settings) == BLACK
    assert load_theme(QSettings(str(config_file), QSettings.Format.IniFormat)) == BLACK
    assert apply_theme(app, BLACK) == BLACK
    assert "#000000" in app.styleSheet() and "#080808" in app.styleSheet() and "#101010" in app.styleSheet()
    assert app.palette().color(QPalette.ColorRole.Window) == QColor("#000000")
    assert apply_theme(app, LIGHT) == LIGHT
    assert "#F4F6F9" in app.styleSheet()


def test_true_black_screenshot_has_black_root_and_dark_widgets(qtbot, monkeypatch, tmp_path):
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window=MainWindow(); qtbot.addWidget(window); window.show(); window.theme_selector.setCurrentText(BLACK); qtbot.wait(20)
    image=window.grab().toImage()
    assert image.pixelColor(2,100)==QColor("#000000")
    details_center=window.details.mapTo(window, window.details.rect().center())
    assert image.pixelColor(details_center)==QColor("#151515")
    card=window.status_card.mapTo(window, window.status_card.rect().center())
    assert image.pixelColor(card)==QColor("#101010")


def test_gui_navigation_true_black_and_live_module_scan(qtbot, monkeypatch, tmp_path):
    from app import main as ui
    calls = []
    def collect_performance():
        calls.append("called")
        return {"memory": {"percent": 45, "available": 1000}, "cpu_percent_per_core": [25, 35]}
    monkeypatch.setitem(ui.COLLECTORS, "QA fixture", (collect_performance,))
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setattr(history, "save", lambda report: tmp_path / "history.jsonl")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window = MainWindow(); qtbot.addWidget(window); window.show()
    for index in range(window.tabs.count()): window.tabs.setCurrentIndex(index); qtbot.wait(5)
    assert window.tabs.count() == 10
    window.theme_selector.setCurrentText(BLACK)
    assert "#000000" in QApplication.instance().styleSheet()
    assert window.metric_bars["cpu"].value() == 0
    window.section.addItem("QA fixture"); window.section.setCurrentText("QA fixture")
    qtbot.mouseClick(window.run_button, Qt.MouseButton.LeftButton)
    active_thread = window.thread
    window.start_scan()  # Verify a rapid duplicate call does not create a second worker.
    assert window.thread is active_thread
    assert not window.run_button.isEnabled()
    qtbot.waitUntil(lambda: window.thread is None, timeout=5000)
    assert calls == ["called"]
    assert window.report is not None and window.report.data["performance"]["memory"]["percent"] == 45
    assert window.metric_bars["cpu"].value() == 30
    window.theme_selector.setCurrentText(LIGHT)
    assert "#F4F6F9" in QApplication.instance().styleSheet()


def test_gui_worker_error_is_reported_and_button_recovers(qtbot, monkeypatch, tmp_path):
    from app import main as ui
    def broken_collector(): raise RuntimeError("fixture failure")
    monkeypatch.setitem(ui.COLLECTORS, "Broken fixture", (broken_collector,))
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setattr(QMessageBox, "critical", lambda *args: QMessageBox.StandardButton.Ok)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window = MainWindow(); qtbot.addWidget(window); window.show()
    window.section.addItem("Broken fixture"); window.section.setCurrentText("Broken fixture")
    qtbot.mouseClick(window.run_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.thread is None, timeout=5000)
    assert window.run_button.isEnabled()
    assert window.statusBar().currentMessage() == "Диагностика завершилась с ошибкой"
    assert window.report is None


def test_gui_closes_after_current_worker_finishes(qtbot, monkeypatch, tmp_path):
    from app import main as ui
    def slow_collector(): time.sleep(.1); return {}
    monkeypatch.setitem(ui.COLLECTORS, "Slow fixture", (slow_collector,))
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window = MainWindow(); qtbot.addWidget(window); window.show()
    window.section.addItem("Slow fixture"); window.section.setCurrentText("Slow fixture")
    qtbot.mouseClick(window.run_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.thread is not None and window.thread.isRunning(), timeout=1000)
    window.close()
    qtbot.waitUntil(lambda: window.thread is None, timeout=5000)
    assert not window.isVisible()


def test_export_button_action_writes_selected_report(qtbot, monkeypatch, tmp_path):
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window = MainWindow(); qtbot.addWidget(window)
    destination = tmp_path / "via_ui.json"
    monkeypatch.setattr(QFileDialog, "exec", lambda self: 1)
    monkeypatch.setattr(QFileDialog, "selectedFiles", lambda self: [str(destination)])
    window.report = DiagnosticReport.create({"hostname": "qa"}, {"x": 1}, [], .1)
    window.export("json")
    assert json.loads(destination.read_text())["host"]["hostname"] == "qa"
    assert "сохранён" in window.statusBar().currentMessage()


def test_export_io_error_is_reported(qtbot, monkeypatch, tmp_path):
    from app import main as ui
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(QFileDialog, "exec", lambda self: 1)
    monkeypatch.setattr(QFileDialog, "selectedFiles", lambda self: [str(tmp_path / "failed.json")])
    monkeypatch.setattr(ui, "export_json", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    dialogs=[]
    monkeypatch.setattr(QMessageBox, "critical", lambda *args: dialogs.append(args[2]))
    window=MainWindow(); qtbot.addWidget(window)
    window.report=DiagnosticReport.create({}, {}, [], .1)
    window.export("json")
    assert dialogs==["disk full"]


def test_gui_large_long_findings_and_filter_updates(qtbot, monkeypatch, tmp_path):
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window = MainWindow(); qtbot.addWidget(window); window.show()
    findings = [Finding("Ошибка " + ("x" * 300) + str(i), "critical" if i % 2 else "warning", "confirmed") for i in range(200)]
    window.report = DiagnosticReport.create({}, {}, findings, .1)
    window.refresh_findings()
    assert window.finding_list.count() == 200
    window.filter.setCurrentIndex(1)
    assert window.finding_list.count() == 100
    window.resize(640, 480); qtbot.wait(50)
    assert window.size().width() == 640
    assert window.details.toPlainText().startswith("Ошибка")


def test_full_scan_runs_each_distinct_collector_once(qtbot, monkeypatch, tmp_path):
    from app import main as ui
    calls=[]
    def first(): calls.append("first"); return {"ok": True}
    def second(): calls.append("second"); return {"ok": True}
    monkeypatch.setattr(ui, "COLLECTORS", {"A": (first, second), "B": (first,)})
    monkeypatch.setattr(history, "recent", lambda: [])
    monkeypatch.setattr(history, "save", lambda report: tmp_path / "history.jsonl")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    window=MainWindow(); qtbot.addWidget(window); window.show()
    window.section.setCurrentText("Полная диагностика")
    qtbot.mouseClick(window.run_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.thread is None, timeout=5000)
    assert calls==["first","second"]
    assert set(window.report.data)=={"first","second"}
