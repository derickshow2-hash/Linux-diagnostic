from __future__ import annotations

import json
import re
import sys
import time
from typing import Any

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app import history
from app.analyzers.rules import analyze
from app.collectors.commands import run as run_command
from app.collectors.system import COLLECTORS, host_info
from app.models import DiagnosticReport
from app.reliability.collector import (
    collect_events,
    collect_system_changes,
    sample_performance,
)
from app.reliability.investigation import investigate
from app.reliability.store import DEFAULT_INTERVAL_SECONDS, ReliabilityStore
from app.reports.export import export_html, export_json
from app.reports.reliability_export import (
    export_reliability_html,
    export_reliability_json,
)
from app.ui.theme import THEMES, apply_theme, load_theme, save_theme


def _fmt_pct(value: Any) -> str:
    return "—" if value is None else f"{float(value):.1f}%"


def _reliability_setting(key: str, default: Any) -> Any:
    try:
        return ReliabilityStore().get_setting(key, default)
    except Exception:
        return default


def _reliability_store_available() -> bool:
    try:
        ReliabilityStore()
        return True
    except Exception:
        return False


def _json_field(value: Any, fallback: str) -> str:
    try:
        return json.dumps(json.loads(value), ensure_ascii=False)
    except (TypeError, json.JSONDecodeError):
        return fallback


class DiagnosticWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    cancelled = Signal()
    def __init__(self, section: str): super().__init__(); self.section=section
    def run(self) -> None:
        start=time.monotonic()
        try:
            if self.section == "Полная диагностика":
                funcs=[]
                for group in COLLECTORS.values():
                    for fn in group:
                        if fn not in funcs: funcs.append(fn)
            else: funcs=list(COLLECTORS[self.section])
            data={}
            for fn in funcs:
                if QThread.currentThread().isInterruptionRequested(): self.cancelled.emit(); return
                key=fn.__name__.removeprefix("collect_")
                data[key]=fn()
            if QThread.currentThread().isInterruptionRequested(): self.cancelled.emit(); return
            report=DiagnosticReport.create(host_info(),data,analyze(data),time.monotonic()-start)
            self.finished.emit(report)
        except Exception as exc: self.failed.emit(f"{type(exc).__name__}: {exc}")


class ReliabilityWorker(QObject):
    updated = Signal()
    status = Signal(str)
    finished = Signal()
    def __init__(self, interval: int, continuous: bool):
        super().__init__(); self.interval=max(10,min(int(interval),300)); self.continuous=continuous; self._last_event_scan=time.monotonic()
    def run(self) -> None:
        try:
            store=ReliabilityStore()
            self.status.emit("Собираю инциденты и системные изменения…")
            if QThread.currentThread().isInterruptionRequested(): return
            event_status=collect_events(store, "24 hours ago")
            if QThread.currentThread().isInterruptionRequested(): return
            collect_system_changes(store)
            if QThread.currentThread().isInterruptionRequested(): return
            store.add_sample(sample_performance()); store.rotate(); self.updated.emit()
            unavailable=[]
            for name in ("journal", "coredump"):
                source=event_status.get(f"{name}_status", {})
                if not source.get("available"):
                    unavailable.append(f"{name}: утилита отсутствует")
                elif source.get("error"):
                    unavailable.append(f"{name}: {source['error'][:160]}")
                elif source.get("warning"):
                    unavailable.append(f"{name}: частичный доступ · {source['warning'][:120]}")
            if unavailable:
                self.status.emit("Часть источников недоступна · " + "; ".join(unavailable))
            else:
                self.status.emit("События журналов и метрики обновлены")
            if self.continuous:
                elapsed=0
                while not QThread.currentThread().isInterruptionRequested():
                    QThread.msleep(250)
                    elapsed += .25
                    if elapsed < self.interval: continue
                    elapsed=0
                    try:
                        store.add_sample(sample_performance())
                        self.status.emit("Мониторинг активен · новый снимок сохранён")
                        self.updated.emit()
                        # Longer journal and RPM reads are deliberately rate-limited.
                        if time.monotonic() - self._last_event_scan >= 300:
                            event_status=collect_events(store, "10 minutes ago")
                            changes=collect_system_changes(store)
                            self._last_event_scan=time.monotonic()
                            self.status.emit(f"Мониторинг активен · новых событий: {event_status['new_events']}, изменений: {changes}")
                            self.updated.emit()
                    except Exception as exc:
                        self.status.emit(f"Ошибка очередного цикла: {type(exc).__name__}: {exc}")
            self.status.emit("Мониторинг остановлен")
        except Exception as exc:
            self.status.emit(f"Подсистема надёжности недоступна: {type(exc).__name__}: {exc}")
        finally:
            self.finished.emit()


class CoredumpStackWorker(QObject):
    result = Signal(str, str, str)
    finished = Signal()
    def __init__(self, pid: int, fingerprint: str): super().__init__(); self.pid=pid; self.fingerprint=fingerprint
    def run(self):
        command=run_command(["coredumpctl", "info", "--no-pager", str(self.pid)], timeout=15, max_chars=300_000)
        if not command.available or command.returncode != 0:
            self.result.emit(self.fingerprint, "", command.error or command.stderr or "coredumpctl завершился с ошибкой")
        else:
            match=re.search(r"(?ms)^Stack trace of thread .*?(?=^ELF object binary architecture:|\Z)", command.stdout)
            stack=match.group(0).strip() if match else ""
            self.result.emit(self.fingerprint, stack, "" if stack else "В выводе coredumpctl нет доступного stack trace.")
        self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("Fedora Doctor"); self.resize(1120,760); self.report=None; self.thread=None; self.worker=None; self._close_requested=False
        root=QWidget(); self.setCentralWidget(root); layout=QVBoxLayout(root)
        header=QHBoxLayout(); title=QLabel("Fedora Doctor"); title.setObjectName("title"); header.addWidget(title,1)
        self.theme_selector=QComboBox(); self.theme_selector.setAccessibleName("Тема приложения"); self.theme_selector.addItems(THEMES); header.addWidget(self.theme_selector)
        theme=load_theme(); self.theme_selector.setCurrentText(theme); self.theme_selector.currentTextChanged.connect(self.change_theme)
        layout.addLayout(header)
        controls=QHBoxLayout(); self.host_label=QLabel("Определение системы…"); self.host_label.setWordWrap(True); self.host_label.setMinimumWidth(0); self.host_label.setSizePolicy(QSizePolicy.Policy.Expanding,QSizePolicy.Policy.Preferred); controls.addWidget(self.host_label,1)
        self.section=QComboBox(); self.section.addItems(["Полная диагностика", *COLLECTORS.keys()]); controls.addWidget(self.section)
        self.run_button=QPushButton("Запустить диагностику"); self.run_button.clicked.connect(self.start_scan); controls.addWidget(self.run_button)
        layout.addLayout(controls)
        cards=QHBoxLayout(); self.status_card=self._card("Состояние", "Нет результатов"); self.critical_card=self._card("Критические", "—"); self.warning_card=self._card("Предупреждения", "—"); self.time_card=self._card("Проверка", "—")
        for x in [self.status_card,self.critical_card,self.warning_card,self.time_card]: cards.addWidget(x)
        layout.addLayout(cards)
        metrics=QHBoxLayout(); self.metric_bars={}
        for key,label in [("cpu","CPU"),("memory","RAM"),("gpu","GPU"),("storage","Накопители")]:
            group=QFrame(); column=QVBoxLayout(group); column.addWidget(QLabel(label)); bar=QProgressBar(); bar.setRange(0,100); bar.setValue(0); bar.setFormat("нет данных"); column.addWidget(bar); self.metric_bars[key]=bar; metrics.addWidget(group)
        layout.addLayout(metrics)
        self.tabs=QTabWidget(); layout.addWidget(self.tabs,1)
        self.overview=QWidget(); ov=QVBoxLayout(self.overview); self.summary=QLabel("Запустите проверку. Сбор данных выполняется локально; приложение не изменяет настройки системы."); self.summary.setWordWrap(True); ov.addWidget(self.summary)
        split=QSplitter(); self.finding_list=QListWidget(); self.finding_list.currentRowChanged.connect(self.show_finding); self.details=QTextEdit(); self.details.setReadOnly(True); split.addWidget(self.finding_list); split.addWidget(self.details); ov.addWidget(split,1)
        self.details.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.details.customContextMenuRequested.connect(self.copy_current_commands)
        self.tabs.addTab(self.overview,"Обзор")
        self.component_views={}
        for name in ["CPU и RAM","GPU и графика","Накопители","Сеть","Службы и процессы","Системные журналы","Загрузка"]:
            page=QWidget(); v=QVBoxLayout(page); component_label=QLabel(f"Данные диагностики компонента: {name}"); component_label.setWordWrap(True); v.addWidget(component_label); view=QTextEdit(); view.setReadOnly(True); view.setPlaceholderText("Запустите диагностику этого компонента."); v.addWidget(view,1); self.component_views[name]=view; self.tabs.addTab(page,name)
        self.tabs.addTab(self._reports_tab(),"Отчёты")
        self.reliability_thread=None; self.reliability_worker=None
        self.stack_thread=None; self.stack_worker=None
        reliability_scroll=QScrollArea(); reliability_scroll.setWidgetResizable(True); reliability_scroll.setFrameShape(QFrame.Shape.NoFrame); reliability_scroll.setWidget(self._reliability_tab())
        self.tabs.addTab(reliability_scroll,"Надёжность")
        self.filter=QComboBox(); self.filter.addItems(["Все проблемы","Критические","Предупреждения","Информация"]); self.filter.currentIndexChanged.connect(self.refresh_findings); ov.insertWidget(1,self.filter)
        self.statusBar().showMessage("Режим без root · сбор преимущественно только для чтения")
        h=host_info(); self.host_label.setText(f"{h.get('os')} · {h.get('kernel')} · {h.get('session_type')}")
        apply_theme(QApplication.instance(),theme)

    @staticmethod
    def _card(label: str, value: str) -> QFrame:
        f=QFrame(); v=QVBoxLayout(f); a=QLabel(label); b=QLabel(value); b.setObjectName("value"); b.setStyleSheet("font-size:18px;font-weight:600"); v.addWidget(a); v.addWidget(b); f.value_label=b; return f

    def _reports_tab(self) -> QWidget:
        page=QWidget(); v=QVBoxLayout(page); description=QLabel("Отчёт можно сохранить в JSON или автономный HTML. История проверок хранится в каталоге данных пользователя."); description.setWordWrap(True); v.addWidget(description)
        row=QHBoxLayout(); j=QPushButton("Экспорт JSON"); j.clicked.connect(lambda:self.export("json")); h=QPushButton("Экспорт HTML"); h.clicked.connect(lambda:self.export("html")); refresh=QPushButton("Обновить историю"); refresh.clicked.connect(self.show_history)
        for b in [j,h,refresh]: row.addWidget(b)
        v.addLayout(row); self.history_list=QListWidget(); v.addWidget(self.history_list,1); self.show_history(); return page

    def _reliability_tab(self) -> QWidget:
        page=QWidget(); layout=QVBoxLayout(page)
        intro=QLabel("Локальный мониторинг инцидентов и метрик. Сбор выполняется только пока открыт Fedora Doctor и мониторинг включён.")
        intro.setWordWrap(True); layout.addWidget(intro)
        controls=QVBoxLayout(); settings_row=QHBoxLayout(); self.reliability_status=QLabel("Мониторинг выключен"); self.reliability_status.setWordWrap(True); settings_row.addWidget(self.reliability_status,1)
        self.reliability_interval=QSpinBox(); self.reliability_interval.setRange(10,300); self.reliability_interval.setSuffix(" с"); self.reliability_interval.setValue(DEFAULT_INTERVAL_SECONDS); self.reliability_interval.setToolTip("Интервал сохранения ряда метрик")
        self.reliability_interval.setValue(
            int(_reliability_setting("interval_seconds", DEFAULT_INTERVAL_SECONDS))
        )
        if not _reliability_store_available():
            self.reliability_status.setText("Локальная база недоступна; проверьте права на каталог данных пользователя.")
        self.reliability_interval.valueChanged.connect(self.save_reliability_interval)
        settings_row.addWidget(QLabel("Интервал")); settings_row.addWidget(self.reliability_interval)
        self.reliability_retention=QSpinBox(); self.reliability_retention.setRange(1,3650); self.reliability_retention.setSuffix(" дн")
        self.reliability_retention.setValue(int(_reliability_setting("retention_days",30)))
        self.reliability_retention.valueChanged.connect(self.save_reliability_retention)
        settings_row.addWidget(QLabel("Хранить")); settings_row.addWidget(self.reliability_retention)
        self.reliability_max_samples=QSpinBox(); self.reliability_max_samples.setRange(100,2_000_000); self.reliability_max_samples.setSingleStep(1000); self.reliability_max_samples.setSuffix(" точек")
        self.reliability_max_samples.setValue(int(_reliability_setting("max_sample_rows",250_000)))
        self.reliability_max_samples.valueChanged.connect(self.save_reliability_sample_limit)
        settings_row.addWidget(QLabel("Предел ряда")); settings_row.addWidget(self.reliability_max_samples)
        controls.addLayout(settings_row)
        actions_row=QHBoxLayout()
        self.reliability_scan_button=QPushButton("Обновить события"); self.reliability_scan_button.clicked.connect(lambda:self.start_reliability(False)); actions_row.addWidget(self.reliability_scan_button)
        self.reliability_start_button=QPushButton("Начать мониторинг"); self.reliability_start_button.clicked.connect(lambda:self.start_reliability(True)); actions_row.addWidget(self.reliability_start_button)
        self.reliability_stop_button=QPushButton("Остановить"); self.reliability_stop_button.setEnabled(False); self.reliability_stop_button.clicked.connect(self.stop_reliability); actions_row.addWidget(self.reliability_stop_button)
        controls.addLayout(actions_row)
        export_row=QHBoxLayout()
        self.stack_button=QPushButton("Получить stack trace…"); self.stack_button.clicked.connect(self.fetch_coredump_stack); export_row.addWidget(self.stack_button)
        self.reliability_json_button=QPushButton("Экспорт JSON"); self.reliability_json_button.clicked.connect(lambda:self.export_reliability("json")); export_row.addWidget(self.reliability_json_button)
        self.reliability_html_button=QPushButton("Экспорт HTML"); self.reliability_html_button.clicked.connect(lambda:self.export_reliability("html")); export_row.addWidget(self.reliability_html_button)
        controls.addLayout(export_row); layout.addLayout(controls)
        self.reliability_tabs=QTabWidget()
        incident_page=QWidget(); incident_layout=QVBoxLayout(incident_page); incident_split=QSplitter()
        self.incident_table=QTableWidget(0,5); self.incident_table.setSizePolicy(QSizePolicy.Policy.Ignored,QSizePolicy.Policy.Expanding); self.incident_table.setHorizontalHeaderLabels(["Событие UTC","Тип","Процесс / компонент","Событий","Временной интервал"]); self.incident_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.incident_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.incident_table.currentCellChanged.connect(self.show_incident_group)
        self.incident_detail=QPlainTextEdit(); self.incident_detail.setReadOnly(True); incident_split.addWidget(self.incident_table); incident_split.addWidget(self.incident_detail); incident_split.setStretchFactor(1,1); incident_layout.addWidget(incident_split)
        self.reliability_tabs.addTab(incident_page,"Инциденты и расследование")
        self.performance_history=QTableWidget(0,10); self.performance_history.setSizePolicy(QSizePolicy.Policy.Ignored,QSizePolicy.Policy.Expanding); self.performance_history.setHorizontalHeaderLabels(["Время UTC","CPU","RAM","Swap","GPU","VRAM","Температуры","Disk I/O","Network","Load average"]); self.performance_history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.reliability_tabs.addTab(self.performance_history,"История нагрузки")
        self.change_history=QPlainTextEdit(); self.change_history.setReadOnly(True); self.reliability_tabs.addTab(self.change_history,"Изменения системы")
        layout.addWidget(self.reliability_tabs,1)
        self.reliability_groups=[]
        return page

    def save_reliability_interval(self, value: int):
        try:
            ReliabilityStore().set_setting("interval_seconds", int(value))
        except Exception as exc:
            self.reliability_status.setText(f"Не удалось сохранить интервал: {exc}")

    def save_reliability_retention(self, value: int):
        try: ReliabilityStore().set_setting("retention_days", int(value))
        except Exception as exc: self.reliability_status.setText(f"Не удалось сохранить срок хранения: {exc}")

    def save_reliability_sample_limit(self, value: int):
        try: ReliabilityStore().set_setting("max_sample_rows", int(value))
        except Exception as exc: self.reliability_status.setText(f"Не удалось сохранить предел ряда: {exc}")

    def export_reliability(self, kind: str):
        ext="json" if kind=="json" else "html"
        path,_=QFileDialog.getSaveFileName(self,"Экспорт истории надёжности",f"fedora-doctor-reliability.{ext}",f"{ext.upper()} (*.{ext})")
        if not path: return
        if not path.lower().endswith(f".{ext}"): path+=f".{ext}"
        try:
            fn=export_reliability_json if kind=="json" else export_reliability_html
            fn(ReliabilityStore(),path); self.reliability_status.setText(f"Отчёт надёжности сохранён: {path}")
        except Exception as exc:
            QMessageBox.critical(self,"Не удалось сохранить отчёт надёжности",str(exc))

    def start_reliability(self, continuous: bool):
        if self.reliability_thread is not None and self.reliability_thread.isRunning(): return
        self.reliability_interval.setEnabled(False); self.reliability_scan_button.setEnabled(False); self.reliability_start_button.setEnabled(False)
        self.reliability_stop_button.setEnabled(continuous)
        self.reliability_status.setText("Запрашиваю системные журналы и метрики…")
        self.reliability_thread=QThread(self); self.reliability_worker=ReliabilityWorker(self.reliability_interval.value(),continuous)
        self.reliability_worker.moveToThread(self.reliability_thread)
        self.reliability_thread.started.connect(self.reliability_worker.run)
        self.reliability_worker.updated.connect(self.refresh_reliability)
        self.reliability_worker.status.connect(self.reliability_status.setText)
        self.reliability_worker.finished.connect(self.reliability_thread.quit)
        self.reliability_worker.finished.connect(self.reliability_worker.deleteLater)
        self.reliability_thread.finished.connect(self._reliability_thread_finished)
        self.reliability_thread.finished.connect(self.reliability_thread.deleteLater)
        self.reliability_thread.start()

    def stop_reliability(self):
        if self.reliability_thread is not None and self.reliability_thread.isRunning():
            self.reliability_status.setText("Остановка мониторинга после текущей ограниченной команды…")
            self.reliability_stop_button.setEnabled(False); self.reliability_thread.requestInterruption()

    def fetch_coredump_stack(self):
        row=self.incident_table.currentRow()
        if row < 0 or row >= len(self.reliability_groups):
            QMessageBox.information(self,"Нет выбранного инцидента","Выберите группу падений в таблице инцидентов."); return
        choices=[e for e in self.reliability_groups[row]["events"] if e.get("pid") and e.get("category")=="crash"]
        if not choices:
            QMessageBox.information(self,"Дамп не найден","В выбранной группе нет аварии с известным PID."); return
        event=next((e for e in choices if e.get("source")=="systemd-coredump"),choices[-1])
        accepted=QMessageBox.question(self,"Прочитать стек аварии?",
            f"Запустить coredumpctl info для PID {event['pid']}? Команда прочитает метаданные дампа для получения stack trace; полный дамп не будет сохранён приложением.",
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
        if accepted != QMessageBox.StandardButton.Yes: return
        if self.stack_thread is not None and self.stack_thread.isRunning(): return
        self.stack_button.setEnabled(False); self.reliability_status.setText("Получаю stack trace в фоновом потоке…")
        self.stack_thread=QThread(self); self.stack_worker=CoredumpStackWorker(int(event["pid"]),event["fingerprint"])
        self.stack_worker.moveToThread(self.stack_thread); self.stack_thread.started.connect(self.stack_worker.run)
        self.stack_worker.result.connect(self._stack_result); self.stack_worker.finished.connect(self.stack_thread.quit)
        self.stack_worker.finished.connect(self.stack_worker.deleteLater); self.stack_thread.finished.connect(self._stack_thread_finished)
        self.stack_thread.finished.connect(self.stack_thread.deleteLater); self.stack_thread.start()

    def _stack_result(self, fingerprint: str, stack: str, error: str):
        if stack:
            ReliabilityStore().update_stack_trace(fingerprint, stack); self.reliability_status.setText("Stack trace сохранён в локальной базе SQLite")
            self.refresh_reliability()
        else: self.reliability_status.setText(f"Stack trace недоступен: {error}")

    def _stack_thread_finished(self):
        self.stack_thread=None; self.stack_worker=None; self.stack_button.setEnabled(True)
        if self._close_requested and (self.thread is None or not self.thread.isRunning()) and (self.reliability_thread is None or not self.reliability_thread.isRunning()): self.close()

    def _reliability_thread_finished(self):
        self.reliability_thread=None; self.reliability_worker=None
        self.reliability_interval.setEnabled(True); self.reliability_scan_button.setEnabled(True); self.reliability_start_button.setEnabled(True); self.reliability_stop_button.setEnabled(False)
        self.refresh_reliability()
        if self._close_requested and (self.thread is None or not self.thread.isRunning()): self.close()

    def refresh_reliability(self):
        try:
            store=ReliabilityStore(); incidents=store.incidents(500); changes=store.changes(300); samples=store.samples(3000)
        except Exception as exc:
            self.reliability_status.setText(f"SQLite недоступна: {type(exc).__name__}: {exc}"); return
        investigation=investigate(incidents,changes); self.reliability_groups=investigation["groups"]
        self.incident_table.setRowCount(len(self.reliability_groups))
        for row,group in enumerate(self.reliability_groups):
            first=group["events"][0]; process=first.get("process") or ", ".join(group["components"]) or first.get("category","")
            values=[group.get("start",""),first.get("category",""),process,str(group["count"]),f"{group.get('start','')} — {group.get('end','')}"]
            for column,value in enumerate(values): self.incident_table.setItem(row,column,QTableWidgetItem(str(value)))
        if self.reliability_groups: self.incident_table.selectRow(0); self.show_incident_group(0,0,0,0)
        else: self.incident_detail.setPlainText("Инциденты пока не обнаружены или журналы недоступны. Отсутствие записей не доказывает отсутствие сбоев.")
        self.performance_history.setRowCount(len(samples))
        for row,sample in enumerate(reversed(samples)):
            vram="—" if sample.get("vram_used") is None else f"{sample['vram_used']/1024**2:.0f}/{(sample.get('vram_total') or 0)/1024**2:.0f} MiB"
            values=[sample.get("captured_at",""),_fmt_pct(sample.get("cpu_percent")),_fmt_pct(sample.get("ram_percent")),_fmt_pct(sample.get("swap_percent")),_fmt_pct(sample.get("gpu_percent")),vram,
                    _json_field(sample.get("temperatures_json","{}"),"{}"),
                    _json_field(sample.get("disk_io_json","{}"),"{}"),
                    _json_field(sample.get("network_json","{}"),"{}"),
                    _json_field(sample.get("load_json","[]"),"[]")]
            for column,value in enumerate(values): self.performance_history.setItem(row,column,QTableWidgetItem(value))
        self.change_history.setPlainText("\n\n".join(f"{x['occurred_at']} · {x['kind']} · {x['subject']}\n{x['source']}\n{json.dumps(x['details'],ensure_ascii=False)}" for x in changes) or "Изменения пока не зафиксированы. Первая проверка создаёт базовый снимок, последующие сравнивают метаданные выбранных пакетов и системных файлов.")

    def show_incident_group(self, row: int, *_args):
        if row < 0 or row >= len(self.reliability_groups): return
        group=self.reliability_groups[row]; investigation=investigate(group["events"], ReliabilityStore().changes(300))
        lines=[f"Группа: {group['group_key']}",f"Событий: {group['count']} · компоненты: {', '.join(group['components']) or 'не определены'}",group["assessment"],"","Хронология:"]
        for candidate in investigation["possible_causes"]:
            lines.insert(4, f"Кандидат для проверки: {candidate['component']} · {candidate['related_events']} событий · уверенность {candidate['confidence']:.0%}; причинность не доказана.")
        for event in group["events"]:
            lines.extend([f"{event.get('occurred_at')} · {event.get('summary')} · {event.get('process') or 'процесс неизвестен'} PID={event.get('pid') or '—'} · {event.get('signal') or event.get('exit_code') or 'код не найден'}",*([f"  {x}" for x in event.get('evidence',[])])])
            if event.get("stack_trace"): lines.append("Stack trace:\n"+event["stack_trace"][:12000])
        if investigation["change_correlations"]:
            lines.extend(["","Изменения перед событиями (временная корреляция):"])
            for item in investigation["change_correlations"]:
                lines.append(f"• {item['change']['occurred_at']} · {item['change']['kind']} {item['change']['subject']} · за {item['seconds_before']} с до события; уверенность {item['confidence']:.0%}. Причинность не установлена.")
        self.incident_detail.setPlainText("\n".join(lines))

    def show_history(self):
        self.history_list.clear()
        try:
            for r in history.recent():
                if r.get("_error"): self.history_list.addItem(r["_error"])
                else: self.history_list.addItem(f"{r.get('created_at','')} · {r.get('host',{}).get('hostname','')} · проблем: {len(r.get('findings',[]))}")
        except OSError as exc: self.history_list.addItem(f"История недоступна: {exc}")

    def start_scan(self):
        if self.thread is not None and self.thread.isRunning(): return
        self.run_button.setEnabled(False); self.statusBar().showMessage("Собираю диагностические данные…")
        self.thread=QThread(self); self.worker=DiagnosticWorker(self.section.currentText()); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.finished.connect(self.scan_done); self.worker.failed.connect(self.scan_failed)
        self.worker.cancelled.connect(self.scan_cancelled)
        self.worker.finished.connect(self.thread.quit); self.worker.failed.connect(self.thread.quit); self.worker.cancelled.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self._thread_finished); self.thread.finished.connect(self.thread.deleteLater); self.thread.start()

    def scan_failed(self, message: str):
        self.statusBar().showMessage("Диагностика завершилась с ошибкой")
        QMessageBox.critical(self,"Ошибка диагностики",message)

    def scan_cancelled(self): self.statusBar().showMessage("Диагностика остановлена перед закрытием")

    def _thread_finished(self):
        self.run_button.setEnabled(True); self.thread=None; self.worker=None
        if self._close_requested: self.close()

    def closeEvent(self, event):
        if self.thread is not None and self.thread.isRunning():
            self._close_requested=True; self.run_button.setEnabled(False); self.statusBar().showMessage("Остановка после текущей команды диагностики…")
            self.thread.requestInterruption(); event.ignore(); return
        if self.reliability_thread is not None and self.reliability_thread.isRunning():
            self._close_requested=True; self.reliability_status.setText("Остановка мониторинга перед закрытием…")
            self.reliability_thread.requestInterruption(); event.ignore(); return
        if self.stack_thread is not None and self.stack_thread.isRunning():
            self._close_requested=True; self.stack_thread.requestInterruption(); event.ignore(); return
        event.accept()

    def scan_done(self, report: DiagnosticReport):
        self.report=report; self.statusBar().showMessage("Диагностика завершена")
        critical=sum(f.severity=="critical" for f in report.findings); warning=sum(f.severity=="warning" for f in report.findings)
        self.status_card.value_label.setText("Есть проблемы" if critical or warning else "Без проблем по правилам")
        self.critical_card.value_label.setText(str(critical)); self.warning_card.value_label.setText(str(warning)); self.time_card.value_label.setText(report.created_at[:19].replace("T"," "))
        self._update_metrics(report.data)
        self.refresh_findings()
        for tab, view in self.component_views.items():
            keys={"CPU и RAM":["performance","hardware"],"GPU и графика":["gpu"],"Накопители":["storage"],"Сеть":["network"],"Службы и процессы":["system","performance"],"Системные журналы":["logs"],"Загрузка":["logs"]}[tab]
            fragments=[f"{key}\n{json.dumps(value,ensure_ascii=False,indent=2)}" for key,value in report.data.items() if key in keys]
            view.setPlainText("\n\n".join(fragments) if fragments else "Данных для этого компонента в текущем отчёте нет. Запустите соответствующую проверку.")
        self.summary.setText(f"Хост: {report.host.get('hostname')} · {report.host.get('os')} · ядро {report.host.get('kernel')}\nСканирование заняло {report.duration_seconds:.1f} с. Статус «подтверждено» относится к самому наблюдению; корреляция указана как вероятная и не доказывает причинность.")
        if report.findings: self.finding_list.setCurrentRow(0); self.show_finding(0)
        else: self.details.setPlainText("Проблем по включённым правилам не обнаружено. Это не заменяет расширенную проверку оборудования; часть данных может быть недоступна без дополнительных утилит или прав.")
        try: history.save(report.to_dict()); self.show_history()
        except OSError as exc: self.statusBar().showMessage(f"Отчёт готов, историю сохранить не удалось: {exc}")

    def refresh_findings(self):
        self.finding_list.clear()
        if not self.report:return
        selected={0:None,1:"critical",2:"warning",3:"info"}.get(self.filter.currentIndex())
        for f in self.report.findings:
            if selected is None or f.severity==selected:
                item=QListWidgetItem(f"[{f.severity.upper()}] {f.title}")
                item.setForeground(QColor({"critical":"#EF4444","warning":"#EAB308","info":"#8B5CF6"}.get(f.severity,"#A0A0A0")))
                self.finding_list.addItem(item)
        if self.finding_list.count(): self.finding_list.setCurrentRow(0)
        else: self.details.clear()

    def _update_metrics(self, data: dict):
        perf=data.get("performance",{}); per_cpu=perf.get("cpu_percent_per_core") or []
        cpu=sum(per_cpu)/len(per_cpu) if per_cpu else None
        memory=perf.get("memory",{}).get("percent")
        gpu_text=data.get("gpu",{}).get("nvidia_smi",{}).get("stdout","")
        gpu=None
        if gpu_text:
            try: gpu=float(gpu_text.splitlines()[0].split(",")[2].strip())
            except (IndexError, ValueError): gpu=None
        parts=data.get("storage",{}).get("partitions",[]); storage=max((p.get("percent",0) for p in parts),default=None)
        for key,value in [("cpu",cpu),("memory",memory),("gpu",gpu),("storage",storage)]:
            bar=self.metric_bars[key]
            if value is None: bar.setValue(0); bar.setFormat("нет данных")
            else: value=max(0,min(100,int(value))); bar.setValue(value); bar.setFormat(f"{value}%")

    def show_finding(self, row: int):
        if not self.report or row<0:return
        selected={0:None,1:"critical",2:"warning",3:"info"}.get(self.filter.currentIndex())
        findings=[f for f in self.report.findings if selected is None or f.severity==selected]
        if row>=len(findings):return
        f=findings[row]
        lines=[f.title,f"Категория: {f.category}",f"Степень: {f.severity} · Статус: {f.status} · Уверенность: {f.confidence:.0%}","",f.explanation,"","Доказательства:",*[f"• {x}" for x in f.evidence],"","Рекомендации:",*[f"• {x}" for x in f.recommendations],"","Команды для копирования:",*[f"$ {x}" for x in f.commands]]
        self.details.setPlainText("\n".join(lines))

    def copy_current_commands(self, _pos):
        row=self.finding_list.currentRow()
        if not self.report or row<0:return
        selected={0:None,1:"critical",2:"warning",3:"info"}.get(self.filter.currentIndex())
        findings=[f for f in self.report.findings if selected is None or f.severity==selected]
        if row<len(findings):self.copy_commands(findings[row].commands)

    def copy_commands(self, commands: list[str]):
        if commands: QGuiApplication.clipboard().setText("\n".join(commands)); self.statusBar().showMessage("Команды скопированы")

    def export(self, kind: str):
        if not self.report: QMessageBox.information(self,"Нет отчёта","Сначала запустите диагностику."); return
        ext="json" if kind=="json" else "html"
        dialog=QFileDialog(self,"Сохранить отчёт",f"fedora-doctor-report.{ext}"); dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave); dialog.setNameFilter(f"{ext.upper()} (*.{ext})"); dialog.setDefaultSuffix(ext); dialog.setOption(QFileDialog.Option.DontUseNativeDialog,True)
        if not dialog.exec():return
        path=dialog.selectedFiles()[0]
        try:
            (export_json if kind=="json" else export_html)(self.report,path); self.statusBar().showMessage(f"Отчёт сохранён: {path}")
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self,"Не удалось сохранить отчёт",str(exc))

    def change_theme(self, theme: str):
        selected=save_theme(theme); apply_theme(QApplication.instance(),selected)


def main() -> None:
    app=QApplication(sys.argv); app.setOrganizationName("FedoraDoctor"); app.setApplicationName("FedoraDoctor"); w=MainWindow(); w.show(); sys.exit(app.exec())


if __name__=="__main__": main()
