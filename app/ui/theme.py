from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


LIGHT = "Светлая"
BLACK = "Чёрная (True Black)"
THEMES = (LIGHT, BLACK)

BLACK_QSS = """
#title { font-size:24px; font-weight:650; color:#FFFFFF; }
#value { font-size:18px; font-weight:600; color:#FFFFFF; }
QWidget { background-color:#000000; color:#FFFFFF; selection-background-color:#8B5CF6; selection-color:#FFFFFF; }
QMainWindow, QDialog, QMessageBox, QFileDialog, QTabWidget::pane { background-color:#000000; color:#FFFFFF; }
QFrame, QGroupBox { background-color:#101010; color:#FFFFFF; border:1px solid #252525; border-radius:10px; }
QLabel { background:transparent; color:#FFFFFF; }
QLabel[secondary="true"] { color:#A0A0A0; }
QLineEdit, QTextEdit, QPlainTextEdit, QListWidget, QTreeWidget, QTableWidget, QComboBox, QSpinBox, QDoubleSpinBox {
 background-color:#151515; color:#FFFFFF; border:1px solid #252525; border-radius:6px; padding:6px;
}
QComboBox QAbstractItemView { background:#151515; color:#FFFFFF; selection-background-color:#8B5CF6; border:1px solid #252525; }
QPushButton { background:#151515; color:#FFFFFF; border:1px solid #252525; border-radius:7px; padding:8px 12px; }
QPushButton:hover { background:#24202f; border-color:#8B5CF6; }
QPushButton:pressed { background:#39265f; }
QPushButton:disabled { color:#777777; background:#101010; }
QTabBar::tab { background:#080808; color:#A0A0A0; border:1px solid #252525; padding:8px 12px; }
QTabBar::tab:selected { background:#101010; color:#FFFFFF; border-bottom:2px solid #8B5CF6; }
QStatusBar { background:#080808; color:#A0A0A0; border-top:1px solid #252525; }
QScrollBar:vertical, QScrollBar:horizontal { background:#080808; border:none; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background:#393939; border-radius:4px; min-height:24px; min-width:24px; }
QHeaderView::section { background:#101010; color:#FFFFFF; border:1px solid #252525; padding:5px; }
QProgressBar { background:#151515; color:#FFFFFF; border:1px solid #252525; border-radius:5px; text-align:center; }
QProgressBar::chunk { background:#8B5CF6; border-radius:4px; }
QToolTip { background:#101010; color:#FFFFFF; border:1px solid #8B5CF6; }
QMenu { background:#080808; color:#FFFFFF; border:1px solid #252525; }
QMenu::item:selected { background:#8B5CF6; }
"""

LIGHT_QSS = """
#title { font-size:24px; font-weight:650; color:#233248; }
#value { font-size:18px; font-weight:600; color:#20242A; }
QWidget { background-color:#F4F6F9; color:#20242A; selection-background-color:#8B5CF6; selection-color:#FFFFFF; }
QMainWindow, QDialog, QMessageBox, QFileDialog, QTabWidget::pane { background-color:#F4F6F9; color:#20242A; }
QFrame, QGroupBox { background-color:#FFFFFF; color:#20242A; border:1px solid #DCE2EA; border-radius:10px; }
QLabel { background:transparent; color:#20242A; }
QLabel[secondary="true"] { color:#667085; }
QLineEdit, QTextEdit, QPlainTextEdit, QListWidget, QTreeWidget, QTableWidget, QComboBox, QSpinBox, QDoubleSpinBox { background:#FFFFFF; color:#20242A; border:1px solid #DCE2EA; border-radius:6px; padding:6px; }
QComboBox QAbstractItemView { background:#FFFFFF; color:#20242A; selection-background-color:#8B5CF6; }
QPushButton { background:#FFFFFF; color:#20242A; border:1px solid #DCE2EA; border-radius:7px; padding:8px 12px; }
QPushButton:hover { background:#F2EDFF; border-color:#8B5CF6; }
QPushButton:pressed { background:#E9DFFF; }
QPushButton:disabled { color:#9299A5; background:#ECEFF3; }
QTabBar::tab { background:#EAEDF2; color:#555D6B; border:1px solid #DCE2EA; padding:8px 12px; }
QTabBar::tab:selected { background:#FFFFFF; color:#20242A; border-bottom:2px solid #8B5CF6; }
QStatusBar { background:#FFFFFF; color:#667085; border-top:1px solid #DCE2EA; }
QScrollBar:vertical, QScrollBar:horizontal { background:#ECEFF3; border:none; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { background:#BEC5D0; border-radius:4px; min-height:24px; min-width:24px; }
QHeaderView::section { background:#EAEDF2; color:#20242A; border:1px solid #DCE2EA; padding:5px; }
QProgressBar { background:#FFFFFF; color:#20242A; border:1px solid #DCE2EA; border-radius:5px; text-align:center; }
QProgressBar::chunk { background:#8B5CF6; border-radius:4px; }
QToolTip { background:#FFFFFF; color:#20242A; border:1px solid #8B5CF6; }
QMenu { background:#FFFFFF; color:#20242A; border:1px solid #DCE2EA; }
QMenu::item:selected { background:#8B5CF6; color:#FFFFFF; }
"""


def apply_theme(app: QApplication, theme: str) -> str:
    selected = theme if theme in THEMES else LIGHT
    app.setStyleSheet(BLACK_QSS if selected == BLACK else LIGHT_QSS)
    palette = QPalette()
    if selected == BLACK:
        palette.setColor(QPalette.ColorRole.Window, QColor("#000000"))
        palette.setColor(QPalette.ColorRole.Base, QColor("#151515"))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#101010"))
        palette.setColor(QPalette.ColorRole.Text, QColor("#FFFFFF"))
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#FFFFFF"))
        palette.setColor(QPalette.ColorRole.Button, QColor("#101010"))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor("#FFFFFF"))
        palette.setColor(QPalette.ColorRole.Highlight, QColor("#8B5CF6"))
    app.setPalette(palette)
    return selected


def load_theme(settings: QSettings | None = None) -> str:
    settings = settings or QSettings()
    value = settings.value("ui/theme", LIGHT, type=str)
    return value if value in THEMES else LIGHT


def save_theme(theme: str, settings: QSettings | None = None) -> str:
    selected = theme if theme in THEMES else LIGHT
    settings = settings or QSettings()
    settings.setValue("ui/theme", selected)
    settings.sync()
    return selected
