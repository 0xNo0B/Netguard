"""Dark / light themes (QSS) and the palette the models read at paint time."""
from __future__ import annotations

from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QApplication

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#0e131f", "surface": "#151c2c", "surface2": "#1c2539", "alt_row": "#182033",
        "border": "#26314a", "text": "#e6ebf5", "muted": "#8c98b3", "disabled": "#56607a",
        "accent": "#4f8cff", "danger": "#ef4f5f", "danger_hover": "#ff6474",
        "success": "#2fbf71", "success_hover": "#45d686", "success_text": "#04140b",
        "warning": "#f2b33d", "blocked_row": "rgba(239,79,95,0.15)", "selection": "rgba(79,140,255,0.35)",
    },
    "light": {
        "bg": "#f3f5fa", "surface": "#ffffff", "surface2": "#eef1f7", "alt_row": "#f7f9fc",
        "border": "#d5dbe7", "text": "#172033", "muted": "#5d6880", "disabled": "#a3abbd",
        "accent": "#2f6fec", "danger": "#d93445", "danger_hover": "#e8505f",
        "success": "#1f9d5c", "success_hover": "#26b56b", "success_text": "#ffffff",
        "warning": "#b7791f", "blocked_row": "rgba(217,52,69,0.10)", "selection": "rgba(47,111,236,0.20)",
    },
}

_current = "dark"


def current_name() -> str:
    return _current


def color(name: str) -> QColor:
    value = PALETTES[_current][name]
    if value.startswith("rgba"):
        r, g, b, a = (float(x) for x in value[5:-1].split(","))
        return QColor(int(r), int(g), int(b), int(a * 255))
    return QColor(value)


def stylesheet(name: str) -> str:
    p = PALETTES[name]
    return f"""
* {{ color: {p['text']}; }}
QMainWindow, QWidget#Central, QDialog {{ background: {p['bg']}; }}
QLabel#AppTitle {{ font-size: 20px; font-weight: 700; }}
QLabel#Subtitle, QLabel#Hint {{ color: {p['muted']}; }}
QLabel#SectionTitle {{ font-size: 14px; font-weight: 700; }}
QLabel#Badge {{
    background: {p['surface2']}; border: 1px solid {p['border']}; border-radius: 10px;
    padding: 4px 10px; color: {p['muted']};
}}
QLabel#Badge[ok="true"] {{ color: {p['success']}; border-color: {p['success']}; }}
QLabel#Badge[ok="false"] {{ color: {p['warning']}; border-color: {p['warning']}; }}
QLabel#Banner {{
    background: transparent; border: 1px solid {p['warning']};
    border-radius: 8px; padding: 8px 12px; color: {p['warning']};
}}
QFrame#KillAlert {{ background: {p['danger']}; border-radius: 8px; }}
QFrame#KillAlert QLabel {{ color: white; font-weight: 700; }}
QFrame#KillAlert QPushButton {{ background: white; color: {p['danger']}; border: none; }}
QLabel#BigStatus {{ font-size: 18px; font-weight: 700; }}
QLabel#BigStatus[on="true"] {{ color: {p['danger']}; }}
QLabel#BigStatus[on="false"] {{ color: {p['success']}; }}
QFrame#Card, QFrame#ActionBar {{
    background: {p['surface']}; border: 1px solid {p['border']}; border-radius: 10px;
}}
QFrame#Segment {{ background: {p['surface2']}; border: 1px solid {p['border']}; border-radius: 9px; }}
QFrame#Segment QPushButton {{ background: transparent; border: none; border-radius: 7px; padding: 5px 14px; }}
QFrame#Segment QPushButton:checked {{ background: {p['accent']}; color: white; }}
QLineEdit, QSpinBox, QComboBox, QTimeEdit {{
    background: {p['surface2']}; border: 1px solid {p['border']}; border-radius: 7px;
    padding: 6px 9px; selection-background-color: {p['accent']};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTimeEdit:focus {{ border-color: {p['accent']}; }}
QComboBox QAbstractItemView {{
    background: {p['surface2']}; border: 1px solid {p['border']}; selection-background-color: {p['accent']};
}}
QPushButton {{
    background: {p['surface2']}; border: 1px solid {p['border']}; border-radius: 7px;
    padding: 7px 14px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {p['accent']}; }}
QPushButton:disabled {{ color: {p['disabled']}; border-color: {p['border']}; }}
QPushButton#DangerButton {{ background: {p['danger']}; border: none; color: white; }}
QPushButton#DangerButton:hover {{ background: {p['danger_hover']}; }}
QPushButton#SuccessButton {{ background: {p['success']}; border: none; color: {p['success_text']}; }}
QPushButton#SuccessButton:hover {{ background: {p['success_hover']}; }}
QPushButton#DangerButton:disabled, QPushButton#SuccessButton:disabled {{
    background: {p['surface2']}; color: {p['disabled']};
}}
QCheckBox, QRadioButton {{ spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px; height: 16px; border: 1px solid {p['border']}; background: {p['surface2']};
}}
QCheckBox::indicator {{ border-radius: 4px; }}
QRadioButton::indicator {{ border-radius: 9px; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{ background: {p['accent']}; border-color: {p['accent']}; }}
QTableView {{
    background: {p['surface']}; alternate-background-color: {p['alt_row']};
    border: 1px solid {p['border']}; border-radius: 10px; gridline-color: transparent;
    selection-background-color: {p['selection']}; selection-color: {p['text']};
}}
QTableView::item {{ padding: 4px 6px; }}
QHeaderView::section {{
    background: {p['surface2']}; color: {p['muted']}; border: none;
    border-bottom: 1px solid {p['border']}; padding: 7px 8px; font-weight: 600;
}}
QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 10px; background: {p['surface']}; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {p['muted']}; padding: 8px 16px;
    border-bottom: 2px solid transparent; font-weight: 600;
}}
QTabBar::tab:selected {{ color: {p['text']}; border-bottom-color: {p['accent']}; }}
QSplitter::handle {{ background: transparent; height: 8px; }}
QStatusBar {{ background: {p['surface']}; border-top: 1px solid {p['border']}; color: {p['muted']}; }}
QStatusBar QLabel {{ color: {p['muted']}; padding: 0 8px; }}
QMenu {{ background: {p['surface2']}; border: 1px solid {p['border']}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 5px; }}
QMenu::item:selected {{ background: {p['accent']}; color: white; }}
QMenu::separator {{ height: 1px; background: {p['border']}; margin: 4px 6px; }}
QToolTip {{ background: {p['surface2']}; color: {p['text']}; border: 1px solid {p['border']}; padding: 6px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p['border']}; border-radius: 4px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p['border']}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QMessageBox {{ background: {p['surface']}; }}
"""


def apply_theme(app: QApplication, name: str = "dark") -> None:
    global _current
    _current = name if name in PALETTES else "dark"
    app.setStyle("Fusion")
    font = QFont()
    font.setFamilies(["Segoe UI", "Tahoma", "Noto Sans Arabic", "DejaVu Sans"])
    font.setPointSize(10)
    app.setFont(font)
    app.setStyleSheet(stylesheet(_current))
