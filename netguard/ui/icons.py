"""App icon drawn in code (no binary assets needed at runtime)."""
from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap

SIZES = (16, 24, 32, 48, 64, 128, 256)


def _shield_path(s: float) -> QPainterPath:
    path = QPainterPath()
    path.moveTo(s * 0.50, s * 0.06)
    path.cubicTo(s * 0.66, s * 0.14, s * 0.80, s * 0.17, s * 0.90, s * 0.18)
    path.cubicTo(s * 0.90, s * 0.58, s * 0.76, s * 0.82, s * 0.50, s * 0.95)
    path.cubicTo(s * 0.24, s * 0.82, s * 0.10, s * 0.58, s * 0.10, s * 0.18)
    path.cubicTo(s * 0.20, s * 0.17, s * 0.34, s * 0.14, s * 0.50, s * 0.06)
    path.closeSubpath()
    return path


def draw_icon(size: int, alert: bool = False) -> QPixmap:
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    grad = QLinearGradient(0, 0, size, size)
    if alert:
        grad.setColorAt(0, QColor("#ff6b78"))
        grad.setColorAt(1, QColor("#c81e33"))
    else:
        grad.setColorAt(0, QColor("#5b9bff"))
        grad.setColorAt(1, QColor("#2a55d6"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    p.drawPath(_shield_path(size))

    # globe: circle + meridian + equator, crossed by a slash when "alert"
    pen = QPen(QColor("white"))
    pen.setWidthF(max(1.2, size * 0.055))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    r = size * 0.22
    c = QPointF(size * 0.5, size * 0.47)
    p.drawEllipse(c, r, r)
    if size >= 24:
        p.drawEllipse(c, r * 0.45, r)
        p.drawLine(QPointF(c.x() - r, c.y()), QPointF(c.x() + r, c.y()))
    if alert:
        p.drawLine(QPointF(c.x() - r * 1.15, c.y() + r * 1.15), QPointF(c.x() + r * 1.15, c.y() - r * 1.15))
    p.end()
    return pix


def app_icon(alert: bool = False) -> QIcon:
    icon = QIcon()
    for s in SIZES:
        icon.addPixmap(draw_icon(s, alert))
    return icon


def render_png(path: str, size: int = 256) -> None:
    draw_icon(size).save(path, "PNG")

