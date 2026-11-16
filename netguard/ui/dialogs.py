"""Dialogs."""
from __future__ import annotations

import os

from PySide6.QtCore import QTime
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)

from ..i18n import WEEK_ORDER, day_name, tr
from ..policies import Policy


class PolicyDialog(QDialog):
    """Create / edit a permanent or scheduled block rule."""

    def __init__(self, policy: Policy, parent=None) -> None:
        super().__init__(parent)
        self._policy = policy
        self.setWindowTitle(tr("rule_dialog_title"))
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel(policy.name, objectName="SectionTitle")
        path = QLabel(policy.exe, objectName="Hint")
        path.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(path)

        self.always = QRadioButton(tr("kind_always_long"))
        self.schedule = QRadioButton(tr("kind_schedule_long"))
        group = QButtonGroup(self)
        group.addButton(self.always)
        group.addButton(self.schedule)
        layout.addWidget(self.always)
        layout.addWidget(self.schedule)

        self.schedule_box = QWidget()
        grid = QGridLayout(self.schedule_box)
        grid.setContentsMargins(24, 0, 0, 0)
        grid.addWidget(QLabel(tr("days")), 0, 0)
        days_row = QHBoxLayout()
        self.day_boxes: dict[int, QCheckBox] = {}
        for weekday in WEEK_ORDER:
            box = QCheckBox(day_name(weekday))
            box.setChecked(weekday in policy.days)
            self.day_boxes[weekday] = box
            days_row.addWidget(box)
        days_row.addStretch(1)
        grid.addLayout(days_row, 0, 1)
        grid.addWidget(QLabel(tr("from_time")), 1, 0)
        self.start = QTimeEdit(QTime(policy.start // 60, policy.start % 60))
        self.start.setDisplayFormat("HH:mm")
        grid.addWidget(self.start, 1, 1)
        grid.addWidget(QLabel(tr("to_time")), 2, 0)
        self.end = QTimeEdit(QTime(policy.end // 60, policy.end % 60))
        self.end.setDisplayFormat("HH:mm")
        grid.addWidget(self.end, 2, 1)
        hint = QLabel(tr("schedule_hint"), objectName="Hint")
        hint.setWordWrap(True)
        grid.addWidget(hint, 3, 0, 1, 2)
        layout.addWidget(self.schedule_box)

        self.enabled = QCheckBox(tr("rule_enabled"))
        self.enabled.setChecked(policy.enabled)
        layout.addWidget(self.enabled)

        self.error = QLabel("", objectName="Banner")
        self.error.hide()
        layout.addWidget(self.error)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("save"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("cancel"))
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        (self.always if policy.kind == "always" else self.schedule).setChecked(True)
        self.schedule.toggled.connect(self._sync)
        self._sync()

    def _sync(self) -> None:
        self.schedule_box.setEnabled(self.schedule.isChecked())

    def _accept(self) -> None:
        days = [d for d, box in self.day_boxes.items() if box.isChecked()]
        if self.schedule.isChecked() and not days:
            self.error.setText(tr("err_no_days"))
            self.error.show()
            return
        self.accept()

    def result_policy(self) -> Policy:
        start = self.start.time()
        end = self.end.time()
        return Policy(
            exe=self._policy.exe,
            name=self._policy.name or os.path.basename(self._policy.exe),
            kind="always" if self.always.isChecked() else "schedule",
            days=[d for d, box in self.day_boxes.items() if box.isChecked()] or list(self._policy.days),
            start=start.hour() * 60 + start.minute(),
            end=end.hour() * 60 + end.minute(),
            enabled=self.enabled.isChecked(),
            package_sid=self._policy.package_sid,
            id=self._policy.id,
        )
