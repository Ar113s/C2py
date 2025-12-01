
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QLabel, QAbstractItemView)
from PyQt6.QtCore import Qt
from ...core.loot_manager import LootManager
from pathlib import Path

class LootManagerView(QWidget):
    def __init__(self):
        super().__init__()
        self.loot_manager = LootManager(Path.home() / ".c2py" / "loot.db")
        self.init_ui()
        self.load_loot()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        title = QLabel("Collected Loot")
        title.setStyleSheet("font-size: 12pt; font-weight: bold; padding: 5px;")
        layout.addWidget(title)

        self.loot_table = QTableWidget()
        self.loot_table.setColumnCount(6)
        self.loot_table.setHorizontalHeaderLabels(["ID", "Agent ID", "Hostname", "Type", "Source", "Timestamp"])
        self.loot_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.loot_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.loot_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.loot_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                gridline-color: #5a5a5a;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #e0e0e0;
                padding: 4px;
                border: 1px solid #5a5a5a;
            }
        """)
        layout.addWidget(self.loot_table)

    def load_loot(self):
        self.loot_table.setRowCount(0)
        all_loot = self.loot_manager.get_all_loot()
        for loot_item in all_loot:
            row_position = self.loot_table.rowCount()
            self.loot_table.insertRow(row_position)
            
            self.loot_table.setItem(row_position, 0, QTableWidgetItem(str(loot_item[0])))
            self.loot_table.setItem(row_position, 1, QTableWidgetItem(str(loot_item[1])))
            self.loot_table.setItem(row_position, 2, QTableWidgetItem(loot_item[2]))
            self.loot_table.setItem(row_position, 3, QTableWidgetItem(loot_item[3]))
            self.loot_table.setItem(row_position, 4, QTableWidgetItem(loot_item[5]))
            self.loot_table.setItem(row_position, 5, QTableWidgetItem(loot_item[6]))
