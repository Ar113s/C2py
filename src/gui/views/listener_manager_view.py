
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QLabel, QAbstractItemView)
from PyQt6.QtCore import Qt

class ListenerManagerView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        title = QLabel("Listeners")
        title.setStyleSheet("font-size: 12pt; font-weight: bold; padding: 5px;")
        layout.addWidget(title)

        self.listener_table = QTableWidget()
        self.listener_table.setColumnCount(4)
        self.listener_table.setHorizontalHeaderLabels(["Name", "Host", "Port", "Status"])
        self.listener_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.listener_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.listener_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.listener_table.setStyleSheet("""
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
        layout.addWidget(self.listener_table)

    def add_listener(self, config):
        row_position = self.listener_table.rowCount()
        self.listener_table.insertRow(row_position)
        
        self.listener_table.setItem(row_position, 0, QTableWidgetItem(config.get("name")))
        self.listener_table.setItem(row_position, 1, QTableWidgetItem(config.get("host")))
        self.listener_table.setItem(row_position, 2, QTableWidgetItem(str(config.get("port"))))
        
        status_item = QTableWidgetItem("Running")
        status_item.setForeground(Qt.GlobalColor.green)
        self.listener_table.setItem(row_position, 3, status_item)
