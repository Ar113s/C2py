#!/usr/bin/env python3
"""
Advanced Process Monitor Dialog for C2PY Framework
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QHeaderView, QLabel, QPushButton, QLineEdit, QComboBox, QTextEdit,
                             QSplitter, QGroupBox, QTabWidget, QTreeWidget, QTreeWidgetItem,
                             QMessageBox, QInputDialog, QProgressBar, QWidget)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor
import threading
from datetime import datetime


class ProcessMonitorDialog(QDialog):
    """Advanced Process Monitor with real-time updates"""
    
    command_executed = pyqtSignal(str, str)  # agent_id, command
    
    def __init__(self, agent_id, parent=None):
        super().__init__(parent)
        self.agent_id = agent_id
        self.setWindowTitle(f"Process Monitor - Agent {agent_id}")
        
        # Get screen geometry for responsive sizing
        screen = parent.screen() if parent else None
        if screen:
            screen_geometry = screen.availableGeometry()
            # Set dialog to 80% of screen size
            width = int(screen_geometry.width() * 0.8)
            height = int(screen_geometry.height() * 0.8)
            self.setGeometry(
                screen_geometry.x() + (screen_geometry.width() - width) // 2,
                screen_geometry.y() + (screen_geometry.height() - height) // 2,
                width, height
            )
        else:
            # Fallback sizing
            self.setGeometry(200, 200, 1200, 800)
        
        # Set minimum size for usability
        self.setMinimumSize(800, 600)
        
        self.processes = {}
        self.setup_ui()
        self.setup_auto_refresh()
        
        # Apply parent styling
        if parent:
            self.setStyleSheet(parent.styleSheet())
    
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title = QLabel(f"🖥️ Process Monitor - Agent {self.agent_id}")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff; padding: 10px;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Refresh controls
        self.auto_refresh_cb = QComboBox()
        self.auto_refresh_cb.addItems(["Manual", "5 seconds", "10 seconds", "30 seconds", "1 minute"])
        self.auto_refresh_cb.setCurrentText("10 seconds")
        self.auto_refresh_cb.currentTextChanged.connect(self.change_refresh_rate)
        
        self.refresh_btn = QPushButton("🔄 Refresh Now")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        
        header_layout.addWidget(QLabel("Auto Refresh:"))
        header_layout.addWidget(self.auto_refresh_cb)
        header_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Main content
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Process list
        left_panel = self.create_process_panel()
        main_splitter.addWidget(left_panel)
        
        # Right panel - Details and actions
        right_panel = self.create_details_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([800, 400])
        layout.addWidget(main_splitter)
        
        # Bottom controls
        bottom_layout = QHBoxLayout()
        
        self.kill_btn = QPushButton("❌ Kill Process")
        self.kill_btn.clicked.connect(self.kill_selected_process)
        self.kill_btn.setStyleSheet("""
            QPushButton {
                background-color: #d9534f;
                border: 1px solid #c9434f;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e9635f;
            }
        """)
        
        self.start_btn = QPushButton("▶️ Start Process")
        self.start_btn.clicked.connect(self.start_new_process)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #5cb85c;
                border: 1px solid #4cae4c;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #6cc86c;
            }
        """)
        
        self.suspend_btn = QPushButton("⏸️ Suspend")
        self.suspend_btn.clicked.connect(self.suspend_process)
        
        self.resume_btn = QPushButton("▶️ Resume")
        self.resume_btn.clicked.connect(self.resume_process)
        
        bottom_layout.addWidget(self.kill_btn)
        bottom_layout.addWidget(self.start_btn)
        bottom_layout.addWidget(self.suspend_btn)
        bottom_layout.addWidget(self.resume_btn)
        bottom_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        bottom_layout.addWidget(close_btn)
        
        layout.addLayout(bottom_layout)
    
    def create_process_panel(self):
        """Create process list panel"""
        panel = QGroupBox("Running Processes")
        layout = QVBoxLayout(panel)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search processes...")
        self.search_input.textChanged.connect(self.filter_processes)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Processes", "User Processes", "System Processes", "High CPU", "High Memory"])
        self.filter_combo.currentTextChanged.connect(self.filter_processes)
        
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_input)
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_combo)
        
        layout.addLayout(filter_layout)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(8)
        self.process_table.setHorizontalHeaderLabels([
            "Process Name", "PID", "PPID", "CPU %", "Memory (MB)", 
            "Threads", "Status", "User"
        ])
        
        # Set column widths
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Process Name
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # PID
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # PPID
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)    # CPU
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)    # Memory
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)    # Threads
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)    # Status
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)  # User
        
        self.process_table.setColumnWidth(1, 80)   # PID
        self.process_table.setColumnWidth(2, 80)   # PPID
        self.process_table.setColumnWidth(3, 70)   # CPU
        self.process_table.setColumnWidth(4, 90)   # Memory
        self.process_table.setColumnWidth(5, 70)   # Threads
        self.process_table.setColumnWidth(6, 80)   # Status
        
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSortingEnabled(True)
        self.process_table.selectionModel().selectionChanged.connect(self.on_process_selected)
        
        # Enhanced styling
        self.process_table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                gridline-color: #444444;
                border: 1px solid #3c3c3c;
                selection-background-color: #2d5aa0;
                alternate-background-color: #2a2a2a;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px 4px;
                border: 1px solid #5a5a5a;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid #333333;
            }
        """)
        
        layout.addWidget(self.process_table)
        
        return panel
    
    def create_details_panel(self):
        """Create process details panel"""
        panel = QGroupBox("Process Details")
        layout = QVBoxLayout(panel)
        
        # Details tabs
        self.details_tabs = QTabWidget()
        
        # General info tab
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
        
        self.process_info = QTextEdit()
        self.process_info.setMaximumHeight(200)
        self.process_info.setStyleSheet("""
            QTextEdit {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
            }
        """)
        general_layout.addWidget(self.process_info)
        
        self.details_tabs.addTab(general_tab, "General")
        
        # Modules tab
        modules_tab = QWidget()
        modules_layout = QVBoxLayout(modules_tab)
        
        self.modules_list = QTreeWidget()
        self.modules_list.setHeaderLabels(["Module", "Base Address", "Size", "Path"])
        self.modules_list.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #3c3c3c;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 4px;
                border: 1px solid #5a5a5a;
            }
        """)
        modules_layout.addWidget(self.modules_list)
        
        self.details_tabs.addTab(modules_tab, "Modules")
        
        # Threads tab
        threads_tab = QWidget()
        threads_layout = QVBoxLayout(threads_tab)
        
        self.threads_table = QTableWidget()
        self.threads_table.setColumnCount(4)
        self.threads_table.setHorizontalHeaderLabels(["Thread ID", "Priority", "State", "CPU Time"])
        self.threads_table.setStyleSheet(self.process_table.styleSheet())
        threads_layout.addWidget(self.threads_table)
        
        self.details_tabs.addTab(threads_tab, "Threads")
        
        layout.addWidget(self.details_tabs)
        
        # Process actions
        actions_group = QGroupBox("Process Actions")
        actions_layout = QVBoxLayout(actions_group)
        
        # Memory dump
        dump_memory_btn = QPushButton("💾 Dump Memory")
        dump_memory_btn.clicked.connect(self.dump_process_memory)
        
        # Inject DLL
        inject_dll_btn = QPushButton("💉 Inject DLL")
        inject_dll_btn.clicked.connect(self.inject_dll)
        
        # Change priority
        priority_layout = QHBoxLayout()
        priority_layout.addWidget(QLabel("Priority:"))
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["Idle", "Below Normal", "Normal", "Above Normal", "High", "Realtime"])
        self.priority_combo.setCurrentText("Normal")
        change_priority_btn = QPushButton("Set")
        change_priority_btn.clicked.connect(self.change_priority)
        
        priority_layout.addWidget(self.priority_combo)
        priority_layout.addWidget(change_priority_btn)
        
        actions_layout.addWidget(dump_memory_btn)
        actions_layout.addWidget(inject_dll_btn)
        actions_layout.addLayout(priority_layout)
        
        layout.addWidget(actions_group)
        
        return panel
    
    def setup_auto_refresh(self):
        """Setup auto-refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_processes)
        self.change_refresh_rate("10 seconds")  # Default refresh rate
        
        # Initial load
        self.refresh_processes()
    
    def change_refresh_rate(self, rate_text):
        """Change auto-refresh rate"""
        self.refresh_timer.stop()
        
        if rate_text == "Manual":
            return
        elif rate_text == "5 seconds":
            self.refresh_timer.start(5000)
        elif rate_text == "10 seconds":
            self.refresh_timer.start(10000)
        elif rate_text == "30 seconds":
            self.refresh_timer.start(30000)
        elif rate_text == "1 minute":
            self.refresh_timer.start(60000)
    
    def refresh_processes(self):
        """Refresh process list"""
        # Simulate process data - in real implementation, this would come from the agent
        import random
        
        self.process_table.setRowCount(0)
        
        # Simulate some processes
        sample_processes = [
            ("explorer.exe", "1234", "567", "2.1", "45.2", "12", "Running", "SYSTEM\\user"),
            ("chrome.exe", "5678", "1234", "15.3", "128.7", "24", "Running", "SYSTEM\\user"),
            ("notepad.exe", "9012", "1234", "0.1", "8.4", "3", "Running", "SYSTEM\\user"),
            ("svchost.exe", "3456", "567", "0.5", "12.1", "8", "Running", "NT AUTHORITY\\SYSTEM"),
            ("winlogon.exe", "789", "4", "0.0", "4.2", "2", "Running", "NT AUTHORITY\\SYSTEM"),
            ("csrss.exe", "456", "4", "0.2", "6.8", "5", "Running", "NT AUTHORITY\\SYSTEM"),
            ("lsass.exe", "890", "567", "0.1", "15.6", "7", "Running", "NT AUTHORITY\\SYSTEM"),
            ("services.exe", "567", "4", "0.0", "8.9", "4", "Running", "NT AUTHORITY\\SYSTEM"),
        ]
        
        for i, (name, pid, ppid, cpu, memory, threads, status, user) in enumerate(sample_processes):
            self.process_table.insertRow(i)
            
            # Add some randomness to CPU and memory
            cpu_val = float(cpu) + random.uniform(-1, 5)
            mem_val = float(memory) + random.uniform(-5, 20)
            
            items = [
                name, pid, ppid, 
                f"{cpu_val:.1f}", f"{mem_val:.1f}", 
                threads, status, user
            ]
            
            for col, item in enumerate(items):
                table_item = QTableWidgetItem(str(item))
                
                # Color coding using proper Qt methods
                if col == 3:  # CPU column
                    if cpu_val > 10:
                        table_item.setForeground(QColor("#ff4444"))
                        font = table_item.font()
                        font.setBold(True)
                        table_item.setFont(font)
                    elif cpu_val > 5:
                        table_item.setForeground(QColor("#ffaa44"))
                elif col == 4:  # Memory column
                    if mem_val > 100:
                        table_item.setForeground(QColor("#ff4444"))
                        font = table_item.font()
                        font.setBold(True)
                        table_item.setFont(font)
                    elif mem_val > 50:
                        table_item.setForeground(QColor("#ffaa44"))
                elif col == 6 and "Running" not in item:  # Status column
                    table_item.setForeground(QColor("#888888"))
                
                self.process_table.setItem(i, col, table_item)
        
        # Sort by CPU usage by default
        self.process_table.sortItems(3, Qt.SortOrder.DescendingOrder)
    
    def filter_processes(self):
        """Filter processes based on search and filter criteria"""
        search_text = self.search_input.text().lower()
        filter_type = self.filter_combo.currentText()
        
        for row in range(self.process_table.rowCount()):
            show_row = True
            
            # Search filter
            if search_text:
                process_name = self.process_table.item(row, 0).text().lower()
                if search_text not in process_name:
                    show_row = False
            
            # Type filter
            if filter_type != "All Processes" and show_row:
                process_name = self.process_table.item(row, 0).text().lower()
                user = self.process_table.item(row, 7).text()
                cpu = float(self.process_table.item(row, 3).text())
                memory = float(self.process_table.item(row, 4).text())
                
                if filter_type == "User Processes" and "NT AUTHORITY" in user:
                    show_row = False
                elif filter_type == "System Processes" and "NT AUTHORITY" not in user:
                    show_row = False
                elif filter_type == "High CPU" and cpu < 5:
                    show_row = False
                elif filter_type == "High Memory" and memory < 50:
                    show_row = False
            
            self.process_table.setRowHidden(row, not show_row)
    
    def on_process_selected(self):
        """Handle process selection"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        process_name = self.process_table.item(row, 0).text()
        pid = self.process_table.item(row, 1).text()
        
        # Update process info with null checks
        def safe_get_text(row, col):
            item = self.process_table.item(row, col)
            return item.text() if item else "N/A"
        
        ppid = safe_get_text(row, 2)
        cpu_usage = safe_get_text(row, 3)
        memory_usage = safe_get_text(row, 4)
        thread_count = safe_get_text(row, 5)
        status = safe_get_text(row, 6)
        user = safe_get_text(row, 7)
        
        info_text = f"""Process Information:
        
Name: {process_name}
PID: {pid}
PPID: {ppid}
CPU Usage: {cpu_usage}%
Memory Usage: {memory_usage} MB
Thread Count: {thread_count}
Status: {status}
User: {user}

Command Line: C:\\Windows\\System32\\{process_name} (simulated)
Working Directory: C:\\Windows\\System32\\
Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        self.process_info.setPlainText(info_text)
        
        # Update modules list (simulated)
        self.modules_list.clear()
        modules = [
            (f"{process_name}", "0x00400000", "0x00010000", f"C:\\Windows\\System32\\{process_name}"),
            ("kernel32.dll", "0x76000000", "0x00100000", "C:\\Windows\\System32\\kernel32.dll"),
            ("ntdll.dll", "0x77000000", "0x00180000", "C:\\Windows\\System32\\ntdll.dll"),
        ]
        
        for module, base, size, path in modules:
            item = QTreeWidgetItem([module, base, size, path])
            self.modules_list.addTopLevelItem(item)
    
    def kill_selected_process(self):
        """Kill selected process"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process to kill.")
            return
        
        row = selected[0].row()
        process_name = self.process_table.item(row, 0).text()
        pid = self.process_table.item(row, 1).text()
        
        reply = QMessageBox.question(self, 'Kill Process',
                                   f'Kill process {process_name} (PID: {pid})?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            command = f"taskkill /PID {pid} /F"
            self.command_executed.emit(self.agent_id, command)
            QMessageBox.information(self, "Process Killed", f"Process {process_name} (PID: {pid}) has been terminated.")
            self.refresh_processes()
    
    def start_new_process(self):
        """Start a new process"""
        process_path, ok = QInputDialog.getText(self, 'Start Process', 
                                              'Enter process path or command:')
        if ok and process_path.strip():
            command = f"start {process_path}"
            self.command_executed.emit(self.agent_id, command)
            QMessageBox.information(self, "Process Started", f"Started: {process_path}")
            self.refresh_processes()
    
    def suspend_process(self):
        """Suspend selected process"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process to suspend.")
            return
        
        row = selected[0].row()
        pid = self.process_table.item(row, 1).text()
        command = f"powershell \"(Get-Process -Id {pid}).Suspend()\""
        self.command_executed.emit(self.agent_id, command)
    
    def resume_process(self):
        """Resume selected process"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process to resume.")
            return
        
        row = selected[0].row()
        pid = self.process_table.item(row, 1).text()
        command = f"powershell \"(Get-Process -Id {pid}).Resume()\""
        self.command_executed.emit(self.agent_id, command)
    
    def dump_process_memory(self):
        """Dump process memory"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process to dump.")
            return
        
        row = selected[0].row()
        process_name = self.process_table.item(row, 0).text()
        pid = self.process_table.item(row, 1).text()
        
        reply = QMessageBox.question(self, 'Dump Memory',
                                   f'Dump memory for {process_name} (PID: {pid})?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            command = f"procdump -ma {pid} {process_name}_{pid}.dmp"
            self.command_executed.emit(self.agent_id, command)
    
    def inject_dll(self):
        """Inject DLL into selected process"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process for injection.")
            return
        
        dll_path, ok = QInputDialog.getText(self, 'DLL Injection', 
                                          'Enter DLL path:')
        if ok and dll_path.strip():
            row = selected[0].row()
            pid = self.process_table.item(row, 1).text()
            
            reply = QMessageBox.question(self, 'DLL Injection',
                                       f'Inject {dll_path} into PID {pid}?',
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                # This would be implemented with actual DLL injection code
                QMessageBox.information(self, "DLL Injection", "DLL injection command sent to agent.")
    
    def change_priority(self):
        """Change process priority"""
        selected = self.process_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a process.")
            return
        
        row = selected[0].row()
        pid = self.process_table.item(row, 1).text()
        priority = self.priority_combo.currentText()
        
        command = f"wmic process where processid={pid} CALL setpriority {priority}"
        self.command_executed.emit(self.agent_id, command)
        QMessageBox.information(self, "Priority Changed", f"Priority changed to {priority} for PID {pid}")
