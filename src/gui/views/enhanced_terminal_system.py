"""
Enhanced Terminal Output System with Syntax Highlighting
Optimized terminal display with command output management
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QSplitter,
                             QPushButton, QComboBox, QLabel, QFrame, QScrollArea, QListWidget,
                             QTabWidget, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
                             QHeaderView, QLineEdit, QGroupBox, QGridLayout, QProgressBar)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread, pyqtSlot
from PyQt6.QtGui import (QFont, QColor, QPalette, QTextCharFormat, QSyntaxHighlighter, 
                         QTextDocument, QPixmap, QIcon)
import re
import json
import html
import time
from datetime import datetime
import subprocess
import threading

class TerminalSyntaxHighlighter(QSyntaxHighlighter):
    """Advanced syntax highlighting for terminal output"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_highlighting_rules()
    
    def setup_highlighting_rules(self):
        """Setup syntax highlighting rules"""
        self.highlighting_rules = []
        
        # Command prompts
        prompt_format = QTextCharFormat()
        prompt_format.setForeground(QColor("#00ff00"))  # Bright green
        prompt_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((
            re.compile(r'^\[.*?\]\s*agent_\d+\>'),
            prompt_format
        ))
        
        # Timestamps
        timestamp_format = QTextCharFormat()
        timestamp_format.setForeground(QColor("#888888"))  # Gray
        self.highlighting_rules.append((
            re.compile(r'\[\d{2}:\d{2}:\d{2}\]'),
            timestamp_format
        ))
        
        # IP addresses
        ip_format = QTextCharFormat()
        ip_format.setForeground(QColor("#ff9500"))  # Orange
        self.highlighting_rules.append((
            re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            ip_format
        ))
        
        # File paths
        path_format = QTextCharFormat()
        path_format.setForeground(QColor("#ffff00"))  # Yellow
        self.highlighting_rules.append((
            re.compile(r'[A-Za-z]:\\[^\\/:*?"<>|\\r\\n]*'),
            path_format
        ))
        
        # Errors
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("#ff0000"))  # Red
        error_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((
            re.compile(r'(?i)(error|failed|exception|denied).*'),
            error_format
        ))
        
        # Success messages
        success_format = QTextCharFormat()
        success_format.setForeground(QColor("#00ff00"))  # Green
        self.highlighting_rules.append((
            re.compile(r'(?i)(success|completed|done|ok).*'),
            success_format
        ))
        
        # Process IDs
        pid_format = QTextCharFormat()
        pid_format.setForeground(QColor("#ff00ff"))  # Magenta
        self.highlighting_rules.append((
            re.compile(r'\\bPID\\s*:?\\s*\\d+\\b'),
            pid_format
        ))
        
        # Usernames
        user_format = QTextCharFormat()
        user_format.setForeground(QColor("#00ffff"))  # Cyan
        self.highlighting_rules.append((
            re.compile(r'\\b[A-Za-z0-9_-]+\\\\[A-Za-z0-9_-]+\\b'),
            user_format
        ))
        
        # Registry keys
        registry_format = QTextCharFormat()
        registry_format.setForeground(QColor("#9999ff"))  # Light blue
        self.highlighting_rules.append((
            re.compile(r'HKEY_[A-Z_]+\\\\[^\\n]*'),
            registry_format
        ))
        
        # URLs
        url_format = QTextCharFormat()
        url_format.setForeground(QColor("#0099ff"))  # Blue
        url_format.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SingleUnderline)
        self.highlighting_rules.append((
            re.compile(r'https?://[^\\s]+'),
            url_format
        ))
    
    def highlightBlock(self, text):
        """Apply highlighting to text block"""
        for pattern, format_obj in self.highlighting_rules:
            for match in pattern.finditer(text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, format_obj)

class EnhancedTerminalOutput(QTextEdit):
    """Enhanced terminal output with syntax highlighting and improved functionality"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_terminal_style()
        self.setup_syntax_highlighting()
        self.command_history = []
        self.current_agent_id = None
        
    def setup_terminal_style(self):
        """Setup terminal styling"""
        # Black background terminal style
        self.setStyleSheet("""
            QTextEdit {
                background-color: #000000;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 5px;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.2;
                padding: 10px;
                selection-background-color: #444444;
                selection-color: #ffffff;
            }
            QScrollBar:vertical {
                background-color: #2b2b2b;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #555555;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #777777;
            }
        """)
        
        # Set monospace font
        font = QFont("Consolas", 11)
        font.setFixedPitch(True)
        self.setFont(font)
        
        # Set read-only and other properties
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        
    def setup_syntax_highlighting(self):
        """Setup syntax highlighting"""
        self.highlighter = TerminalSyntaxHighlighter(self.document())
    
    def append_output(self, agent_id, command, output, output_type="stdout"):
        """Append command output with formatting"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Format based on output type
        if output_type == "command":
            formatted_text = f"[{timestamp}] agent_{agent_id}> {command}\\n"
        elif output_type == "error":
            formatted_text = f"[{timestamp}] ERROR: {output}\\n"
        elif output_type == "success":
            formatted_text = f"[{timestamp}] SUCCESS: {output}\\n"
        elif output_type == "info":
            formatted_text = f"[{timestamp}] INFO: {output}\\n"
        else:
            formatted_text = f"{output}\\n"
        
        # Append to terminal
        self.append(formatted_text)
        
        # Auto-scroll to bottom
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
        # Store in history
        self.command_history.append({
            'timestamp': timestamp,
            'agent_id': agent_id,
            'command': command if output_type == "command" else None,
            'output': output,
            'type': output_type
        })
    
    def clear_output(self):
        """Clear terminal output"""
        self.clear()
        self.command_history.clear()
    
    def export_log(self, filename):
        """Export terminal log to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"C2PY Terminal Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n")
                f.write("=" * 80 + "\\n\\n")
                
                for entry in self.command_history:
                    f.write(f"[{entry['timestamp']}] Agent {entry['agent_id']} - {entry['type'].upper()}\\n")
                    if entry['command']:
                        f.write(f"Command: {entry['command']}\\n")
                    f.write(f"Output: {entry['output']}\\n")
                    f.write("-" * 40 + "\\n")
            
            return True
        except Exception as e:
            return False

class SystemInfoDisplay(QWidget):
    """Enhanced system information display"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.agent_data = {}
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Create tabs for different data views
        self.tabs = QTabWidget()
        
        # System Info Tab
        self.system_tab = self.create_system_info_tab()
        self.tabs.addTab(self.system_tab, "System Info")
        
        # Processes Tab
        self.processes_tab = self.create_processes_tab()
        self.tabs.addTab(self.processes_tab, "Processes")
        
        # Files Tab
        self.files_tab = self.create_files_tab()
        self.tabs.addTab(self.files_tab, "File System")
        
        # Network Tab
        self.network_tab = self.create_network_tab()
        self.tabs.addTab(self.network_tab, "Network")
        
        # Environment Tab
        self.env_tab = self.create_environment_tab()
        self.tabs.addTab(self.env_tab, "Environment")
        
        layout.addWidget(self.tabs)
    
    def create_system_info_tab(self):
        """Create system information tab"""
        widget = QWidget()
        layout = QGridLayout(widget)
        
        # System info groups
        groups = [
            ("Basic Info", ["hostname", "username", "domain", "os", "arch"]),
            ("Hardware", ["cpu", "memory", "disk"]),
            ("Security", ["av_status", "firewall", "uac"]),
            ("Network", ["ip_internal", "ip_external", "mac"])
        ]
        
        row = 0
        for group_name, fields in groups:
            group_box = QGroupBox(group_name)
            group_layout = QGridLayout(group_box)
            
            for i, field in enumerate(fields):
                label = QLabel(f"{field.replace('_', ' ').title()}:")
                value = QLabel("N/A")
                value.setStyleSheet("color: #00ffff; font-weight: bold;")
                
                group_layout.addWidget(label, i, 0)
                group_layout.addWidget(value, i, 1)
                
                setattr(self, f"{field}_label", value)
            
            layout.addWidget(group_box, row // 2, row % 2)
            row += 1
        
        return widget
    
    def create_processes_tab(self):
        """Create processes tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Controls
        controls = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_processes)
        controls.addWidget(refresh_btn)
        
        kill_btn = QPushButton("❌ Kill Process")
        kill_btn.clicked.connect(self.kill_selected_process)
        controls.addWidget(kill_btn)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        # Processes table
        self.processes_table = QTableWidget()
        self.processes_table.setColumnCount(5)
        self.processes_table.setHorizontalHeaderLabels(["PID", "Name", "CPU", "Memory", "User"])
        
        header = self.processes_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        self.processes_table.setAlternatingRowColors(True)
        self.processes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.processes_table)
        
        return widget
    
    def create_files_tab(self):
        """Create file system tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Size", "Type", "Modified"])
        
        layout.addWidget(self.file_tree)
        
        return widget
    
    def create_network_tab(self):
        """Create network tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Network connections table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(5)
        self.network_table.setHorizontalHeaderLabels(["Protocol", "Local Address", "Remote Address", "State", "PID"])
        
        header = self.network_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.network_table)
        
        return widget
    
    def create_environment_tab(self):
        """Create environment variables tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Environment variables table
        self.env_table = QTableWidget()
        self.env_table.setColumnCount(2)
        self.env_table.setHorizontalHeaderLabels(["Variable", "Value"])
        
        header = self.env_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.env_table)
        
        return widget
    
    def update_agent_data(self, agent_id, data):
        """Update agent data"""
        self.agent_data[agent_id] = data
        self.refresh_display(agent_id)
    
    def refresh_display(self, agent_id):
        """Refresh display for specific agent"""
        if agent_id not in self.agent_data:
            return
        
        data = self.agent_data[agent_id]
        
        # Update system info labels
        for field in ["hostname", "username", "domain", "os", "arch", "ip_internal", "ip_external"]:
            if hasattr(self, f"{field}_label"):
                label = getattr(self, f"{field}_label")
                label.setText(data.get(field, "N/A"))
    
    def refresh_processes(self):
        """Refresh processes list"""
        # This would be connected to agent command
        pass
    
    def kill_selected_process(self):
        """Kill selected process"""
        # This would be connected to agent command
        pass

class InteractiveCommandInterface(QWidget):
    """Enhanced interactive command interface"""
    
    command_sent = pyqtSignal(str, str)  # agent_id, command
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_agent_id = None
        self.command_history = []
        self.history_index = -1
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Quick action buttons
        self.create_quick_actions(layout)
        
        # Command input
        self.create_command_input(layout)
    
    def create_quick_actions(self, layout):
        """Create quick action buttons"""
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QGridLayout(actions_group)
        
        # Define quick actions
        quick_actions = [
            ("📋 System Info", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\""),
            ("👤 Current User", "whoami /all"),
            ("📁 List Directory", "dir"),
            ("📊 Processes", "tasklist"),
            ("🌐 Network", "netstat -an"),
            ("🔐 Privileges", "whoami /priv"),
            ("💾 Drives", "wmic logicaldisk get caption,size,freespace"),
            ("🔍 Running Services", "sc query state= running"),
            ("🏠 Home Directory", "cd %USERPROFILE% && dir"),
            ("📝 Environment", "set"),
            ("🔄 Refresh All", "REFRESH_ALL"),
            ("🛡️ Defender Status", "Get-MpComputerStatus")
        ]
        
        for i, (name, command) in enumerate(quick_actions):
            btn = QPushButton(name)
            btn.setToolTip(f"Execute: {command}")
            btn.clicked.connect(lambda checked, cmd=command: self.execute_quick_command(cmd))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #555555;
                    border-radius: 5px;
                    padding: 8px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #3d3d3d;
                    border-color: #777777;
                }
                QPushButton:pressed {
                    background-color: #1d1d1d;
                }
            """)
            
            row = i // 3
            col = i % 3
            actions_layout.addWidget(btn, row, col)
        
        layout.addWidget(actions_group)
    
    def create_command_input(self, layout):
        """Create command input area"""
        input_group = QGroupBox("Command Input")
        input_layout = QVBoxLayout(input_group)
        
        # Command input with history
        input_row = QHBoxLayout()
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute on selected agent...")
        self.command_input.returnPressed.connect(self.send_command)
        self.command_input.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 8px;
                font-family: 'Consolas', monospace;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #0099ff;
            }
        """)
        
        # Add keyboard shortcuts for history navigation
        self.command_input.keyPressEvent = self.handle_key_press
        
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_command)
        send_btn.setStyleSheet("""
            QPushButton {
                background-color: #0099ff;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0088ee;
            }
            QPushButton:pressed {
                background-color: #0077dd;
            }
        """)
        
        input_row.addWidget(self.command_input)
        input_row.addWidget(send_btn)
        input_layout.addLayout(input_row)
        
        layout.addWidget(input_group)
    
    def handle_key_press(self, event):
        """Handle key press events for command input"""
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QKeyEvent
        
        if event.key() == Qt.Key.Key_Up:
            self.navigate_history(-1)
        elif event.key() == Qt.Key.Key_Down:
            self.navigate_history(1)
        else:
            # Call original keyPressEvent
            QLineEdit.keyPressEvent(self.command_input, event)
    
    def navigate_history(self, direction):
        """Navigate command history"""
        if not self.command_history:
            return
        
        self.history_index += direction
        self.history_index = max(0, min(len(self.command_history) - 1, self.history_index))
        
        if 0 <= self.history_index < len(self.command_history):
            self.command_input.setText(self.command_history[self.history_index])
    
    def execute_quick_command(self, command):
        """Execute quick command"""
        if command == "REFRESH_ALL":
            self.refresh_all_data()
        else:
            self.send_custom_command(command)
    
    def send_command(self):
        """Send command from input"""
        command = self.command_input.text().strip()
        if command:
            self.send_custom_command(command)
            self.command_input.clear()
    
    def send_custom_command(self, command):
        """Send custom command"""
        if not self.current_agent_id:
            return
        
        # Add to history
        if command not in self.command_history:
            self.command_history.append(command)
            if len(self.command_history) > 100:  # Limit history size
                self.command_history.pop(0)
        
        self.history_index = len(self.command_history)
        
        # Emit signal
        self.command_sent.emit(self.current_agent_id, command)
    
    def refresh_all_data(self):
        """Refresh all agent data"""
        if not self.current_agent_id:
            return
        
        refresh_commands = [
            "systeminfo",
            "tasklist /fo csv",
            "netstat -an",
            "wmic process get processid,name,commandline /format:csv",
            "whoami /all",
            "set"
        ]
        
        for cmd in refresh_commands:
            self.command_sent.emit(self.current_agent_id, cmd)
    
    def set_current_agent(self, agent_id):
        """Set current agent for commands"""
        self.current_agent_id = agent_id
        if agent_id:
            self.command_input.setEnabled(True)
            self.command_input.setPlaceholderText(f"Enter command for agent_{agent_id}...")
        else:
            self.command_input.setEnabled(False)
            self.command_input.setPlaceholderText("No agent selected...")

class EnhancedAgentInteractionView(QWidget):
    """Enhanced agent interaction view with improved terminal and data display"""
    
    command_sent = pyqtSignal(str, str)  # agent_id, command
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_agent_id = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Create main splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Terminal and commands
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Terminal output
        terminal_group = QGroupBox("Terminal Output")
        terminal_layout = QVBoxLayout(terminal_group)
        
        # Terminal controls
        terminal_controls = QHBoxLayout()
        
        clear_btn = QPushButton("🗑️ Clear")
        export_btn = QPushButton("💾 Export Log")
        
        clear_btn.clicked.connect(self.clear_terminal)
        export_btn.clicked.connect(self.export_terminal_log)
        
        terminal_controls.addWidget(clear_btn)
        terminal_controls.addWidget(export_btn)
        terminal_controls.addStretch()
        
        terminal_layout.addLayout(terminal_controls)
        
        # Terminal output widget
        self.terminal_output = EnhancedTerminalOutput()
        terminal_layout.addWidget(self.terminal_output)
        
        left_layout.addWidget(terminal_group)
        
        # Command interface
        self.command_interface = InteractiveCommandInterface()
        self.command_interface.command_sent.connect(self.command_sent.emit)
        left_layout.addWidget(self.command_interface)
        
        # Right side - System information
        self.system_info = SystemInfoDisplay()
        
        # Add to splitter
        main_splitter.addWidget(left_widget)
        main_splitter.addWidget(self.system_info)
        main_splitter.setSizes([600, 400])
        
        layout.addWidget(main_splitter)
    
    def set_current_agent(self, agent_id):
        """Set current agent"""
        self.current_agent_id = agent_id
        self.command_interface.set_current_agent(agent_id)
    
    def handle_command_response(self, agent_id, command, response):
        """Handle command response"""
        # Add command to terminal
        self.terminal_output.append_output(agent_id, command, "", "command")
        
        # Add response to terminal
        self.terminal_output.append_output(agent_id, "", response, "stdout")
        
        # Update system info if relevant
        self.update_system_info(agent_id, command, response)
    
    def update_system_info(self, agent_id, command, response):
        """Update system information based on command response"""
        # Parse different command outputs
        if "systeminfo" in command.lower():
            self.parse_systeminfo(agent_id, response)
        elif "tasklist" in command.lower():
            self.parse_processes(agent_id, response)
        elif "netstat" in command.lower():
            self.parse_network(agent_id, response)
        elif "whoami" in command.lower():
            self.parse_user_info(agent_id, response)
    
    def parse_systeminfo(self, agent_id, output):
        """Parse systeminfo output"""
        data = {}
        lines = output.split('\\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'os name' in key:
                    data['os'] = value
                elif 'system type' in key:
                    data['arch'] = value
                elif 'total physical memory' in key:
                    data['memory'] = value
        
        self.system_info.update_agent_data(agent_id, data)
    
    def parse_processes(self, agent_id, output):
        """Parse process list output"""
        # Update processes table
        pass
    
    def parse_network(self, agent_id, output):
        """Parse network connections output"""
        # Update network table
        pass
    
    def parse_user_info(self, agent_id, output):
        """Parse user information output"""
        # Update user info
        pass
    
    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output.clear_output()
    
    def export_terminal_log(self):
        """Export terminal log"""
        from PyQt6.QtWidgets import QFileDialog
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Terminal Log", f"agent_{self.current_agent_id}_log.txt", 
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            success = self.terminal_output.export_log(filename)
            if success:
                self.terminal_output.append_output(
                    self.current_agent_id, "", f"Log exported to {filename}", "success"
                )
            else:
                self.terminal_output.append_output(
                    self.current_agent_id, "", f"Failed to export log to {filename}", "error"
                )
