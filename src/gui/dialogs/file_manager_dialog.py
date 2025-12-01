#!/usr/bin/env python3
"""
Advanced File Manager Dialog for C2PY Framework
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
                             QLabel, QPushButton, QLineEdit, QTextEdit, QSplitter, QGroupBox,
                             QTabWidget, QWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                             QMessageBox, QInputDialog, QFileDialog, QProgressBar, QComboBox)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QColor
from datetime import datetime
import os


class FileManagerDialog(QDialog):
    """Advanced File Manager with remote file operations"""
    
    command_executed = pyqtSignal(str, str)  # agent_id, command
    
    def __init__(self, agent_id, parent=None):
        super().__init__(parent)
        self.agent_id = agent_id
        self.current_path = "C:\\"
        self.setWindowTitle(f"File Manager - Agent {agent_id}")
        
        # Get screen geometry for responsive sizing
        screen = parent.screen() if parent else None
        if screen:
            screen_geometry = screen.availableGeometry()
            # Set dialog to 85% of screen size (larger for file management)
            width = int(screen_geometry.width() * 0.85)
            height = int(screen_geometry.height() * 0.85)
            self.setGeometry(
                screen_geometry.x() + (screen_geometry.width() - width) // 2,
                screen_geometry.y() + (screen_geometry.height() - height) // 2,
                width, height
            )
        else:
            # Fallback sizing
            self.setGeometry(150, 150, 1400, 900)
        
        # Set minimum size for usability
        self.setMinimumSize(900, 700)
        
        self.setup_ui()
        
        # Apply parent styling
        if parent:
            self.setStyleSheet(parent.styleSheet())
        
        # Load initial directory
        self.refresh_directory()
    
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        
        # Header with navigation
        header_layout = QHBoxLayout()
        
        title = QLabel(f"📁 File Manager - Agent {self.agent_id}")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff; padding: 10px;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Navigation controls
        self.back_btn = QPushButton("⬅️ Back")
        self.back_btn.clicked.connect(self.go_back)
        
        self.up_btn = QPushButton("⬆️ Up")
        self.up_btn.clicked.connect(self.go_up)
        
        self.home_btn = QPushButton("🏠 Home")
        self.home_btn.clicked.connect(self.go_home)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_directory)
        
        header_layout.addWidget(self.back_btn)
        header_layout.addWidget(self.up_btn)
        header_layout.addWidget(self.home_btn)
        header_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Path bar
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Path:"))
        
        self.path_input = QLineEdit()
        self.path_input.setText(self.current_path)
        self.path_input.returnPressed.connect(self.navigate_to_path)
        
        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self.navigate_to_path)
        
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.go_btn)
        
        layout.addLayout(path_layout)
        
        # Main content splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Directory tree
        left_panel = self.create_directory_tree_panel()
        main_splitter.addWidget(left_panel)
        
        # Center panel - File list
        center_panel = self.create_file_list_panel()
        main_splitter.addWidget(center_panel)
        
        # Right panel - File details and operations
        right_panel = self.create_operations_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([300, 600, 300])
        layout.addWidget(main_splitter)
        
        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.progress_bar)
        
        layout.addLayout(status_layout)
        
        # Bottom buttons
        bottom_layout = QHBoxLayout()
        
        self.download_btn = QPushButton("⬇️ Download Selected")
        self.download_btn.clicked.connect(self.download_selected)
        self.download_btn.setStyleSheet("""
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
        
        self.upload_btn = QPushButton("⬆️ Upload File")
        self.upload_btn.clicked.connect(self.upload_file)
        self.upload_btn.setStyleSheet("""
            QPushButton {
                background-color: #5a9fd4;
                border: 1px solid #4a8fc4;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #6ab0e5;
            }
        """)
        
        self.delete_btn = QPushButton("🗑️ Delete Selected")
        self.delete_btn.clicked.connect(self.delete_selected)
        self.delete_btn.setStyleSheet("""
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
        
        bottom_layout.addWidget(self.download_btn)
        bottom_layout.addWidget(self.upload_btn)
        bottom_layout.addWidget(self.delete_btn)
        bottom_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        bottom_layout.addWidget(close_btn)
        
        layout.addLayout(bottom_layout)
    
    def create_directory_tree_panel(self):
        """Create directory tree panel"""
        panel = QGroupBox("Directory Tree")
        layout = QVBoxLayout(panel)
        
        self.dir_tree = QTreeWidget()
        self.dir_tree.setHeaderLabel("Directories")
        self.dir_tree.itemClicked.connect(self.on_directory_selected)
        self.dir_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #3c3c3c;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px;
                border: 1px solid #5a5a5a;
                font-weight: bold;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:selected {
                background-color: #2d5aa0;
            }
        """)
        
        layout.addWidget(self.dir_tree)
        
        return panel
    
    def create_file_list_panel(self):
        """Create file list panel"""
        panel = QGroupBox("Files and Folders")
        layout = QVBoxLayout(panel)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search files...")
        self.search_input.textChanged.connect(self.filter_files)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Files", "Executables", "Documents", "Images", "Archives", "Hidden Files"])
        self.filter_combo.currentTextChanged.connect(self.filter_files)
        
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_input)
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_combo)
        
        layout.addLayout(filter_layout)
        
        # File table
        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels([
            "Name", "Type", "Size", "Modified", "Attributes", "Owner"
        ])
        
        # Set column widths
        header = self.file_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Name
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # Type
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # Size
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)    # Modified
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)    # Attributes
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # Owner
        
        self.file_table.setColumnWidth(1, 100)  # Type
        self.file_table.setColumnWidth(2, 100)  # Size
        self.file_table.setColumnWidth(3, 150)  # Modified
        self.file_table.setColumnWidth(4, 80)   # Attributes
        
        self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setSortingEnabled(True)
        self.file_table.itemDoubleClicked.connect(self.on_file_double_clicked)
        self.file_table.selectionModel().selectionChanged.connect(self.on_file_selected)
        
        self.file_table.setStyleSheet("""
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
        
        layout.addWidget(self.file_table)
        
        return panel
    
    def create_operations_panel(self):
        """Create file operations panel"""
        panel = QGroupBox("File Operations")
        layout = QVBoxLayout(panel)
        
        # File details
        details_group = QGroupBox("File Details")
        details_layout = QVBoxLayout(details_group)
        
        self.file_details = QTextEdit()
        self.file_details.setMaximumHeight(200)
        self.file_details.setStyleSheet("""
            QTextEdit {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                font-family: 'Consolas', monospace;
                font-size: 9pt;
            }
        """)
        details_layout.addWidget(self.file_details)
        
        layout.addWidget(details_group)
        
        # Quick operations
        ops_group = QGroupBox("Quick Operations")
        ops_layout = QVBoxLayout(ops_group)
        
        # File operations buttons
        self.view_btn = QPushButton("👁️ View File")
        self.view_btn.clicked.connect(self.view_file)
        
        self.edit_btn = QPushButton("✏️ Edit File")
        self.edit_btn.clicked.connect(self.edit_file)
        
        self.copy_btn = QPushButton("📋 Copy Path")
        self.copy_btn.clicked.connect(self.copy_path)
        
        self.rename_btn = QPushButton("✏️ Rename")
        self.rename_btn.clicked.connect(self.rename_file)
        
        self.properties_btn = QPushButton("🔍 Properties")
        self.properties_btn.clicked.connect(self.show_properties)
        
        ops_layout.addWidget(self.view_btn)
        ops_layout.addWidget(self.edit_btn)
        ops_layout.addWidget(self.copy_btn)
        ops_layout.addWidget(self.rename_btn)
        ops_layout.addWidget(self.properties_btn)
        
        # Directory operations
        ops_layout.addWidget(QLabel("Directory Operations:"))
        
        self.new_folder_btn = QPushButton("📁 New Folder")
        self.new_folder_btn.clicked.connect(self.create_new_folder)
        
        self.new_file_btn = QPushButton("📄 New File")
        self.new_file_btn.clicked.connect(self.create_new_file)
        
        ops_layout.addWidget(self.new_folder_btn)
        ops_layout.addWidget(self.new_file_btn)
        
        layout.addWidget(ops_group)
        
        # Advanced operations
        advanced_group = QGroupBox("Advanced")
        advanced_layout = QVBoxLayout(advanced_group)
        
        self.execute_btn = QPushButton("▶️ Execute")
        self.execute_btn.clicked.connect(self.execute_file)
        
        self.hash_btn = QPushButton("🔐 Calculate Hash")
        self.hash_btn.clicked.connect(self.calculate_hash)
        
        self.permissions_btn = QPushButton("🔒 Permissions")
        self.permissions_btn.clicked.connect(self.show_permissions)
        
        advanced_layout.addWidget(self.execute_btn)
        advanced_layout.addWidget(self.hash_btn)
        advanced_layout.addWidget(self.permissions_btn)
        
        layout.addWidget(advanced_group)
        
        return panel
    
    def refresh_directory(self):
        """Refresh current directory listing"""
        self.status_label.setText(f"Loading {self.current_path}...")
        self.path_input.setText(self.current_path)
        
        # Clear current content
        self.file_table.setRowCount(0)
        
        # Simulate directory listing - in real implementation, this would come from the agent
        import random
        
        # Simulate files and folders
        sample_items = [
            ("📁", "..", "Folder", "", datetime.now().strftime("%Y-%m-%d %H:%M"), "d", "SYSTEM"),
            ("📁", "Windows", "Folder", "", datetime.now().strftime("%Y-%m-%d %H:%M"), "d", "SYSTEM"),
            ("📁", "Program Files", "Folder", "", datetime.now().strftime("%Y-%m-%d %H:%M"), "d", "SYSTEM"),
            ("📁", "Program Files (x86)", "Folder", "", datetime.now().strftime("%Y-%m-%d %H:%M"), "d", "SYSTEM"),
            ("📁", "Users", "Folder", "", datetime.now().strftime("%Y-%m-%d %H:%M"), "d", "SYSTEM"),
            ("📄", "pagefile.sys", "System File", "4.2 GB", datetime.now().strftime("%Y-%m-%d %H:%M"), "rhs", "SYSTEM"),
            ("📄", "hiberfil.sys", "System File", "3.1 GB", datetime.now().strftime("%Y-%m-%d %H:%M"), "rhs", "SYSTEM"),
            ("📄", "bootmgr", "Boot Manager", "512 KB", datetime.now().strftime("%Y-%m-%d %H:%M"), "rhs", "SYSTEM"),
            ("⚙️", "notepad.exe", "Application", "2.1 MB", datetime.now().strftime("%Y-%m-%d %H:%M"), "r", "SYSTEM"),
            ("📄", "autoexec.bat", "Batch File", "1 KB", datetime.now().strftime("%Y-%m-%d %H:%M"), "r", "SYSTEM"),
        ]
        
        for i, (icon, name, file_type, size, modified, attrs, owner) in enumerate(sample_items):
            self.file_table.insertRow(i)
            
            items = [name, file_type, size, modified, attrs, owner]
            
            for col, item in enumerate(items):
                table_item = QTableWidgetItem(str(item))
                
                # Color coding using proper Qt methods
                if file_type == "Folder":
                    table_item.setForeground(QColor("#5a9fd4"))
                    font = table_item.font()
                    font.setBold(True)
                    table_item.setFont(font)
                elif "System" in file_type:
                    table_item.setForeground(QColor("#ff8844"))
                elif "Application" in file_type or ".exe" in name:
                    table_item.setForeground(QColor("#44ff44"))
                elif "h" in attrs:  # Hidden
                    table_item.setForeground(QColor("#888888"))
                    font = table_item.font()
                    font.setItalic(True)
                    table_item.setFont(font)
                
                self.file_table.setItem(i, col, table_item)
        
        self.status_label.setText(f"Loaded {self.file_table.rowCount()} items from {self.current_path}")
        
        # Update directory tree
        self.update_directory_tree()
    
    def update_directory_tree(self):
        """Update directory tree"""
        self.dir_tree.clear()
        
        # Simulate directory structure
        drives = ["C:\\", "D:\\", "E:\\"]
        
        for drive in drives:
            drive_item = QTreeWidgetItem([drive])
            self.dir_tree.addTopLevelItem(drive_item)
            
            if drive == "C:\\":
                # Add some common directories
                common_dirs = ["Windows", "Program Files", "Program Files (x86)", "Users", "Temp"]
                for dir_name in common_dirs:
                    dir_item = QTreeWidgetItem([dir_name])
                    drive_item.addChild(dir_item)
        
        self.dir_tree.expandAll()
    
    def filter_files(self):
        """Filter files based on search and filter criteria"""
        search_text = self.search_input.text().lower()
        filter_type = self.filter_combo.currentText()
        
        for row in range(self.file_table.rowCount()):
            show_row = True
            
            # Search filter
            if search_text:
                filename = self.file_table.item(row, 0).text().lower()
                if search_text not in filename:
                    show_row = False
            
            # Type filter
            if filter_type != "All Files" and show_row:
                filename = self.file_table.item(row, 0).text().lower()
                file_type = self.file_table.item(row, 1).text().lower()
                attrs = self.file_table.item(row, 4).text()
                
                if filter_type == "Executables" and not filename.endswith(('.exe', '.bat', '.cmd', '.msi')):
                    show_row = False
                elif filter_type == "Documents" and not filename.endswith(('.txt', '.doc', '.docx', '.pdf', '.rtf')):
                    show_row = False
                elif filter_type == "Images" and not filename.endswith(('.jpg', '.png', '.gif', '.bmp', '.ico')):
                    show_row = False
                elif filter_type == "Archives" and not filename.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                    show_row = False
                elif filter_type == "Hidden Files" and 'h' not in attrs:
                    show_row = False
            
            self.file_table.setRowHidden(row, not show_row)
    
    def on_directory_selected(self, item):
        """Handle directory selection in tree"""
        path = item.text(0)
        if path in ["C:\\", "D:\\", "E:\\"]:
            self.current_path = path
        else:
            parent = item.parent()
            if parent:
                self.current_path = os.path.join(parent.text(0), path)
        
        self.refresh_directory()
    
    def on_file_selected(self):
        """Handle file selection"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        file_type = self.file_table.item(row, 1).text()
        size = self.file_table.item(row, 2).text()
        modified = self.file_table.item(row, 3).text()
        attrs = self.file_table.item(row, 4).text()
        owner = self.file_table.item(row, 5).text()
        
        # Update file details
        details_text = f"""File Information:

Name: {filename}
Type: {file_type}
Size: {size}
Modified: {modified}
Attributes: {attrs}
Owner: {owner}
Full Path: {os.path.join(self.current_path, filename)}

Attributes Legend:
r = Read-only
h = Hidden
s = System
d = Directory
        """
        
        self.file_details.setPlainText(details_text)
    
    def on_file_double_clicked(self, item):
        """Handle file double-click"""
        row = item.row()
        filename = self.file_table.item(row, 0).text()
        file_type = self.file_table.item(row, 1).text()
        
        if file_type == "Folder":
            if filename == "..":
                self.go_up()
            else:
                self.current_path = os.path.join(self.current_path, filename)
                self.refresh_directory()
        else:
            # Open/execute file
            self.view_file()
    
    def navigate_to_path(self):
        """Navigate to specified path"""
        new_path = self.path_input.text().strip()
        if new_path:
            self.current_path = new_path
            self.refresh_directory()
    
    def go_back(self):
        """Go back in navigation history"""
        # Simple implementation - just go up one level
        self.go_up()
    
    def go_up(self):
        """Go up one directory level"""
        if self.current_path and self.current_path != "C:\\":
            self.current_path = os.path.dirname(self.current_path)
            if not self.current_path.endswith("\\"):
                self.current_path += "\\"
            self.refresh_directory()
    
    def go_home(self):
        """Go to home directory"""
        self.current_path = "C:\\Users\\%USERNAME%"
        self.refresh_directory()
    
    def download_selected(self):
        """Download selected files"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select files to download.")
            return
        
        files_to_download = []
        for index in selected:
            row = index.row()
            filename = self.file_table.item(row, 0).text()
            if filename != "..":  # Skip parent directory
                full_path = os.path.join(self.current_path, filename)
                files_to_download.append((filename, full_path))
        
        if files_to_download:
            reply = QMessageBox.question(self, 'Download Files',
                                       f'Download {len(files_to_download)} file(s)?',
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                for filename, full_path in files_to_download:
                    command = f'powershell "Get-Content \\"{full_path}\\" -Raw | Out-File -FilePath \\".\\{filename}\\" -Encoding UTF8"'
                    self.command_executed.emit(self.agent_id, command)
                
                QMessageBox.information(self, "Download Started", f"Download started for {len(files_to_download)} file(s).")
    
    def upload_file(self):
        """Upload file to current directory"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if file_path:
            filename = os.path.basename(file_path)
            remote_path = os.path.join(self.current_path, filename)
            
            reply = QMessageBox.question(self, 'Upload File',
                                       f'Upload {filename} to {remote_path}?',
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                # In real implementation, this would encode and upload the file
                QMessageBox.information(self, "Upload Started", f"Upload of {filename} started.")
                self.refresh_directory()
    
    def delete_selected(self):
        """Delete selected files"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select files to delete.")
            return
        
        files_to_delete = []
        for index in selected:
            row = index.row()
            filename = self.file_table.item(row, 0).text()
            if filename != "..":  # Skip parent directory
                files_to_delete.append(filename)
        
        if files_to_delete:
            reply = QMessageBox.question(self, 'Delete Files',
                                       f'Delete {len(files_to_delete)} file(s)? This cannot be undone.',
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                for filename in files_to_delete:
                    full_path = os.path.join(self.current_path, filename)
                    command = f'del "{full_path}" /f /q'
                    self.command_executed.emit(self.agent_id, command)
                
                QMessageBox.information(self, "Delete Started", f"Deletion of {len(files_to_delete)} file(s) started.")
                self.refresh_directory()
    
    def view_file(self):
        """View selected file content"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        command = f'type "{full_path}"'
        self.command_executed.emit(self.agent_id, command)
    
    def edit_file(self):
        """Edit selected file"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        command = f'notepad "{full_path}"'
        self.command_executed.emit(self.agent_id, command)
    
    def copy_path(self):
        """Copy file path to clipboard"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(full_path)
        
        QMessageBox.information(self, "Copied", f"Path copied to clipboard: {full_path}")
    
    def rename_file(self):
        """Rename selected file"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        old_name = self.file_table.item(row, 0).text()
        
        new_name, ok = QInputDialog.getText(self, 'Rename File', 
                                          f'Enter new name for {old_name}:', text=old_name)
        if ok and new_name.strip() and new_name != old_name:
            old_path = os.path.join(self.current_path, old_name)
            new_path = os.path.join(self.current_path, new_name)
            
            command = f'ren "{old_path}" "{new_name}"'
            self.command_executed.emit(self.agent_id, command)
            
            QMessageBox.information(self, "Rename", f"Renamed {old_name} to {new_name}")
            self.refresh_directory()
    
    def show_properties(self):
        """Show file properties"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        command = f'powershell "Get-ItemProperty \\"{full_path}\\" | Format-List *"'
        self.command_executed.emit(self.agent_id, command)
    
    def create_new_folder(self):
        """Create new folder"""
        folder_name, ok = QInputDialog.getText(self, 'New Folder', 'Enter folder name:')
        if ok and folder_name.strip():
            full_path = os.path.join(self.current_path, folder_name)
            command = f'mkdir "{full_path}"'
            self.command_executed.emit(self.agent_id, command)
            
            QMessageBox.information(self, "Folder Created", f"Created folder: {folder_name}")
            self.refresh_directory()
    
    def create_new_file(self):
        """Create new file"""
        file_name, ok = QInputDialog.getText(self, 'New File', 'Enter file name:')
        if ok and file_name.strip():
            full_path = os.path.join(self.current_path, file_name)
            command = f'echo. > "{full_path}"'
            self.command_executed.emit(self.agent_id, command)
            
            QMessageBox.information(self, "File Created", f"Created file: {file_name}")
            self.refresh_directory()
    
    def execute_file(self):
        """Execute selected file"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        reply = QMessageBox.question(self, 'Execute File',
                                   f'Execute {filename}?',
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            command = f'"{full_path}"'
            self.command_executed.emit(self.agent_id, command)
    
    def calculate_hash(self):
        """Calculate file hash"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        hash_type, ok = QInputDialog.getItem(self, 'Calculate Hash', 
                                           'Select hash algorithm:', 
                                           ['MD5', 'SHA1', 'SHA256'], 0, False)
        if ok:
            command = f'powershell "Get-FileHash \\"{full_path}\\" -Algorithm {hash_type} | Format-List"'
            self.command_executed.emit(self.agent_id, command)
    
    def show_permissions(self):
        """Show file permissions"""
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            return
        
        row = selected[0].row()
        filename = self.file_table.item(row, 0).text()
        full_path = os.path.join(self.current_path, filename)
        
        command = f'icacls "{full_path}"'
        self.command_executed.emit(self.agent_id, command)
