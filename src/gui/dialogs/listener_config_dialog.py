
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QComboBox, QDialogButtonBox, QPushButton, QLabel
from PyQt6.QtCore import Qt

class ListenerConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Listener Configuration")
        
        # Get screen geometry for responsive sizing
        screen = parent.screen() if parent else None
        if screen:
            screen_geometry = screen.availableGeometry()
            # Set dialog to smaller size for config (40% width, 50% height)
            width = int(screen_geometry.width() * 0.4)
            height = int(screen_geometry.height() * 0.5)
            
            # Minimum viable size for config dialog
            width = max(width, 450)
            height = max(height, 350)
            
            # Center the dialog
            x = screen_geometry.x() + (screen_geometry.width() - width) // 2
            y = screen_geometry.y() + (screen_geometry.height() - height) // 2
            self.setGeometry(x, y, width, height)
        else:
            # Fallback sizing
            self.setGeometry(300, 300, 450, 350)
        
        # Set minimum size
        self.setMinimumSize(400, 300)
        
        # Apply parent styling if available
        if parent:
            self.setStyleSheet(parent.styleSheet())
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the responsive UI"""
        self.layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Configure New Listener")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #ffffff; padding: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(title)
        
        form_layout = QFormLayout()
        
        # Input fields with better styling
        self.name_input = QLineEdit("HTTP-Listener")
        self.host_input = QLineEdit("0.0.0.0")
        self.port_input = QLineEdit("8080")
        self.type_input = QComboBox()
        self.type_input.addItems(["HTTP", "HTTPS", "TCP"])
        
        # Style input fields
        input_style = """
            QLineEdit, QComboBox {
                padding: 8px;
                font-size: 11pt;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                background-color: #2d2d2d;
                color: #ffffff;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #0078d4;
            }
        """
        
        for widget in [self.name_input, self.host_input, self.port_input, self.type_input]:
            widget.setStyleSheet(input_style)
        
        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Host:", self.host_input)
        form_layout.addRow("Port:", self.port_input)
        form_layout.addRow("Type:", self.type_input)
        
        self.layout.addLayout(form_layout)
        
        # Button box with styling
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.setStyleSheet("""
            QPushButton {
                background-color: #0078d4;
                color: #ffffff;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
        """)
        
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        
        self.layout.addWidget(self.button_box)

    def get_config(self):
        return {
            "name": self.name_input.text(),
            "host": self.host_input.text(),
            "port": int(self.port_input.text()),
            "type": self.type_input.currentText()
        }
