
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QGroupBox, QLabel, 
                             QLineEdit, QComboBox, QPushButton, QCheckBox, QTextEdit,
                             QScrollArea)
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor
from PyQt6.QtCore import QRegularExpression

from ...generators.advanced_agent_generator import generate_undetectable_agent
from ...generators.elite_revshell_generator import EliteRevShellGenerator
from ...generators.lolbas_generator import LOLBASGenerator
from ...core.av_evasion_engine import AVEvasionEngine

class PythonSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.highlighting_rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569cd6"))
        keywords = ["import", "from", "def", "class", "if", "else", "elif", 
                    "while", "for", "try", "except", "finally", "with", "as",
                    "return", "True", "False", "None"]
        self.highlighting_rules += [(QRegularExpression(f"\\b{keyword}\\b"), keyword_format) for keyword in keywords]

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.highlighting_rules.append((QRegularExpression("\".*\""), string_format))
        self.highlighting_rules.append((QRegularExpression("'.*'"), string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6a9955"))
        self.highlighting_rules.append((QRegularExpression("#[^\n]*"), comment_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegularExpression(pattern)
            it = expression.globalMatch(text)
            while it.hasNext():
                match = it.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class PayloadGeneratorView(QWidget):
    def __init__(self):
        super().__init__()
        self.revshell_generator = EliteRevShellGenerator()
        self.lolbas_generator = LOLBASGenerator()
        self.av_engine = AVEvasionEngine()
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Enhanced Payload Generator Button
        enhanced_group = QGroupBox("🚀 Advanced Payload Generation")
        enhanced_layout = QVBoxLayout(enhanced_group)
        
        self.enhanced_generator_btn = QPushButton("🎯 Open Enhanced Payload Generator")
        self.enhanced_generator_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0078d4, stop:1 #106ebe);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #106ebe, stop:1 #005a9e);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #005a9e, stop:1 #004578);
            }
        """)
        self.enhanced_generator_btn.clicked.connect(self.open_enhanced_generator)
        enhanced_layout.addWidget(self.enhanced_generator_btn)
        
        info_label = QLabel("✨ Professional-grade payload generation with:")
        info_label.setStyleSheet("color: #666; font-style: italic; margin: 5px;")
        enhanced_layout.addWidget(info_label)
        
        features_text = QTextEdit()
        features_text.setMaximumHeight(100)
        features_text.setReadOnly(True)
        features_text.setStyleSheet("border: none; background: transparent; color: #666;")
        features_text.setText("""
• LOLBAS Techniques with AMSI/ETW Bypass
• Agent Compilation with Binary Disguises (update.exe, svchost.exe, etc.)
• Multi-layer Obfuscation & Signature Evasion
• Quality Assessment & Payload Optimization
• Advanced Agent Generation with Stealth Features
        """)
        enhanced_layout.addWidget(features_text)
        
        main_layout.addWidget(enhanced_group)
        
        # Scroll area for legacy features
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        main_layout.addWidget(scroll_area)

        container = QWidget()
        scroll_area.setWidget(container)
        layout = QGridLayout(container)

        # --- Agent Generator ---
        agent_group = QGroupBox("Advanced Agent Generator")
        agent_layout = QGridLayout(agent_group)

        agent_layout.addWidget(QLabel("LHOST:"), 0, 0)
        self.agent_lhost = QLineEdit("127.0.0.1")
        agent_layout.addWidget(self.agent_lhost, 0, 1)

        agent_layout.addWidget(QLabel("LPORT:"), 0, 2)
        self.agent_lport = QLineEdit("4444")
        agent_layout.addWidget(self.agent_lport, 0, 3)

        agent_layout.addWidget(QLabel("Agent Type:"), 1, 0)
        self.agent_type = QComboBox()
        self.agent_type.addItems(["basic", "powershell"])
        agent_layout.addWidget(self.agent_type, 1, 1)
        
        generate_agent_btn = QPushButton("Generate Agent")
        generate_agent_btn.clicked.connect(self.generate_agent)
        agent_layout.addWidget(generate_agent_btn, 1, 2, 1, 2)

        layout.addWidget(agent_group, 0, 0)

        # --- Reverse Shell Generator ---
        revshell_group = QGroupBox("Elite Reverse Shell Generator")
        revshell_layout = QGridLayout(revshell_group)

        revshell_layout.addWidget(QLabel("LHOST:"), 0, 0)
        self.revshell_lhost = QLineEdit("127.0.0.1")
        revshell_layout.addWidget(self.revshell_lhost, 0, 1)

        revshell_layout.addWidget(QLabel("LPORT:"), 0, 2)
        self.revshell_lport = QLineEdit("4444")
        revshell_layout.addWidget(self.revshell_lport, 0, 3)

        revshell_layout.addWidget(QLabel("Category:"), 1, 0)
        self.revshell_category = QComboBox()
        self.revshell_category.addItems(self.revshell_generator.get_categories())
        self.revshell_category.currentTextChanged.connect(self.update_revshell_subcategories)
        revshell_layout.addWidget(self.revshell_category, 1, 1)

        revshell_layout.addWidget(QLabel("Subcategory:"), 1, 2)
        self.revshell_subcategory = QComboBox()
        revshell_layout.addWidget(self.revshell_subcategory, 1, 3)
        self.update_revshell_subcategories(self.revshell_category.currentText())
        self.revshell_subcategory.currentTextChanged.connect(self.update_revshell_payloads)

        revshell_layout.addWidget(QLabel("Payload:"), 2, 0)
        self.revshell_payload = QComboBox()
        revshell_layout.addWidget(self.revshell_payload, 2, 1)
        self.update_revshell_payloads(self.revshell_subcategory.currentText())

        self.obfuscate_check = QCheckBox("Obfuscate Payload")
        self.obfuscate_check.setChecked(True)
        revshell_layout.addWidget(self.obfuscate_check, 2, 2)

        generate_revshell_btn = QPushButton("Generate Reverse Shell")
        generate_revshell_btn.clicked.connect(self.generate_revshell)
        revshell_layout.addWidget(generate_revshell_btn, 2, 3)

        layout.addWidget(revshell_group, 0, 1)

        # --- LOLBAS Generator ---
        lolbas_group = QGroupBox("LOLBAS Payload Generator")
        lolbas_layout = QGridLayout(lolbas_group)
        
        # ... (Implementation for LOLBAS Generator UI) ...

        layout.addWidget(lolbas_group, 1, 0)

        # --- AV Evasion ---
        av_group = QGroupBox("AV Evasion Techniques")
        av_layout = QGridLayout(av_group)

        av_layout.addWidget(QLabel("Technique:"), 0, 0)
        self.av_technique = QComboBox()
        self.av_technique.addItems(["auto"] + self.av_engine.get_available_techniques())
        av_layout.addWidget(self.av_technique, 0, 1)

        obfuscate_btn = QPushButton("Apply to Generated Code")
        obfuscate_btn.clicked.connect(self.apply_av_evasion)
        av_layout.addWidget(obfuscate_btn, 0, 2)

        layout.addWidget(av_group, 1, 1)
    
    def open_enhanced_generator(self):
        """Open the enhanced payload generator dialog"""
        try:
            from ..dialogs.enhanced_payload_generator_dialog import EnhancedPayloadGeneratorDialog
            from PyQt6.QtWidgets import QMessageBox
            
            # Get current server configuration
            server_ip = self.agent_lhost.text() or "127.0.0.1"
            server_port = int(self.agent_lport.text()) if self.agent_lport.text().isdigit() else 4444
            
            dialog = EnhancedPayloadGeneratorDialog(
                server_ip=server_ip,
                server_port=server_port,
                parent=self
            )
            
            result = dialog.exec()
            if result == EnhancedPayloadGeneratorDialog.Accepted:
                QMessageBox.information(self, "Success", "Enhanced payload generation completed successfully!")
                
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Error", f"Failed to open enhanced payload generator:\\n{str(e)}")

        # --- Output ---
        output_group = QGroupBox("Generated Code")
        output_layout = QVBoxLayout(output_group)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas';")
        self.highlighter = PythonSyntaxHighlighter(self.output_text.document())
        output_layout.addWidget(self.output_text)
        layout.addWidget(output_group, 2, 0, 1, 2)

    def generate_agent(self):
        host = self.agent_lhost.text()
        port = int(self.agent_lport.text())
        agent_type = self.agent_type.currentText()
        code = generate_undetectable_agent(host, port, agent_type)
        self.output_text.setPlainText(code)

    def update_revshell_subcategories(self, category):
        self.revshell_subcategory.clear()
        self.revshell_subcategory.addItems(self.revshell_generator.get_subcategories(category))

    def update_revshell_payloads(self, subcategory):
        category = self.revshell_category.currentText()
        self.revshell_payload.clear()
        if category and subcategory:
            self.revshell_payload.addItems(self.revshell_generator.get_payloads(category, subcategory))

    def generate_revshell(self):
        lhost = self.revshell_lhost.text()
        lport = int(self.revshell_lport.text())
        category = self.revshell_category.currentText()
        subcategory = self.revshell_subcategory.currentText()
        payload_type = self.revshell_payload.currentText()
        obfuscate = self.obfuscate_check.isChecked()

        code = self.revshell_generator.generate_payload(
            category, subcategory, payload_type, lhost, lport, obfuscate
        )
        self.output_text.setPlainText(code)

    def apply_av_evasion(self):
        current_code = self.output_text.toPlainText()
        if not current_code:
            return
        
        technique = self.av_technique.currentText()
        obfuscated_code = self.av_engine.obfuscate_code(current_code, technique)
        self.output_text.setPlainText(obfuscated_code)
