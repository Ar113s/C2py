# C2PY Framework

<p align="center">
  <img src="img/c2py_logo.png" alt="C2PY Logo" width="350"/>
</p>

<h2 align="center">Advanced Command & Control Framework</h2>

<p align="center">
  <strong>Professional-grade C2 framework with cyberpunk aesthetics and modern GUI</strong><br>
  For authorized penetration testing and security research
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python" alt="Python Version"/>
  <img src="https://img.shields.io/badge/GUI-PyQt6-green?style=flat-square" alt="GUI Framework"/>
  <img src="https://img.shields.io/badge/Platform-Windows-red?style=flat-square&logo=windows" alt="Platform"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License"/>
</p>

---

## 🚀 Features

### 🖥️ C2 Server (GUI)

- **Modern PyQt6 Interface**: Professional dark-themed GUI
- **Multi-Agent Management**: Handle unlimited simultaneous connections
- **Real-time Monitoring**: Live agent status and system information
- **Enhanced Terminal**: Black background with syntax highlighting
- **Command History**: Persistent command history per agent
- **Payload Generator**: Built-in agent generation with LOLBAS techniques

### 🔧 Advanced Agent

- **Cross-Platform**: Windows-focused with Linux compatibility
- **Stealth Operations**: Anti-detection and evasion techniques
- **File Operations**: Secure upload/download capabilities
- **System Intelligence**: Comprehensive system enumeration
- **PowerShell Integration**: Native PowerShell command execution
- **UTF-8 Support**: Proper handling of international characters

### 🛡️ Security Features

- **Encrypted Communications**: XOR encryption with obfuscation
- **Safe Operations**: Read-only registry access, limited privilege escalation
- **Error Handling**: Graceful degradation and error recovery
- **Logging**: Comprehensive activity logging

---

## 📋 Requirements

### Core Dependencies

- **Python 3.8+**
- **PyQt6** (GUI framework)
- **Standard libraries** (socket, threading, etc.)

### Optional Dependencies (Enhanced Features)

```bash
pip install psutil requests urllib3 pillow pywin32 cryptography
```

---

## 🛠 Installation

### 1. Clone Repository

```bash
git clone https://github.com/Ar113s/C2py.git
cd c2py
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Launch Framework

```bash
python c2py.py
```

---

## 🚀 Quick Start Guide

### Starting the C2 Server

1. **Launch the application**:

   ```bash
   python c2py.py
   ```

2. **Configure a listener**:

   - Click **"New Listener"**
   - Set **Host**: `0.0.0.0` (all interfaces)
   - Set **Port**: `4444` (or custom port)
   - Click **"Start Listener"**

3. **Monitor connections**:
   - View agents in the **Agent Manager**
   - Real-time status updates
   - System information display

### Deploying Agents

#### Option 1: Use Built-in Generator

1. Navigate to **"Payload Generator"** tab
2. Configure target details
3. Generate custom agent
4. Deploy on target system

#### Option 2: Use Simple Agent

```bash
# On target system
python simple_agent.py <server_ip> <server_port>
```

### Basic Usage

1. **Select Agent**: Choose from connected agents
2. **Execute Commands**: Use the enhanced terminal
3. **View Results**: Real-time command output
4. **Manage Sessions**: Multiple concurrent agent sessions

---

## 🎯 Core Features

### Command Categories

#### 📊 System Information

```bash
systeminfo          # Comprehensive system details
whoami              # Current user information
hostname            # Computer name
pwd                 # Current directory
```

#### 📁 File Operations

```bash
dir / ls            # List directory contents
cd <directory>      # Change directory
type <file>         # Display file contents
```

#### ⚙️ Process Management

```bash
tasklist           # List running processes
netstat            # Network connections
services           # Windows services
```

#### 💻 PowerShell Integration

```bash
powershell <cmd>   # Execute PowerShell commands
ps <cmd>           # PowerShell shorthand
```

### Advanced Features

#### 🎯 Payload Generator

- **LOLBAS Techniques**: Living-off-the-land binaries
- **Multiple Formats**: Python, PowerShell, Batch
- **Customizable**: IP, port, and evasion options
- **Export Options**: Save generated payloads

#### 🖥️ Enhanced Terminal

- **Syntax Highlighting**: Colorized command output
- **Command History**: Arrow key navigation
- **Real-time Updates**: Live command execution
- **UTF-8 Support**: International character handling

#### 📡 Agent Management

- **Connection Status**: Real-time monitoring
- **System Details**: Hardware and software info
- **Session Management**: Multiple concurrent sessions
- **Automatic Reconnection**: Persistent connections

---

## 🔧 Advanced Configuration

### Server Configuration

```python
# Default settings in c2py.py
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 4444
ENCRYPTION_KEY = "your_custom_key"
```

### Agent Customization

```python
# simple_agent.py configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 4444
RECONNECT_DELAY = 30
```

### Building Standalone Agents

```bash
# Use the build system
python build_final_agents.py <server_ip> <server_port>
```

---

## 🛡️ Security Considerations

### ✅ Safety Features

- **Read-only Operations**: Registry access limited to read operations
- **Error Handling**: Graceful failure and recovery
- **Logging**: Comprehensive activity logs
- **Authorization Check**: Built-in safety mechanisms

### 🔐 Encryption

- **Method**: XOR encryption with base64 encoding
- **Obfuscation**: Random padding for pattern avoidance
- **Key Management**: Configurable encryption keys

### ⚠️ Responsible Use

1. **Authorization Only**: Use only in authorized environments
2. **Legal Compliance**: Follow local laws and regulations
3. **Ethical Guidelines**: Respect privacy and data protection
4. **Documentation**: Maintain audit trails of activities

---

## 📁 Project Structure

```
c2py/
├── c2py.py                     # Main application entry point
├── simple_agent.py             # Basic agent implementation
├── build_final_agents.py       # Agent build system
├── src/                        # Core framework modules
│   ├── gui/                    # GUI components
│   │   ├── main_window.py      # Main application window
│   │   └── views/              # UI views and dialogs
│   ├── core/                   # Core functionality
│   │   ├── c2_server.py        # C2 server implementation
│   │   └── loot_manager.py     # Data management
│   ├── generators/             # Payload generators
│   └── utils/                  # Utility functions
├── lolbas_templates/           # LOLBAS payload templates
├── img/                        # Icons and images
├── requirements.txt            # Python dependencies
└── README.md                   # This documentation
```

---

## 🔍 Troubleshooting

### Common Issues

#### Connection Problems

- **Firewall**: Ensure port is open
- **Network**: Check IP/port configuration
- **Antivirus**: May block agent execution

#### GUI Issues

- **PyQt6**: Install with `pip install PyQt6`
- **Display**: Check system DPI settings
- **Dependencies**: Install all requirements

#### Agent Issues

- **Encoding**: UTF-8 fixes included
- **Permissions**: Run with appropriate privileges
- **Network**: Verify server connectivity

### Getting Help

1. Check the [Issues](https://github.com/Ar113s/C2py/issues) page
2. Review troubleshooting steps
3. Submit detailed bug reports

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**This framework is intended for authorized penetration testing, security research, and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The developers assume no liability for misuse of this software.**

---

<p align="center">
  <strong>Made with ❤️ for the cybersecurity community</strong>
</p>
