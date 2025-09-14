"""
SSH Emulator - AI-enhanced SSH honeypot service
"""

import socket
import threading
import time
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any

from .base_emulator import BaseServiceEmulator


class SSHEmulator(BaseServiceEmulator):
    """
    SSH service emulator with AI-driven dynamic responses
    Emulates SSH protocol interactions for honeypot purposes
    """
    
    SERVICE_NAME = "ssh"
    DEFAULT_PORT = 22
    
    def __init__(self, port: int = DEFAULT_PORT, **kwargs):
        super().__init__(self.SERVICE_NAME, port, **kwargs)
        
        # SSH-specific configurations
        self.ssh_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        self.supported_auth_methods = ["password", "publickey"]
        self.fake_host_key = self._generate_fake_host_key()
        
        # Session management
        self.active_sessions = {}
        self.session_counter = 0
        
        # SSH protocol states
        self.PROTOCOL_VERSION = "2.0"
        self.SERVER_VERSION = "OpenSSH_8.2p1"
        
    def start_service(self):
        """Start SSH emulator service"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(10)
            
            self.log_event({
                "action": "service_started",
                "service": self.SERVICE_NAME,
                "port": self.port,
                "banner": self.ssh_banner
            })
            
            print(f"[{datetime.now()}] SSH Emulator started on {self.bind_ip}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Create new session thread
                    session_thread = threading.Thread(
                        target=self._handle_ssh_session,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    session_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        self.log_event({
                            "action": "socket_error",
                            "error": str(e),
                            "service": self.SERVICE_NAME
                        })
                        
        except Exception as e:
            self.log_event({
                "action": "service_error",
                "error": str(e),
                "service": self.SERVICE_NAME
            })
            
    def _handle_ssh_session(self, client_socket: socket.socket, client_address: tuple):
        """Handle individual SSH session"""
        session_id = self._create_session_id()
        client_ip, client_port = client_address
        
        session_info = {
            "session_id": session_id,
            "client_ip": client_ip,
            "client_port": client_port,
            "start_time": datetime.now(),
            "authenticated": False,
            "username": None,
            "commands": [],
            "current_directory": "/root",
            "environment": self._create_fake_environment()
        }
        
        self.active_sessions[session_id] = session_info
        
        try:
            self.log_event({
                "action": "connection_established",
                "session_id": session_id,
                "client_ip": client_ip,
                "client_port": client_port
            })
            
            # Send SSH banner
            self._send_ssh_banner(client_socket)
            
            # Handle SSH protocol negotiation
            if self._handle_protocol_negotiation(client_socket, session_info):
                # Handle authentication
                if self._handle_authentication(client_socket, session_info):
                    # Handle interactive shell session
                    self._handle_shell_session(client_socket, session_info)
            
        except Exception as e:
            self.log_event({
                "action": "session_error",
                "session_id": session_id,
                "error": str(e)
            })
        finally:
            self._cleanup_session(client_socket, session_id)
    
    def _send_ssh_banner(self, client_socket: socket.socket):
        """Send SSH protocol banner"""
        banner = f"{self.ssh_banner}\r\n"
        client_socket.send(banner.encode())
    
    def _handle_protocol_negotiation(self, client_socket: socket.socket, 
                                   session_info: Dict[str, Any]) -> bool:
        """Handle SSH protocol version negotiation"""
        try:
            # Receive client banner
            client_banner = client_socket.recv(1024).decode().strip()
            
            self.log_event({
                "action": "protocol_negotiation",
                "session_id": session_info["session_id"],
                "client_banner": client_banner
            })
            
            # Simple protocol validation
            if "SSH-" in client_banner:
                return True
            else:
                return False
                
        except Exception as e:
            self.log_event({
                "action": "protocol_negotiation_error",
                "session_id": session_info["session_id"],
                "error": str(e)
            })
            return False
    
    def _handle_authentication(self, client_socket: socket.socket, 
                             session_info: Dict[str, Any]) -> bool:
        """Handle SSH authentication process"""
        max_auth_attempts = 3
        auth_attempts = 0
        
        while auth_attempts < max_auth_attempts:
            try:
                # Send authentication request
                auth_prompt = "login as: "
                client_socket.send(auth_prompt.encode())
                
                # Receive username
                username_data = client_socket.recv(1024).decode().strip()
                if not username_data:
                    break
                
                session_info["username"] = username_data
                
                # Send password prompt
                password_prompt = f"{username_data}@{self.bind_ip}'s password: "
                client_socket.send(password_prompt.encode())
                
                # Receive password
                password_data = client_socket.recv(1024).decode().strip()
                
                # Log authentication attempt
                self.log_event({
                    "action": "authentication_attempt",
                    "session_id": session_info["session_id"],
                    "username": username_data,
                    "password": password_data,
                    "attempt": auth_attempts + 1
                })
                
                # Process authentication with AI
                auth_result = self._process_authentication(
                    username_data, password_data, session_info
                )
                
                if auth_result["success"]:
                    session_info["authenticated"] = True
                    
                    # Send success message
                    success_msg = f"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n\r\n"
                    success_msg += f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {session_info['client_ip']}\r\n"
                    client_socket.send(success_msg.encode())
                    
                    return True
                else:
                    auth_attempts += 1
                    if auth_attempts < max_auth_attempts:
                        error_msg = "Permission denied, please try again.\r\n"
                        client_socket.send(error_msg.encode())
                    else:
                        error_msg = "Permission denied (publickey,password).\r\n"
                        client_socket.send(error_msg.encode())
                        
            except Exception as e:
                self.log_event({
                    "action": "authentication_error",
                    "session_id": session_info["session_id"],
                    "error": str(e)
                })
                break
        
        return False
    
    def _process_authentication(self, username: str, password: str, 
                              session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process authentication using AI coordinator"""
        if self.ai_coordinator:
            # Use AI to determine authentication response
            ai_response = self.ai_coordinator.process_interaction(
                service=self.SERVICE_NAME,
                attacker_ip=session_info["client_ip"],
                command=f"auth:{username}:{password}",
                context={
                    "session_info": session_info,
                    "auth_type": "password"
                }
            )
            
            # AI-driven authentication decision
            behavior_analysis = ai_response.get("behavior_analysis", {})
            attack_type = behavior_analysis.get("attack_type", "unknown")
            
            # Allow authentication for certain scenarios to gather more intelligence
            if attack_type in ["reconnaissance", "exploitation"]:
                success_probability = 0.7  # Higher chance to allow access
            elif attack_type == "brute_force":
                success_probability = 0.1  # Lower chance for brute force
            else:
                success_probability = 0.3  # Default probability
            
            import random
            success = random.random() < success_probability
            
            return {
                "success": success,
                "ai_decision": True,
                "attack_type": attack_type,
                "confidence": ai_response.get("ai_confidence", 0.5)
            }
        else:
            # Fallback authentication logic
            # Allow some common credentials for honeypot purposes
            common_credentials = [
                ("root", "root"), ("admin", "admin"), ("user", "password"),
                ("test", "test"), ("guest", "guest")
            ]
            
            success = (username, password) in common_credentials
            return {"success": success, "ai_decision": False}
    
    def _handle_shell_session(self, client_socket: socket.socket, 
                            session_info: Dict[str, Any]):
        """Handle interactive shell session"""
        try:
            # Send shell prompt
            self._send_shell_prompt(client_socket, session_info)
            
            while self.running and session_info["authenticated"]:
                try:
                    # Receive command
                    command_data = client_socket.recv(1024).decode().strip()
                    if not command_data:
                        break
                    
                    # Process command with AI
                    response = self._process_shell_command(command_data, session_info)
                    
                    # Send response
                    if response:
                        # Add realistic delay
                        time.sleep(response.get("delay", 0.5))
                        
                        # Send command output
                        output = response.get("text", "")
                        if output:
                            client_socket.send(f"{output}\r\n".encode())
                    
                    # Send next prompt
                    self._send_shell_prompt(client_socket, session_info)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log_event({
                        "action": "shell_command_error",
                        "session_id": session_info["session_id"],
                        "error": str(e)
                    })
                    break
                    
        except Exception as e:
            self.log_event({
                "action": "shell_session_error",
                "session_id": session_info["session_id"],
                "error": str(e)
            })
    
    def _process_shell_command(self, command: str, session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process shell command using AI coordinator"""
        session_info["commands"].append({
            "command": command,
            "timestamp": datetime.now().isoformat()
        })
        
        self.log_event({
            "action": "shell_command",
            "session_id": session_info["session_id"],
            "command": command,
            "directory": session_info["current_directory"]
        })
        
        if self.ai_coordinator:
            # Use AI coordinator for dynamic response
            ai_response = self.ai_coordinator.process_interaction(
                service=self.SERVICE_NAME,
                attacker_ip=session_info["client_ip"],
                command=command,
                context={
                    "session_info": session_info,
                    "current_directory": session_info["current_directory"],
                    "environment": session_info["environment"]
                }
            )
            
            return ai_response.get("response", {})
        else:
            # Fallback command processing
            return self._fallback_command_processing(command, session_info)
    
    def _fallback_command_processing(self, command: str, session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback command processing when AI is not available"""
        command_lower = command.lower().strip()
        
        # Basic command responses
        if command_lower == "whoami":
            return {"text": session_info["username"], "delay": 0.1}
        elif command_lower == "pwd":
            return {"text": session_info["current_directory"], "delay": 0.1}
        elif command_lower in ["ls", "ls -la"]:
            return {
                "text": "total 24\ndrwx------ 2 root root 4096 Dec  1 10:30 .\ndrwxr-xr-x 3 root root 4096 Dec  1 10:29 ..\n-rw------- 1 root root  220 Dec  1 10:29 .bash_logout\n-rw------- 1 root root 3771 Dec  1 10:29 .bashrc\n-rw------- 1 root root  807 Dec  1 10:29 .profile",
                "delay": 0.2
            }
        elif command_lower == "id":
            return {"text": "uid=0(root) gid=0(root) groups=0(root)", "delay": 0.1}
        elif command_lower == "uname -a":
            return {"text": "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux", "delay": 0.3}
        else:
            return {"text": f"bash: {command}: command not found", "delay": 0.5}
    
    def _send_shell_prompt(self, client_socket: socket.socket, session_info: Dict[str, Any]):
        """Send shell prompt"""
        username = session_info["username"]
        hostname = "honeypot"
        current_dir = session_info["current_directory"]
        
        if current_dir == f"/home/{username}" or current_dir == "/root":
            dir_display = "~"
        else:
            dir_display = current_dir
        
        prompt = f"{username}@{hostname}:{dir_display}$ "
        client_socket.send(prompt.encode())
    
    def _create_session_id(self) -> str:
        """Create unique session ID"""
        self.session_counter += 1
        return f"ssh_{self.session_counter}_{int(time.time())}"
    
    def _create_fake_environment(self) -> Dict[str, str]:
        """Create fake environment variables"""
        return {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "USER": "root",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8"
        }
    
    def _generate_fake_host_key(self) -> str:
        """Generate fake SSH host key"""
        import random
        import string
        
        # Generate fake RSA key fingerprint
        key_data = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        return base64.b64encode(key_data.encode()).decode()
    
    def _cleanup_session(self, client_socket: Optional[socket.socket], session_id: str):
        """Clean up session resources"""
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
        
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            
            self.log_event({
                "action": "session_ended",
                "session_id": session_id,
                "duration": (datetime.now() - session_info["start_time"]).total_seconds(),
                "commands_executed": len(session_info["commands"]),
                "authenticated": session_info["authenticated"]
            })
            
            del self.active_sessions[session_id]
    
    def stop_service(self):
        """Stop SSH emulator service"""
        super().stop_service()
        
        # Close all active sessions
        for session_id in list(self.active_sessions.keys()):
            self._cleanup_session(None, session_id)
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get SSH service statistics"""
        base_stats = super().get_service_stats()
        
        ssh_stats = {
            "active_sessions": len(self.active_sessions),
            "total_commands": sum(len(session["commands"]) for session in self.active_sessions.values()),
            "authenticated_sessions": sum(1 for session in self.active_sessions.values() if session["authenticated"])
        }
        
        base_stats.update(ssh_stats)
        return base_stats