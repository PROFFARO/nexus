"""
FTP Emulator - AI-enhanced FTP honeypot service
"""

import socket
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import tempfile

from .base_emulator import BaseServiceEmulator


class FTPSession:
    """FTP session state management"""
    
    def __init__(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        self.socket: socket.socket = client_socket
        self.address: Tuple[str, int] = client_address
        self.authenticated: bool = False
        self.username: Optional[str] = None
        self.current_dir: str = "/"
        self.data_socket: Optional[socket.socket] = None
        self.passive_server: Optional[socket.socket] = None
        self.binary_mode: bool = True
        self.last_activity: datetime = datetime.now()


class FTPEmulator(BaseServiceEmulator):
    """
    FTP service emulator with AI-driven dynamic responses
    Emulates FTP protocol interactions for honeypot purposes
    """
    
    SERVICE_NAME = "ftp"
    DEFAULT_PORT = 21
    
    def __init__(self, port: int = DEFAULT_PORT, **kwargs):
        super().__init__(self.SERVICE_NAME, port, **kwargs)
        
        # FTP server settings
        self.banner = "220 ProFTPD 1.3.5rc3 Server"
        self.max_login_attempts = 3
        
        # Virtual filesystem setup
        self.root_dir = tempfile.mkdtemp(prefix="ftp_honeypot_")
        self._setup_virtual_filesystem()
        
        # Session management
        self.active_sessions: Dict[str, FTPSession] = {}
        self.login_attempts: Dict[str, int] = {}
        
        # Command handlers
        self.command_handlers = {
            'USER': self._handle_user,
            'PASS': self._handle_pass,
            'SYST': self._handle_syst,
            'PWD': self._handle_pwd,
            'TYPE': self._handle_type,
            'PASV': self._handle_pasv,
            'LIST': self._handle_list,
            'CWD': self._handle_cwd,
            'RETR': self._handle_retr,
            'STOR': self._handle_stor,
            'QUIT': self._handle_quit,
            'FEAT': self._handle_feat
        }
    
    def _setup_virtual_filesystem(self):
        """Set up virtual filesystem structure"""
        directories = [
            'pub',
            'incoming',
            'users/admin',
            'backup/system',
            'logs'
        ]
        
        sample_files = {
            'pub/README.txt': 'Public file sharing directory\n',
            'backup/system/backup.conf': 'backup_interval=daily\nretention=30days\n',
            'logs/access.log': '# System access logs\n'
        }
        
        # Create directories
        for directory in directories:
            path = os.path.join(self.root_dir, directory)
            os.makedirs(path, exist_ok=True)
        
        # Create sample files
        for filepath, content in sample_files.items():
            full_path = os.path.join(self.root_dir, filepath)
            with open(full_path, 'w') as f:
                f.write(content)
    
    def start_service(self):
        """Start FTP emulator service"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            
            self.log_event({
                "action": "service_started",
                "service": self.SERVICE_NAME,
                "port": self.port,
                "virtual_root": self.root_dir
            })
            
            print(f"[{datetime.now()}] FTP Emulator started on {self.bind_ip}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    session_thread = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    session_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"[{datetime.now()}] Error accepting FTP connection: {e}")
                        
        except Exception as e:
            print(f"[{datetime.now()}] FTP service error: {e}")
        finally:
            self._cleanup()
    
    def _handle_client_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle new FTP client connection"""
        session = FTPSession(client_socket, client_address)
        session_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            self.active_sessions[session_id] = session
            self.connection_count += 1
            
            self.log_event({
                "action": "client_connected",
                "client_ip": client_address[0],
                "client_port": client_address[1],
                "protocol": "ftp"
            })
            
            # Send welcome banner
            self._send_response(session, self.banner)
            
            while self.running:
                try:
                    command_line = self._receive_command(session)
                    if not command_line:
                        break
                    
                    self._process_command(session, command_line)
                    session.last_activity = datetime.now()
                    
                except Exception as e:
                    print(f"[{datetime.now()}] Error processing FTP command: {e}")
                    break
                    
        except Exception as e:
            print(f"[{datetime.now()}] FTP session error: {e}")
        finally:
            self._cleanup_session(session_id)
    
    def _receive_command(self, session: FTPSession) -> Optional[str]:
        """Receive FTP command from client"""
        try:
            data = session.socket.recv(1024).decode('utf-8').strip()
            if data:
                self.total_interactions += 1
                self.log_event({
                    "action": "command_received",
                    "client_ip": session.address[0],
                    "command": data,
                    "authenticated": session.authenticated
                })
                return data
        except:
            pass
        return None
    
    def _send_response(self, session: FTPSession, response: str):
        """Send response to FTP client"""
        try:
            session.socket.send(f"{response}\r\n".encode('utf-8'))
        except:
            pass
    
    def _process_command(self, session: FTPSession, command_line: str):
        """Process FTP command"""
        try:
            cmd_parts = command_line.split(' ', 1)
            command = cmd_parts[0].upper()
            argument = cmd_parts[1] if len(cmd_parts) > 1 else ''
            
            # Get AI-driven response if available
            if self.ai_coordinator and self.adaptive_responses:
                ai_context = {
                    "service": "ftp",
                    "command": command,
                    "argument": argument,
                    "authenticated": session.authenticated,
                    "username": session.username,
                    "client_ip": session.address[0],
                    "session_commands": []  # Add command history here
                }
                
                ai_response = self.ai_coordinator.process_interaction(
                    self.SERVICE_NAME,
                    session.address[0],
                    command_line,
                    ai_context
                )
                
                if ai_response.get("block_ip", False):
                    self.block_ip(session.address[0], "ai_policy_violation")
                    return
                
                if ai_response.get("custom_response"):
                    self._send_response(session, ai_response["custom_response"])
                    return
            
            # Process command with standard handler
            handler = self.command_handlers.get(command)
            if handler:
                handler(session, argument)
            else:
                self._send_response(session, "500 Unknown command.")
                
        except Exception as e:
            print(f"[{datetime.now()}] Error processing FTP command: {e}")
            self._send_response(session, "550 Internal error.")
    
    def _handle_user(self, session: FTPSession, username: str):
        """Handle USER command"""
        session.username = username
        session.authenticated = False
        self._send_response(session, "331 Password required for " + username)
        
        self.log_event({
            "action": "login_attempt",
            "client_ip": session.address[0],
            "username": username,
            "stage": "username"
        })
    
    def _handle_pass(self, session: FTPSession, password: str):
        """Handle PASS command"""
        if not session.username:
            self._send_response(session, "503 Login with USER first.")
            return
        
        # Log login attempt
        self.log_event({
            "action": "login_attempt",
            "client_ip": session.address[0],
            "username": session.username,
            "password": password,
            "stage": "password"
        })
        
        # AI-driven authentication response
        if self.ai_coordinator:
            auth_context = {
                "service": "ftp",
                "username": session.username,
                "password": password,
                "client_ip": session.address[0],
                "previous_attempts": self.login_attempts.get(session.address[0], 0)
            }
            
            ai_response = self.ai_coordinator.process_authentication(
                self.SERVICE_NAME,
                session.address[0],
                auth_context
            )
            
            if ai_response.get("allow_login", False):
                session.authenticated = True
                self._send_response(session, "230 User logged in.")
                return
        
        # Default: deny login
        self.login_attempts[session.address[0]] = self.login_attempts.get(session.address[0], 0) + 1
        self._send_response(session, "530 Login incorrect.")
        
        # Block IP if too many attempts
        if self.login_attempts[session.address[0]] >= self.max_login_attempts:
            self.block_ip(session.address[0], "exceeded_login_attempts")
    
    def _handle_syst(self, session: FTPSession, argument: str):
        """Handle SYST command"""
        self._send_response(session, "215 UNIX Type: L8")
    
    def _handle_pwd(self, session: FTPSession, argument: str):
        """Handle PWD command"""
        if not session.authenticated:
            self._send_response(session, "530 Please login first.")
            return
        
        self._send_response(session, f'257 "{session.current_dir}" is current directory.')
    
    def _handle_type(self, session: FTPSession, type_code: str):
        """Handle TYPE command"""
        if type_code.upper() in ['I', 'A']:
            session.binary_mode = (type_code.upper() == 'I')
            self._send_response(session, "200 Type set to " + type_code)
        else:
            self._send_response(session, "504 Type not supported.")
    
    def _handle_pasv(self, session: FTPSession, argument: str):
        """Handle PASV command"""
        if not session.authenticated:
            self._send_response(session, "530 Please login first.")
            return
        
        # Create passive server
        passive_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        passive_sock.bind((self.bind_ip, 0))
        passive_sock.listen(1)
        
        ip_parts = self.bind_ip.split('.')
        port = passive_sock.getsockname()[1]
        port_hi = port >> 8
        port_lo = port & 0xFF
        
        session.passive_server = passive_sock
        response = f"227 Entering Passive Mode ({','.join(ip_parts)},{port_hi},{port_lo})"
        self._send_response(session, response)
    
    def _handle_list(self, session: FTPSession, argument: str):
        """Handle LIST command"""
        if not session.authenticated:
            self._send_response(session, "530 Please login first.")
            return
        
        if not session.passive_server:
            self._send_response(session, "425 Use PASV first.")
            return
        
        self._send_response(session, "150 Opening ASCII mode data connection for file list")
        
        try:
            data_socket, _ = session.passive_server.accept()
            
            # Generate listing for current directory
            listing = self._generate_directory_listing(session.current_dir)
            data_socket.send(listing.encode('utf-8'))
            data_socket.close()
            
            self._send_response(session, "226 Transfer complete.")
            
        except Exception as e:
            print(f"[{datetime.now()}] Error in LIST: {e}")
            self._send_response(session, "550 Error during transfer.")
        finally:
            session.passive_server.close()
            session.passive_server = None
    
    def _handle_cwd(self, session: FTPSession, path: str):
        """Handle CWD command"""
        if not session.authenticated:
            self._send_response(session, "530 Please login first.")
            return
        
        # Normalize and validate path
        new_path = os.path.normpath(os.path.join(session.current_dir, path))
        if not new_path.startswith('/'):
            new_path = '/' + new_path
        
        # Check if path exists in virtual filesystem
        real_path = os.path.join(self.root_dir, new_path.lstrip('/'))
        if os.path.exists(real_path) and os.path.isdir(real_path):
            session.current_dir = new_path
            self._send_response(session, f'250 CWD command successful. "{new_path}" is current directory.')
        else:
            self._send_response(session, "550 Directory not found.")
    
    def _handle_retr(self, session: FTPSession, filename: str):
        """Handle RETR command"""
        if not session.authenticated:
            self._send_response(session, "530 Please login first.")
            return
        
        if not session.passive_server:
            self._send_response(session, "425 Use PASV first.")
            return
        
        filepath = os.path.join(self.root_dir, session.current_dir.lstrip('/'), filename)
        
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self._send_response(session, "550 File not found.")
            return
        
        self._send_response(session, "150 Opening data connection for file transfer.")
        
        try:
            data_socket, _ = session.passive_server.accept()
            
            with open(filepath, 'rb') as f:
                data_socket.sendall(f.read())
            
            data_socket.close()
            self._send_response(session, "226 Transfer complete.")
            
        except Exception as e:
            print(f"[{datetime.now()}] Error in RETR: {e}")
            self._send_response(session, "550 Error during transfer.")
        finally:
            session.passive_server.close()
            session.passive_server = None
    
    def _handle_stor(self, session: FTPSession, filename: str):
        """Handle STOR command"""
        if not session.authenticated:
            self._send_response(session, "530 Please login first.")
            return
        
        if not session.passive_server:
            self._send_response(session, "425 Use PASV first.")
            return
        
        filepath = os.path.join(self.root_dir, session.current_dir.lstrip('/'), filename)
        
        self._send_response(session, "150 Opening data connection for file upload.")
        
        try:
            data_socket, _ = session.passive_server.accept()
            
            # Create a temporary file for analysis
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                while True:
                    data = data_socket.recv(8192)
                    if not data:
                        break
                    temp_file.write(data)
            
            # Analyze uploaded file if AI coordinator is available
            if self.ai_coordinator:
                analysis_context = {
                    "service": "ftp",
                    "client_ip": session.address[0],
                    "filename": filename,
                    "file_path": temp_file.name,
                    "file_size": os.path.getsize(temp_file.name)
                }
                
                ai_response = self.ai_coordinator.analyze_upload(
                    self.SERVICE_NAME,
                    session.address[0],
                    analysis_context
                )
                
                if ai_response.get("block_upload", False):
                    os.unlink(temp_file.name)
                    self._send_response(session, "550 Upload rejected: potential malware detected.")
                    if ai_response.get("block_ip", False):
                        self.block_ip(session.address[0], "malicious_upload")
                    return
            
            # Move file to final location
            os.rename(temp_file.name, filepath)
            
            data_socket.close()
            self._send_response(session, "226 Transfer complete.")
            
            self.log_event({
                "action": "file_upload",
                "client_ip": session.address[0],
                "filename": filename,
                "size": os.path.getsize(filepath)
            })
            
        except Exception as e:
            print(f"[{datetime.now()}] Error in STOR: {e}")
            self._send_response(session, "550 Error during transfer.")
        finally:
            session.passive_server.close()
            session.passive_server = None
    
    def _handle_feat(self, session: FTPSession, argument: str):
        """Handle FEAT command"""
        features = [
            "Features:",
            " PASV",
            " UTF8",
            " SIZE",
            " REST STREAM",
            "End"
        ]
        self._send_response(session, "\n".join(features))
    
    def _handle_quit(self, session: FTPSession, argument: str):
        """Handle QUIT command"""
        self._send_response(session, "221 Goodbye.")
        session.socket.close()
    
    def _generate_directory_listing(self, current_dir: str) -> str:
        """Generate directory listing in Unix format"""
        listing = []
        base_path = os.path.join(self.root_dir, current_dir.lstrip('/'))
        
        try:
            for entry in os.scandir(base_path):
                # Format: "type permissions owner group size month day time name"
                mode = 'drwxr-xr-x' if entry.is_dir() else '-rw-r--r--'
                size = 4096 if entry.is_dir() else entry.stat().st_size
                mtime = datetime.fromtimestamp(entry.stat().st_mtime)
                name = entry.name
                
                listing.append(f"{mode} 1 ftp ftp {size:8d} {mtime.strftime('%b %d %H:%M')} {name}")
        except Exception as e:
            print(f"Error generating directory listing: {e}")
        
        return "\r\n".join(listing) + "\r\n"
    
    def _cleanup_session(self, session_id: str):
        """Clean up client session"""
        try:
            session = self.active_sessions.get(session_id)
            if session:
                if session.socket:
                    session.socket.close()
                if session.passive_server:
                    session.passive_server.close()
                del self.active_sessions[session_id]
                
                self.log_event({
                    "action": "client_disconnected",
                    "client_ip": session.address[0],
                    "client_port": session.address[1]
                })
        except Exception as e:
            print(f"[{datetime.now()}] Error cleaning up session: {e}")
    
    def _cleanup(self):
        """Clean up resources"""
        try:
            # Close all active sessions
            for session_id in list(self.active_sessions.keys()):
                self._cleanup_session(session_id)
            
            # Clean up temporary files
            if os.path.exists(self.root_dir):
                for root, dirs, files in os.walk(self.root_dir, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(self.root_dir)
                
        except Exception as e:
            print(f"[{datetime.now()}] Error during cleanup: {e}")