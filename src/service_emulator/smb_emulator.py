"""
SMB Emulator - AI-enhanced SMB/CIFS honeypot service
"""

import socket
import struct
import threading
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import tempfile
from pathlib import Path

from .base_emulator import BaseServiceEmulator


class SMBSession:
    """SMB session state management"""
    
    def __init__(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        self.socket: socket.socket = client_socket
        self.address: Tuple[str, int] = client_address
        self.authenticated: bool = False
        self.username: Optional[str] = None
        self.domain: Optional[str] = None
        self.current_tree: Optional[str] = None
        self.open_files: Dict[int, str] = {}  # FID -> path mapping
        self.file_id_counter: int = 1
        self.last_activity: datetime = datetime.now()
        self.dialect: str = "NT LM 0.12"  # SMB1
        self.session_id: int = 0
        self.tree_id: int = 0
        self.process_id: int = 0
        self.multiplex_id: int = 0


class SMBEmulator(BaseServiceEmulator):
    """
    SMB/CIFS service emulator with AI-driven dynamic responses
    Emulates SMB protocol interactions for honeypot purposes
    """
    
    SERVICE_NAME = "smb"
    DEFAULT_PORT = 445
    
    # SMB Command Codes
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_NT_CREATE_ANDX = 0xA2
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F
    SMB_COM_CLOSE = 0x04
    SMB_COM_TREE_DISCONNECT = 0x71
    
    def __init__(self, port: int = DEFAULT_PORT, **kwargs):
        super().__init__(self.SERVICE_NAME, port, **kwargs)
        
        # SMB server settings
        self.server_name = "HONEYPOT-SMB"
        self.domain_name = "WORKGROUP"
        self.max_buffer = 16644
        self.capabilities = 0x8000044  # Extended security, Unicode, NT SMB
        
        # Virtual filesystem setup
        self.root_dir = tempfile.mkdtemp(prefix="smb_honeypot_")
        self._setup_virtual_filesystem()
        
        # Session management
        self.active_sessions: Dict[str, SMBSession] = {}
        self.login_attempts: Dict[str, int] = {}
        self.max_login_attempts = 3
    
    def _setup_virtual_filesystem(self):
        """Set up virtual filesystem structure"""
        shares = {
            'C$': {
                'type': 'disk',
                'comment': 'Default share',
                'path': 'windows'
            },
            'ADMIN$': {
                'type': 'disk',
                'comment': 'Remote Admin',
                'path': 'admin'
            },
            'IPC$': {
                'type': 'ipc',
                'comment': 'Remote IPC',
                'path': 'ipc'
            },
            'SHARED': {
                'type': 'disk',
                'comment': 'Shared Files',
                'path': 'shared'
            }
        }
        
        # Create share directories
        for share, info in shares.items():
            if info['type'] == 'disk':
                share_path = os.path.join(self.root_dir, info['path'])
                os.makedirs(share_path, exist_ok=True)
                
                # Add sample files
                if share == 'SHARED':
                    with open(os.path.join(share_path, 'README.txt'), 'w') as f:
                        f.write('Shared network drive\n')
                elif share == 'C$':
                    windows_dirs = ['Windows', 'Program Files', 'Users']
                    for dir_name in windows_dirs:
                        os.makedirs(os.path.join(share_path, dir_name), exist_ok=True)
    
    def start_service(self):
        """Start SMB emulator service"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(5)
            
            self.log_event({
                "action": "service_started",
                "service": self.SERVICE_NAME,
                "port": self.port,
                "server_name": self.server_name
            })
            
            print(f"[{datetime.now()}] SMB Emulator started on {self.bind_ip}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    if self.is_ip_blocked(client_address[0]):
                        client_socket.close()
                        continue
                    
                    session_thread = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    session_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"[{datetime.now()}] Error accepting SMB connection: {e}")
                    
        except Exception as e:
            print(f"[{datetime.now()}] SMB service error: {e}")
        finally:
            self._cleanup()
    
    def _handle_client_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle new SMB client connection"""
        session = SMBSession(client_socket, client_address)
        session_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            self.active_sessions[session_id] = session
            self.connection_count += 1
            
            self.log_event({
                "action": "client_connected",
                "client_ip": client_address[0],
                "client_port": client_address[1],
                "protocol": "smb"
            })
            
            while self.running:
                try:
                    smb_packet = self._receive_smb_packet(session)
                    if not smb_packet:
                        break
                    
                    self._process_smb_packet(session, smb_packet)
                    session.last_activity = datetime.now()
                    
                except Exception as e:
                    print(f"[{datetime.now()}] Error processing SMB packet: {e}")
                    break
                    
        except Exception as e:
            print(f"[{datetime.now()}] SMB session error: {e}")
        finally:
            self._cleanup_session(session_id)
    
    def _receive_smb_packet(self, session: SMBSession) -> Optional[bytes]:
        """Receive SMB packet from client"""
        try:
            # Read NetBIOS header (4 bytes)
            nb_header = session.socket.recv(4)
            if not nb_header or len(nb_header) < 4:
                return None
            
            # Get packet length from NetBIOS header
            packet_length = struct.unpack('>L', nb_header)[0]
            
            # Read SMB packet
            packet = session.socket.recv(packet_length)
            if not packet:
                return None
            
            self.total_interactions += 1
            return packet
            
        except:
            return None
    
    def _process_smb_packet(self, session: SMBSession, packet: bytes):
        """Process SMB packet"""
        try:
            if not packet.startswith(b'\xff\x53\x4d\x42'):  # SMB magic number
                self.log_event({
                    "action": "invalid_packet",
                    "client_ip": session.address[0],
                    "reason": "invalid_magic_number"
                })
                return
            
            command = packet[4]  # SMB command code
            
            # Get AI-driven response if available
            if self.ai_coordinator and self.adaptive_responses:
                ai_context = {
                    "service": "smb",
                    "command": command,
                    "authenticated": session.authenticated,
                    "username": session.username,
                    "client_ip": session.address[0],
                    "session_data": {
                        "dialect": session.dialect,
                        "tree": session.current_tree
                    }
                }
                
                ai_response = self.ai_coordinator.process_interaction(
                    self.SERVICE_NAME,
                    session.address[0],
                    f"SMB_COM_0x{command:02X}",
                    ai_context
                )
                
                if ai_response.get("block_ip", False):
                    self.block_ip(session.address[0], "ai_policy_violation")
                    return
            
            # Process command
            if command == self.SMB_COM_NEGOTIATE:
                self._handle_negotiate(session, packet)
            elif command == self.SMB_COM_SESSION_SETUP_ANDX:
                self._handle_session_setup(session, packet)
            elif command == self.SMB_COM_TREE_CONNECT_ANDX:
                self._handle_tree_connect(session, packet)
            elif command == self.SMB_COM_NT_CREATE_ANDX:
                self._handle_create_file(session, packet)
            elif command == self.SMB_COM_READ_ANDX:
                self._handle_read(session, packet)
            elif command == self.SMB_COM_WRITE_ANDX:
                self._handle_write(session, packet)
            elif command == self.SMB_COM_CLOSE:
                self._handle_close(session, packet)
            elif command == self.SMB_COM_TREE_DISCONNECT:
                self._handle_tree_disconnect(session, packet)
            else:
                self._send_error_response(session, command, 'NOT_IMPLEMENTED')
        
        except Exception as e:
            print(f"[{datetime.now()}] Error processing SMB command: {e}")
            self._send_error_response(session, 0, 'INTERNAL_ERROR')
    
    def _handle_negotiate(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_NEGOTIATE"""
        # Extract dialects from packet
        offset = 36  # Skip header
        dialects = []
        while offset < len(packet):
            if packet[offset] == 0x02:
                length = 0
                while offset + length < len(packet) and packet[offset + length] != 0:
                    length += 1
                dialect = packet[offset+1:offset+length].decode('ascii')
                dialects.append(dialect)
                offset += length + 1
            offset += 1
        
        # Select dialect
        selected_dialect = "NT LM 0.12"
        dialect_index = dialects.index(selected_dialect) if selected_dialect in dialects else 0xFF
        
        # Build response
        current_time = int(time.time())
        response = struct.pack('<BBH', 0xff, 0x53, 0x4d)  # Start of SMB response
        response += struct.pack('>B', self.SMB_COM_NEGOTIATE)  # Command
        response += struct.pack('>L', 0)  # NT Status (SUCCESS)
        response += struct.pack('>B', 0)  # Flags
        response += struct.pack('>H', self.capabilities)  # Capabilities
        response += struct.pack('>H', dialect_index)  # Selected dialect
        response += struct.pack('>H', 1)  # Security mode (User level)
        response += struct.pack('>L', current_time)  # System time
        response += struct.pack('>H', self.max_buffer)  # Max buffer size
        
        self._send_response(session, response)
        
        self.log_event({
            "action": "smb_negotiate",
            "client_ip": session.address[0],
            "selected_dialect": selected_dialect
        })
    
    def _handle_session_setup(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_SESSION_SETUP_ANDX"""
        # Extract credentials (simplified)
        offset = 36
        username_len = struct.unpack('<H', packet[offset:offset+2])[0]
        username = packet[offset+2:offset+2+username_len].decode('utf-16-le')
        
        domain_len = struct.unpack('<H', packet[offset+2+username_len:offset+4+username_len])[0]
        domain = packet[offset+4+username_len:offset+4+username_len+domain_len].decode('utf-16-le')
        
        # Log authentication attempt
        self.log_event({
            "action": "login_attempt",
            "client_ip": session.address[0],
            "username": username,
            "domain": domain
        })
        
        # AI-driven authentication response
        if self.ai_coordinator:
            auth_context = {
                "service": "smb",
                "username": username,
                "domain": domain,
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
                session.username = username
                session.domain = domain
                
                response = self._build_session_setup_response(session, True)
                self._send_response(session, response)
                return
        
        # Default: authentication failure
        self.login_attempts[session.address[0]] = self.login_attempts.get(session.address[0], 0) + 1
        
        if self.login_attempts[session.address[0]] >= self.max_login_attempts:
            self.block_ip(session.address[0], "exceeded_login_attempts")
        
        response = self._build_session_setup_response(session, False)
        self._send_response(session, response)
    
    def _handle_tree_connect(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_TREE_CONNECT_ANDX"""
        if not session.authenticated:
            self._send_error_response(session, self.SMB_COM_TREE_CONNECT_ANDX, 'ACCESS_DENIED')
            return
        
        # Extract share name
        offset = 36
        path_len = struct.unpack('<H', packet[offset:offset+2])[0]
        path = packet[offset+2:offset+2+path_len].decode('utf-16-le')
        share_name = path.split('\\')[-1]
        
        self.log_event({
            "action": "tree_connect",
            "client_ip": session.address[0],
            "username": session.username,
            "share": share_name
        })
        
        # Check if share exists
        if share_name in ['C$', 'ADMIN$', 'IPC$', 'SHARED']:
            session.current_tree = share_name
            session.tree_id += 1
            
            response = self._build_tree_connect_response(session)
            self._send_response(session, response)
        else:
            self._send_error_response(session, self.SMB_COM_TREE_CONNECT_ANDX, 'BAD_NETWORK_NAME')
    
    def _handle_create_file(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_NT_CREATE_ANDX"""
        if not session.authenticated or not session.current_tree:
            self._send_error_response(session, self.SMB_COM_NT_CREATE_ANDX, 'ACCESS_DENIED')
            return
        
        # Extract filename
        offset = 36
        name_len = struct.unpack('<H', packet[offset:offset+2])[0]
        filename = packet[offset+2:offset+2+name_len].decode('utf-16-le')
        
        # Map to virtual filesystem
        virtual_path = os.path.join(self.root_dir, 
                                  session.current_tree.rstrip('$'),
                                  filename.lstrip('\\'))
        
        self.log_event({
            "action": "file_create",
            "client_ip": session.address[0],
            "username": session.username,
            "share": session.current_tree,
            "filename": filename
        })
        
        # Generate file handle
        fid = session.file_id_counter
        session.file_id_counter += 1
        session.open_files[fid] = virtual_path
        
        response = self._build_create_response(session, fid)
        self._send_response(session, response)
    
    def _handle_read(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_READ_ANDX"""
        if not session.authenticated:
            self._send_error_response(session, self.SMB_COM_READ_ANDX, 'ACCESS_DENIED')
            return
        
        # Extract FID and read parameters
        offset = 36
        fid = struct.unpack('<H', packet[offset:offset+2])[0]
        offset = struct.unpack('<L', packet[offset+2:offset+6])[0]
        length = struct.unpack('<H', packet[offset+6:offset+8])[0]
        
        if fid not in session.open_files:
            self._send_error_response(session, self.SMB_COM_READ_ANDX, 'INVALID_HANDLE')
            return
        
        virtual_path = session.open_files[fid]
        
        try:
            with open(virtual_path, 'rb') as f:
                f.seek(offset)
                data = f.read(min(length, self.max_buffer))
                
                response = self._build_read_response(session, data)
                self._send_response(session, response)
                
                self.log_event({
                    "action": "file_read",
                    "client_ip": session.address[0],
                    "username": session.username,
                    "path": virtual_path,
                    "bytes_read": len(data)
                })
                
        except FileNotFoundError:
            self._send_error_response(session, self.SMB_COM_READ_ANDX, 'NO_SUCH_FILE')
        except Exception as e:
            print(f"[{datetime.now()}] Error reading file: {e}")
            self._send_error_response(session, self.SMB_COM_READ_ANDX, 'ACCESS_DENIED')
    
    def _handle_write(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_WRITE_ANDX"""
        if not session.authenticated:
            self._send_error_response(session, self.SMB_COM_WRITE_ANDX, 'ACCESS_DENIED')
            return
        
        # Extract write parameters
        offset = 36
        fid = struct.unpack('<H', packet[offset:offset+2])[0]
        write_offset = struct.unpack('<L', packet[offset+2:offset+6])[0]
        data_length = struct.unpack('<H', packet[offset+6:offset+8])[0]
        data_offset = offset + 8
        data = packet[data_offset:data_offset+data_length]
        
        if fid not in session.open_files:
            self._send_error_response(session, self.SMB_COM_WRITE_ANDX, 'INVALID_HANDLE')
            return
        
        virtual_path = session.open_files[fid]
        
        # Create a temporary file for analysis
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(data)
        
        # Analyze file content if AI coordinator is available
        if self.ai_coordinator:
            analysis_context = {
                "service": "smb",
                "client_ip": session.address[0],
                "username": session.username,
                "path": virtual_path,
                "file_path": temp_file.name,
                "file_size": len(data)
            }
            
            ai_response = self.ai_coordinator.analyze_upload(
                self.SERVICE_NAME,
                session.address[0],
                analysis_context
            )
            
            if ai_response.get("block_upload", False):
                os.unlink(temp_file.name)
                self._send_error_response(session, self.SMB_COM_WRITE_ANDX, 'ACCESS_DENIED')
                
                if ai_response.get("block_ip", False):
                    self.block_ip(session.address[0], "malicious_upload")
                return
        
        try:
            with open(virtual_path, 'wb') as f:
                f.seek(write_offset)
                f.write(data)
            
            response = self._build_write_response(session, len(data))
            self._send_response(session, response)
            
            self.log_event({
                "action": "file_write",
                "client_ip": session.address[0],
                "username": session.username,
                "path": virtual_path,
                "bytes_written": len(data)
            })
            
        except Exception as e:
            print(f"[{datetime.now()}] Error writing file: {e}")
            self._send_error_response(session, self.SMB_COM_WRITE_ANDX, 'ACCESS_DENIED')
        finally:
            os.unlink(temp_file.name)
    
    def _handle_close(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_CLOSE"""
        offset = 36
        fid = struct.unpack('<H', packet[offset:offset+2])[0]
        
        if fid in session.open_files:
            path = session.open_files[fid]
            del session.open_files[fid]
            
            self.log_event({
                "action": "file_close",
                "client_ip": session.address[0],
                "username": session.username,
                "path": path
            })
        
        response = self._build_simple_response(session, self.SMB_COM_CLOSE)
        self._send_response(session, response)
    
    def _handle_tree_disconnect(self, session: SMBSession, packet: bytes):
        """Handle SMB_COM_TREE_DISCONNECT"""
        if session.current_tree:
            self.log_event({
                "action": "tree_disconnect",
                "client_ip": session.address[0],
                "username": session.username,
                "share": session.current_tree
            })
            
            session.current_tree = None
        
        response = self._build_simple_response(session, self.SMB_COM_TREE_DISCONNECT)
        self._send_response(session, response)
    
    def _build_session_setup_response(self, session: SMBSession, success: bool) -> bytes:
        """Build SMB_COM_SESSION_SETUP_ANDX response"""
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(self.SMB_COM_SESSION_SETUP_ANDX)
        response.extend(struct.pack('>L', 0 if success else 0xC000006D))  # NT Status
        response.extend(b'\x00' * 23)  # Padding and flags
        response.extend(struct.pack('<H', session.session_id))  # Session ID
        return bytes(response)
    
    def _build_tree_connect_response(self, session: SMBSession) -> bytes:
        """Build SMB_COM_TREE_CONNECT_ANDX response"""
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(self.SMB_COM_TREE_CONNECT_ANDX)
        response.extend(struct.pack('>L', 0))  # NT Status SUCCESS
        response.extend(b'\x00' * 23)  # Padding and flags
        response.extend(struct.pack('<H', session.tree_id))  # Tree ID
        return bytes(response)
    
    def _build_create_response(self, session: SMBSession, fid: int) -> bytes:
        """Build SMB_COM_NT_CREATE_ANDX response"""
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(self.SMB_COM_NT_CREATE_ANDX)
        response.extend(struct.pack('>L', 0))  # NT Status SUCCESS
        response.extend(b'\x00' * 23)  # Padding and flags
        response.extend(struct.pack('<H', fid))  # File ID
        return bytes(response)
    
    def _build_read_response(self, session: SMBSession, data: bytes) -> bytes:
        """Build SMB_COM_READ_ANDX response"""
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(self.SMB_COM_READ_ANDX)
        response.extend(struct.pack('>L', 0))  # NT Status SUCCESS
        response.extend(b'\x00' * 23)  # Padding and flags
        response.extend(struct.pack('<H', len(data)))  # Data length
        response.extend(data)  # File data
        return bytes(response)
    
    def _build_write_response(self, session: SMBSession, count: int) -> bytes:
        """Build SMB_COM_WRITE_ANDX response"""
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(self.SMB_COM_WRITE_ANDX)
        response.extend(struct.pack('>L', 0))  # NT Status SUCCESS
        response.extend(b'\x00' * 23)  # Padding and flags
        response.extend(struct.pack('<H', count))  # Count of bytes written
        return bytes(response)
    
    def _build_simple_response(self, session: SMBSession, command: int) -> bytes:
        """Build simple SMB response"""
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(command)
        response.extend(struct.pack('>L', 0))  # NT Status SUCCESS
        response.extend(b'\x00' * 23)  # Padding and flags
        return bytes(response)
    
    def _send_response(self, session: SMBSession, response: bytes):
        """Send SMB response to client"""
        try:
            # Add NetBIOS header (packet length)
            nb_header = struct.pack('>L', len(response))
            session.socket.send(nb_header + response)
        except:
            pass
    
    def _send_error_response(self, session: SMBSession, command: int, error: str):
        """Send error response"""
        error_codes = {
            'SUCCESS': 0x00000000,
            'ACCESS_DENIED': 0xC0000022,
            'INVALID_HANDLE': 0xC0000008,
            'NO_SUCH_FILE': 0xC000000F,
            'NOT_IMPLEMENTED': 0xC0000002,
            'BAD_NETWORK_NAME': 0xC00000CC,
            'INTERNAL_ERROR': 0xC0000001
        }
        
        response = bytearray()
        response.extend(b'\xff\x53\x4d\x42')  # SMB magic number
        response.append(command)
        response.extend(struct.pack('>L', error_codes.get(error, 0xC0000001)))  # NT Status
        response.extend(b'\x00' * 23)  # Padding and flags
        
        self._send_response(session, bytes(response))
    
    def _cleanup_session(self, session_id: str):
        """Clean up client session"""
        try:
            session = self.active_sessions.get(session_id)
            if session:
                if session.socket:
                    session.socket.close()
                
                # Close any open files
                for fid in list(session.open_files.keys()):
                    del session.open_files[fid]
                
                del self.active_sessions[session_id]
                
                self.log_event({
                    "action": "client_disconnected",
                    "client_ip": session.address[0],
                    "client_port": session.address[1],
                    "username": session.username
                })
        except Exception as e:
            print(f"[{datetime.now()}] Error cleaning up session: {e}")
    
    def _cleanup(self):
        """Clean up resources"""
        try:
            # Close all active sessions
            for session_id in list(self.active_sessions.keys()):
                self._cleanup_session(session_id)
            
            # Clean up virtual filesystem
            if os.path.exists(self.root_dir):
                for root, dirs, files in os.walk(self.root_dir, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(self.root_dir)
                
        except Exception as e:
            print(f"[{datetime.now()}] Error during cleanup: {e}")