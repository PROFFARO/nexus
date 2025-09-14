"""
RDP Emulator - AI-enhanced RDP honeypot service
"""

import socket
import struct
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import tempfile
from dataclasses import dataclass

from .base_emulator import BaseServiceEmulator


@dataclass
class RDPScreen:
    """RDP screen state"""
    width: int = 1024
    height: int = 768
    bpp: int = 32
    bitmap_cache: Dict[int, bytes] = {}
    
    def __post_init__(self):
        self.bitmap_cache = {}


class RDPSession:
    """RDP session state management"""
    
    def __init__(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        self.socket: socket.socket = client_socket
        self.address: Tuple[str, int] = client_address
        self.authenticated: bool = False
        self.username: Optional[str] = None
        self.domain: Optional[str] = None
        self.screen: RDPScreen = RDPScreen()
        self.last_activity: datetime = datetime.now()
        self.encryption_level: int = 0
        self.protocol_version: int = 0
        self.session_id: int = 0
        self.channel_ids: Dict[str, int] = {}


class RDPEmulator(BaseServiceEmulator):
    """
    RDP service emulator with AI-driven dynamic responses
    Emulates RDP protocol interactions for honeypot purposes
    """
    
    SERVICE_NAME = "rdp"
    DEFAULT_PORT = 3389
    
    # RDP Protocol Constants
    PROTOCOL_VERSION = 0x00080004  # RDP 5.2
    NEG_FAILURE = 0x00000001
    NEG_RSP = 0x00000002
    NEG_REQ = 0x00000003
    
    def __init__(self, port: int = DEFAULT_PORT, **kwargs):
        super().__init__(self.SERVICE_NAME, port, **kwargs)
        
        # RDP server settings
        self.server_name = "HONEYPOT-RDP"
        self.domain_name = "WORKGROUP"
        self.max_channels = 31
        self.encryption_level = 1  # LOW
        self.cert_file = None  # Would contain server certificate in real implementation
        
        # Session management
        self.active_sessions: Dict[str, RDPSession] = {}
        self.login_attempts: Dict[str, int] = {}
        self.max_login_attempts = 3
        
        # Screen content simulation
        self._setup_virtual_screen()
    
    def _setup_virtual_screen(self):
        """Set up virtual screen content"""
        self.login_screen = {
            "background": (0, 120, 215),  # Windows 10 blue
            "elements": [
                {
                    "type": "text",
                    "text": "Press Ctrl+Alt+Del to unlock",
                    "position": (512, 384),
                    "color": (255, 255, 255)
                },
                {
                    "type": "image",
                    "path": "user_avatar.png",
                    "position": (512, 256)
                }
            ]
        }
        
        self.desktop_screen = {
            "background": (0, 120, 215),
            "elements": [
                {
                    "type": "taskbar",
                    "position": (0, 736),
                    "size": (1024, 32),
                    "color": (25, 25, 25)
                },
                {
                    "type": "start_button",
                    "position": (0, 736),
                    "size": (48, 32)
                }
            ]
        }
    
    def start_service(self):
        """Start RDP emulator service"""
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
            
            print(f"[{datetime.now()}] RDP Emulator started on {self.bind_ip}:{self.port}")
            
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
                        print(f"[{datetime.now()}] Error accepting RDP connection: {e}")
                    
        except Exception as e:
            print(f"[{datetime.now()}] RDP service error: {e}")
        finally:
            self._cleanup()
    
    def _handle_client_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle new RDP client connection"""
        session = RDPSession(client_socket, client_address)
        session_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            self.active_sessions[session_id] = session
            self.connection_count += 1
            
            self.log_event({
                "action": "client_connected",
                "client_ip": client_address[0],
                "client_port": client_address[1],
                "protocol": "rdp"
            })
            
            # Initial RDP protocol negotiation
            if not self._handle_initial_negotiation(session):
                return
            
            # Main RDP protocol loop
            while self.running:
                try:
                    packet = self._receive_rdp_packet(session)
                    if not packet:
                        break
                    
                    self._process_rdp_packet(session, packet)
                    session.last_activity = datetime.now()
                    
                except Exception as e:
                    print(f"[{datetime.now()}] Error processing RDP packet: {e}")
                    break
                    
        except Exception as e:
            print(f"[{datetime.now()}] RDP session error: {e}")
        finally:
            self._cleanup_session(session_id)
    
    def _handle_initial_negotiation(self, session: RDPSession) -> bool:
        """Handle initial RDP protocol negotiation"""
        try:
            # Receive client connection request
            packet = self._receive_rdp_packet(session)
            if not packet:
                return False
            
            # Parse connection request
            req_type = struct.unpack('>L', packet[:4])[0]
            if req_type != self.NEG_REQ:
                return False
            
            # Extract requested protocol version
            session.protocol_version = struct.unpack('>L', packet[4:8])[0]
            
            # Build server response
            response = bytearray()
            response.extend(struct.pack('>L', self.NEG_RSP))
            response.extend(struct.pack('>L', self.PROTOCOL_VERSION))
            response.extend(struct.pack('>L', self.encryption_level))
            
            self._send_packet(session, bytes(response))
            
            self.log_event({
                "action": "rdp_negotiation",
                "client_ip": session.address[0],
                "protocol_version": hex(session.protocol_version),
                "encryption_level": self.encryption_level
            })
            
            return True
            
        except Exception as e:
            print(f"[{datetime.now()}] RDP negotiation error: {e}")
            return False
    
    def _receive_rdp_packet(self, session: RDPSession) -> Optional[bytes]:
        """Receive RDP packet from client"""
        try:
            # Read packet header (4 bytes)
            header = session.socket.recv(4)
            if not header or len(header) < 4:
                return None
            
            # Get packet length from header
            packet_length = struct.unpack('>L', header)[0]
            
            # Read packet data
            packet = session.socket.recv(packet_length - 4)
            if not packet:
                return None
            
            self.total_interactions += 1
            return packet
            
        except:
            return None
    
    def _process_rdp_packet(self, session: RDPSession, packet: bytes):
        """Process RDP packet"""
        try:
            if len(packet) < 4:
                return
            
            packet_type = packet[0]
            
            # Get AI-driven response if available
            if self.ai_coordinator and self.adaptive_responses:
                ai_context = {
                    "service": "rdp",
                    "packet_type": packet_type,
                    "authenticated": session.authenticated,
                    "username": session.username,
                    "client_ip": session.address[0],
                    "session_data": {
                        "protocol_version": session.protocol_version,
                        "encryption_level": session.encryption_level
                    }
                }
                
                ai_response = self.ai_coordinator.process_interaction(
                    self.SERVICE_NAME,
                    session.address[0],
                    f"RDP_PKT_0x{packet_type:02X}",
                    ai_context
                )
                
                if ai_response.get("block_ip", False):
                    self.block_ip(session.address[0], "ai_policy_violation")
                    return
            
            # Process different packet types
            if packet_type == 0x01:  # Connection Request
                self._handle_connection_request(session, packet)
            elif packet_type == 0x02:  # License Exchange
                self._handle_license_exchange(session, packet)
            elif packet_type == 0x03:  # Client Info
                self._handle_client_info(session, packet)
            elif packet_type == 0x04:  # Confirm Active
                self._handle_confirm_active(session, packet)
            elif packet_type == 0x05:  # Input
                self._handle_input(session, packet)
            else:
                self._send_error_packet(session, "NOT_IMPLEMENTED")
            
        except Exception as e:
            print(f"[{datetime.now()}] Error processing RDP packet: {e}")
            self._send_error_packet(session, "INTERNAL_ERROR")
    
    def _handle_connection_request(self, session: RDPSession, packet: bytes):
        """Handle RDP connection request"""
        # Extract requested screen dimensions
        width = struct.unpack('>H', packet[4:6])[0]
        height = struct.unpack('>H', packet[6:8])[0]
        bpp = packet[8]
        
        # Update session screen state
        session.screen.width = width
        session.screen.height = height
        session.screen.bpp = bpp
        
        # Send connection confirm
        response = self._build_connection_confirm(session)
        self._send_packet(session, response)
        
        self.log_event({
            "action": "rdp_connection_request",
            "client_ip": session.address[0],
            "screen_width": width,
            "screen_height": height,
            "bpp": bpp
        })
    
    def _handle_license_exchange(self, session: RDPSession, packet: bytes):
        """Handle RDP license exchange"""
        # In a honeypot, we'll just send a license OK response
        response = self._build_license_response(session)
        self._send_packet(session, response)
    
    def _handle_client_info(self, session: RDPSession, packet: bytes):
        """Handle client information and authentication"""
        try:
            # Extract credentials (simplified)
            offset = 4
            username_len = struct.unpack('>H', packet[offset:offset+2])[0]
            username = packet[offset+2:offset+2+username_len].decode('utf-16-le')
            
            domain_len = struct.unpack('>H', packet[offset+2+username_len:offset+4+username_len])[0]
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
                    "service": "rdp",
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
                    
                    # Send success response and initial screen
                    response = self._build_auth_success_response(session)
                    self._send_packet(session, response)
                    self._send_initial_screen(session)
                    return
            
            # Default: authentication failure
            self.login_attempts[session.address[0]] = self.login_attempts.get(session.address[0], 0) + 1
            
            if self.login_attempts[session.address[0]] >= self.max_login_attempts:
                self.block_ip(session.address[0], "exceeded_login_attempts")
            
            response = self._build_auth_failure_response(session)
            self._send_packet(session, response)
            
        except Exception as e:
            print(f"[{datetime.now()}] Error handling client info: {e}")
            self._send_error_packet(session, "INTERNAL_ERROR")
    
    def _handle_confirm_active(self, session: RDPSession, packet: bytes):
        """Handle confirm active PDU"""
        if not session.authenticated:
            self._send_error_packet(session, "ACCESS_DENIED")
            return
        
        # Send capability set
        response = self._build_capability_response(session)
        self._send_packet(session, response)
    
    def _handle_input(self, session: RDPSession, packet: bytes):
        """Handle client input"""
        if not session.authenticated:
            self._send_error_packet(session, "ACCESS_DENIED")
            return
        
        # Extract input type and data
        input_type = packet[4]
        
        self.log_event({
            "action": "rdp_input",
            "client_ip": session.address[0],
            "username": session.username,
            "input_type": input_type
        })
        
        # Process different input types
        if input_type == 0x01:  # Mouse
            self._handle_mouse_input(session, packet[5:])
        elif input_type == 0x02:  # Keyboard
            self._handle_keyboard_input(session, packet[5:])
        elif input_type == 0x03:  # Unicode
            self._handle_unicode_input(session, packet[5:])
    
    def _handle_mouse_input(self, session: RDPSession, data: bytes):
        """Handle mouse input"""
        x, y = struct.unpack('>HH', data[:4])
        flags = data[4]
        
        # Log mouse movement/clicks
        self.log_event({
            "action": "rdp_mouse_input",
            "client_ip": session.address[0],
            "username": session.username,
            "x": x,
            "y": y,
            "flags": flags
        })
    
    def _handle_keyboard_input(self, session: RDPSession, data: bytes):
        """Handle keyboard input"""
        keycode = data[0]
        flags = data[1]
        
        # Log keystrokes
        self.log_event({
            "action": "rdp_keyboard_input",
            "client_ip": session.address[0],
            "username": session.username,
            "keycode": keycode,
            "flags": flags
        })
    
    def _handle_unicode_input(self, session: RDPSession, data: bytes):
        """Handle Unicode input"""
        char = data[:2].decode('utf-16-le')
        
        # Log Unicode input
        self.log_event({
            "action": "rdp_unicode_input",
            "client_ip": session.address[0],
            "username": session.username,
            "char": char
        })
    
    def _build_connection_confirm(self, session: RDPSession) -> bytes:
        """Build connection confirm packet"""
        response = bytearray()
        response.extend(struct.pack('>L', 0x02))  # Confirm type
        response.extend(struct.pack('>L', self.PROTOCOL_VERSION))
        response.extend(struct.pack('>H', session.screen.width))
        response.extend(struct.pack('>H', session.screen.height))
        response.extend(struct.pack('>B', session.screen.bpp))
        return bytes(response)
    
    def _build_license_response(self, session: RDPSession) -> bytes:
        """Build license response packet"""
        response = bytearray()
        response.extend(struct.pack('>L', 0x03))  # License type
        response.extend(struct.pack('>L', 0x00))  # Status: OK
        return bytes(response)
    
    def _build_auth_success_response(self, session: RDPSession) -> bytes:
        """Build authentication success response"""
        response = bytearray()
        response.extend(struct.pack('>L', 0x04))  # Auth response type
        response.extend(struct.pack('>L', 0x00))  # Status: OK
        session.session_id = int(time.time())
        response.extend(struct.pack('>L', session.session_id))
        return bytes(response)
    
    def _build_auth_failure_response(self, session: RDPSession) -> bytes:
        """Build authentication failure response"""
        response = bytearray()
        response.extend(struct.pack('>L', 0x04))  # Auth response type
        response.extend(struct.pack('>L', 0x01))  # Status: Failed
        return bytes(response)
    
    def _build_capability_response(self, session: RDPSession) -> bytes:
        """Build capability response packet"""
        response = bytearray()
        response.extend(struct.pack('>L', 0x05))  # Capability type
        response.extend(struct.pack('>H', 0x0001))  # Version
        response.extend(struct.pack('>H', 0x0001))  # Compression support
        return bytes(response)
    
    def _send_initial_screen(self, session: RDPSession):
        """Send initial screen content to client"""
        try:
            # Send login screen bitmap
            screen_data = self._generate_screen_bitmap(session, self.login_screen)
            
            response = bytearray()
            response.extend(struct.pack('>L', 0x06))  # Bitmap update type
            response.extend(struct.pack('>L', len(screen_data)))
            response.extend(screen_data)
            
            self._send_packet(session, bytes(response))
            
        except Exception as e:
            print(f"[{datetime.now()}] Error sending initial screen: {e}")
    
    def _generate_screen_bitmap(self, session: RDPSession, screen_content: Dict) -> bytes:
        """Generate screen bitmap data"""
        # In a real implementation, this would generate actual bitmap data
        # For honeypot purposes, we return dummy bitmap data
        width = session.screen.width
        height = session.screen.height
        bpp = session.screen.bpp
        
        # Generate simple gradient pattern
        bitmap = bytearray()
        for y in range(height):
            for x in range(width):
                color = screen_content["background"]
                bitmap.extend(bytes(color))
        
        return bytes(bitmap)
    
    def _send_packet(self, session: RDPSession, packet: bytes):
        """Send RDP packet to client"""
        try:
            # Add length header
            header = struct.pack('>L', len(packet) + 4)
            session.socket.send(header + packet)
        except:
            pass
    
    def _send_error_packet(self, session: RDPSession, error: str):
        """Send error packet"""
        error_codes = {
            'SUCCESS': 0x00000000,
            'ACCESS_DENIED': 0x00000005,
            'NOT_IMPLEMENTED': 0x00000001,
            'INTERNAL_ERROR': 0x0000000A
        }
        
        response = bytearray()
        response.extend(struct.pack('>L', 0xFF))  # Error packet type
        response.extend(struct.pack('>L', error_codes.get(error, 0x0000000A)))
        
        self._send_packet(session, bytes(response))
    
    def _cleanup_session(self, session_id: str):
        """Clean up client session"""
        try:
            session = self.active_sessions.get(session_id)
            if session:
                if session.socket:
                    session.socket.close()
                
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
                
        except Exception as e:
            print(f"[{datetime.now()}] Error during cleanup: {e}")