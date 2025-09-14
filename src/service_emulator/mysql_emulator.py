"""
MySQL Emulator - AI-enhanced MySQL honeypot service
"""

import socket
import struct
import threading
import hashlib
import random
from datetime import datetime
from typing import Dict, List, Optional, Any

from .base_emulator import BaseServiceEmulator


class MySQLEmulator(BaseServiceEmulator):
    """
    MySQL service emulator with AI-driven dynamic responses
    Emulates MySQL protocol interactions for honeypot purposes
    """
    
    SERVICE_NAME = "mysql"
    DEFAULT_PORT = 3306
    
    def __init__(self, port: int = DEFAULT_PORT, **kwargs):
        super().__init__(self.SERVICE_NAME, port, **kwargs)
        
        # MySQL protocol constants
        self.PROTOCOL_VERSION = 10
        self.SERVER_VERSION = "8.0.32-0ubuntu0.20.04.2"
        self.CONNECTION_ID = 1
        
        # Capability flags
        self.CLIENT_LONG_PASSWORD = 0x00000001
        self.CLIENT_FOUND_ROWS = 0x00000002
        self.CLIENT_LONG_FLAG = 0x00000004
        self.CLIENT_CONNECT_WITH_DB = 0x00000008
        self.CLIENT_PROTOCOL_41 = 0x00000200
        self.CLIENT_SECURE_CONNECTION = 0x00008000
        
        self.server_capabilities = (
            self.CLIENT_LONG_PASSWORD |
            self.CLIENT_FOUND_ROWS |
            self.CLIENT_LONG_FLAG |
            self.CLIENT_CONNECT_WITH_DB |
            self.CLIENT_PROTOCOL_41 |
            self.CLIENT_SECURE_CONNECTION
        )
        
        # Fake database structure
        self.fake_databases = {
            "information_schema": {
                "tables": ["SCHEMATA", "TABLES", "COLUMNS", "USER_PRIVILEGES"],
                "description": "System information schema"
            },
            "mysql": {
                "tables": ["user", "db", "tables_priv", "columns_priv"],
                "description": "MySQL system database"
            },
            "performance_schema": {
                "tables": ["events_waits_current", "setup_instruments"],
                "description": "Performance monitoring"
            },
            "test": {
                "tables": ["users", "products", "orders"],
                "description": "Test database"
            }
        }
        
        # Session management
        self.active_sessions = {}
        self.session_counter = 0
    
    def start_service(self):
        """Start MySQL emulator service"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(10)
            
            self.log_event({
                "action": "service_started",
                "service": self.SERVICE_NAME,
                "port": self.port,
                "version": self.SERVER_VERSION
            })
            
            print(f"[{datetime.now()}] MySQL Emulator started on {self.bind_ip}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Create new session thread
                    session_thread = threading.Thread(
                        target=self._handle_mysql_session,
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
    
    def _handle_mysql_session(self, client_socket: socket.socket, client_address: tuple):
        """Handle individual MySQL session"""
        session_id = self._create_session_id()
        client_ip, client_port = client_address
        
        session_info = {
            "session_id": session_id,
            "client_ip": client_ip,
            "client_port": client_port,
            "start_time": datetime.now(),
            "authenticated": False,
            "username": None,
            "database": None,
            "queries": [],
            "connection_id": self.CONNECTION_ID
        }
        
        self.CONNECTION_ID += 1
        self.active_sessions[session_id] = session_info
        
        try:
            self.log_event({
                "action": "connection_established",
                "session_id": session_id,
                "client_ip": client_ip,
                "client_port": client_port
            })
            
            # Send initial handshake
            self._send_handshake(client_socket, session_info)
            
            # Handle authentication and queries
            self._handle_mysql_protocol(client_socket, session_info)
            
        except Exception as e:
            self.log_event({
                "action": "session_error",
                "session_id": session_id,
                "error": str(e)
            })
        finally:
            self._cleanup_session(client_socket, session_id)
    
    def _send_handshake(self, client_socket: socket.socket, session_info: Dict[str, Any]):
        """Send MySQL handshake packet"""
        # Generate random salt for authentication
        salt = bytes([random.randint(0, 255) for _ in range(20)])
        
        # Build handshake packet
        packet_data = bytearray()
        packet_data.append(self.PROTOCOL_VERSION)
        packet_data.extend(self.SERVER_VERSION.encode() + b'\x00')
        packet_data.extend(struct.pack('<I', session_info["connection_id"]))
        packet_data.extend(salt[:8])  # First part of salt
        packet_data.append(0)  # Filler
        packet_data.extend(struct.pack('<H', self.server_capabilities & 0xFFFF))
        packet_data.append(0x21)  # Character set (utf8_general_ci)
        packet_data.extend(struct.pack('<H', 0x0002))  # Status flags
        packet_data.extend(struct.pack('<H', (self.server_capabilities >> 16) & 0xFFFF))
        packet_data.append(21)  # Auth plugin data length
        packet_data.extend(b'\x00' * 10)  # Reserved
        packet_data.extend(salt[8:])  # Second part of salt
        packet_data.append(0)  # Null terminator
        packet_data.extend(b'mysql_native_password\x00')
        
        # Send packet with header
        self._send_mysql_packet(client_socket, packet_data, 0)
        
        # Store salt for authentication
        session_info["auth_salt"] = salt
    
    def _handle_mysql_protocol(self, client_socket: socket.socket, session_info: Dict[str, Any]):
        """Handle MySQL protocol messages"""
        while self.running:
            try:
                # Receive packet
                packet_data, sequence_id = self._receive_mysql_packet(client_socket)
                if not packet_data:
                    break
                
                # Handle different packet types
                if not session_info["authenticated"]:
                    # Handle authentication
                    auth_result = self._handle_authentication_packet(
                        packet_data, session_info
                    )
                    
                    if auth_result["success"]:
                        session_info["authenticated"] = True
                        session_info["username"] = auth_result["username"]
                        session_info["database"] = auth_result.get("database")
                        
                        # Send OK packet
                        self._send_ok_packet(client_socket, sequence_id + 1)
                    else:
                        # Send error packet
                        self._send_error_packet(
                            client_socket, sequence_id + 1,
                            1045, "28000", "Access denied for user"
                        )
                        break
                else:
                    # Handle SQL queries
                    self._handle_query_packet(packet_data, client_socket, session_info, sequence_id)
                
            except Exception as e:
                self.log_event({
                    "action": "protocol_error",
                    "session_id": session_info["session_id"],
                    "error": str(e)
                })
                break
    
    def _handle_authentication_packet(self, packet_data: bytes, 
                                    session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MySQL authentication packet"""
        try:
            # Parse authentication packet
            offset = 0
            
            # Client capabilities (4 bytes)
            client_capabilities = struct.unpack('<I', packet_data[offset:offset+4])[0]
            offset += 4
            
            # Max packet size (4 bytes)
            offset += 4
            
            # Character set (1 byte)
            offset += 1
            
            # Reserved (23 bytes)
            offset += 23
            
            # Username (null-terminated)
            username_end = packet_data.find(b'\x00', offset)
            username = packet_data[offset:username_end].decode()
            offset = username_end + 1
            
            # Password length and data
            password_length = packet_data[offset]
            offset += 1
            
            if password_length > 0:
                password_hash = packet_data[offset:offset+password_length]
                offset += password_length
            else:
                password_hash = b''
            
            # Database name (if present)
            database = None
            if offset < len(packet_data):
                db_end = packet_data.find(b'\x00', offset)
                if db_end != -1:
                    database = packet_data[offset:db_end].decode()
            
            # Log authentication attempt
            self.log_event({
                "action": "authentication_attempt",
                "session_id": session_info["session_id"],
                "username": username,
                "database": database,
                "has_password": len(password_hash) > 0
            })
            
            # Process authentication with AI
            auth_result = self._process_mysql_authentication(
                username, password_hash, database or "", session_info
            )
            
            return auth_result
            
        except Exception as e:
            self.log_event({
                "action": "authentication_parse_error",
                "session_id": session_info["session_id"],
                "error": str(e)
            })
            return {"success": False, "error": "Authentication parsing failed"}
    
    def _process_mysql_authentication(self, username: str, password_hash: bytes,
                                    database: str, session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process MySQL authentication using AI coordinator"""
        if self.ai_coordinator:
            # Use AI to determine authentication response
            ai_response = self.ai_coordinator.process_interaction(
                service=self.SERVICE_NAME,
                attacker_ip=session_info["client_ip"],
                command=f"auth:{username}:{database}",
                context={
                    "session_info": session_info,
                    "auth_type": "mysql_native_password",
                    "has_password": len(password_hash) > 0
                }
            )
            
            # AI-driven authentication decision
            behavior_analysis = ai_response.get("behavior_analysis", {})
            attack_type = behavior_analysis.get("attack_type", "unknown")
            
            # Allow authentication for certain scenarios
            if attack_type in ["reconnaissance", "exploitation"]:
                success_probability = 0.8
            elif attack_type == "brute_force":
                success_probability = 0.2
            else:
                success_probability = 0.4
            
            success = random.random() < success_probability
            
            return {
                "success": success,
                "username": username,
                "database": database,
                "ai_decision": True,
                "attack_type": attack_type
            }
        else:
            # Fallback authentication
            common_users = ["root", "admin", "mysql", "user", "test"]
            success = username in common_users
            
            return {
                "success": success,
                "username": username,
                "database": database,
                "ai_decision": False
            }
    
    def _handle_query_packet(self, packet_data: bytes, client_socket: socket.socket,
                           session_info: Dict[str, Any], sequence_id: int):
        """Handle MySQL query packet"""
        try:
            # First byte is command type
            command_type = packet_data[0]
            
            if command_type == 0x03:  # COM_QUERY
                query = packet_data[1:].decode().strip()
                
                session_info["queries"].append({
                    "query": query,
                    "timestamp": datetime.now().isoformat()
                })
                
                self.log_event({
                    "action": "sql_query",
                    "session_id": session_info["session_id"],
                    "query": query,
                    "database": session_info.get("database")
                })
                
                # Process query with AI
                response = self._process_sql_query(query, session_info)
                
                # Send response
                self._send_query_response(client_socket, response, sequence_id + 1)
                
            elif command_type == 0x01:  # COM_QUIT
                self.log_event({
                    "action": "client_quit",
                    "session_id": session_info["session_id"]
                })
                return
            
        except Exception as e:
            self.log_event({
                "action": "query_processing_error",
                "session_id": session_info["session_id"],
                "error": str(e)
            })
            
            # Send error response
            self._send_error_packet(
                client_socket, sequence_id + 1,
                1064, "42000", "You have an error in your SQL syntax"
            )
    
    def _process_sql_query(self, query: str, session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process SQL query using AI coordinator"""
        if self.ai_coordinator:
            ai_response = self.ai_coordinator.process_interaction(
                service=self.SERVICE_NAME,
                attacker_ip=session_info["client_ip"],
                command=query,
                context={
                    "session_info": session_info,
                    "query_type": self._classify_query_type(query),
                    "database": session_info.get("database")
                }
            )
            
            return ai_response.get("response", {})
        else:
            return self._fallback_query_processing(query, session_info)
    
    def _classify_query_type(self, query: str) -> str:
        """Classify SQL query type"""
        query_lower = query.lower().strip()
        
        if query_lower.startswith("select"):
            return "select"
        elif query_lower.startswith("show"):
            return "show"
        elif query_lower.startswith("describe") or query_lower.startswith("desc"):
            return "describe"
        elif query_lower.startswith(("insert", "update", "delete")):
            return "modification"
        elif query_lower.startswith(("create", "drop", "alter")):
            return "ddl"
        else:
            return "unknown"
    
    def _fallback_query_processing(self, query: str, session_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback query processing when AI is not available"""
        query_lower = query.lower().strip()
        
        if "show databases" in query_lower:
            return {
                "type": "resultset",
                "columns": ["Database"],
                "rows": [[db] for db in self.fake_databases.keys()]
            }
        elif "show tables" in query_lower:
            database = session_info.get("database", "test")
            if database in self.fake_databases:
                tables = self.fake_databases[database]["tables"]
                return {
                    "type": "resultset",
                    "columns": [f"Tables_in_{database}"],
                    "rows": [[table] for table in tables]
                }
            else:
                return {"type": "empty"}
        elif query_lower.startswith("select"):
            # Return empty result for SELECT queries
            return {"type": "empty"}
        else:
            return {
                "type": "error",
                "code": 1064,
                "state": "42000",
                "message": "You have an error in your SQL syntax"
            }
    
    def _send_query_response(self, client_socket: socket.socket, 
                           response: Dict[str, Any], sequence_id: int):
        """Send query response to client"""
        response_type = response.get("type", "error")
        
        if response_type == "resultset":
            self._send_resultset(client_socket, response, sequence_id)
        elif response_type == "empty":
            self._send_ok_packet(client_socket, sequence_id, affected_rows=0)
        elif response_type == "error":
            self._send_error_packet(
                client_socket, sequence_id,
                response.get("code", 1064),
                response.get("state", "42000"),
                response.get("message", "Query error")
            )
        else:
            self._send_ok_packet(client_socket, sequence_id)
    
    def _send_resultset(self, client_socket: socket.socket, 
                       response: Dict[str, Any], sequence_id: int):
        """Send MySQL resultset"""
        columns = response.get("columns", [])
        rows = response.get("rows", [])
        
        # Send column count
        self._send_mysql_packet(client_socket, bytes([len(columns)]), sequence_id)
        sequence_id += 1
        
        # Send column definitions
        for column in columns:
            column_packet = self._build_column_packet(column)
            self._send_mysql_packet(client_socket, column_packet, sequence_id)
            sequence_id += 1
        
        # Send EOF packet
        eof_packet = bytes([0xFE, 0x00, 0x00, 0x02, 0x00])
        self._send_mysql_packet(client_socket, eof_packet, sequence_id)
        sequence_id += 1
        
        # Send rows
        for row in rows:
            row_packet = self._build_row_packet(row)
            self._send_mysql_packet(client_socket, row_packet, sequence_id)
            sequence_id += 1
        
        # Send final EOF packet
        self._send_mysql_packet(client_socket, eof_packet, sequence_id)
    
    def _build_column_packet(self, column_name: str) -> bytes:
        """Build MySQL column definition packet"""
        packet = bytearray()
        
        # Catalog, schema, table, org_table (all empty)
        for _ in range(4):
            packet.append(0)
        
        # Column name
        packet.extend(self._encode_length_string(column_name))
        
        # Original column name
        packet.extend(self._encode_length_string(column_name))
        
        # Fixed length fields
        packet.append(0x0C)  # Length of fixed fields
        packet.extend(b'\x21\x00')  # Character set
        packet.extend(b'\xFF\xFF\xFF\xFF')  # Column length
        packet.append(0xFD)  # Column type (VAR_STRING)
        packet.extend(b'\x00\x00')  # Flags
        packet.append(0x00)  # Decimals
        packet.extend(b'\x00\x00')  # Filler
        
        return bytes(packet)
    
    def _build_row_packet(self, row: List[str]) -> bytes:
        """Build MySQL row packet"""
        packet = bytearray()
        
        for value in row:
            if value is None:
                packet.append(0xFB)  # NULL
            else:
                packet.extend(self._encode_length_string(str(value)))
        
        return bytes(packet)
    
    def _encode_length_string(self, s: str) -> bytes:
        """Encode string with length prefix"""
        data = s.encode()
        length = len(data)
        
        if length < 251:
            return bytes([length]) + data
        elif length < 65536:
            return b'\xFC' + struct.pack('<H', length) + data
        else:
            return b'\xFD' + struct.pack('<I', length)[:3] + data
    
    def _send_ok_packet(self, client_socket: socket.socket, sequence_id: int, 
                       affected_rows: int = 0, last_insert_id: int = 0):
        """Send MySQL OK packet"""
        packet = bytearray([0x00])  # OK packet header
        packet.extend(self._encode_length_encoded_int(affected_rows))
        packet.extend(self._encode_length_encoded_int(last_insert_id))
        packet.extend(b'\x02\x00')  # Status flags
        packet.extend(b'\x00\x00')  # Warnings
        
        self._send_mysql_packet(client_socket, packet, sequence_id)
    
    def _send_error_packet(self, client_socket: socket.socket, sequence_id: int,
                          error_code: int, sql_state: str, message: str):
        """Send MySQL error packet"""
        packet = bytearray([0xFF])  # Error packet header
        packet.extend(struct.pack('<H', error_code))
        packet.append(ord('#'))
        packet.extend(sql_state.encode())
        packet.extend(message.encode())
        
        self._send_mysql_packet(client_socket, packet, sequence_id)
    
    def _encode_length_encoded_int(self, value: int) -> bytes:
        """Encode integer with length encoding"""
        if value < 251:
            return bytes([value])
        elif value < 65536:
            return b'\xFC' + struct.pack('<H', value)
        elif value < 16777216:
            return b'\xFD' + struct.pack('<I', value)[:3]
        else:
            return b'\xFE' + struct.pack('<Q', value)
    
    def _send_mysql_packet(self, client_socket: socket.socket, 
                          data: bytes, sequence_id: int):
        """Send MySQL packet with header"""
        packet_length = len(data)
        header = struct.pack('<I', packet_length)[:3] + bytes([sequence_id])
        client_socket.send(header + data)
    
    def _receive_mysql_packet(self, client_socket: socket.socket) -> tuple:
        """Receive MySQL packet"""
        # Read packet header (4 bytes)
        header = client_socket.recv(4)
        if len(header) < 4:
            return None, 0
        
        packet_length = struct.unpack('<I', header[:3] + b'\x00')[0]
        sequence_id = header[3]
        
        # Read packet data
        data = b''
        while len(data) < packet_length:
            chunk = client_socket.recv(packet_length - len(data))
            if not chunk:
                break
            data += chunk
        
        return data, sequence_id
    
    def _create_session_id(self) -> str:
        """Create unique session ID"""
        self.session_counter += 1
        return f"mysql_{self.session_counter}_{int(datetime.now().timestamp())}"
    
    def _cleanup_session(self, client_socket: socket.socket, session_id: str):
        """Clean up session resources"""
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
                "queries_executed": len(session_info["queries"]),
                "authenticated": session_info["authenticated"]
            })
            
            del self.active_sessions[session_id]
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get MySQL service statistics"""
        base_stats = super().get_service_stats()
        
        mysql_stats = {
            "active_sessions": len(self.active_sessions),
            "total_queries": sum(len(session["queries"]) for session in self.active_sessions.values()),
            "authenticated_sessions": sum(1 for session in self.active_sessions.values() if session["authenticated"]),
            "available_databases": len(self.fake_databases)
        }
        
        base_stats.update(mysql_stats)
        return base_stats