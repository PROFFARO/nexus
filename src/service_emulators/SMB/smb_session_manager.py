#!/usr/bin/env python3
"""
SMB Session Manager - Comprehensive session tracking with LLM integration
Manages SMB sessions, conversation history, and attacker behavior profiling
"""

import uuid
import datetime
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

from langchain_core.chat_history import InMemoryChatMessageHistory

logger = logging.getLogger('smb_session')


class SMBSession:
    """Individual SMB session with full tracking"""
    
    def __init__(self, session_id: str, client_ip: str, client_port: int, session_dir: Path):
        self.session_id = session_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_dir = session_dir
        
        # Session state
        self.authenticated = False
        self.username: Optional[str] = None
        self.domain: Optional[str] = None
        self.access_level = 'guest'
        self.session_key = None
        
        # SMB protocol state
        self.tree_connects: Dict[int, str] = {}  # tree_id -> share_name
        self.open_files: Dict[int, Dict[str, Any]] = {}  # file_id -> file_info
        self.challenge = None
        
        # LLM conversation history
        self.llm_history = InMemoryChatMessageHistory()
        
        # Tracking data
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        self.end_time: Optional[datetime.datetime] = None
        self.commands: List[Dict[str, Any]] = []
        self.file_operations: List[Dict[str, Any]] = []
        self.authentication_attempts: List[Dict[str, Any]] = []
        self.attack_analysis: List[Dict[str, Any]] = []
        self.llm_interactions: List[Dict[str, Any]] = []
        
        # Client information
        self.client_info: Dict[str, Any] = {
            'ip': client_ip,
            'port': client_port,
            'hostname': None,
            'os': None,
            'smb_version': None,
            'geolocation': None,
            'reputation': None
        }
        
        # Behavior profiling
        self.behavior_profile: Dict[str, Any] = {
            'sophistication_level': 'unknown',  # novice, intermediate, advanced, apt
            'attack_patterns': [],
            'tools_detected': [],
            'command_frequency': {},
            'file_access_patterns': [],
            'suspicious_activities': []
        }
    
    def authenticate(self, username: str, domain: Optional[str] = None, access_level: str = 'user'):
        """Mark session as authenticated"""
        self.authenticated = True
        self.username = username
        self.domain = domain
        self.access_level = access_level
        logger.info(f"Session {self.session_id} authenticated as {username} with {access_level} access")
    
    def add_tree_connect(self, tree_id: int, share_name: str):
        """Add tree connect"""
        self.tree_connects[tree_id] = share_name
        logger.debug(f"Session {self.session_id} connected to share {share_name} (tree_id={tree_id})")
    
    def remove_tree_connect(self, tree_id: int):
        """Remove tree connect"""
        if tree_id in self.tree_connects:
            share_name = self.tree_connects[tree_id]
            del self.tree_connects[tree_id]
            logger.debug(f"Session {self.session_id} disconnected from share {share_name}")
    
    def add_open_file(self, file_id: int, file_info: Dict[str, Any]):
        """Add open file"""
        self.open_files[file_id] = file_info
        logger.debug(f"Session {self.session_id} opened file {file_info.get('path')} (file_id={file_id})")
    
    def remove_open_file(self, file_id: int):
        """Remove open file"""
        if file_id in self.open_files:
            file_info = self.open_files[file_id]
            del self.open_files[file_id]
            logger.debug(f"Session {self.session_id} closed file {file_info.get('path')}")
    
    def track_command(self, command: str, command_type: str, response: str, **kwargs):
        """Track SMB command"""
        command_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'command': command,
            'command_type': command_type,
            'response': response,
            **kwargs
        }
        self.commands.append(command_data)
        
        # Update command frequency
        self.behavior_profile['command_frequency'][command_type] = \
            self.behavior_profile['command_frequency'].get(command_type, 0) + 1
    
    def track_file_operation(self, operation: str, path: str, share: str, **kwargs):
        """Track file operation"""
        file_op_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'operation': operation,
            'path': path,
            'share': share,
            'username': self.username,
            **kwargs
        }
        self.file_operations.append(file_op_data)
        
        # Track file access patterns
        self.behavior_profile['file_access_patterns'].append({
            'path': path,
            'operation': operation,
            'timestamp': file_op_data['timestamp']
        })
    
    def track_authentication_attempt(self, username: str, success: bool, auth_type: str, **kwargs):
        """Track authentication attempt"""
        auth_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'username': username,
            'success': success,
            'auth_type': auth_type,
            **kwargs
        }
        self.authentication_attempts.append(auth_data)
    
    def track_attack(self, analysis: Dict[str, Any]):
        """Track attack detection"""
        attack_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **analysis
        }
        self.attack_analysis.append(attack_data)
        
        # Update behavior profile
        for attack_type in analysis.get('attack_types', []):
            if attack_type not in self.behavior_profile['attack_patterns']:
                self.behavior_profile['attack_patterns'].append(attack_type)
        
        # Update sophistication level based on attack patterns
        self._update_sophistication_level(analysis)
    
    def track_llm_interaction(self, prompt_type: str, prompt: str, response: str, **kwargs):
        """Track LLM interaction"""
        llm_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'prompt_type': prompt_type,
            'prompt': prompt[:500],  # Truncate
            'response': response[:1000],  # Truncate
            **kwargs
        }
        self.llm_interactions.append(llm_data)
    
    def update_client_info(self, info: Dict[str, Any]):
        """Update client information"""
        self.client_info.update(info)
    
    def _update_sophistication_level(self, analysis: Dict[str, Any]):
        """Update sophistication level based on attack analysis"""
        severity = analysis.get('severity', 'low')
        attack_types = analysis.get('attack_types', [])
        
        # Advanced indicators
        advanced_indicators = ['lateral_movement', 'credential_harvesting', 'apt', 'advanced']
        if any(ind in str(attack_types) for ind in advanced_indicators):
            self.behavior_profile['sophistication_level'] = 'advanced'
        elif severity in ['high', 'critical']:
            if self.behavior_profile['sophistication_level'] in ['unknown', 'novice']:
                self.behavior_profile['sophistication_level'] = 'intermediate'
        elif len(attack_types) > 0 and self.behavior_profile['sophistication_level'] == 'unknown':
            self.behavior_profile['sophistication_level'] = 'novice'
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get session summary"""
        duration = (datetime.datetime.now(datetime.timezone.utc) - self.start_time).total_seconds()
        
        return {
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'username': self.username,
            'authenticated': self.authenticated,
            'access_level': self.access_level,
            'start_time': self.start_time.isoformat(),
            'duration_seconds': duration,
            'total_commands': len(self.commands),
            'total_file_operations': len(self.file_operations),
            'authentication_attempts': len(self.authentication_attempts),
            'successful_auth': sum(1 for a in self.authentication_attempts if a['success']),
            'attacks_detected': len(self.attack_analysis),
            'llm_interactions': len(self.llm_interactions),
            'sophistication_level': self.behavior_profile['sophistication_level'],
            'attack_patterns': self.behavior_profile['attack_patterns'],
            'client_info': self.client_info
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization"""
        return {
            'session_id': self.session_id,
            'client_ip': self.client_ip,
            'client_port': self.client_port,
            'authenticated': self.authenticated,
            'username': self.username,
            'domain': self.domain,
            'access_level': self.access_level,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'commands': self.commands,
            'file_operations': self.file_operations,
            'authentication_attempts': self.authentication_attempts,
            'attack_analysis': self.attack_analysis,
            'llm_interactions': self.llm_interactions,
            'client_info': self.client_info,
            'behavior_profile': self.behavior_profile,
            'summary': self.get_session_summary()
        }


class SMBSessionManager:
    """Manage SMB sessions with LLM integration"""
    
    def __init__(self, sessions_dir: Path):
        self.sessions_dir = sessions_dir
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        
        self.active_sessions: Dict[str, SMBSession] = {}
        logger.info(f"SMB Session Manager initialized with sessions directory: {sessions_dir}")
    
    def create_session(self, client_ip: str, client_port: int) -> SMBSession:
        """Create a new SMB session"""
        session_id = f"smb_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        session_dir = self.sessions_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        session = SMBSession(session_id, client_ip, client_port, session_dir)
        
        session_key = f"{client_ip}:{client_port}"
        self.active_sessions[session_key] = session
        
        logger.info(f"Created session {session_id} for {client_ip}:{client_port}")
        return session
    
    def get_session(self, client_ip: str, client_port: int) -> Optional[SMBSession]:
        """Get existing session"""
        session_key = f"{client_ip}:{client_port}"
        return self.active_sessions.get(session_key)
    
    def get_or_create_session(self, client_ip: str, client_port: int) -> SMBSession:
        """Get existing session or create new one"""
        session = self.get_session(client_ip, client_port)
        if session is None:
            session = self.create_session(client_ip, client_port)
        return session
    
    def close_session(self, client_ip: str, client_port: int):
        """Close and save session"""
        session_key = f"{client_ip}:{client_port}"
        session = self.active_sessions.get(session_key)
        
        if session:
            session.end_time = datetime.datetime.now(datetime.timezone.utc)
            
            # Save session data
            session_file = session.session_dir / f"session_{session.session_id}.json"
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
            
            # Generate session replay
            self._generate_session_replay(session)
            
            # Remove from active sessions
            del self.active_sessions[session_key]
            
            logger.info(f"Closed and saved session {session.session_id}")
    
    def _generate_session_replay(self, session: SMBSession):
        """Generate session replay file"""
        replay_file = session.session_dir / f"replay_{session.session_id}.txt"
        
        with open(replay_file, 'w') as f:
            f.write(f"SMB Session Replay - NEXUS-FS-01\n")
            f.write(f"=" * 80 + "\n\n")
            f.write(f"Session ID: {session.session_id}\n")
            f.write(f"Client: {session.client_ip}:{session.client_port}\n")
            f.write(f"Username: {session.username or 'Not authenticated'}\n")
            f.write(f"Start Time: {session.start_time.isoformat()}\n")
            f.write(f"End Time: {session.end_time.isoformat() if session.end_time else 'N/A'}\n")
            f.write(f"Sophistication: {session.behavior_profile['sophistication_level']}\n")
            f.write(f"\n" + "=" * 80 + "\n\n")
            
            # Authentication attempts
            if session.authentication_attempts:
                f.write("AUTHENTICATION ATTEMPTS:\n")
                f.write("-" * 80 + "\n")
                for auth in session.authentication_attempts:
                    status = "✓ SUCCESS" if auth['success'] else "✗ FAILED"
                    f.write(f"[{auth['timestamp']}] {status}: {auth['username']} ({auth['auth_type']})\n")
                f.write("\n")
            
            # Commands
            if session.commands:
                f.write("COMMANDS:\n")
                f.write("-" * 80 + "\n")
                for cmd in session.commands:
                    f.write(f"[{cmd['timestamp']}] {cmd['command_type']}: {cmd['command']}\n")
                    if cmd.get('response'):
                        f.write(f"  Response: {cmd['response'][:200]}\n")
                    f.write("\n")
            
            # File operations
            if session.file_operations:
                f.write("FILE OPERATIONS:\n")
                f.write("-" * 80 + "\n")
                for op in session.file_operations:
                    f.write(f"[{op['timestamp']}] {op['operation'].upper()}: {op['share']}{op['path']}\n")
                f.write("\n")
            
            # Attacks detected
            if session.attack_analysis:
                f.write("ATTACKS DETECTED:\n")
                f.write("-" * 80 + "\n")
                for attack in session.attack_analysis:
                    f.write(f"[{attack['timestamp']}] Severity: {attack['severity'].upper()}\n")
                    f.write(f"  Types: {', '.join(attack.get('attack_types', []))}\n")
                    f.write(f"  Threat Score: {attack.get('threat_score', 0)}\n")
                    f.write("\n")
            
            # Summary
            summary = session.get_session_summary()
            f.write("SESSION SUMMARY:\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Commands: {summary['total_commands']}\n")
            f.write(f"File Operations: {summary['total_file_operations']}\n")
            f.write(f"Auth Attempts: {summary['authentication_attempts']} ({summary['successful_auth']} successful)\n")
            f.write(f"Attacks Detected: {summary['attacks_detected']}\n")
            f.write(f"LLM Interactions: {summary['llm_interactions']}\n")
            f.write(f"Sophistication Level: {summary['sophistication_level']}\n")
            f.write(f"Attack Patterns: {', '.join(summary['attack_patterns']) if summary['attack_patterns'] else 'None'}\n")
    
    def get_all_sessions(self) -> List[SMBSession]:
        """Get all active sessions"""
        return list(self.active_sessions.values())
    
    def get_session_count(self) -> int:
        """Get count of active sessions"""
        return len(self.active_sessions)
