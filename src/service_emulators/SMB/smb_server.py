#!/usr/bin/env python3

from configparser import ConfigParser
import argparse
import asyncio
import threading
import sys
import json
import os
import traceback
from typing import Optional, Dict, List, Any
import logging
import datetime
import uuid
import hashlib
import re
import time
import random
import shutil
from pathlib import Path
from base64 import b64encode, b64decode
from operator import itemgetter
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_aws import ChatBedrock, ChatBedrockConverse
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama 
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.chat_history import BaseChatMessageHistory, InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
import socket
import struct
import hashlib
import hmac
import secrets
from enum import IntEnum

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")
    print("Environment variables will be loaded from system environment only.")

# Import ML components
try:
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent.parent))
    from ai.detectors import MLDetector
    from ai.config import MLConfig
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: ML components not available. Install dependencies or check ai module.")

class AttackAnalyzer:
    """AI-based attack behavior analyzer with integrated JSON patterns and ML detection"""
    
    def __init__(self):
        # Load attack patterns from JSON file
        self.attack_patterns = self._load_attack_patterns()
        # Load vulnerability signatures from JSON file  
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE:
            try:
                ml_config = MLConfig('smb')
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector('smb', ml_config)
                    logging.info("ML detector initialized for SMB service")
            except Exception as e:
                logging.warning(f"Failed to initialize ML detector: {e}")
                self.ml_detector = None
        
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load attack patterns from JSON configuration"""
        try:
            patterns_file = Path(__file__).parent / "attack_patterns.json"
            with open(patterns_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load attack patterns: {e}")
            # Fallback to basic patterns
            return {
                'reconnaissance': {'patterns': [r'net view', r'net share', r'dir \\\\'], 'severity': 'medium'},
                'lateral_movement': {'patterns': [r'net use', r'psexec', r'wmic'], 'severity': 'high'},
                'credential_harvesting': {'patterns': [r'net user', r'net localgroup'], 'severity': 'high'}
            }
            
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures from JSON configuration"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load vulnerability signatures: {e}")
            return {}
        
    def analyze_command(self, command: str) -> Dict[str, Any]:
        """Analyze an SMB command for attack patterns using integrated JSON data"""
        analysis = {
            'command': command,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'attack_types': [],
            'severity': 'low',
            'indicators': [],
            'vulnerabilities': [],
            'pattern_matches': []
        }
        
        # Check if attack pattern recognition is enabled
        if not config['ai_features'].getboolean('attack_pattern_recognition', True):
            return analysis
        
        # Check attack patterns from JSON
        for attack_type, attack_data in self.attack_patterns.items():
            patterns = attack_data.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    analysis['attack_types'].append(attack_type)
                    analysis['indicators'].extend(attack_data.get('indicators', []))
                    analysis['pattern_matches'].append({
                        'type': attack_type,
                        'pattern': pattern,
                        'severity': attack_data.get('severity', 'medium')
                    })
                    
        # Check vulnerability signatures
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    analysis['vulnerabilities'].append({
                        'id': vuln_id,
                        'name': vuln_data.get('name', vuln_id),
                        'severity': vuln_data.get('severity', 'medium'),
                        'cvss_score': vuln_data.get('cvss_score', 0.0),
                        'pattern_matched': pattern
                    })
                    
        # Determine overall severity based on patterns and vulnerabilities
        severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_severity = 'low'
        
        # Check attack pattern severities
        for match in analysis['pattern_matches']:
            if severity_scores.get(match['severity'], 1) > severity_scores[max_severity]:
                max_severity = match['severity']
                
        # Check vulnerability severities
        for vuln in analysis['vulnerabilities']:
            if severity_scores.get(vuln['severity'], 1) > severity_scores[max_severity]:
                max_severity = vuln['severity']
        
        # Apply sensitivity level adjustment
        sensitivity = config['attack_detection'].get('sensitivity_level', 'medium').lower()
        if sensitivity == 'high' and max_severity == 'low':
            max_severity = 'medium'
        elif sensitivity == 'low' and max_severity == 'medium':
            max_severity = 'low'
        
        analysis['severity'] = max_severity
        
        # Calculate threat score if enabled
        if config['attack_detection'].getboolean('threat_scoring', True):
            threat_score = self._calculate_threat_score(analysis)
            # Check alert threshold
            alert_threshold = config['attack_detection'].getint('alert_threshold', 70)
            analysis['alert_triggered'] = threat_score >= alert_threshold
        
        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                # Prepare comprehensive ML data (NO hardcoded values)
                ml_data = {
                    'command': command,
                    'timestamp': analysis['timestamp'],
                    'attack_types': analysis['attack_types'],
                    'severity': analysis['severity'],
                    'indicators': analysis['indicators'],
                    'vulnerabilities': analysis['vulnerabilities'],
                    'pattern_matches': analysis['pattern_matches']
                }
                
                # Get ML scoring results
                ml_results = self.ml_detector.score(ml_data)
                
                # Integrate ML results into analysis
                analysis['ml_anomaly_score'] = ml_results.get('ml_anomaly_score', 0.0)
                analysis['ml_labels'] = ml_results.get('ml_labels', [])
                analysis['ml_cluster'] = ml_results.get('ml_cluster', -1)
                analysis['ml_reason'] = ml_results.get('ml_reason', 'No ML analysis')
                analysis['ml_confidence'] = ml_results.get('ml_confidence', 0.0)
                analysis['ml_inference_time_ms'] = ml_results.get('ml_inference_time_ms', 0)
                
                # Enhance severity based on ML anomaly score
                ml_score = ml_results.get('ml_anomaly_score', 0)
                if ml_score > 0.8:
                    if analysis['severity'] in ['low', 'medium']:
                        analysis['severity'] = 'high'
                        analysis['attack_types'].append('ml_anomaly_high')
                elif ml_score > 0.6:
                    if analysis['severity'] == 'low':
                        analysis['severity'] = 'medium'
                        analysis['attack_types'].append('ml_anomaly_medium')
                
                # Add ML-specific indicators
                if 'anomaly' in ml_results.get('ml_labels', []):
                    analysis['indicators'].append(f"ML Anomaly Detection: {ml_results.get('ml_reason', 'Unknown')}")
                
                logging.info(f"SMB ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}, Confidence={ml_results.get('ml_confidence', 0):.3f}")
                        
            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                # Add ML error information to analysis
                analysis['ml_error'] = str(e)
                analysis['ml_anomaly_score'] = 0.0
                analysis['ml_labels'] = ['ml_error']
                if not config.get('ml', {}).get('fallback_on_error', True):
                    raise
        
        return analysis
    
    def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate threat score based on analysis"""
        score = 0
        severity_scores = {'low': 10, 'medium': 30, 'high': 60, 'critical': 90}
        
        # Base score from severity
        score += severity_scores.get(analysis['severity'], 0)
        
        # Add points for multiple attack types
        score += len(analysis['attack_types']) * 5
        
        # Add points for vulnerabilities
        score += len(analysis['vulnerabilities']) * 15

        ml_score = analysis.get('ml_anomaly_score', 0)
        if ml_score > 0:
            # ML score contributes up to 30 points
            ml_contribution = int(ml_score * 30)
            score += ml_contribution
            
            # Bonus for high confidence ML detection
            ml_confidence = analysis.get('ml_confidence', 0)
            if ml_confidence > 0.8 and ml_score > 0.7:
                score += 10  # High confidence bonus
               
        return min(score, 100)  # Cap at 100

class FileTransferHandler:
    """Handle file uploads and downloads with forensic logging"""
    
    def __init__(self, session_dir: str):
        self.session_dir = Path(session_dir)
        # Use configured directories or defaults
        downloads_dirname = config['features'].get('downloads_dir', 'downloads')
        uploads_dirname = config['features'].get('uploads_dir', 'uploads')
        self.downloads_dir = self.session_dir / downloads_dirname
        self.uploads_dir = self.session_dir / uploads_dirname
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        
    def handle_download(self, filename: str, content: Optional[bytes] = None) -> Dict[str, Any]:
        """Handle file download requests"""
        download_info = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'filename': filename,
            'type': 'download',
            'status': 'attempted'
        }
        
        # Check if file monitoring is enabled
        if not config['forensics'].getboolean('file_monitoring', True):
            return download_info
        
        # Generate fake file content if not provided
        if content is None:
            content = self._generate_fake_file_content(filename)
        
        file_path = self.downloads_dir / filename
        
        # Save download if enabled
        if config['forensics'].getboolean('save_downloads', True):
            with open(file_path, 'wb') as f:
                f.write(content)
        
        download_info.update(
            file_size=str(len(content)),
            status='completed'
        )
        
        # Only add file_path if downloads are being saved
        if config['forensics'].getboolean('save_downloads', True):
            download_info['file_path'] = str(file_path)
        
        # Add file hash analysis if enabled
        if config['forensics'].getboolean('file_hash_analysis', True):
            download_info['file_hash'] = hashlib.sha256(content).hexdigest()
            download_info['md5_hash'] = hashlib.md5(content).hexdigest()
        
        # Add malware detection if enabled
        if config['forensics'].getboolean('malware_detection', True):
            download_info['malware_detected'] = str(self._detect_malware(filename, content))
            download_info['file_type'] = self._identify_file_type(filename, content)
        
        return download_info
        
    def handle_upload(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Handle file uploads"""
        upload_info = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'filename': filename,
            'type': 'upload',
            'file_size': len(content)
        }
        
        # Check if file monitoring is enabled
        if not config['forensics'].getboolean('file_monitoring', True):
            return upload_info
        
        # Save upload if enabled
        if config['forensics'].getboolean('save_uploads', True):
            file_path = self.uploads_dir / filename
            # amazonq-ignore-next-line
            with open(file_path, 'wb') as f:
                f.write(content)
            upload_info['file_path'] = str(file_path)
        
        # Add file hash analysis if enabled
        if config['forensics'].getboolean('file_hash_analysis', True):
            upload_info['file_hash'] = hashlib.sha256(content).hexdigest()
            upload_info['md5_hash'] = hashlib.md5(content).hexdigest()
        
        # Add malware detection if enabled
        if config['forensics'].getboolean('malware_detection', True):
            upload_info['malware_detected'] = str(self._detect_malware(filename, content))
            upload_info['file_type'] = self._identify_file_type(filename, content)
            
        upload_info['status'] = 'completed'
        return upload_info
        
    def _generate_fake_file_content(self, filename: str) -> bytes:
        """Generate realistic fake file content based on file type"""
        filename_lower = filename.lower()
        
        if filename_lower.endswith(('.exe', '.dll')):
            # Fake Windows executable
            content = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + f"NexusGames Studio File: {filename}".encode() + b"\x00" * 1000
        elif filename_lower.endswith(('.txt', '.log', '.conf', '.cfg')):
            content = f"""# NexusGames Studio Configuration File
# Generated: {datetime.datetime.now()}
# This is a honeypot simulation

server_name=nexus-smb-01
max_connections=1000
share_root=C:\\GameDev\\Shares
admin_email=admin@nexusgames.studio
debug_mode=false
api_key=ng_smb_key_2024_secure
""".encode()
        elif filename_lower.endswith(('.doc', '.docx', '.pdf')):
            content = f"""NexusGames Studio Document: {filename}
Created: {datetime.datetime.now()}
This is a honeypot simulation file.

Document contains sensitive game development information.
Access restricted to authorized personnel only.
""".encode()
        else:
            content = f"""NexusGames Studio File: {filename}
Created: {datetime.datetime.now()}
This is a honeypot simulation file.

File contains sensitive SMB share data.
Access restricted to authorized personnel only.
""".encode()
            
        return content
    
    def _detect_malware(self, filename: str, content: bytes) -> bool:
        """Simple malware detection based on patterns"""
        malware_patterns = [b'malware', b'virus', b'trojan', b'backdoor', b'payload', b'exploit']
        filename_lower = filename.lower()
        
        # Check filename patterns
        if any(pattern in filename_lower for pattern in ['malware', 'virus', 'trojan', 'backdoor', 'payload', 'exploit']):
            return True
        
        # Check content patterns
        for pattern in malware_patterns:
            if pattern in content.lower():
                return True
        
        return False
    
    def _identify_file_type(self, filename: str, content: bytes) -> str:
        """Identify file type based on extension and content"""
        filename_lower = filename.lower()
        
        if filename_lower.endswith(('.exe', '.dll')):
            return 'windows_executable'
        elif filename_lower.endswith(('.txt', '.log', '.conf', '.cfg')):
            return 'text_file'
        elif filename_lower.endswith(('.doc', '.docx', '.pdf')):
            return 'document'
        elif filename_lower.endswith(('.zip', '.rar', '.7z')):
            return 'archive'
        else:
            return 'unknown'

class VulnerabilityLogger:
    """Log and analyze vulnerability exploitation attempts using integrated JSON data"""
    
    def __init__(self):
        # Load vulnerability signatures from JSON file (shared with AttackAnalyzer)
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures from JSON configuration"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load vulnerability signatures: {e}")
            # Fallback patterns
            return {
                'CVE-2017-0144': {'patterns': [r'eternalblue', r'ms17-010'], 'severity': 'critical'},
                'SMB_RELAY': {'patterns': [r'ntlmrelayx', r'smbrelay'], 'severity': 'high'}
            }
        
    def analyze_for_vulnerabilities(self, command: str, headers: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Analyze SMB command for vulnerability exploitation attempts using JSON data"""
        vulnerabilities = []
        
        # Check if vulnerability detection is enabled
        if not config['ai_features'].getboolean('vulnerability_detection', True):
            return vulnerabilities
        
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    vulnerabilities.append({
                        'vulnerability_id': vuln_id,
                        'name': vuln_data.get('name', vuln_id),
                        'description': vuln_data.get('description', ''),
                        'pattern_matched': pattern,
                        'input': command,
                        'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'severity': vuln_data.get('severity', 'medium'),
                        'cvss_score': vuln_data.get('cvss_score', 0.0),
                        'indicators': vuln_data.get('indicators', [])
                    })
                    
        return vulnerabilities

class ForensicChainLogger:
    """Generate forensic chain of custody for attacks"""
    
    def __init__(self, session_dir: str):
        self.session_dir = Path(session_dir)
        self.chain_file = self.session_dir / "forensic_chain.json"
        self.chain_data = {
            'session_id': str(uuid.uuid4()),
            'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'events': [],
            'evidence': [],
            'attack_timeline': []
        }
        
    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log forensic event"""
        # Check if chain of custody is enabled
        if not config['forensics'].getboolean('chain_of_custody', True):
            return
            
        event = {
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'event_type': event_type,
            'data': data,
            'hash': hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        }
        
        self.chain_data['events'].append(event)
        self._save_chain()
        
    def add_evidence(self, evidence_type: str, file_path: str, description: str):
        """Add evidence to forensic chain"""
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                content = f.read()
                
            evidence = {
                'evidence_id': str(uuid.uuid4()),
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'type': evidence_type,
                'file_path': file_path,
                'file_hash': hashlib.sha256(content).hexdigest(),
                'file_size': len(content),
                'description': description
            }
            
            self.chain_data['evidence'].append(evidence)
            self._save_chain()
            
    def _save_chain(self):
        """Save forensic chain to file"""
        with open(self.chain_file, 'w') as f:
            json.dump(self.chain_data, f, indent=2)

class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": getattr(record, "task_name", "-"),
            "src_ip": getattr(record, "src_ip", "-"),
            "src_port": getattr(record, "src_port", "-"),
            "dst_ip": getattr(record, "dst_ip", "-"),
            "dst_port": getattr(record, "dst_port", "-"),
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "smb"
        }
        if hasattr(record, 'interactive'):
            log_record["interactive"] = getattr(record, "interactive", True)
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key != 'args' and key != 'msg':
                log_record[key] = value
        return json.dumps(log_record)

class SMBCommands(IntEnum):
    """SMB1 Command codes"""
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_NT_CREATE_ANDX = 0xA2
    SMB_COM_CLOSE = 0x04
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F

class SMB2Commands(IntEnum):
    """SMB2 Command codes"""
    SMB2_NEGOTIATE = 0x0000
    SMB2_SESSION_SETUP = 0x0001
    SMB2_TREE_CONNECT = 0x0003
    SMB2_CREATE = 0x0005
    SMB2_CLOSE = 0x0006
    SMB2_READ = 0x0008
    SMB2_WRITE = 0x0009

class NTStatus(IntEnum):
    """NT Status codes"""
    STATUS_SUCCESS = 0x00000000
    STATUS_ACCESS_DENIED = 0xC0000022
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NOT_SUPPORTED = 0xC00000BB
    STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034

class SMBSession:
    """SMB Session state"""
    def __init__(self):
        self.authenticated = False
        self.username = None
        self.domain = None
        self.session_id = secrets.randbits(64)
        self.tree_connects = {}
        self.open_files = {}
        self.challenge = secrets.token_bytes(8)

class SMBHoneypot:
    """SMB Honeypot with full protocol implementation"""
    
    def __init__(self):
        self.sessions = {}
        self.active_sessions = {}
        
        # SMB server configuration
        self.server_name = config['smb'].get('server_name', 'NEXUS-FS-01')
        self.workgroup = config['smb'].get('workgroup', 'NEXUSGAMES')
        self.banner = config['smb'].get('banner', 'NexusGames Studio File Server v3.1.1')
        self.welcome_message = config['smb'].get('welcome_message', 'Welcome to NexusGames Studio File Server')
        self.max_connections = config['smb'].getint('max_connections', 100)
        self.connection_timeout = config['smb'].getint('connection_timeout', 300)
        self.enable_smb1 = config['smb'].getboolean('enable_smb1', True)
        self.enable_smb2 = config['smb'].getboolean('enable_smb2', True)
        self.enable_netbios = config['smb'].getboolean('enable_netbios', True)
        self.default_permissions = config['smb'].get('default_permissions', 'read')
        self.allow_guest = config['smb'].getboolean('allow_guest', True)
        self.guest_account = config['smb'].get('guest_account', 'guest')
        
        # Load user accounts from config
        self.user_accounts = self._load_user_accounts()
        
        # Connection tracking for max_connections limit
        self.connection_count = 0
        
        # Latency simulation configuration
        self.latency_enable = config['honeypot'].getboolean('latency_enable', False)
        self.latency_min_ms = config['honeypot'].getint('latency_min_ms', 20)
        self.latency_max_ms = config['honeypot'].getint('latency_max_ms', 250)
        
        # Behavioral analysis and adaptive responses
        self.behavioral_analysis = config['honeypot'].getboolean('behavioral_analysis', True)
        self.adaptive_responses = config['honeypot'].getboolean('adaptive_responses', True)
        self.attack_logging = config['honeypot'].getboolean('attack_logging', True)
        self.forensic_chain = config['honeypot'].getboolean('forensic_chain', True)
        
        # AI features configuration
        self.real_time_analysis = config['ai_features'].getboolean('real_time_analysis', True)
        self.ai_attack_summaries = config['ai_features'].getboolean('ai_attack_summaries', True)
        self.adaptive_banners = config['ai_features'].getboolean('adaptive_banners', True)
        self.deception_techniques = config['ai_features'].getboolean('deception_techniques', True)
        
        # Security configuration
        self.ip_reputation = config['security'].getboolean('ip_reputation', True)
        self.rate_limiting = config['security'].getboolean('rate_limiting', True)
        self.max_connections_per_ip = config['security'].getint('max_connections_per_ip', 5)
        self.intrusion_detection = config['security'].getboolean('intrusion_detection', True)
        self.automated_blocking = config['security'].getboolean('automated_blocking', False)
        
        # Connection tracking per IP for rate limiting
        self.ip_connections = {}
        
        # Session recording and replay configuration
        self.session_recording = config['features'].getboolean('session_recording', True)
        self.command_replay = config['features'].getboolean('command_replay', True)
        self.save_replay = config['features'].getboolean('save_replay', True)
        self.network_analysis = config['features'].getboolean('network_analysis', True)
        self.process_monitoring = config['features'].getboolean('process_monitoring', True)
        
        # Geolocation and reputation analysis
        self.geolocation_analysis = config['attack_detection'].getboolean('geolocation_analysis', True)
        self.reputation_filtering = config['attack_detection'].getboolean('reputation_filtering', True)
        
        # Create session directory
        session_id = f"smb_session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        sessions_dir = Path(config['honeypot'].get('sessions_dir', 'sessions'))
        self.session_dir = sessions_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize integrated components with error handling
        try:
            self.attack_analyzer = AttackAnalyzer()
            self.file_handler = FileTransferHandler(str(self.session_dir)) if config['forensics'].getboolean('file_monitoring', True) else None
            self.vuln_logger = VulnerabilityLogger()
            self.forensic_logger = ForensicChainLogger(str(self.session_dir)) if config['forensics'].getboolean('chain_of_custody', True) else None
        except Exception as e:
            logger.error(f"Failed to initialize SMB honeypot components: {e}")
            self.attack_analyzer = None
            self.file_handler = None
            self.vuln_logger = None
            self.forensic_logger = None
    
    def _load_user_accounts(self) -> Dict[str, str]:
        """Load user accounts from config.ini"""
        accounts = {}
        if 'user_accounts' in config:
            for username, password in config.items('user_accounts'):
                accounts[username.lower()] = password
        return accounts

    async def handle_connection(self, reader, writer):
        """Handle SMB connection with AI analysis"""
        
        # Check connection limit
        if self.connection_count >= self.max_connections:
            logger.warning(f"Connection limit reached ({self.max_connections}), rejecting connection")
            writer.close()
            await writer.wait_closed()
            return
        
        self.connection_count += 1
        logger.debug(f"Connection count increased to {self.connection_count}")
        
        # Get connection details
        peername = writer.get_extra_info('peername')
        sockname = writer.get_extra_info('sockname')
        
        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = '-', '-'
            
        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = '-', '-'
        
        # Rate limiting check
        if self.rate_limiting and src_ip != '-':
            if src_ip not in self.ip_connections:
                self.ip_connections[src_ip] = 0
            
            if self.ip_connections[src_ip] >= self.max_connections_per_ip:
                logger.warning(f"Rate limit exceeded for IP {src_ip} ({self.ip_connections[src_ip]} connections)")
                writer.close()
                await writer.wait_closed()
                self.connection_count -= 1
                return
            
            self.ip_connections[src_ip] += 1
        
        # Store connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port
        
        # Create or get session data
        session_key = f"{src_ip}:{src_port}"
        if session_key not in self.active_sessions:
            client_info = {'ip': src_ip, 'port': src_port}
            
            # Add geolocation analysis if enabled
            if self.geolocation_analysis:
                client_info['geolocation'] = self._analyze_geolocation(src_ip)
            
            # Add reputation analysis if enabled
            if self.reputation_filtering:
                client_info['reputation'] = self._analyze_reputation(src_ip)
            
            self.active_sessions[session_key] = {
                'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'commands': [],
                'attack_analysis': [],
                'vulnerabilities': [],
                'files_transferred': [],
                'client_info': client_info
            }
            
        session_data = self.active_sessions[session_key]
        
        # Log connection
        connection_info = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "session_key": session_key
        }
        
        logger.info("SMB connection received", extra=connection_info)
        
        # Create SMB session
        smb_session = SMBSession()
        
        try:
            # Handle SMB protocol negotiation and commands with timeout
            while True:
                try:
                    # Read SMB packet with timeout
                    data = await asyncio.wait_for(
                        reader.read(4096), 
                        timeout=self.connection_timeout
                    )
                    if not data:
                        logger.debug(f"No data received from {src_ip}:{src_port}, closing connection")
                        break
                    
                    # Process SMB packet
                    response = await self._process_smb_packet(data, smb_session, session_data)
                    if response:
                        writer.write(response)
                        await writer.drain()
                    
                    # Simulate latency if enabled
                    await self._simulate_latency()
                    
                except asyncio.TimeoutError:
                    logger.info(f"Connection timeout after {self.connection_timeout}s")
                    break
                except asyncio.IncompleteReadError:
                    logger.debug(f"Incomplete read from {src_ip}:{src_port}")
                    break
                except Exception as e:
                    logger.error(f"Error processing SMB command: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"SMB connection error: {e}")
        finally:
            # Decrement connection count
            self.connection_count -= 1
            
            # Decrement IP connection count for rate limiting
            if self.rate_limiting and src_ip != '-' and src_ip in self.ip_connections:
                self.ip_connections[src_ip] -= 1
                if self.ip_connections[src_ip] <= 0:
                    del self.ip_connections[src_ip]
            
            writer.close()
            await writer.wait_closed()
            
            # Save session data with enhanced information
            session_data['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            session_data['server_info'] = {
                'server_name': self.server_name,
                'workgroup': self.workgroup,
                'banner': self.banner,
                'welcome_message': self.welcome_message
            }
            
            # Add network analysis if enabled
            if self.network_analysis:
                session_data['network_analysis'] = {
                    'total_commands': len(session_data['commands']),
                    'attack_commands': len([cmd for cmd in session_data['commands'] if cmd.get('attack_analysis', {}).get('attack_types')]),
                    'vulnerability_attempts': len(session_data['vulnerabilities']),
                    'file_transfers': len(session_data['files_transferred'])
                }
            
            session_file = self.session_dir / f"session_{uuid.uuid4().hex[:8]}.json"
            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
            
            # Save replay file if enabled
            if self.save_replay:
                replay_file = self.session_dir / f"replay_{uuid.uuid4().hex[:8]}.txt"
                with open(replay_file, 'w') as f:
                    f.write(f"SMB Session Replay - {self.server_name}\n")
                    f.write(f"Session: {session_key}\n")
                    f.write(f"Start: {session_data['start_time']}\n")
                    f.write(f"End: {session_data['end_time']}\n\n")
                    
                    for cmd in session_data['commands']:
                        f.write(f"[{cmd['timestamp']}] {cmd['command']}\n")
                        if cmd.get('response'):
                            f.write(f"Response: {cmd['response']}\n")
                        f.write("\n")
                
            logger.info("SMB connection closed", extra={"session_key": session_key, "active_connections": self.connection_count})

    async def _process_smb_packet(self, data: bytes, smb_session: SMBSession, session_data: Dict) -> Optional[bytes]:
        """Process SMB packet and generate response"""
        try:
            if len(data) < 4:
                return None
            
            # Check for NetBIOS session request first
            if data[0] == 0x81:  # NetBIOS session request
                return self._handle_netbios_session_request(data)
            
            # Check for SMB signature
            if data[:4] == b'\xffSMB':
                return await self._handle_smb1_packet(data, smb_session, session_data)
            elif data[:4] == b'\xfeSMB':
                return await self._handle_smb2_packet(data, smb_session, session_data)
            
            # Try to handle as telnet for backward compatibility
            try:
                text_data = data.decode('utf-8', errors='ignore').strip()
                if text_data and not any(ord(c) < 32 for c in text_data if c not in '\r\n\t'):
                    return await self._handle_telnet_command(text_data, session_data)
            # amazonq-ignore-next-line
            # amazonq-ignore-next-line
            except:
                pass
            
            return None
            
        except Exception as e:
            logger.error(f"Error processing SMB packet: {e}")
            return None
    
    def _handle_netbios_session_request(self, data: bytes) -> bytes:
        """Handle NetBIOS session request"""
        # NetBIOS positive session response
        return b'\x82\x00\x00\x00'
    
    async def _handle_smb1_packet(self, data: bytes, smb_session: SMBSession, session_data: Dict) -> bytes:
        """Handle SMB1 packet"""
        if len(data) < 32:
            return self._create_smb1_error_response(NTStatus.STATUS_INVALID_PARAMETER)
        
        command = data[4]
        
        if command == SMBCommands.SMB_COM_NEGOTIATE:
            return self._handle_smb1_negotiate(data)
        elif command == SMBCommands.SMB_COM_SESSION_SETUP_ANDX:
            return await self._handle_smb1_session_setup(data, smb_session, session_data)
        elif command == SMBCommands.SMB_COM_TREE_CONNECT_ANDX:
            return self._handle_smb1_tree_connect(data, smb_session)
        else:
            return self._create_smb1_error_response(NTStatus.STATUS_NOT_SUPPORTED)
    
    async def _handle_smb2_packet(self, data: bytes, smb_session: SMBSession, session_data: Dict) -> bytes:
        """Handle SMB2 packet"""
        if len(data) < 64:
            return self._create_smb2_error_response(NTStatus.STATUS_INVALID_PARAMETER)
        
        command = struct.unpack('<H', data[12:14])[0]
        
        if command == SMB2Commands.SMB2_NEGOTIATE:
            return self._handle_smb2_negotiate(data)
        elif command == SMB2Commands.SMB2_SESSION_SETUP:
            return await self._handle_smb2_session_setup(data, smb_session, session_data)
        elif command == SMB2Commands.SMB2_TREE_CONNECT:
            return self._handle_smb2_tree_connect(data, smb_session)
        else:
            return self._create_smb2_error_response(NTStatus.STATUS_NOT_SUPPORTED)
    
    def _handle_smb1_negotiate(self, data: bytes) -> bytes:
        """Handle SMB1 negotiate request"""
        # SMB1 negotiate response
        response = bytearray(b'\x00\x00\x00\x47')  # NetBIOS header
        response += b'\xffSMB'  # SMB signature
        response += bytes([SMBCommands.SMB_COM_NEGOTIATE])  # Command
        response += b'\x00\x00\x00\x00'  # Status
        response += b'\x18'  # Flags
        response += b'\x07\xc0'  # Flags2
        response += b'\x00\x00' * 6  # Process ID, etc.
        response += b'\x00\x00'  # Dialect index (NT LM 0.12)
        response += b'\x03'  # Security mode
        response += b'\x00\x00'  # Max multiplex
        response += b'\x01\x00'  # Max VCs
        response += b'\x00\x00\x01\x00'  # Max buffer size
        response += b'\x00\x00\x00\x00'  # Max raw size
        response += b'\x00\x00\x00\x00'  # Session key
        response += b'\x00\x00\x00\x00'  # Capabilities
        response += b'\x00' * 8  # System time
        response += b'\x00\x00'  # Server timezone
        response += b'\x08'  # Challenge length
        response += secrets.token_bytes(8)  # Challenge
        return bytes(response)
    
    async def _handle_smb1_session_setup(self, data: bytes, smb_session: SMBSession, session_data: Dict) -> bytes:
        """Handle SMB1 session setup request"""
        try:
            # Extract username and password from session setup
            username, password = self._extract_smb1_credentials(data)
            
            # Log authentication attempt
            auth_info = {
                'username': username,
                'auth_type': 'SMB1_NTLM',
                'success': False
            }
            
            # Verify credentials
            if self._verify_credentials(username, password):
                smb_session.authenticated = True
                smb_session.username = username
                auth_info['success'] = True
                logger.info(f"SMB1 authentication successful for user: {username}")
                return self._create_smb1_session_setup_response(True)
            else:
                logger.warning(f"SMB1 authentication failed for user: {username}")
                session_data['auth_attempts'] = session_data.get('auth_attempts', []) + [auth_info]
                return self._create_smb1_session_setup_response(False)
                
        except Exception as e:
            logger.error(f"Error in SMB1 session setup: {e}")
            return self._create_smb1_error_response(NTStatus.STATUS_LOGON_FAILURE)
    
    async def _handle_smb2_session_setup(self, data: bytes, smb_session: SMBSession, session_data: Dict) -> bytes:
        """Handle SMB2 session setup request"""
        try:
            # Extract username and password from session setup
            username, password = self._extract_smb2_credentials(data)
            
            # Log authentication attempt
            auth_info = {
                'username': username,
                'auth_type': 'SMB2_NTLM',
                'success': False
            }
            
            # Verify credentials
            if self._verify_credentials(username, password):
                smb_session.authenticated = True
                smb_session.username = username
                auth_info['success'] = True
                logger.info(f"SMB2 authentication successful for user: {username}")
                return self._create_smb2_session_setup_response(True, smb_session.session_id)
            else:
                logger.warning(f"SMB2 authentication failed for user: {username}")
                session_data['auth_attempts'] = session_data.get('auth_attempts', []) + [auth_info]
                return self._create_smb2_session_setup_response(False, 0)
                
        except Exception as e:
            logger.error(f"Error in SMB2 session setup: {e}")
            return self._create_smb2_error_response(NTStatus.STATUS_LOGON_FAILURE)
    
    def _extract_smb1_credentials(self, data: bytes) -> tuple:
        """Extract username and password from SMB1 session setup"""
        try:
            # Basic extraction - in real implementation, parse NTLM properly
            username = "unknown"
            password = ""
            
            # Look for username in the packet
            if len(data) > 100:
                # Try to find username string
                for i in range(50, len(data) - 10):
                    if data[i:i+2] == b'\x00\x00' and i > 60:
                        potential_user = data[60:i].decode('utf-8', errors='ignore').strip('\x00')
                        if potential_user and len(potential_user) < 50:
                            username = potential_user
                            break
            
            return username, password
        except:
            return "unknown", ""
    
    def _extract_smb2_credentials(self, data: bytes) -> tuple:
        """Extract username and password from SMB2 session setup"""
        try:
            # Basic extraction - in real implementation, parse NTLM properly
            username = "unknown"
            password = ""
            
            # Look for username in the packet
            if len(data) > 100:
                # Try to find username string
                for i in range(70, len(data) - 10):
                    if data[i:i+2] == b'\x00\x00' and i > 80:
                        potential_user = data[80:i].decode('utf-16le', errors='ignore').strip('\x00')
                        if potential_user and len(potential_user) < 50:
                            username = potential_user
                            break
            
            return username, password
        except:
            return "unknown", ""
    
    def _verify_credentials(self, username: str, password: str) -> bool:
        """Verify credentials against config.ini accounts"""
        username_lower = username.lower()
        
        # Check if username exists in accounts
        if username_lower in self.user_accounts:
            stored_password = self.user_accounts[username_lower]
            
            # Handle wildcard password (accepts any password)
            if stored_password == '*':
                return True
            
            # Handle empty password
            if stored_password == '' and password == '':
                return True
            
            # Check exact password match
            if stored_password == password:
                return True
        
        # Check guest access
        if self.allow_guest and username_lower == self.guest_account.lower():
            return True
        
        return False
    
    def _handle_smb1_tree_connect(self, data: bytes, smb_session: SMBSession) -> bytes:
        """Handle SMB1 tree connect request"""
        if not smb_session.authenticated:
            return self._create_smb1_error_response(NTStatus.STATUS_ACCESS_DENIED)
        
        # Extract share name and create tree connect response
        tree_id = len(smb_session.tree_connects) + 1
        smb_session.tree_connects[tree_id] = "IPC$"  # Default share
        
        return self._create_smb1_tree_connect_response(tree_id)
    
    def _handle_smb2_tree_connect(self, data: bytes, smb_session: SMBSession) -> bytes:
        """Handle SMB2 tree connect request"""
        if not smb_session.authenticated:
            return self._create_smb2_error_response(NTStatus.STATUS_ACCESS_DENIED)
        
        # Extract share name and create tree connect response
        tree_id = len(smb_session.tree_connects) + 1
        smb_session.tree_connects[tree_id] = "IPC$"  # Default share
        
        return self._create_smb2_tree_connect_response(tree_id)
    
    def _handle_smb2_negotiate(self, data: bytes) -> bytes:
        """Handle SMB2 negotiate request"""
        # SMB2 negotiate response
        response = bytearray(b'\x00\x00\x00\x41')  # NetBIOS header
        response += b'\xfeSMB'  # SMB2 signature
        response += b'\x40\x00'  # Header length
        response += b'\x00\x00'  # Credit charge
        response += b'\x00\x00\x00\x00'  # Status
        response += struct.pack('<H', SMB2Commands.SMB2_NEGOTIATE)  # Command
        response += b'\x01\x00'  # Credit response
        response += b'\x00\x00\x00\x00'  # Flags
        response += b'\x00\x00\x00\x00'  # Next command
        response += b'\x00' * 8  # Message ID
        response += b'\x00' * 4  # Process ID
        response += b'\x00' * 4  # Tree ID
        response += b'\x00' * 8  # Session ID
        response += b'\x00' * 16  # Signature
        response += b'\x41\x00'  # Structure size
        response += b'\x00\x00'  # Security mode
        response += b'\x11\x03'  # Dialect revision (SMB 3.1.1)
        response += b'\x00\x00'  # Negotiate context count
        response += b'\x00' * 16  # Server GUID
        response += b'\x00\x00\x00\x00'  # Capabilities
        response += b'\x00\x00\x01\x00'  # Max transact size
        response += b'\x00\x00\x01\x00'  # Max read size
        response += b'\x00\x00\x01\x00'  # Max write size
        response += b'\x00' * 8  # System time
        response += b'\x00' * 8  # Server start time
        response += b'\x80\x00'  # Security buffer offset
        response += b'\x00\x00'  # Security buffer length
        return bytes(response)
    
    def _create_smb1_session_setup_response(self, success: bool) -> bytes:
        """Create SMB1 session setup response"""
        status = NTStatus.STATUS_SUCCESS if success else NTStatus.STATUS_LOGON_FAILURE
        
        response = bytearray(b'\x00\x00\x00\x27')  # NetBIOS header
        response += b'\xffSMB'  # SMB signature
        response += bytes([SMBCommands.SMB_COM_SESSION_SETUP_ANDX])  # Command
        response += struct.pack('<L', status)  # Status
        response += b'\x18'  # Flags
        response += b'\x07\xc0'  # Flags2
        response += b'\x00\x00' * 6  # Process ID, etc.
        response += b'\xff'  # AndX command (none)
        response += b'\x00' * 7  # AndX parameters
        response += b'\x00\x00'  # Byte count
        return bytes(response)
    
    def _create_smb2_session_setup_response(self, success: bool, session_id: int) -> bytes:
        """Create SMB2 session setup response"""
        status = NTStatus.STATUS_SUCCESS if success else NTStatus.STATUS_LOGON_FAILURE
        
        response = bytearray(b'\x00\x00\x00\x48')  # NetBIOS header
        response += b'\xfeSMB'  # SMB2 signature
        response += b'\x40\x00'  # Header length
        response += b'\x00\x00'  # Credit charge
        response += struct.pack('<L', status)  # Status
        response += struct.pack('<H', SMB2Commands.SMB2_SESSION_SETUP)  # Command
        response += b'\x01\x00'  # Credit response
        response += b'\x01\x00\x00\x00'  # Flags (response)
        response += b'\x00\x00\x00\x00'  # Next command
        response += b'\x00' * 8  # Message ID
        response += b'\x00' * 4  # Process ID
        response += b'\x00' * 4  # Tree ID
        response += struct.pack('<Q', session_id)  # Session ID
        response += b'\x00' * 16  # Signature
        response += b'\x09\x00'  # Structure size
        response += b'\x00\x00'  # Session flags
        response += b'\x00\x00'  # Security buffer offset
        response += b'\x00\x00'  # Security buffer length
        return bytes(response)
    
    def _create_smb1_tree_connect_response(self, tree_id: int) -> bytes:
        """Create SMB1 tree connect response"""
        response = bytearray(b'\x00\x00\x00\x27')  # NetBIOS header
        response += b'\xffSMB'  # SMB signature
        response += bytes([SMBCommands.SMB_COM_TREE_CONNECT_ANDX])  # Command
        response += struct.pack('<L', NTStatus.STATUS_SUCCESS)  # Status
        response += b'\x18'  # Flags
        response += b'\x07\xc0'  # Flags2
        response += b'\x00\x00' * 6  # Process ID, etc.
        response += struct.pack('<H', tree_id)  # Tree ID
        response += b'\xff'  # AndX command (none)
        response += b'\x00' * 5  # AndX parameters
        response += b'\x00\x00'  # Byte count
        return bytes(response)
    
    def _create_smb2_tree_connect_response(self, tree_id: int) -> bytes:
        """Create SMB2 tree connect response"""
        response = bytearray(b'\x00\x00\x00\x48')  # NetBIOS header
        response += b'\xfeSMB'  # SMB2 signature
        response += b'\x40\x00'  # Header length
        response += b'\x00\x00'  # Credit charge
        response += struct.pack('<L', NTStatus.STATUS_SUCCESS)  # Status
        response += struct.pack('<H', SMB2Commands.SMB2_TREE_CONNECT)  # Command
        response += b'\x01\x00'  # Credit response
        response += b'\x01\x00\x00\x00'  # Flags (response)
        response += b'\x00\x00\x00\x00'  # Next command
        response += b'\x00' * 8  # Message ID
        response += b'\x00' * 4  # Process ID
        response += struct.pack('<L', tree_id)  # Tree ID
        response += b'\x00' * 8  # Session ID
        response += b'\x00' * 16  # Signature
        response += b'\x10\x00'  # Structure size
        response += b'\x01'  # Share type (disk)
        response += b'\x00'  # Reserved
        response += b'\x00\x00\x00\x00'  # Share flags
        response += b'\x00\x00\x00\x00'  # Capabilities
        response += b'\x00\x00\x00\x00'  # Maximal access
        return bytes(response)
    
    def _create_smb1_error_response(self, status: int) -> bytes:
        """Create SMB1 error response"""
        response = bytearray(b'\x00\x00\x00\x23')  # NetBIOS header
        response += b'\xffSMB'  # SMB signature
        response += b'\x00'  # Command (generic)
        response += struct.pack('<L', status)  # Status
        response += b'\x18'  # Flags
        response += b'\x07\xc0'  # Flags2
        response += b'\x00\x00' * 6  # Process ID, etc.
        response += b'\x00\x00'  # Byte count
        return bytes(response)
    
    def _create_smb2_error_response(self, status: int) -> bytes:
        """Create SMB2 error response"""
        response = bytearray(b'\x00\x00\x00\x40')  # NetBIOS header
        response += b'\xfeSMB'  # SMB2 signature
        response += b'\x40\x00'  # Header length
        response += b'\x00\x00'  # Credit charge
        response += struct.pack('<L', status)  # Status
        response += b'\x00\x00'  # Command (generic)
        response += b'\x01\x00'  # Credit response
        response += b'\x01\x00\x00\x00'  # Flags (response)
        response += b'\x00\x00\x00\x00'  # Next command
        response += b'\x00' * 8  # Message ID
        response += b'\x00' * 4  # Process ID
        response += b'\x00' * 4  # Tree ID
        response += b'\x00' * 8  # Session ID
        response += b'\x00' * 16  # Signature
        return bytes(response)
    
    async def _handle_telnet_command(self, command: str, session_data: Dict) -> bytes:
        """Handle telnet command for backward compatibility"""
        if command.lower() in ['quit', 'exit', 'bye']:
            return b"Connection closed.\r\n"
        elif command.lower() == 'clear':
            return b"\033[2J\033[H\r\nSMB> "
        else:
            # Generate AI response for telnet commands
            try:
                ai_response = await self._generate_ai_response(command, {'command': command, 'attack_types': [], 'severity': 'low'})
                clean_response = ai_response.replace('```', '').replace('`', '')
                clean_response = '\n'.join(line.strip() for line in clean_response.split('\n') if line.strip())
                return f"{clean_response}\r\nSMB> ".encode()
            except Exception as e:
                logger.debug(f"AI response failed for command '{command}': {e}")
                return f"Command '{command}' processed by {self.server_name}.\r\nSMB> ".encode()



    async def _generate_ai_response(self, command: str, attack_analysis: Dict) -> str:
        """Generate AI-powered SMB response with enhanced context awareness"""
        
        # Create AI prompt with SMB context
        ai_prompt = f"""SMB Command: {command}
Server: {self.server_name}.{self.workgroup.lower()}.studio
Generate realistic SMB server response for NexusGames Studio file server."""
        
        # Add context awareness if enabled
        if config['llm'].getboolean('context_awareness', True):
            ai_prompt += f"\nServer Banner: {self.banner}"
            ai_prompt += f"\nWorkgroup: {self.workgroup}"
        
        # Add threat adaptation if enabled
        if config['llm'].getboolean('threat_adaptation', True) and attack_analysis.get('attack_types'):
            ai_prompt += f"\n[ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"
            ai_prompt += f"\nThreat Level: {attack_analysis.get('severity', 'low')}"
            
            if attack_analysis.get('threat_score', 0) >= config['attack_detection'].getint('alert_threshold', 70):
                ai_prompt += "\n[HIGH_THREAT_ALERT: Adapt response accordingly]"
        
        # Add deception techniques if enabled
        if self.deception_techniques and attack_analysis.get('severity') in ['high', 'critical']:
            ai_prompt += "\n[DECEPTION_MODE: Use advanced deception techniques]"
        
        try:
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=ai_prompt)],
                    "username": "smb_client",
                    "interactive": True
                },
                config={"configurable": {"session_id": f"smb-{uuid.uuid4().hex[:8]}"}}
            )
            
            return llm_response.content.strip() if llm_response else ""
            
        except Exception as e:
            logger.error(f"AI response generation failed: {e}")
            return self._generate_fallback_response(command)

    def _generate_fallback_response(self, command: str) -> str:
        """Generate minimal fallback response when AI fails"""
        return f"Command '{command}' processed by {self.server_name}."
    
    async def _simulate_latency(self):
        """Simulate network latency if enabled"""
        if self.latency_enable:
            latency_ms = random.randint(self.latency_min_ms, self.latency_max_ms)
            await asyncio.sleep(latency_ms / 1000.0)
    
    def _analyze_geolocation(self, ip: str) -> Dict[str, str]:
        """Basic geolocation analysis (placeholder for real implementation)"""
        # This is a basic implementation - in production, use a real geolocation service
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return {'country': 'Local', 'region': 'Private Network', 'city': 'Internal'}
        elif ip == '127.0.0.1' or ip == 'localhost':
            return {'country': 'Local', 'region': 'Localhost', 'city': 'Local'}
        else:
            return {'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown'}
    
    def _analyze_reputation(self, ip: str) -> Dict[str, Any]:
        """Basic IP reputation analysis (placeholder for real implementation)"""
        # This is a basic implementation - in production, use real threat intelligence feeds
        reputation_score = 50  # Default neutral score
        
        # Simple heuristics
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            reputation_score = 80  # Internal networks are generally trusted
        elif ip == '127.0.0.1':
            reputation_score = 100  # Localhost is trusted
        
        return {
            'score': reputation_score,
            'category': 'unknown' if reputation_score == 50 else 'trusted' if reputation_score > 70 else 'suspicious',
            'last_updated': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

async def start_server():
    """Start the SMB honeypot server"""
    honeypot = SMBHoneypot()
    
    port = config['smb'].getint('port', 445)
    llm_provider = config['llm'].get('llm_provider', 'openai')
    model_name = config['llm'].get('model_name', 'gpt-4o-mini')
    
    print(f"\n✅ SMB Honeypot Starting...")
    print(f"📡 Port: {port}")
    print(f"🖥️  Server: {honeypot.server_name}.{honeypot.workgroup.lower()}.studio")
    print(f"🏢 Workgroup: {honeypot.workgroup}")
    print(f"📋 Banner: {honeypot.banner}")
    print(f"🤖 LLM Provider: {llm_provider}")
    print(f"📊 Model: {model_name}")
    print(f"🔍 Sensor: {sensor_name}")
    print(f"📁 Log File: {config['honeypot'].get('log_file', 'smb_log.log')}")
    print(f"🔗 Max Connections: {honeypot.max_connections}")
    print(f"⏱️  Connection Timeout: {honeypot.connection_timeout}s")
    print(f"🛡️  Rate Limiting: {'Enabled' if honeypot.rate_limiting else 'Disabled'}")
    print(f"🌍 Geolocation Analysis: {'Enabled' if honeypot.geolocation_analysis else 'Disabled'}")
    print(f"🔍 Behavioral Analysis: {'Enabled' if honeypot.behavioral_analysis else 'Disabled'}")
    print(f"🎭 Adaptive Responses: {'Enabled' if honeypot.adaptive_responses else 'Disabled'}")
    print(f"⚠️  Press Ctrl+C to stop\n")
    
    server = await asyncio.start_server(
        honeypot.handle_connection,
        '0.0.0.0',
        port
    )
    
    logger.info(f"SMB honeypot started on 0.0.0.0:{port}")
    print(f"✅ SMB honeypot listening on 0.0.0.0:{port}")
    print("📡 Ready for connections...")
    
    async with server:
        await server.serve_forever()

class ContextFilter(logging.Filter):
    """Filter to add connection details to log records"""

    def filter(self, record):
        try:
            task_name = getattr(asyncio.current_task(), 'get_name', lambda: '-')()
        except RuntimeError:
            task_name = thread_local.__dict__.get('session_id', '-')

        record.src_ip = thread_local.__dict__.get('src_ip', '-')
        record.src_port = thread_local.__dict__.get('src_port', '-')   
        record.dst_ip = thread_local.__dict__.get('dst_ip', '-')
        record.dst_port = thread_local.__dict__.get('dst_port', '-')
        record.task_name = task_name
        
        return True

def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]

def get_user_accounts() -> dict:
    if (not 'user_accounts' in config) or (len(config.items('user_accounts')) == 0):
        return {'admin': 'admin', 'guest': 'guest'}
    
    accounts = dict()
    for k, v in config.items('user_accounts'):
        accounts[k] = v
    return accounts

def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    llm_provider_name = llm_provider or config['llm'].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = model_name or config['llm'].get("model_name", "gpt-4o-mini")
    
    temperature = config['llm'].getfloat("temperature", 0.2)
    base_kwargs = {"temperature": temperature}
    openai_kwargs = {**base_kwargs, "request_timeout": 30, "max_retries": 2}
    gemini_kwargs = {**base_kwargs, "timeout": 30}
    other_kwargs = {**base_kwargs, "request_timeout": 30, "max_retries": 2}

    if llm_provider_name == 'openai':
        llm_model = ChatOpenAI(model=model_name, **openai_kwargs)
    elif llm_provider_name == 'azure':
        llm_model = AzureChatOpenAI(
            azure_deployment=config['llm'].get("azure_deployment"),
            azure_endpoint=config['llm'].get("azure_endpoint"),
            api_version=config['llm'].get("azure_api_version"),
            model=config['llm'].get("model_name"),
            **openai_kwargs
        )
    elif llm_provider_name == 'ollama':
        base_url = config['llm'].get('base_url', 'http://localhost:11434')
        llm_model = ChatOllama(model=model_name, base_url=base_url, **other_kwargs)
    elif llm_provider_name == 'aws':
        llm_model = ChatBedrockConverse(
            model=model_name,
            region_name=config['llm'].get("aws_region", "us-east-1"),
            credentials_profile_name=config['llm'].get("aws_credentials_profile", "default"),
            **other_kwargs
        )
    elif llm_provider_name == 'gemini':
        llm_model = ChatGoogleGenerativeAI(model=model_name, **gemini_kwargs)
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    return llm_model

def get_prompts(prompt: Optional[str], prompt_file: Optional[str]) -> dict:
    system_prompt = config['llm']['system_prompt']
    if prompt is not None:
        if not prompt.strip():
            print("Error: The prompt text cannot be empty.", file=sys.stderr)
            sys.exit(1)
        user_prompt = prompt
    elif prompt_file:
        if not os.path.exists(prompt_file):
            print(f"Error: The specified prompt file '{prompt_file}' does not exist.", file=sys.stderr)
            sys.exit(1)
        # amazonq-ignore-next-line
        with open(prompt_file, "r") as f:
            user_prompt = f.read()
    elif os.path.exists("prompt.txt"):
        with open("prompt.txt", "r") as f:
            user_prompt = f.read()
    else:
        raise ValueError("Either prompt or prompt_file must be provided.")
    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt
    }

#### MAIN ####

try:
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Start the SMB honeypot server.')
    parser.add_argument('-c', '--config', type=str, default=None, help='Path to the configuration file')
    parser.add_argument('-p', '--prompt', type=str, help='The entire text of the prompt')
    parser.add_argument('-f', '--prompt-file', type=str, default='prompt.txt', help='Path to the prompt file')
    parser.add_argument('-l', '--llm-provider', type=str, help='The LLM provider to use')
    parser.add_argument('-m', '--model-name', type=str, help='The model name to use')
    parser.add_argument('-t', '--trimmer-max-tokens', type=int, help='The maximum number of tokens to send to the LLM backend in a single request')
    parser.add_argument('-s', '--system-prompt', type=str, help='System prompt for the LLM')
    parser.add_argument('-r', '--temperature', type=float, help='Temperature parameter for controlling randomness in LLM responses (0.0-2.0)')
    parser.add_argument('-P', '--port', type=int, help='The port the SMB honeypot will listen on')
    parser.add_argument('-L', '--log-file', type=str, help='The name of the file you wish to write the honeypot log to')
    parser.add_argument('-S', '--sensor-name', type=str, help='The name of the sensor, used to identify this honeypot in the logs')
    parser.add_argument('-u', '--user-account', action='append', help='User account in the form username=password. Can be repeated.')
    args = parser.parse_args()

    # Determine which config file to load
    config = ConfigParser()
    if args.config is not None:
        if not os.path.exists(args.config):
            print(f"Error: The specified config file '{args.config}' does not exist.", file=sys.stderr)
            sys.exit(1)
        config.read(args.config)
    else:
        default_config = "config.ini"
        if os.path.exists(default_config):
            config.read(default_config)
        else:
            # Use defaults when no config file found
            default_log_file = str(Path(__file__).parent.parent.parent / 'logs' / 'smb_log.log')
            config['honeypot'] = {
                'log_file': default_log_file, 
                'sensor_name': socket.gethostname(),
                'sessions_dir': 'sessions',
                'latency_min_ms': '20',
                'latency_max_ms': '250',
                'latency_enable': 'false',
                'attack_logging': 'true',
                'behavioral_analysis': 'true',
                'forensic_chain': 'true',
                'adaptive_responses': 'true'
            }
            config['smb'] = {
                'port': '445',
                'server_name': 'NEXUS-FS-01',
                'workgroup': 'NEXUSGAMES',
                'banner': 'NexusGames Studio File Server v3.1.1',
                'welcome_message': 'Welcome to NexusGames Studio File Server',
                'max_connections': '100',
                'connection_timeout': '300',
                'enable_smb1': 'true',
                'enable_smb2': 'true',
                'enable_netbios': 'true',
                'default_permissions': 'read',
                'allow_guest': 'true',
                'guest_account': 'guest'
            }
            config['llm'] = {
                'llm_provider': 'openai', 
                'model_name': 'gpt-3.5-turbo', 
                'trimmer_max_tokens': '64000', 
                'temperature': '0.7', 
                'system_prompt': '',
                'context_awareness': 'true',
                'threat_adaptation': 'true'
            }
            config['user_accounts'] = {}
            config['ai_features'] = {
                'dynamic_responses': 'true',
                'attack_pattern_recognition': 'true',
                'vulnerability_detection': 'true',
                'real_time_analysis': 'true',
                'ai_attack_summaries': 'true',
                'adaptive_banners': 'true',
                'deception_techniques': 'true'
            }
            config['attack_detection'] = {
                'sensitivity_level': 'medium',
                'threat_scoring': 'true',
                'alert_threshold': '70',
                'geolocation_analysis': 'true',
                'reputation_filtering': 'true'
            }
            config['forensics'] = {
                'file_monitoring': 'true',
                'save_uploads': 'true',
                'save_downloads': 'true',
                'file_hash_analysis': 'true',
                'malware_detection': 'true',
                'forensic_reports': 'true',
                'chain_of_custody': 'true'
            }
            config['features'] = {
                'save_downloads': 'true',
                'save_replay': 'true',
                'downloads_dir': 'downloads',
                'uploads_dir': 'uploads',
                'session_recording': 'true',
                'command_replay': 'true',
                'network_analysis': 'true',
                'process_monitoring': 'true'
            }
            config['logging'] = {
                'log_level': 'INFO',
                'structured_logging': 'true',
                'real_time_streaming': 'true'
            }
            config['security'] = {
                'ip_reputation': 'true',
                'rate_limiting': 'true',
                'max_connections_per_ip': '5',
                'intrusion_detection': 'true',
                'automated_blocking': 'false'
            }

    # Override config values with command line arguments if provided
    if args.llm_provider:
        config['llm']['llm_provider'] = args.llm_provider
    if args.model_name:
        config['llm']['model_name'] = args.model_name
    if args.trimmer_max_tokens:
        config['llm']['trimmer_max_tokens'] = str(args.trimmer_max_tokens)
    if args.system_prompt:
        config['llm']['system_prompt'] = args.system_prompt
    if args.temperature is not None:
        config['llm']['temperature'] = str(args.temperature)
    if args.port:
        config['smb']['port'] = str(args.port)
    if args.log_file:
        config['honeypot']['log_file'] = args.log_file
    if args.sensor_name:
        config['honeypot']['sensor_name'] = args.sensor_name

    # Merge command-line user accounts into the config
    if args.user_account:
        if 'user_accounts' not in config:
            config['user_accounts'] = {}
        for account in args.user_account:
            if '=' in account:
                key, value = account.split('=', 1)
                config['user_accounts'][key.strip()] = value.strip()
            else:
                config['user_accounts'][account.strip()] = ''

    # Read the user accounts from the configuration
    accounts = get_user_accounts()

    # Always use UTC for logging
    logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T",timespec="milliseconds"))

    # Get the sensor name from the config or use the system's hostname
    sensor_name = config['honeypot'].get('sensor_name', socket.gethostname())

    # Set up the honeypot logger with configurable log level
    logger = logging.getLogger(__name__)  
    log_level = config['logging'].get('log_level', 'INFO').upper()  # Back to INFO to reduce noise
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "smb_log.log"))
    logger.addHandler(log_file_handler)

    # Configure structured logging
    if config['logging'].getboolean('structured_logging', True):
        log_file_handler.setFormatter(JSONFormatter(sensor_name))
    else:
        log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    
    # Add console handler for real-time streaming if enabled
    if config['logging'].getboolean('real_time_streaming', True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        if config['logging'].getboolean('structured_logging', True):
            console_handler.setFormatter(JSONFormatter(sensor_name))
        else:
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(console_handler)

    f = ContextFilter()
    logger.addFilter(f)

    # Now get access to the LLM
    prompts = get_prompts(args.prompt, args.prompt_file)
    llm_system_prompt = prompts["system_prompt"]
    llm_user_prompt = prompts["user_prompt"]

    llm = choose_llm(config['llm'].get("llm_provider"), config['llm'].get("model_name"))

    llm_sessions = dict()

    llm_trimmer = trim_messages(
        max_tokens=config['llm'].getint("trimmer_max_tokens", 64000),
        strategy="last",
        token_counter=llm,
        include_system=True,
        allow_partial=False,
        start_on="human",
    )

    llm_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                llm_system_prompt
            ),
            (
                "system",
                llm_user_prompt
            ),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    llm_chain = (
        RunnablePassthrough.assign(messages=itemgetter("messages") | llm_trimmer)
        | llm_prompt
        | llm
    )

    with_message_history = RunnableWithMessageHistory(
        llm_chain, 
        llm_get_session_history,
        input_messages_key="messages"
    )
    
    # Thread-local storage for connection details
    thread_local = threading.local()

    # Kick off the server!
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n🛑 SMB honeypot stopped by user")
        logger.info("SMB honeypot stopped by user")
    finally:
        try:
            loop.close()
        except Exception:
            pass

except KeyboardInterrupt:
    print("\n🛑 SMB honeypot stopped by user")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)