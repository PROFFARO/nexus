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

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")
    print("Environment variables will be loaded from system environment only.")

class AttackAnalyzer:
    """AI-based attack behavior analyzer with integrated JSON patterns"""
    
    def __init__(self):
        # Load attack patterns from JSON file
        self.attack_patterns = self._load_attack_patterns()
        # Load vulnerability signatures from JSON file  
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
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
                'reconnaissance': {'patterns': [r'LIST', r'NLST', r'PWD', r'SYST'], 'severity': 'medium'},
                'privilege_escalation': {'patterns': [r'SITE.*CHMOD', r'SITE.*EXEC'], 'severity': 'high'}
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
        """Analyze an FTP command for attack patterns using integrated JSON data"""
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
            analysis['threat_score'] = threat_score
            
            # Check alert threshold
            alert_threshold = config['attack_detection'].getint('alert_threshold', 70)
            analysis['alert_triggered'] = threat_score >= alert_threshold
        
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
        """Handle file download requests (RETR command)"""
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
        
    def _generate_fake_file_content(self, filename: str) -> bytes:
        """Generate realistic fake file content based on file type"""
        filename_lower = filename.lower()
        
        if filename_lower.endswith(('.txt', '.log', '.conf', '.cfg')):
            # Text configuration files
            content = f"""# Configuration file for NexusGames Studio
# Generated: {datetime.datetime.now()}
# This is a honeypot simulation

server_name=nexus-ftp-01
max_connections=100
allow_anonymous=false
local_enable=true
write_enable=true
local_umask=022
dirmessage_enable=true
use_localtime=true
xferlog_enable=true
connect_from_port_20=true
chroot_local_user=true
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=false
""".encode()
        elif filename_lower.endswith(('.sh', '.bash')):
            # Shell scripts
            content = f"""#!/bin/bash
# NexusGames Studio deployment script
# This is a honeypot simulation

echo "Starting game server deployment..."
echo "Connecting to production servers..."
echo "Deploying build artifacts..."
echo "Updating configuration files..."
echo "Restarting services..."
echo "Deployment complete!"
""".encode()
        elif filename_lower.endswith(('.py', '.python')):
            # Python scripts
            content = f"""#!/usr/bin/env python3
# NexusGames Studio automation script
# This is a honeypot simulation

import os
import sys
import time

def deploy_game_build():
    print("Deploying game build...")
    print("Validating assets...")
    print("Uploading to CDN...")
    print("Updating database...")
    print("Build deployed successfully!")

if __name__ == "__main__":
    deploy_game_build()
""".encode()
        elif filename_lower.endswith(('.sql', '.db')):
            # Database files
            content = f"""-- NexusGames Studio Database Schema
-- This is a honeypot simulation

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    created_at TIMESTAMP
);

CREATE TABLE games (
    id INT PRIMARY KEY,
    title VARCHAR(100),
    genre VARCHAR(50),
    release_date DATE
);

INSERT INTO users VALUES (1, 'admin', 'admin@nexusgames.com', NOW());
INSERT INTO games VALUES (1, 'Stellar Conquest', 'Strategy', '2024-12-01');
""".encode()
        else:
            # Generic file
            content = f"""NexusGames Studio File: {filename}
Created: {datetime.datetime.now()}
This is a honeypot simulation file.

File contains sensitive game development data.
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
        
        if filename_lower.endswith(('.txt', '.log', '.conf', '.cfg')):
            return 'text_file'
        elif filename_lower.endswith(('.sh', '.bash')):
            return 'shell_script'
        elif filename_lower.endswith(('.py', '.python')):
            return 'python_script'
        elif filename_lower.endswith(('.sql', '.db')):
            return 'database_file'
        elif b'#!/bin/bash' in content[:100]:
            return 'shell_script'
        elif b'#!/usr/bin/env python' in content[:100]:
            return 'python_script'
        else:
            return 'unknown'
        
    def handle_upload(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Handle file uploads via STOR command"""
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
                'FTP_BOUNCE_ATTACK': {'patterns': [r'PORT.*127\.0\.0\.1', r'PORT.*localhost'], 'severity': 'high'},
                'DIRECTORY_TRAVERSAL': {'patterns': [r'\.\./\.\./\.\./', r'\.\.\\\.\.\\\.\.\\'], 'severity': 'critical'}
            }
        
    def analyze_for_vulnerabilities(self, command: str, headers: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Analyze FTP command for vulnerability exploitation attempts using JSON data"""
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
        # amazonq-ignore-next-line
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
        # Check if chain of custody is enabled
        if not config['forensics'].getboolean('chain_of_custody', True):
            return
            
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                content = f.read()
                
            evidence = {
                'evidence_id': str(uuid.uuid4()),
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'type': evidence_type,
                'file_path': file_path,
                'file_size': len(content),
                'description': description
            }
            
            # Add file hash analysis if enabled
            if config['forensics'].getboolean('file_hash_analysis', True):
                evidence['file_hash'] = hashlib.sha256(content).hexdigest()
                evidence['md5_hash'] = hashlib.md5(content).hexdigest()
            
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
            "sensor_protocol": "ftp"
        }
        if hasattr(record, 'interactive'):
            log_record["interactive"] = getattr(record, "interactive", True)
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key not in ['args', 'msg', 'exc_info', 'exc_text', 'stack_info', 'pathname', 'filename', 'module', 'funcName', 'lineno', 'created', 'msecs', 'relativeCreated', 'thread', 'threadName', 'processName', 'process']:
                log_record[key] = value
        return json.dumps(log_record)

class FTPSession:
    """Represents an FTP session with AI-enhanced responses"""
    
    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server
        self.authenticated = False
        self.username = ""
        self.current_directory = "/home/ftp"
        self.data_connection = None
        self.data_reader = None
        self.data_writer = None
        self.data_ip = None
        self.data_port = None
        self.passive_port = None
        self.transfer_mode = "ASCII"
        self.session_data = {
            'commands': [],
            'files_uploaded': [],
            'files_downloaded': [],
            'vulnerabilities': [],
            'attack_analysis': [],
            'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        # Initialize seed filesystem if configured
        self.seed_fs = self._load_seed_filesystem()
        self.seed_first_reply = config['honeypot'].getboolean('seed_first_reply', False)
        # Initialize session recording if enabled
        self.session_recording = config['features'].getboolean('session_recording', True)
        self.save_replay = config['features'].getboolean('save_replay', True)
        self.session_transcript = [] if self.session_recording else None
        
        # Initialize integrated components
        self._initialize_components(server)
        
    def _load_seed_filesystem(self) -> Dict[str, Any]:
        """Load seed filesystem from configured directory"""
        seed_dir = config['honeypot'].get('seed_fs_dir', '')
        if not seed_dir or not os.path.exists(seed_dir):
            return {}
        
        try:
            seed_fs = {}
            for root, dirs, files in os.walk(seed_dir):
                rel_path = os.path.relpath(root, seed_dir)
                if rel_path == '.':
                    rel_path = '/home/ftp'
                else:
                    rel_path = f'/home/ftp/{rel_path.replace(os.sep, "/")}'
                
                seed_fs[rel_path] = {
                    'dirs': dirs[:],
                    'files': files[:]
                }
            return seed_fs
        except Exception as e:
            logger.error(f"Failed to load seed filesystem: {e}")
            return {}
    
    def _initialize_components(self, server):
        """Initialize integrated components"""
        try:
            self.attack_analyzer = AttackAnalyzer()
            self.file_handler = FileTransferHandler(str(server.session_dir)) if config['forensics'].getboolean('file_monitoring', True) else None
            self.vuln_logger = VulnerabilityLogger()
            self.forensic_logger = ForensicChainLogger(str(server.session_dir)) if config['forensics'].getboolean('chain_of_custody', True) else None
        except Exception as e:
            logger.error(f"Failed to initialize FTP session components: {e}")
            self.attack_analyzer = None
            self.file_handler = None
            self.vuln_logger = None
            self.forensic_logger = None

    async def send_response(self, code: int, message: str):
        """Send FTP response to client"""
        response = f"{code} {message}\r\n"
        self.writer.write(response.encode())
        await self.writer.drain()
        
        # Record response in session transcript if enabled
        if self.session_recording and self.session_transcript is not None:
            self.session_transcript.append({
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'type': 'output',
                'content': response.strip(),
                'code': code,
                'message': message
            })
        
        # Log response
        logger.info("FTP response", extra={
            "details": b64encode(response.encode('utf-8')).decode('utf-8'),
            "response_code": code,
            "response_message": message
        })

    async def handle_command(self, command_line: str):
        """Handle FTP command with AI analysis"""
        command_line = command_line.strip()
        if not command_line:
            return
            
        # Handle special case where user just types password after USER command
        if not command_line.upper().startswith(('USER', 'PASS', 'QUIT', 'HELP', 'LIST', 'NLST', 'PWD', 'CWD', 'SYST', 'PORT', 'PASV', 'TYPE', 'RETR', 'STOR', 'NOOP', 'CDUP', 'LS', 'DIR')) and self.username and not self.authenticated:
            # Treat as password
            command = "PASS"
            args = command_line
        else:
            # Parse command normally
            parts = command_line.split(' ', 1)
            command = parts[0].upper()
            # Handle telnet aliases
            if command == "LS" or command == "DIR":
                command = "LIST"
            args = parts[1] if len(parts) > 1 else ""
        
        # Record session transcript if enabled
        if self.session_recording and self.session_transcript is not None:
            self.session_transcript.append({
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'type': 'input',
                'content': command_line,
                'command': command,
                'args': args
            })
        
        # Log command
        logger.info("FTP command", extra={
            "details": b64encode(command_line.encode('utf-8')).decode('utf-8'),
            "command": command,
            "command_args": args,
            "username": self.username
        })
        
        # Analyze command for attacks if real-time analysis is enabled
        attack_analysis = {'command': command_line, 'attack_types': [], 'severity': 'low'}
        vulnerabilities = []
        
        if self.attack_analyzer and config['ai_features'].getboolean('real_time_analysis', True):
            try:
                attack_analysis = self.attack_analyzer.analyze_command(command_line)
                self.session_data['attack_analysis'].append(attack_analysis)
            except Exception as e:
                logger.error(f"Attack analysis failed: {e}")
        
        if self.vuln_logger and config['ai_features'].getboolean('vulnerability_detection', True):
            try:
                vulnerabilities = self.vuln_logger.analyze_for_vulnerabilities(command_line)
                self.session_data['vulnerabilities'].extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Vulnerability analysis failed: {e}")
        
        # Log attack analysis if threats detected
        if attack_analysis.get('attack_types'):
            log_extra = {
                "attack_types": attack_analysis['attack_types'],
                "severity": attack_analysis['severity'],
                "indicators": attack_analysis.get('indicators', []),
                "command": command_line
            }
            
            # Add threat score if available
            if 'threat_score' in attack_analysis:
                log_extra['threat_score'] = attack_analysis['threat_score']
                
            # Check if alert should be triggered
            if attack_analysis.get('alert_triggered', False):
                logger.critical("High-threat FTP attack detected", extra=log_extra)
            else:
                logger.warning("FTP attack pattern detected", extra=log_extra)
                
            if self.forensic_logger:
                try:
                    self.forensic_logger.log_event("attack_detected", attack_analysis)
                except Exception as e:
                    logger.error(f"Forensic logging failed: {e}")
        
        # Log vulnerabilities with enhanced context
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = dict(vuln)
                enhanced_vuln['related_attack_types'] = attack_analysis.get('attack_types', [])
                enhanced_vuln['overall_severity'] = attack_analysis.get('severity', 'low')
                enhanced_vuln['threat_score'] = attack_analysis.get('threat_score', 0)
                
                # Check alert threshold for vulnerabilities
                alert_threshold = config['attack_detection'].getint('alert_threshold', 70)
                if enhanced_vuln['threat_score'] >= alert_threshold:
                    logger.critical("Critical FTP vulnerability exploitation attempt", extra=enhanced_vuln)
                else:
                    logger.critical("FTP vulnerability exploitation attempt", extra=enhanced_vuln)
                    
                if self.forensic_logger:
                    self.forensic_logger.log_event("vulnerability_exploit", enhanced_vuln)
            except Exception as e:
                logger.error(f"Vulnerability logging failed: {e}")
        
        # Store command in session data
        self.session_data['commands'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'command': command_line,
            'attack_analysis': attack_analysis,
            'vulnerabilities': vulnerabilities
        })
        
        # Handle specific FTP commands
        result = await self.handle_ftp_command(command, args, attack_analysis)
        return result if result is not None else True

    async def handle_ftp_command(self, command: str, args: str, attack_analysis: Dict[str, Any]):
        """Handle FTP commands with AI-enhanced responses like SSH server"""
        
        # Handle authentication commands specially
        if command == "USER":
            self.username = args
            await self.send_response(331, f"Password required for {args}")
            return True
        elif command == "PASS":
            if not self.username:
                await self.send_response(503, "Login with USER first")
                return True
            if self.username in accounts and (args == accounts[self.username] or accounts[self.username] == "*"):
                self.authenticated = True
                await self.send_response(230, f"User {self.username} logged in")
                logger.info("FTP authentication success", extra={"username": self.username, "password": args})
            else:
                await self.send_response(530, "Login incorrect")
                logger.info("FTP authentication failed", extra={"username": self.username, "password": args})
            return True
        elif command == "QUIT":
            await self.send_response(221, "Goodbye")
            return False
        elif command == "PORT":
            await self.handle_active_mode(args)
            return True
        elif command == "LIST" or command == "NLST":
            if not self.authenticated:
                await self.send_response(530, "Not logged in")
                return True
            await self.handle_list_command(command, args, attack_analysis)
            return True
        elif command == "HELP":
            await self.send_response(214, "The following commands are supported:")
            await self.send_response(214, "USER PASS QUIT SYST PORT PASV TYPE RETR STOR")
            await self.send_response(214, "LIST NLST PWD CWD CDUP NOOP HELP")
            await self.send_response(214, "This is an FTP server running at ftp.nexusgames.studio.")
            await self.send_response(214, "For assistance, please contact the NexusGames IT department.")
            return True
        
        # Let AI handle ALL other commands like SSH does
        full_command = f"{command} {args}".strip()
        
        # Create AI prompt with FTP context
        ai_prompt = f"FTP: {full_command}\nDir: {self.current_directory}\nUser: {self.username}\nAuth: {self.authenticated}\nRespond with standard FTP code and message."
        
        # Apply dynamic responses if enabled
        if config['ai_features'].getboolean('dynamic_responses', True) and attack_analysis.get('attack_types'):
            ai_prompt += f"\n[ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"
        
        # Apply deception techniques if enabled
        if config['ai_features'].getboolean('deception_techniques', True):
            # Add deception context for more realistic responses
            if 'reconnaissance' in attack_analysis.get('attack_types', []):
                ai_prompt += "\n[DECEPTION: Show realistic but controlled directory information]"
            elif 'privilege_escalation' in attack_analysis.get('attack_types', []):
                ai_prompt += "\n[DECEPTION: Simulate security resistance while logging attempts]"
        
        try:
            # Get AI response for the command
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=ai_prompt)],
                    "username": self.username or "anonymous",
                    "interactive": True
                },
                config={"configurable": {"session_id": f"ftp-{self.username or 'anon'}-{uuid.uuid4().hex[:8]}"}}
            )
            
            ai_output = llm_response.content.strip() if llm_response else ""
            logger.debug("LLM raw output for command", extra={"command": full_command, "ai_output_preview": (ai_output[:200] + '...') if len(ai_output) > 200 else ai_output})
            
            # Parse AI response for proper FTP formatting
            if ai_output:
                lines = ai_output.strip().split('\n')
                first_line = lines[0].strip()
                
                # Check if first line has proper FTP code format
                if len(first_line) >= 3 and first_line[:3].isdigit():
                    try:
                        code = int(first_line[:3])
                        message = first_line[4:] if len(first_line) > 4 else "OK"
                        await self.send_response(code, message)
                        
                        # Send additional lines directly to telnet clients
                        for line in lines[1:]:
                            if line.strip():
                                response = f"{line.strip()}\r\n"
                                self.writer.write(response.encode())
                                await self.writer.drain()
                    except ValueError:
                        await self.send_response(200, first_line)
                        # Send remaining lines for multi-line responses
                        for line in lines[1:]:
                            if line.strip():
                                response = f"{line.strip()}\r\n"
                                self.writer.write(response.encode())
                                await self.writer.drain()
                else:
                    await self.send_response(200, first_line)
                    # Send remaining lines for multi-line responses
                    for line in lines[1:]:
                        if line.strip():
                            response = f"{line.strip()}\r\n"
                            self.writer.write(response.encode())
                            await self.writer.drain()
            else:
                await self.send_response(200, "Command processed")
                    
        except Exception as e:
            logger.error(f"AI command processing failed: {e}")
            # Fallback to basic responses
            if command == "OPTS" and args.upper() == "UTF8 ON":
                await self.send_response(200, "OPTS set to UTF8.")
            elif command == "SYST":
                await self.send_response(215, "UNIX Type: L8")
            elif command == "PWD":
                await self.send_response(257, f'"{self.current_directory}" is current directory')
            else:
                await self.send_response(502, "Command not implemented")
                
        return True

    async def handle_list_command(self, command: str, args: str, attack_analysis: Dict[str, Any]):
        """Handle LIST/NLST commands with proper data connection"""
        
        await self.send_response(150, "Opening data connection for directory list")
        
        # First, try to get a dynamic listing from the LLM
        directory_listing = None
        # Read llm_list_timeout safely (ConfigParser may not have getfloat with fallback in some setups)
        try:
            if 'ftp' in config:
                val = config['ftp'].get('llm_list_timeout')
                if val is not None:
                    try:
                        llm_list_timeout = float(val)
                    except Exception:
                        llm_list_timeout = 3.0
                else:
                    llm_list_timeout = 3.0
            else:
                llm_list_timeout = 3.0
        except Exception:
            llm_list_timeout = 3.0
        try:
            ai_prompt = f"FTP LIST command request\nCurrent directory: {self.current_directory}\nUser: {self.username}\nAuthenticated: {self.authenticated}\nArgs: {args}"
            start_ts = datetime.datetime.now()
            llm_response = await asyncio.wait_for(
                with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=ai_prompt)],
                        "username": self.username or "anonymous",
                        "interactive": True
                    },
                    config={"configurable": {"session_id": f"ftp-list-{self.username or 'anon'}-{uuid.uuid4().hex[:8]}"}}
                ),
                timeout=llm_list_timeout
            )
            took = (datetime.datetime.now() - start_ts).total_seconds()
            if llm_response and llm_response.content:
                ai_text = llm_response.content.strip()
                # Accept AI listing unless it is clearly a single FTP status line (e.g., "226 Transfer complete")
                lines = [l for l in ai_text.splitlines() if l.strip()]
                if not (len(lines) == 1 and re.match(r'^[245]\d{2}\b', lines[0])):
                    # If AI returned leading control codes like 150/226, strip them and treat remaining as listing
                    if re.match(r'^[12]\d{2}\b', lines[0]):
                        # remove the first control line
                        lines = lines[1:]
                    directory_listing = "\n".join(lines) if lines else None
                    logger.info("AI provided directory listing", extra={"username": self.username, "directory": self.current_directory, "llm_time_s": took})
                else:
                    logger.debug("AI returned only a status line for LIST; falling back", extra={"ai_text": ai_text, "llm_time_s": took})
        except asyncio.TimeoutError:
            logger.warning("AI LIST request timed out, using fallback listing", extra={"username": self.username})
        except Exception as e:
            logger.error(f"AI LIST generation failed: {e}", extra={"username": self.username})

        # Generate directory listing fallback if AI did not provide one
        if not directory_listing:
            directory_listing = self._generate_fallback_listing()
        
        # Parse AI-provided control lines vs data lines
        final_code = None
        final_message = None
        try:
            lines = [l for l in directory_listing.splitlines()]
            control_lines = [l for l in lines if re.match(r'^[1-5]\d{2}\b', l.strip())]
            data_lines = [l for l in lines if not re.match(r'^[1-5]\d{2}\b', l.strip())]

            # If AI provided a final control code (e.g., 226 Transfer complete), use it
            if control_lines:
                last_ctrl = control_lines[-1].strip()
                m = re.match(r'^([1-5]\d{2})\s*(.*)$', last_ctrl)
                if m:
                    final_code = int(m.group(1))
                    final_message = m.group(2).strip() or None

            # If AI returned data lines, prefer those as listing; otherwise if only control lines, no data
            send_payload = "\n".join(data_lines) if data_lines else ("\n".join(lines) if lines and not control_lines else "")

            # Send data via data connection (simulated)
            if send_payload:
                if hasattr(self, 'data_writer') and self.data_writer:
                    try:
                        self.data_writer.write(send_payload.encode() + b'\r\n')
                        await self.data_writer.drain()
                        self.data_writer.close()
                        await self.data_writer.wait_closed()
                        self.data_writer = None
                    except Exception as e:
                        logger.error(f"Data connection error: {e}")
                else:
                    # Send directory listing directly to telnet clients via control connection
                    for line in send_payload.split('\n'):
                        if line.strip():
                            response = f"{line.strip()}\r\n"
                            self.writer.write(response.encode())
                            await self.writer.drain()

        except Exception as e:
            logger.error(f"Error preparing listing payload: {e}")
            final_code = None

        # Simulate data transfer time
        await asyncio.sleep(0.1)

        # Send final response: prefer AI-provided final code/message, otherwise default 226
        if final_code:
            try:
                await self.send_response(final_code, final_message or "")
            except Exception as e:
                logger.error(f"Failed to send AI-provided final response: {e}")
                await self.send_response(226, "Transfer complete")
        else:
            await self.send_response(226, "Transfer complete")
        
        logger.info("FTP directory listing", extra={
            "details": b64encode(directory_listing.encode('utf-8')).decode('utf-8'),
            "command": command,
            "directory": self.current_directory,
            "ai_response": directory_listing
        })

    async def handle_download(self, filename: str, attack_analysis: Dict[str, Any]):
        """Handle file download (RETR command)"""
        
        if self.file_handler:
            try:
                download_info = self.file_handler.handle_download(filename)
                self.session_data['files_downloaded'].append(download_info)
                
                await self.send_response(150, f"Opening data connection for {filename}")
                await asyncio.sleep(0.2)  # Simulate transfer time
                await self.send_response(226, "Transfer complete")
                
                logger.info("FTP file download", extra=download_info)
                
                if self.forensic_logger:
                    self.forensic_logger.log_event("file_download", download_info)
                    if download_info.get('file_path'):
                        self.forensic_logger.add_evidence("downloaded_file", download_info['file_path'], f"File downloaded via FTP: {filename}")
                        
            except Exception as e:
                logger.error(f"File download handling failed: {e}")
                await self.send_response(550, "File not found")
        else:
            await self.send_response(550, "File not found")

    async def handle_upload(self, filename: str, attack_analysis: Dict[str, Any]):
        """Handle file upload (STOR command)"""
        
        await self.send_response(150, f"Opening data connection for {filename}")
        
        # Simulate receiving file data
        fake_content = f"Uploaded file: {filename}\nTimestamp: {datetime.datetime.now()}\nThis is a honeypot simulation".encode()
        
        if self.file_handler:
            try:
                upload_info = self.file_handler.handle_upload(filename, fake_content)
                self.session_data['files_uploaded'].append(upload_info)
                
                await self.send_response(226, "Transfer complete")
                
                logger.info("FTP file upload", extra=upload_info)
                
                if self.forensic_logger:
                    self.forensic_logger.log_event("file_upload", upload_info)
                    if upload_info.get('file_path'):
                        self.forensic_logger.add_evidence("uploaded_file", upload_info['file_path'], f"File uploaded via FTP: {filename}")
                        
            except Exception as e:
                logger.error(f"File upload handling failed: {e}")
                await self.send_response(550, "Upload failed")
        else:
            await self.send_response(550, "Upload failed")

    async def handle_passive_mode(self):
        """Handle PASV command"""
        # Generate fake passive mode response
        ip_parts = "192,168,1,100"  # Fake IP
        port_high = 20
        port_low = 21
        await self.send_response(227, f"Entering Passive Mode ({ip_parts},{port_high},{port_low})")

    async def handle_active_mode(self, args: str):
        """Handle PORT command with proper data connection setup"""
        try:
            # Parse PORT command arguments
            parts = args.split(',')
            if len(parts) == 6:
                ip = '.'.join(parts[:4])
                port = int(parts[4]) * 256 + int(parts[5])
                
                # Store data connection info
                self.data_ip = ip
                self.data_port = port
                
                # Try to establish data connection for next data transfer
                try:
                    reader, writer = await asyncio.open_connection(ip, port)
                    self.data_reader = reader
                    self.data_writer = writer
                    await self.send_response(200, "PORT command successful. Consider using PASV for better firewall compatibility.")
                    logger.info("FTP active mode", extra={"client_ip": ip, "client_port": port})
                except Exception as conn_error:
                    logger.warning(f"Could not establish data connection to {ip}:{port}: {conn_error}")
                    await self.send_response(200, "PORT command successful. Consider using PASV for better firewall compatibility.")
            else:
                await self.send_response(501, "Syntax error in PORT command")
        except Exception as e:
            await self.send_response(501, "Syntax error in PORT command")

    async def handle_unknown_command(self, command: str, args: str, attack_analysis: Dict[str, Any]):
        """Handle unknown FTP commands with AI response"""
        
        # Default response
        default_response = (502, "Command not implemented")
        
        try:
            if 'with_message_history' in globals():
                enhanced_command = f"FTP command: {command} {args}. Respond with proper FTP status code and message."
                if attack_analysis.get('attack_types'):
                    enhanced_command += f" [ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"
                
                llm_response = await with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=enhanced_command)],
                        "username": self.username,
                        "interactive": True
                    },
                    config={"configurable": {"session_id": f"ftp-{uuid.uuid4()}"}}
                )
                
                # Parse AI response for FTP code and message
                if llm_response and llm_response.content:
                    response_text = llm_response.content.strip()
                    if response_text.startswith(('2', '3', '4', '5')) and len(response_text) > 3:
                        code = int(response_text[:3])
                        message = response_text[4:]
                        await self.send_response(code, message)
                        return
                        
        except Exception as e:
            logger.error(f"LLM request failed for unknown command: {e}")
            
        # Use default response
        await self.send_response(default_response[0], default_response[1])

    def _resolve_path(self, path: str) -> str:
        """Resolve path with security checks"""
        # Sanitize path to prevent traversal attacks
        path = path.replace('..', '').replace('\\', '/')
        
        if path.startswith("/"):
            # Ensure path stays within allowed root
            if not path.startswith("/home/ftp"):
                return "/home/ftp"
            return path
        else:
            resolved = f"{self.current_directory}/{path}".replace("//", "/")
            # Ensure resolved path stays within allowed root
            if not resolved.startswith("/home/ftp"):
                return "/home/ftp"
            return resolved

    def _generate_fallback_listing(self) -> str:
        """Generate fallback directory listing"""
        return """drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 assets
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 backups
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 builds
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 config
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 games
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 logs
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 pub
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 uploads"""

class MyFTPServer:
    """FTP Server with AI-enhanced responses and comprehensive logging"""
    
    def __init__(self):
        self.sessions = {}
        
        # Create session directory
        session_id = f"ftp_session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        sessions_dir = Path(config['honeypot'].get('sessions_dir', 'sessions'))
        self.session_dir = sessions_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)

    async def generate_session_summary(self, session):
        """Generate AI-powered session summary like SSH server"""
        try:
            prompt = f'''Analyze this FTP session for malicious activity:
- Commands: {[cmd['command'] for cmd in session.session_data.get('commands', [])]}
- Attack patterns: {[analysis['attack_types'] for analysis in session.session_data.get('attack_analysis', []) if analysis.get('attack_types')]}
- Vulnerabilities: {[vuln['vulnerability_id'] for vuln in session.session_data.get('vulnerabilities', [])]}
- Files downloaded: {[file['filename'] for file in session.session_data.get('files_downloaded', [])]}
- Files uploaded: {[file['filename'] for file in session.session_data.get('files_uploaded', [])]}
- Duration: {session.session_data.get('duration', 'unknown')}
- Username: {session.username}

Provide analysis covering:
1. Attack stage identification
2. Primary objectives
3. Threat level assessment

End with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]"'''
            
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=prompt)],
                    "username": session.username,
                    "interactive": True
                },
                config={"configurable": {"session_id": f"ftp-summary-{uuid.uuid4().hex[:8]}"}}
            )
            
            judgement = "UNKNOWN"
            if "Judgement: BENIGN" in llm_response.content:
                judgement = "BENIGN"
            elif "Judgement: SUSPICIOUS" in llm_response.content:
                judgement = "SUSPICIOUS"
            elif "Judgement: MALICIOUS" in llm_response.content:
                judgement = "MALICIOUS"
                
            logger.info("FTP session summary", extra={
                "details": llm_response.content,
                "judgement": judgement,
                "session_commands": len(session.session_data.get('commands', [])),
                "attack_patterns_detected": len([a for a in session.session_data.get('attack_analysis', []) if a.get('attack_types')])
            })
            
        except Exception as e:
            logger.error(f"Session summary generation failed: {e}")

    async def handle_client(self, reader, writer):
        """Handle FTP client connection"""
        
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
        
        # Store connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port
        
        # Create session
        session = FTPSession(reader, writer, self)
        task_uuid = f"ftp-session-{uuid.uuid4()}"
        
        # Set task name for logging
        current_task = asyncio.current_task()
        if current_task is not None and hasattr(current_task, "set_name"):
            current_task.set_name(task_uuid)
        
        # Log connection
        connection_info = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "session_id": task_uuid,
            "session_dir": str(self.session_dir)
        }
        
        # Add AI features status
        connection_info["ai_features_enabled"] = {
            "dynamic_responses": config['ai_features'].getboolean('dynamic_responses', True),
            "attack_pattern_recognition": config['ai_features'].getboolean('attack_pattern_recognition', True),
            "vulnerability_detection": config['ai_features'].getboolean('vulnerability_detection', True),
            "adaptive_banners": config['ai_features'].getboolean('adaptive_banners', True),
            "deception_techniques": config['ai_features'].getboolean('deception_techniques', True)
        }
        
        # Add forensics configuration status
        connection_info["file_monitoring_enabled"] = config['forensics'].getboolean('file_monitoring', True)
        connection_info["chain_of_custody_enabled"] = config['forensics'].getboolean('chain_of_custody', True)
        
        logger.info("FTP connection received", extra=connection_info)
        
        if session.forensic_logger:
            try:
                session.forensic_logger.log_event("connection_established", connection_info)
            except Exception as e:
                logger.error(f"Forensic logging failed: {e}")
        
        try:
            # Send welcome message with adaptive banner if enabled
            banner_message = "NexusGames Studio FTP Server Ready"
            
            # Apply adaptive banners if enabled
            if config['ai_features'].getboolean('adaptive_banners', True):
                # Modify banner based on source IP or attack patterns
                if src_ip != 'unknown' and not src_ip.startswith('192.168.'):
                    banner_message += f" (Last connection from {src_ip})"
            
            await session.send_response(220, banner_message)
            
            # Handle commands
            while True:
                try:
                    data = await reader.readline()
                    if not data:
                        break
                        
                    command_line = data.decode('utf-8', errors='ignore').strip()
                    if not command_line:
                        continue
                        
                    # Handle command
                    try:
                        continue_session = await session.handle_command(command_line)
                        if not continue_session:
                            break
                    except Exception as cmd_error:
                        logger.error(f"Command processing error: {cmd_error}")
                        await session.send_response(500, "Internal server error")
                        continue
                        
                except asyncio.IncompleteReadError:
                    break
                except Exception as e:
                    logger.error(f"Error handling FTP command: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"FTP session error: {e}")
        finally:
            # Save session summary
            session.session_data['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            session.session_data['duration'] = str(datetime.datetime.fromisoformat(session.session_data['end_time']) - 
                                                   datetime.datetime.fromisoformat(session.session_data['start_time']))
            
            # Save session data if forensic reports are enabled
            if config['forensics'].getboolean('forensic_reports', True):
                session_file = self.session_dir / "session_summary.json"
                with open(session_file, 'w') as f:
                    json.dump(session.session_data, f, indent=2)
                
                # Save replay data if enabled
                if session.save_replay and hasattr(session, 'session_transcript') and session.session_transcript:
                    replay_file = self.session_dir / "session_replay.json"
                    with open(replay_file, 'w') as f:
                        json.dump({
                            'session_id': task_uuid,
                            'start_time': session.session_data['start_time'],
                            'end_time': session.session_data['end_time'],
                            'transcript': session.session_transcript
                        }, f, indent=2)
                
                if session.forensic_logger:
                    try:
                        session.forensic_logger.add_evidence("session_summary", str(session_file), "Complete FTP session activity summary")
                        if session.save_replay and hasattr(session, 'session_transcript') and session.session_transcript:
                            replay_file = self.session_dir / "session_replay.json"
                            session.forensic_logger.add_evidence("session_replay", str(replay_file), "Complete FTP session transcript for replay")
                        session.forensic_logger.log_event("connection_closed", {"reason": "normal_closure"})
                    except Exception as e:
                        logger.error(f"Forensic finalization failed: {e}")

            # Ensure downloads/uploads directories exist under the session dir
            try:
                downloads_dir = self.session_dir / "downloads"
                uploads_dir = self.session_dir / "uploads"
                downloads_dir.mkdir(parents=True, exist_ok=True)
                uploads_dir.mkdir(parents=True, exist_ok=True)

                # Write metadata file
                meta = {
                    "session_id": task_uuid,
                    "username": session.username,
                    "client_ip": thread_local.__dict__.get('src_ip', '-'),
                    "started": session.session_data.get('start_time'),
                    "ended": session.session_data.get('end_time')
                }
                with open(self.session_dir / "meta.json", 'w', encoding='utf-8') as mf:
                    json.dump(meta, mf, indent=2)
            except Exception as e:
                logger.error(f"Session finalization failed: {e}")
            
            
            # Generate session summary using AI if enabled
            if session.session_data.get('commands') and config['ai_features'].getboolean('ai_attack_summaries', True):
                try:
                    await self.generate_session_summary(session)
                except Exception as e:
                    logger.error(f"Session summary generation failed: {e}")
            
            logger.info("FTP connection closed")
            writer.close()
            await writer.wait_closed()

async def start_server():
    """Start the FTP server"""
    server_instance = MyFTPServer()
    
    port = config['ftp'].getint('port', 2121)
    
    server = await asyncio.start_server(
        server_instance.handle_client,
        host='127.0.0.1',
        port=port,
        reuse_address=True
    )
    
    llm_provider = config['llm'].get('llm_provider', 'openai')
    model_name = config['llm'].get('model_name', 'gpt-4o-mini')
    
    print(f"\n✅ FTP Honeypot Starting...")
    print(f"📡 Port: {port}")
    print(f"🤖 LLM Provider: {llm_provider}")
    print(f"📊 Model: {model_name}")
    print(f"🔍 Sensor: {sensor_name}")
    print(f"📁 Log File: {config['honeypot'].get('log_file', 'ftp_log.log')}")
    print(f"⚠️  Press Ctrl+C to stop\n")
    
    logger.info(f"FTP honeypot started on 127.0.0.1:{port}")
    print(f"✅ FTP honeypot listening on 127.0.0.1:{port}")
    print("📡 Ready for connections...")
    
    try:
        async with server:
            await server.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n🛑 FTP honeypot stopped by user")
        logger.info("FTP honeypot stopped by user")
        raise

class ContextFilter(logging.Filter):
    """Filter to add asyncio task name to log records"""

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
        raise ValueError("No user accounts found in configuration file.")
    
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
    parser = argparse.ArgumentParser(description='Start the FTP honeypot server.')
    parser.add_argument('-c', '--config', type=str, default=None, help='Path to the configuration file')
    parser.add_argument('-p', '--prompt', type=str, help='The entire text of the prompt')
    parser.add_argument('-f', '--prompt-file', type=str, default='prompt.txt', help='Path to the prompt file')
    parser.add_argument('-l', '--llm-provider', type=str, help='The LLM provider to use')
    parser.add_argument('-m', '--model-name', type=str, help='The model name to use')
    parser.add_argument('-t', '--trimmer-max-tokens', type=int, help='The maximum number of tokens to send to the LLM backend in a single request')
    parser.add_argument('-s', '--system-prompt', type=str, help='System prompt for the LLM')
    parser.add_argument('-r', '--temperature', type=float, help='Temperature parameter for controlling randomness in LLM responses (0.0-2.0)')
    parser.add_argument('-P', '--port', type=int, help='The port the FTP honeypot will listen on')
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
            default_log_file = str(Path(__file__).parent.parent.parent / 'logs' / 'ftp_log.log')
            config['honeypot'] = {'log_file': default_log_file, 'sensor_name': socket.gethostname()}
            config['ftp'] = {'port': '2121'}
            config['llm'] = {'llm_provider': 'openai', 'model_name': 'gpt-3.5-turbo', 'trimmer_max_tokens': '64000', 'temperature': '0.7', 'system_prompt': ''}
            config['user_accounts'] = {}

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
        config['ftp']['port'] = str(args.port)
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
    log_level = config['logging'].get('log_level', 'INFO').upper()
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "ftp_log.log"))
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
        RunnablePassthrough.assign(messages=(itemgetter("messages") | llm_trimmer))
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

    # Start the server
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n🛑 FTP honeypot stopped by user")
        logger.info("FTP honeypot stopped by user")
    finally:
        try:
            loop.close()
        except (OSError, RuntimeError):
            pass

except (KeyboardInterrupt, asyncio.CancelledError):
    print("\n🛑 FTP honeypot stopped by user")
    logger.info("FTP honeypot stopped by user")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)