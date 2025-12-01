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
import aiohttp
from aiohttp import web, ClientSession
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from urllib.parse import urlparse, parse_qs, unquote


# Load environment variables from .env file
try:
    from dotenv import load_dotenv
except ImportError:
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")
    print("Environment variables will be loaded from system environment only.")

# Import ML components with robust path handling
ML_AVAILABLE = False
MLDetector = None
MLConfig = None

try:
    # Try relative imports first
    from ...ai.detectors import MLDetector
    from ...ai.config import MLConfig
    ML_AVAILABLE = True
except ImportError:
    try:
        # Try absolute imports with path adjustment
        import sys
        from pathlib import Path
        ai_path = Path(__file__).parent.parent.parent / "ai"
        if ai_path.exists() and str(ai_path) not in sys.path:
            sys.path.insert(0, str(ai_path.parent))
        
        from ai.detectors import MLDetector
        from ai.config import MLConfig
        ML_AVAILABLE = True
    except ImportError as e:
        ML_AVAILABLE = False
        # Only print warning if running directly, not during imports
        if __name__ == "__main__":
            print(f"Warning: ML components not available: {e}")


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
                ml_config = MLConfig('http')
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector('http', ml_config)
                    logging.info("ML detector initialized for HTTP service")
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
                'sql_injection': {'patterns': [r'union.*select', r'or.*1=1', r'drop.*table'], 'severity': 'critical'},
                'xss': {'patterns': [r'<script', r'javascript:', r'onerror='], 'severity': 'high'},
                'path_traversal': {'patterns': [r'\.\./', r'\.\.\\', r'%2e%2e%2f'], 'severity': 'high'},
                'command_injection': {'patterns': [r';.*rm', r'&&.*cat', r'\|.*nc'], 'severity': 'critical'},
                'reconnaissance': {'patterns': [r'/admin', r'/wp-admin', r'/.git', r'/config'], 'severity': 'medium'}
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
        
    def analyze_request(self, method: str, path: str, headers: Dict, body: str = "") -> Dict[str, Any]:
        """Analyze HTTP request for attack patterns using integrated JSON data"""
        analysis = {
            'method': method,
            'path': path,
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
        
        # Combine all request data for analysis
        request_data = f"{method} {path} {str(headers)} {body}"
        
        # Check attack patterns from JSON
        for attack_type, attack_data in self.attack_patterns.items():
            patterns = attack_data.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, request_data, re.IGNORECASE):
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
                if re.search(pattern, request_data, re.IGNORECASE):
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
        
        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                # Prepare comprehensive ML data
                ml_data = {
                    'method': method,
                    'url': path,
                    'headers': str(headers) if headers else '',
                    'body': body if body else '',
                    'timestamp': analysis['timestamp'],
                    'attack_types': analysis['attack_types'],
                    'severity': analysis['severity'],
                    'indicators': analysis['indicators'],
                    'vulnerabilities': analysis['vulnerabilities'],
                    'pattern_matches': analysis['pattern_matches']
                }
                
                ml_data['command'] = f"{method} {path}"  # Add command field for compatibility
                ml_results = self.ml_detector.score(ml_data)
                
                if ml_results is None:
                    ml_results = {
                        "ml_anomaly_score": 0.0,
                        "ml_labels": ["ml_error"],
                        "ml_cluster": -1,
                        "ml_reason": "ML detector returned None",
                        "ml_confidence": 0.0,
                        "ml_inference_time_ms": 0
                    }


                # Ensure ml_results is a dictionary
                if not isinstance(ml_results, dict):
                    logging.warning(f"ML detector returned non-dict result: {type(ml_results)}")
                    ml_results = {
                    'indicators': analysis['indicators'],
                    'vulnerabilities': analysis['vulnerabilities'],
                    'pattern_matches': analysis['pattern_matches']
                }
                
                # Get ML scoring results
                try:
                    # Debug ML data before scoring
                    import logging
                    logging.info(f"ML data type: {type(ml_data)}, keys: {list(ml_data.keys()) if isinstance(ml_data, dict) else "Not a dict"}")
                    # Temporary bypass for HTTP ML scoring issue
                    ml_results = {
                        "ml_anomaly_score": 0.5,
                        "ml_labels": ["http_analysis"],
                        "ml_cluster": -1,
                        "ml_reason": "HTTP ML analysis (bypassed due to compatibility issue)",
                        "ml_confidence": 0.5,
                        "ml_inference_time_ms": 1.0
                    }
                    if ml_results is None:
                        ml_results = {"ml_anomaly_score": 0.0, "ml_labels": ["ml_error"], "ml_cluster": -1, "ml_reason": "ML detector returned None", "ml_confidence": 0.0, "ml_inference_time_ms": 0}
                except Exception as ml_error:
                    logging.error(f"ML scoring failed with exception: {ml_error}")
                    ml_results = {"ml_anomaly_score": 0.0, "ml_labels": ["ml_error"], "ml_cluster": -1, "ml_reason": f"ML scoring exception: {str(ml_error)}", "ml_confidence": 0.0, "ml_inference_time_ms": 0}
                
                # Ensure ml_results is a dictionary
                if not isinstance(ml_results, dict):
                    logging.warning(f"ML detector returned non-dict result: {type(ml_results)}")
                    ml_results = {
                        'ml_anomaly_score': 0.0,
                        'ml_labels': ['ml_error'],
                        'ml_cluster': -1,
                        'ml_reason': f'Invalid ML result type: {type(ml_results)}',
                        'ml_confidence': 0.0,
                        'ml_inference_time_ms': 0
                    }
                
                # Integrate ML results into analysis
                analysis['ml_anomaly_score'] = ml_results.get('ml_anomaly_score', 0.0)
                analysis['ml_labels'] = ml_results.get('ml_labels', [])
                analysis['ml_cluster'] = ml_results.get('ml_cluster', -1)
                analysis['ml_reason'] = ml_results.get('ml_reason', 'No ML analysis')
                analysis['ml_confidence'] = ml_results.get('ml_confidence', 0.0)
                analysis['ml_inference_time_ms'] = ml_results.get('ml_inference_time_ms', 0)# Integrate ML results into analysis
                analysis['ml_anomaly_score'] = ml_results.get('ml_anomaly_score', 0.0)
                analysis['ml_labels'] = ml_results.get('ml_labels', [])
                analysis['ml_cluster'] = ml_results.get('ml_cluster', -1)
                analysis['ml_reason'] = ml_results.get('ml_reason', 'No ML analysis')
                analysis['ml_confidence'] = ml_results.get('ml_confidence', 0.0)
                analysis['ml_risk_score'] = ml_results.get('ml_risk_score', 0.0)
                analysis['ml_inference_time_ms'] = ml_results.get('ml_inference_time_ms', 0)
                
                # Calculate risk level using new ML method
                ml_score = ml_results.get('ml_anomaly_score', 0)
                risk_info = self.ml_detector.calculate_risk_level(
                    ml_score,
                    attack_types=analysis['attack_types'],
                    severity=analysis['severity']
                )
                analysis['ml_risk_level'] = risk_info['risk_level']
                analysis['ml_threat_score'] = risk_info['threat_score']
                analysis['ml_risk_color'] = risk_info['color']
                
                # Detect attack vectors using new ML method
                attack_vectors = self.ml_detector.detect_attack_vectors(ml_data, ml_results)
                analysis['attack_vectors'] = attack_vectors
                
                
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
                
                logging.info(f"HTTP ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}, Confidence={ml_results.get('ml_confidence', 0):.3f}")# Add ML-specific indicators
                if 'anomaly' in ml_results.get('ml_labels', []):
                    analysis['indicators'].append(f"ML Anomaly Detection: {ml_results.get('ml_reason', 'Unknown')}")
                
                # Add attack vector indicators
                if attack_vectors:
                    for vector in attack_vectors:
                        analysis['indicators'].append(
                            f"Attack Vector: {vector['technique']} (MITRE {vector['mitre_id']}) - Confidence: {vector['confidence']:.2f}"
                        )
                
                logging.info(
                    f"HTTP ML Analysis: Score={ml_score:.3f}, Risk={risk_info['risk_level']}, "
                    f"Vectors={len(attack_vectors)}, Labels={ml_results.get('ml_labels', [])}"
                )
                        
            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                # Add ML error information to analysis
                analysis['ml_error'] = str(e)
                analysis['ml_anomaly_score'] = 0.0
                analysis['ml_labels'] = ['ml_error']
                analysis['attack_vectors'] = []
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
        
        # Add ML-based scoring
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
        self.downloads_dir = self.session_dir / "downloads"
        self.uploads_dir = self.session_dir / "uploads"
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        
    def handle_upload(self, filename: str, content: bytes, content_type: str = "") -> Dict[str, Any]:
        """Handle file uploads via HTTP POST"""
        upload_info = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'filename': filename,
            'type': 'upload',
            'file_size': len(content),
            'content_type': content_type
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
        
        if filename_lower.endswith(('.html', '.htm')):
            return 'html_file'
        elif filename_lower.endswith(('.php', '.asp', '.jsp')):
            return 'web_script'
        elif filename_lower.endswith(('.js', '.css')):
            return 'web_resource'
        elif filename_lower.endswith(('.jpg', '.png', '.gif')):
            return 'image_file'
        elif filename_lower.endswith(('.exe', '.dll')):
            return 'executable'
        elif b'<script' in content[:1000]:
            return 'html_with_script'
        else:
            return 'unknown'
        
    def generate_fake_file_content(self, filename: str, file_type: str = "") -> bytes:
        """Generate realistic fake file content based on file type"""
        filename_lower = filename.lower()
        
        if filename_lower.endswith(('.html', '.htm')):
            content = f"""<!DOCTYPE html>
<html>
<head>
    <title>NexusGames Studio - {filename}</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>NexusGames Studio Internal Document</h1>
    <p>This is a confidential document from NexusGames Studio.</p>
    <p>Generated: {datetime.datetime.now()}</p>
    <p>This is a honeypot simulation.</p>
</body>
</html>""".encode()
        elif filename_lower.endswith(('.php', '.asp', '.jsp')):
            content = f"""<?php
// NexusGames Studio Web Application
// This is a honeypot simulation
// Generated: {datetime.datetime.now()}

$config = array(
    'db_host' => 'localhost',
    'db_user' => 'nexus_user',
    'db_pass' => 'nexus_pass_2024',
    'db_name' => 'nexus_games_db'
);

echo "NexusGames Studio Application";
?>""".encode()
        elif filename_lower.endswith(('.txt', '.log', '.conf', '.cfg')):
            content = f"""# NexusGames Studio Configuration
# Generated: {datetime.datetime.now()}
# This is a honeypot simulation

server_name=nexus-web-01
max_connections=1000
document_root=/var/www/nexusgames
admin_email=admin@nexusgames.studio
debug_mode=false
api_key=ng_api_key_2024_secure
database_url=mysql://nexus_user:nexus_pass@localhost/nexus_games
""".encode()
        else:
            content = f"""NexusGames Studio File: {filename}
Created: {datetime.datetime.now()}
This is a honeypot simulation file.

File contains sensitive web application data.
Access restricted to authorized personnel only.
""".encode()
            
        return content

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
                'CVE-2021-44228': {'patterns': [r'\$\{jndi:', r'ldap://'], 'severity': 'critical'},
                'SQL_INJECTION': {'patterns': [r'union.*select', r'or.*1=1'], 'severity': 'critical'},
                'XSS': {'patterns': [r'<script', r'javascript:'], 'severity': 'high'},
                'PATH_TRAVERSAL': {'patterns': [r'\.\./', r'%2e%2e%2f'], 'severity': 'high'}
            }
        
    def analyze_for_vulnerabilities(self, request_data: str, headers: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Analyze HTTP request for vulnerability exploitation attempts using JSON data"""
        vulnerabilities = []
        
        # Check if vulnerability detection is enabled
        if not config['ai_features'].getboolean('vulnerability_detection', True):
            return vulnerabilities
        
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get('patterns', [])
            for pattern in patterns:
                if re.search(pattern, request_data, re.IGNORECASE):
                    vulnerabilities.append({
                        'vulnerability_id': vuln_id,
                        'name': vuln_data.get('name', vuln_id),
                        'description': vuln_data.get('description', ''),
                        'pattern_matched': pattern,
                        'input': request_data,
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
        # Check if chain of custody is enabled
        if not config['forensics'].getboolean('chain_of_custody', True):
            return
            
        if os.path.exists(file_path):
            # amazonq-ignore-next-line
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
                # amazonq-ignore-next-line
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
            "sensor_protocol": "http"
        }
        if hasattr(record, 'interactive'):
            log_record["interactive"] = getattr(record, "interactive", True)
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key not in ['args', 'msg', 'exc_info', 'exc_text', 'stack_info', 'pathname', 'filename', 'module', 'funcName', 'lineno', 'created', 'msecs', 'relativeCreated', 'thread', 'threadName', 'processName', 'process']:
                log_record[key] = value
        return json.dumps(log_record)

class HTTPHoneypot:
    """HTTP Honeypot with AI-enhanced responses and comprehensive logging"""
    
    def __init__(self):
        self.sessions = {}
        self.active_sessions = {}
        
        # HTTP server configuration
        self.port = config['http'].getint('port', 8080)
        self.server_name = config['http'].get('server_name', 'Apache/2.4.41 (Ubuntu)')
        self.document_root = config['http'].get('document_root', '/var/www/nexusgames')
        self.max_connections = config['http'].getint('max_connections', 100)
        self.connection_timeout = config['http'].getint('connection_timeout', 300)
        self.enable_ssl = config['http'].getboolean('enable_ssl', False)
        self.ssl_cert = config['http'].get('ssl_cert', 'server.crt')
        self.ssl_key = config['http'].get('ssl_key', 'server.key')
        self.max_request_size = config['http'].getint('max_request_size', 10485760)
        self.max_header_size = config['http'].getint('max_header_size', 8192)
        self.keep_alive_timeout = config['http'].getint('keep_alive_timeout', 5)
        self.max_keep_alive_requests = config['http'].getint('max_keep_alive_requests', 100)
        self.enable_http2 = config['http'].getboolean('enable_http2', False)
        self.enable_compression = config['http'].getboolean('enable_compression', True)
        self.llm_response_timeout = config['http'].getfloat('llm_response_timeout', 60.0)
        
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
        
        # Security configuration
        self.ip_reputation = config['security'].getboolean('ip_reputation', True)
        self.rate_limiting = config['security'].getboolean('rate_limiting', True)
        self.max_connections_per_ip = config['security'].getint('max_connections_per_ip', 10)
        self.intrusion_detection = config['security'].getboolean('intrusion_detection', True)
        self.automated_blocking = config['security'].getboolean('automated_blocking', False)
        
        # Connection tracking per IP for rate limiting
        self.ip_connections = {}
        
        # Create session directory
        session_id = f"http_session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        sessions_dir = Path(config['honeypot'].get('sessions_dir', 'sessions'))
        self.session_dir = sessions_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Create downloads and uploads directories
        downloads_dirname = config['features'].get('downloads_dir', 'downloads')
        uploads_dirname = config['features'].get('uploads_dir', 'uploads')
        (self.session_dir / downloads_dirname).mkdir(parents=True, exist_ok=True)
        (self.session_dir / uploads_dirname).mkdir(parents=True, exist_ok=True)
        
        # Initialize integrated components with error handling
        try:
            self.attack_analyzer = AttackAnalyzer()
            self.file_handler = FileTransferHandler(str(self.session_dir)) if config['forensics'].getboolean('file_monitoring', True) else None
            self.vuln_logger = VulnerabilityLogger()
            self.forensic_logger = ForensicChainLogger(str(self.session_dir)) if config['forensics'].getboolean('chain_of_custody', True) else None
        except Exception as e:
            logging.error(f"Failed to initialize HTTP honeypot components: {e}")
            self.attack_analyzer = None
            self.file_handler = None
            self.vuln_logger = None
            self.forensic_logger = None

    async def handle_request(self, request: Request) -> Response:
        """Handle HTTP request with AI analysis"""
        
        # Get connection details
        peername = request.transport.get_extra_info('peername') if request.transport else None
        sockname = request.transport.get_extra_info('sockname') if request.transport else None
        
        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = request.remote or '-', '-'
            
        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = request.host.split(':')[0] if ':' in str(request.host) else str(request.host), request.url.port or 80
        
        # Check connection limit
        if self.connection_count >= self.max_connections:
            logging.warning(f"Connection limit reached ({self.max_connections}), rejecting request from {src_ip}")
            return Response(text="Service Unavailable", status=503)
        
        # Rate limiting check
        if self.rate_limiting and src_ip != '-':
            if src_ip not in self.ip_connections:
                self.ip_connections[src_ip] = 0
            
            if self.ip_connections[src_ip] >= self.max_connections_per_ip:
                logging.warning(f"Rate limit exceeded for IP {src_ip} ({self.ip_connections[src_ip]} connections)")
                return Response(text="Too Many Requests", status=429)
            
            self.ip_connections[src_ip] += 1
        
        self.connection_count += 1
        
        # Store connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port
        
        # Simulate latency if enabled
        await self._simulate_latency()
        
        # Get request data
        method = request.method
        path = request.path_qs
        headers = dict(request.headers)
        
        # Read request body safely
        try:
            body = await request.read()
            body_text = body.decode('utf-8', errors='ignore')
        except Exception:
            body_text = ""
        
        # Create or get session data
        session_key = f"{src_ip}:{src_port}"
        if session_key not in self.active_sessions:
            self.active_sessions[session_key] = {
                'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'requests': [],
                'attack_analysis': [],
                'vulnerabilities': [],
                'files_uploaded': [],
                'client_info': {'ip': src_ip, 'port': src_port}
            }
            
            # Initialize session recording if enabled
            if config['features'].getboolean('session_recording', True):
                self.active_sessions[session_key]['session_transcript'] = []
                
        session_data = self.active_sessions[session_key]
        
        # Log request
        request_info = {
            "method": method,
            "path": path,
            "headers": headers,
            "body_size": len(body_text),
            "user_agent": headers.get('User-Agent', ''),
            "referer": headers.get('Referer', ''),
            "src_ip": src_ip,
            "src_port": src_port
        }
        
        logging.info("HTTP request received")
        
        # Analyze request for attacks
        attack_analysis = {'method': method, 'path': path, 'attack_types': [], 'severity': 'low'}
        vulnerabilities = []
        
        if self.attack_analyzer:
            try:
                attack_analysis = self.attack_analyzer.analyze_request(method, path, headers, body_text)
                session_data['attack_analysis'].append(attack_analysis)
            except Exception as e:
                logging.error(f"Attack analysis failed: {e}")
        
        if self.vuln_logger:
            try:
                request_data = f"{method} {path} {str(headers)} {body_text}"
                vulnerabilities = self.vuln_logger.analyze_for_vulnerabilities(request_data, headers)
                session_data['vulnerabilities'].extend(vulnerabilities)
            except Exception as e:
                logging.error(f"Vulnerability analysis failed: {e}")
        
        # Log attack analysis if threats detected
        if attack_analysis.get('attack_types'):
            log_extra = {
                "attack_types": attack_analysis['attack_types'],
                "severity": attack_analysis['severity'],
                "indicators": attack_analysis.get('indicators', []),
                "method": method,
                "path": path
            }
            
            # Add threat score if available
            if 'threat_score' in attack_analysis:
                log_extra['threat_score'] = attack_analysis['threat_score']
                
            # Check if alert should be triggered
            if attack_analysis.get('alert_triggered', False):
                logging.critical("High-threat HTTP attack detected")
            else:
                logging.warning("HTTP attack pattern detected")
                
            if self.forensic_logger:
                try:
                    self.forensic_logger.log_event("attack_detected", attack_analysis)
                except Exception as e:
                    logging.error(f"Forensic logging failed: {e}")
        
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
                    logging.critical("Critical HTTP vulnerability exploitation attempt")
                else:
                    logging.critical("HTTP vulnerability exploitation attempt")
                    
                if self.forensic_logger:
                    self.forensic_logger.log_event("vulnerability_exploit", enhanced_vuln)
            except Exception as e:
                logging.error(f"Vulnerability logging failed: {e}")
        
        # Handle file uploads
        if method == 'POST' and request.content_type and 'multipart' in request.content_type and self.file_handler:
            try:
                reader = await request.multipart()
                async for part in reader:
                    if part.filename:
                        file_content = await part.read()
                        upload_info = self.file_handler.handle_upload(part.filename, file_content, part.content_type)
                        session_data['files_uploaded'].append(upload_info)
                        logging.info("HTTP file upload")
                        if self.forensic_logger:
                            self.forensic_logger.log_event("file_upload", upload_info)
                            self.forensic_logger.add_evidence("uploaded_file", upload_info['file_path'], f"File uploaded via HTTP: {part.filename}")
            except Exception as e:
                logging.error(f"File upload handling failed: {e}")
        
        # Generate AI response
        response_content, status_code, response_headers = await self.generate_ai_response(
            method, path, headers, body_text, attack_analysis
        )
        
        # Store request in session data
        request_data = {
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'method': method,
            'path': path,
            'headers': headers,
            'body': body_text[:1000],  # Limit body size in logs
            'attack_analysis': attack_analysis,
            'vulnerabilities': vulnerabilities,
            'response_content': response_content[:2000],  # Store AI response
            'response_status': status_code,
            'response_headers': response_headers
        }
        session_data['requests'].append(request_data)
        
        # Record in session transcript if enabled
        if config['features'].getboolean('session_recording', True) and 'session_transcript' in session_data:
            session_data['session_transcript'].append({
                'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'type': 'http_request',
                'method': method,
                'path': path,
                'status_code': status_code,
                'user_agent': headers.get('User-Agent', ''),
                'attack_detected': bool(attack_analysis.get('attack_types'))
            })
        
        # Log response
        logging.info(f"HTTP response: {status_code}")
        
        # Save session data if forensic reports are enabled
        if config['forensics'].getboolean('forensic_reports', True):
            session_data['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            session_file = self.session_dir / f"session_{uuid.uuid4().hex[:8]}.json"
            with open(session_file, 'w') as f:
                json.dump(session_data, f, indent=2)
                
            # Save replay data if enabled
            if config['features'].getboolean('save_replay', True) and 'session_transcript' in session_data:
                replay_file = self.session_dir / f"session_replay_{uuid.uuid4().hex[:8]}.json"
                with open(replay_file, 'w') as f:
                    json.dump({
                        'session_id': session_key,
                        'start_time': session_data['start_time'],
                        'end_time': session_data['end_time'],
                        'transcript': session_data['session_transcript']
                    }, f, indent=2)
                    
                if self.forensic_logger:
                    try:
                        self.forensic_logger.add_evidence("session_replay", str(replay_file), "Complete HTTP session transcript for replay")
                    except Exception as e:
                        logging.error(f"Replay data forensic logging failed: {e}")
                
            # Generate AI session summary if enabled
            if config['ai_features'].getboolean('ai_attack_summaries', True):
                await self.generate_session_summary(session_data, session_file)
                
            if self.forensic_logger:
                try:
                    self.forensic_logger.add_evidence("session_summary", str(session_file), "HTTP session activity summary")
                except Exception as e:
                    logging.error(f"Forensic finalization failed: {e}")
        
        # Cleanup connection counts
        try:
            self.connection_count -= 1
            
            # Decrement IP connection count for rate limiting
            if self.rate_limiting and src_ip != '-' and src_ip in self.ip_connections:
                self.ip_connections[src_ip] -= 1
                if self.ip_connections[src_ip] <= 0:
                    del self.ip_connections[src_ip]
        except Exception as e:
            logging.debug(f"Connection cleanup error: {e}")
        
        return Response(
            text=response_content,
            status=status_code,
            headers=response_headers
        )

    async def generate_ai_response(self, method: str, path: str, headers: Dict, body: str, attack_analysis: Dict) -> tuple:
        """Generate AI-powered HTTP response with enhanced context awareness"""
        
        # Create AI prompt with HTTP context
        ai_prompt = f"""HTTP Request: {method} {path}
Server: {self.server_name}
Document Root: {self.document_root}
Headers: {json.dumps(headers, indent=2)}
Body: {body[:500]}
User-Agent: {headers.get('User-Agent', 'Unknown')}
Generate realistic HTTP response for NexusGames Studio website."""
        
        # Add context awareness if enabled
        if config['llm'].getboolean('context_awareness', True):
            ai_prompt += f"\nServer Configuration: {self.server_name}"
            ai_prompt += f"\nSSL Enabled: {self.enable_ssl}"
            ai_prompt += f"\nCompression: {self.enable_compression}"
        
        # Add threat adaptation if enabled
        if config['llm'].getboolean('threat_adaptation', True) and attack_analysis.get('attack_types'):
            ai_prompt += f"\n[ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"
            ai_prompt += f"\nThreat Level: {attack_analysis.get('severity', 'low')}"
            
            if attack_analysis.get('threat_score', 0) >= config['attack_detection'].getint('alert_threshold', 70):
                ai_prompt += "\n[HIGH_THREAT_ALERT: Adapt response accordingly]"
        
        # Apply deception techniques if enabled
        if config['ai_features'].getboolean('deception_techniques', True):
            # Add deception context for more realistic responses
            if 'reconnaissance' in attack_analysis.get('attack_types', []):
                ai_prompt += "\n[DECEPTION: Show realistic but controlled system information]"
            elif 'sql_injection' in attack_analysis.get('attack_types', []):
                ai_prompt += "\n[DECEPTION: Simulate database errors while logging attempts]"
            elif attack_analysis.get('severity') in ['high', 'critical']:
                ai_prompt += "\n[DECEPTION_MODE: Use advanced deception techniques]"
        
        # Get AI response timeout from config
        llm_response_timeout = self.llm_response_timeout
        
        try:
            # Get AI response with timeout
            llm_response = await asyncio.wait_for(
                with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=ai_prompt)],
                        "username": headers.get('User-Agent', 'anonymous'),
                        "interactive": True
                    },
                    config={"configurable": {"session_id": f"http-{uuid.uuid4().hex[:8]}"}}
                ),
                timeout=llm_response_timeout
            )
            
            ai_content = llm_response.content.strip() if llm_response else ""
            
            # Parse AI response for HTTP format
            if ai_content:
                # Check if AI provided HTTP status code
                status_match = re.search(r'(\d{3})\s+', ai_content)
                status_code = int(status_match.group(1)) if status_match else 200
                
                # Extract content after status line
                content_lines = ai_content.split('\n')
                content = '\n'.join(content_lines[1:]) if len(content_lines) > 1 else ai_content
                
                # Generate appropriate response headers
                response_headers = self.generate_response_headers(path, content, attack_analysis)
                
                return content, status_code, response_headers
            else:
                return self.generate_fallback_response(path, attack_analysis)
                
        except asyncio.TimeoutError:
            logging.warning(f"AI response timed out, using fallback (timeout: {llm_response_timeout})")
            return self.generate_fallback_response(path, attack_analysis)
        except Exception as e:
            logging.error(f"AI response generation failed: {e}")
            return self.generate_fallback_response(path, attack_analysis)

    def generate_response_headers(self, path: str, content: str, attack_analysis: Dict) -> Dict[str, str]:
        """Generate appropriate HTTP response headers"""
        # Sanitize path to prevent traversal attacks
        path = path.replace('..', '').replace('\\', '/')
        
        server_name = config['http'].get('server_name', 'Apache/2.4.41 (Ubuntu)')
        
        # Apply adaptive banners if enabled
        if config['ai_features'].getboolean('adaptive_banners', True) and attack_analysis.get('attack_types'):
            # Modify server header based on attack patterns
            if 'reconnaissance' in attack_analysis.get('attack_types', []):
                server_name = 'nginx/1.18.0 (Ubuntu)'  # Change server type to confuse attackers
        
        headers = {
            'Server': server_name,
            'Date': datetime.datetime.now(datetime.UTC).strftime('%a, %d %b %Y %H:%M:%S GMT'),
            'Connection': 'close'
        }
        
        # Determine content type based on path
        if path.endswith(('.html', '.htm')) or path == '/':
            headers['Content-Type'] = 'text/html; charset=UTF-8'
        elif path.endswith('.css'):
            headers['Content-Type'] = 'text/css'
        elif path.endswith('.js'):
            headers['Content-Type'] = 'application/javascript'
        elif path.endswith('.json'):
            headers['Content-Type'] = 'application/json'
        elif path.endswith(('.jpg', '.jpeg')):
            headers['Content-Type'] = 'image/jpeg'
        elif path.endswith('.png'):
            headers['Content-Type'] = 'image/png'
        elif path.endswith('.gif'):
            headers['Content-Type'] = 'image/gif'
        else:
            headers['Content-Type'] = 'text/html; charset=UTF-8'
        
        headers['Content-Length'] = str(len(content.encode('utf-8')))
        
        # Add security headers for realistic corporate website
        headers.update({
            'X-Frame-Options': 'SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        })
        
        return headers

    def generate_fallback_response(self, path: str, attack_analysis: Dict) -> tuple:
        """Generate error response when AI completely fails"""
        content = "<html><head><title>Service Unavailable</title></head><body><h1>503 Service Unavailable</h1><p>The service is temporarily unavailable. Please try again later.</p></body></html>"
        status_code = 503
        headers = self.generate_response_headers(path, content, attack_analysis)
        return content, status_code, headers
    
    async def _simulate_latency(self):
        """Simulate network latency if enabled"""
        if self.latency_enable:
            latency_ms = random.randint(self.latency_min_ms, self.latency_max_ms)
            await asyncio.sleep(latency_ms / 1000.0)

    async def generate_session_summary(self, session_data: Dict, session_file: Path):
        """Generate AI-powered session summary like SSH/FTP services"""
        try:
            prompt = f'''Analyze this HTTP session for malicious activity:
- Total requests: {len(session_data.get('requests', []))}
- Paths accessed: {[req['path'] for req in session_data.get('requests', [])]}
- Methods used: {list(set(req['method'] for req in session_data.get('requests', [])))}
- User agents: {list(set(req['headers'].get('User-Agent', 'Unknown') for req in session_data.get('requests', [])))}
- Attack patterns: {[analysis['attack_types'] for analysis in session_data.get('attack_analysis', []) if analysis.get('attack_types')]}
- Vulnerabilities: {[vuln['vulnerability_id'] for vuln in session_data.get('vulnerabilities', [])]}
- Files uploaded: {len(session_data.get('files_uploaded', []))}

Provide analysis covering:
1. Attack stage identification
2. Primary objectives
3. Threat level assessment

End with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]"'''

            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=prompt)],
                    "username": "http_analyzer",
                    "interactive": True
                },
                config={"configurable": {"session_id": f"http-summary-{uuid.uuid4().hex[:8]}"}}
            )
            
            judgement = "UNKNOWN"
            if "Judgement: BENIGN" in llm_response.content:
                judgement = "BENIGN"
            elif "Judgement: SUSPICIOUS" in llm_response.content:
                judgement = "SUSPICIOUS"
            elif "Judgement: MALICIOUS" in llm_response.content:
                judgement = "MALICIOUS"

            logging.info(f"HTTP session summary: {judgement}")
            
        except Exception as e:
            logging.error(f"Session summary generation failed: {e}")

async def create_app():
    """Create aiohttp application"""
    honeypot = HTTPHoneypot()
    
    app = web.Application()
    
    # Add catch-all route to handle all requests
    app.router.add_route('*', '/{path:.*}', honeypot.handle_request)
    
    return app

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
        return {'admin': 'admin', 'user': 'password'}
    
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
    parser = argparse.ArgumentParser(description='Start the HTTP honeypot server.')
    parser.add_argument('-c', '--config', type=str, default=None, help='Path to the configuration file')
    parser.add_argument('-p', '--prompt', type=str, help='The entire text of the prompt')
    parser.add_argument('-f', '--prompt-file', type=str, default='prompt.txt', help='Path to the prompt file')
    parser.add_argument('-l', '--llm-provider', type=str, help='The LLM provider to use')
    parser.add_argument('-m', '--model-name', type=str, help='The model name to use')
    parser.add_argument('-t', '--trimmer-max-tokens', type=int, help='The maximum number of tokens to send to the LLM backend in a single request')
    parser.add_argument('-s', '--system-prompt', type=str, help='System prompt for the LLM')
    parser.add_argument('-r', '--temperature', type=float, help='Temperature parameter for controlling randomness in LLM responses (0.0-2.0)')
    parser.add_argument('-H', '--host', type=str, help='The host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)')
    parser.add_argument('-P', '--port', type=int, help='The port the HTTP honeypot will listen on')
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
            default_log_file = str(Path(__file__).parent.parent.parent / 'logs' / 'http_log.log')
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
            config['http'] = {
                'host': '0.0.0.0',
                'port': '8080',
                'server_name': 'Apache/2.4.41 (Ubuntu)',
                'document_root': '/var/www/nexusgames',
                'max_connections': '100',
                'connection_timeout': '300',
                'enable_ssl': 'false',
                # amazonq-ignore-next-line
                'ssl_cert': 'server.crt',
                'ssl_key': 'server.key',
                'max_request_size': '10485760',
                'max_header_size': '8192',
                'keep_alive_timeout': '5',
                'max_keep_alive_requests': '100',
                'enable_http2': 'false',
                'enable_compression': 'true',
                'llm_response_timeout': '60.0'
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
            config['visualization'] = {
                'real_time_dashboard': 'true',
                'attack_visualization': 'true',
                'geographic_mapping': 'true',
                'timeline_analysis': 'true'
            }
            config['security'] = {
                'ip_reputation': 'true',
                'rate_limiting': 'true',
                'max_connections_per_ip': '10',
                'connection_timeout': '300',
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
    if args.host:
        config['http']['host'] = args.host
    if args.port:
        config['http']['port'] = str(args.port)
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

    log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "http_log.log"))
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
    host = config['http'].get('host', '0.0.0.0')
    port = config['http'].getint('port', 8080)
    llm_provider = config['llm'].get('llm_provider', 'openai')
    model_name = config['llm'].get('model_name', 'gpt-4o-mini')
    
    # Get honeypot instance for configuration display
    honeypot_instance = HTTPHoneypot()
    
    print(f"\n[INFO] HTTP Honeypot Starting...")
    print(f"[INFO] Host: {host}")
    print(f"[INFO] Port: {port}")
    print(f"[INFO] Server: {honeypot_instance.server_name}")
    print(f"[INFO] Document Root: {honeypot_instance.document_root}")
    print(f"[INFO] LLM Provider: {llm_provider}")
    print(f"[INFO] Model: {model_name}")
    print(f"[INFO] Sensor: {sensor_name}")
    print(f"[INFO] Log File: {config['honeypot'].get('log_file', 'http_log.log')}")
    print(f"[INFO] Max Connections: {honeypot_instance.max_connections}")
    print(f"[INFO] Connection Timeout: {honeypot_instance.connection_timeout}s")
    print(f"[INFO] Rate Limiting: {'Enabled' if honeypot_instance.rate_limiting else 'Disabled'}")
    print(f"[INFO] SSL/HTTPS: {'Enabled' if honeypot_instance.enable_ssl else 'Disabled'}")
    print(f"[INFO] Compression: {'Enabled' if honeypot_instance.enable_compression else 'Disabled'}")
    print(f"[INFO] Behavioral Analysis: {'Enabled' if honeypot_instance.behavioral_analysis else 'Disabled'}")
    print(f"[INFO] Adaptive Responses: {'Enabled' if honeypot_instance.adaptive_responses else 'Disabled'}")
    print(f"[INFO] Press Ctrl+C to stop\n")
    
    logger.info(f"HTTP honeypot started on {host}:{port}")
    print(f"[SUCCESS] HTTP honeypot listening on {host}:{port}")
    print("[INFO] Ready for connections...")
    
    try:
        app = asyncio.run(create_app())
        web.run_app(app, host=host, port=port)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[INFO] HTTP honeypot stopped by user")
        logger.info("HTTP honeypot stopped by user")

except (KeyboardInterrupt, asyncio.CancelledError):
    print("\n[INFO] HTTP honeypot stopped by user")
    logging.info("HTTP honeypot stopped by user")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)