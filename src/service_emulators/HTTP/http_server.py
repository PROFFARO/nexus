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
from aiohttp import web, ClientSession
from aiohttp.web_request import Request
from aiohttp.web_response import Response
import aiohttp
from urllib.parse import urlparse, parse_qs, unquote


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
                
        analysis['severity'] = max_severity
        return analysis

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
            'file_hash': hashlib.sha256(content).hexdigest(),
            'content_type': content_type
        }
        
        file_path = self.uploads_dir / filename
        with open(file_path, 'wb') as f:
            f.write(content)
            
        upload_info['file_path'] = str(file_path)
        upload_info['status'] = 'completed'
        
        return upload_info
        
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
        
        # Create session directory
        session_id = f"http_session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        sessions_dir = Path(config['honeypot'].get('sessions_dir', 'sessions'))
        self.session_dir = sessions_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize integrated components
        try:
            self.attack_analyzer = AttackAnalyzer()
            self.file_handler = FileTransferHandler(str(self.session_dir))
            self.vuln_logger = VulnerabilityLogger()
            self.forensic_logger = ForensicChainLogger(str(self.session_dir))
        except Exception as e:
            logger.error(f"Failed to initialize HTTP honeypot components: {e}")
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
        
        # Store connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port
        
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
        
        # Create session data
        session_data = {
            'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'requests': [],
            'attack_analysis': [],
            'vulnerabilities': [],
            'files_uploaded': []
        }
        
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
        
        logger.info("HTTP request received", extra=request_info)
        
        # Analyze request for attacks
        attack_analysis = {'method': method, 'path': path, 'attack_types': [], 'severity': 'low'}
        vulnerabilities = []
        
        if self.attack_analyzer:
            try:
                attack_analysis = self.attack_analyzer.analyze_request(method, path, headers, body_text)
                session_data['attack_analysis'].append(attack_analysis)
            except Exception as e:
                logger.error(f"Attack analysis failed: {e}")
        
        if self.vuln_logger:
            try:
                request_data = f"{method} {path} {str(headers)} {body_text}"
                vulnerabilities = self.vuln_logger.analyze_for_vulnerabilities(request_data, headers)
                session_data['vulnerabilities'].extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Vulnerability analysis failed: {e}")
        
        # Log attack analysis if threats detected
        if attack_analysis.get('attack_types'):
            logger.warning("HTTP attack pattern detected", extra={
                "attack_types": attack_analysis['attack_types'],
                "severity": attack_analysis['severity'],
                "indicators": attack_analysis.get('indicators', []),
                "method": method,
                "path": path
            })
            if self.forensic_logger:
                try:
                    self.forensic_logger.log_event("attack_detected", attack_analysis)
                except Exception as e:
                    logger.error(f"Forensic logging failed: {e}")
        
        # Log vulnerabilities
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = dict(vuln)
                enhanced_vuln['related_attack_types'] = attack_analysis.get('attack_types', [])
                enhanced_vuln['overall_severity'] = attack_analysis.get('severity', 'low')
                logger.critical("HTTP vulnerability exploitation attempt", extra=enhanced_vuln)
                if self.forensic_logger:
                    self.forensic_logger.log_event("vulnerability_exploit", enhanced_vuln)
            except Exception as e:
                logger.error(f"Vulnerability logging failed: {e}")
        
        # Handle file uploads
        if method == 'POST' and request.content_type and 'multipart' in request.content_type:
            try:
                reader = await request.multipart()
                async for part in reader:
                    if part.filename:
                        file_content = await part.read()
                        upload_info = self.file_handler.handle_upload(part.filename, file_content, part.content_type)
                        session_data['files_uploaded'].append(upload_info)
                        logger.info("HTTP file upload", extra=upload_info)
                        if self.forensic_logger:
                            self.forensic_logger.log_event("file_upload", upload_info)
                            self.forensic_logger.add_evidence("uploaded_file", upload_info['file_path'], f"File uploaded via HTTP: {part.filename}")
            except Exception as e:
                logger.error(f"File upload handling failed: {e}")
        
        # Store request in session data
        session_data['requests'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'method': method,
            'path': path,
            'headers': headers,
            'body': body_text[:1000],  # Limit body size in logs
            'attack_analysis': attack_analysis,
            'vulnerabilities': vulnerabilities
        })
        
        # Generate AI response
        response_content, status_code, response_headers = await self.generate_ai_response(
            method, path, headers, body_text, attack_analysis
        )
        
        # Log response
        logger.info("HTTP response", extra={
            "status_code": status_code,
            "content_length": len(response_content),
            "content_type": response_headers.get('Content-Type', 'text/html')
        })
        
        # Save session data
        session_data['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        session_file = self.session_dir / f"session_{uuid.uuid4().hex[:8]}.json"
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
            
        if self.forensic_logger:
            try:
                self.forensic_logger.add_evidence("session_summary", str(session_file), "HTTP session activity summary")
            except Exception as e:
                logger.error(f"Forensic finalization failed: {e}")
        
        return Response(
            text=response_content,
            status=status_code,
            headers=response_headers
        )

    async def generate_ai_response(self, method: str, path: str, headers: Dict, body: str, attack_analysis: Dict) -> tuple:
        """Generate AI-powered HTTP response"""
        
        # Create AI prompt with HTTP context
        ai_prompt = f"""HTTP Request: {method} {path}
Headers: {json.dumps(headers, indent=2)}
Body: {body[:500]}
User-Agent: {headers.get('User-Agent', 'Unknown')}
Generate realistic HTTP response for NexusGames Studio website."""
        
        if attack_analysis.get('attack_types'):
            ai_prompt += f"\n[ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"
        
        try:
            # Get AI response
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=ai_prompt)],
                    "username": headers.get('User-Agent', 'anonymous'),
                    "interactive": True
                },
                config={"configurable": {"session_id": f"http-{uuid.uuid4().hex[:8]}"}}
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
                
        except Exception as e:
            logger.error(f"AI response generation failed: {e}")
            return self.generate_fallback_response(path, attack_analysis)

    def generate_response_headers(self, path: str, content: str, attack_analysis: Dict) -> Dict[str, str]:
        """Generate appropriate HTTP response headers"""
        headers = {
            'Server': 'Apache/2.4.41 (Ubuntu)',
            'Date': datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
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
        """Generate minimal fallback HTTP response when AI fails"""
        
        # Simple fallback responses without static templates
        if path == '/' or path == '/index.html':
            content = "<html><head><title>NexusGames Studio</title></head><body><h1>NexusGames Studio</h1><p>Welcome to our game development company.</p></body></html>"
            status_code = 200
        elif path.startswith('/admin'):
            content = "<html><head><title>Admin Login</title></head><body><h1>Administrator Login</h1><form><input type='text' placeholder='Username'><input type='password' placeholder='Password'><button>Login</button></form></body></html>"
            status_code = 200
        elif attack_analysis.get('attack_types'):
            content = "<html><head><title>Access Denied</title></head><body><h1>403 Forbidden</h1><p>Your request has been blocked for security reasons.</p></body></html>"
            status_code = 403
        else:
            content = "<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1><p>The requested page could not be found.</p></body></html>"
            status_code = 404
        
        headers = self.generate_response_headers(path, content, attack_analysis)
        return content, status_code, headers

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
            config['honeypot'] = {'log_file': default_log_file, 'sensor_name': socket.gethostname()}
            config['http'] = {'port': '8080'}
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

    # Set up the honeypot logger
    logger = logging.getLogger(__name__)  
    logger.setLevel(logging.INFO)  

    log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "http_log.log"))
    logger.addHandler(log_file_handler)

    log_file_handler.setFormatter(JSONFormatter(sensor_name))

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
    port = config['http'].getint('port', 8080)
    
    logger.info(f"HTTP honeypot started on 127.0.0.1:{port}")
    print(f"HTTP honeypot listening on 127.0.0.1:{port}")
    
    app = asyncio.run(create_app())
    web.run_app(app, host='127.0.0.1', port=port)

except KeyboardInterrupt:
    print("\nHTTP honeypot stopped by user")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)