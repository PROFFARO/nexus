#!/usr/bin/env python3
"""
SMB Rich Logger - Enhanced logging for SMB honeypot
Provides structured JSON logging, rich console output, and comprehensive session tracking
"""

import json
import logging
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from logging.handlers import RotatingFileHandler
import threading

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: rich library not available. Install with: pip install rich")

# Thread-local storage for connection context
thread_local = threading.local()


class SMBJSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def __init__(self, sensor_name: str):
        super().__init__()
        self.sensor_name = sensor_name
    
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "sensor_name": self.sensor_name,
            "sensor_protocol": "smb",
            "message": record.getMessage(),
        }
        
        # Add connection context from thread-local storage
        if hasattr(thread_local, 'src_ip'):
            log_record["src_ip"] = thread_local.src_ip
            log_record["src_port"] = thread_local.src_port
            log_record["dst_ip"] = thread_local.dst_ip
            log_record["dst_port"] = thread_local.dst_port
        
        # Add any extra fields from the record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                          'levelname', 'levelno', 'lineno', 'module', 'msecs',
                          'message', 'pathname', 'process', 'processName',
                          'relativeCreated', 'thread', 'threadName', 'exc_info',
                          'exc_text', 'stack_info']:
                log_record[key] = value
        
        return json.dumps(log_record)


class SMBRichLogger:
    """Rich formatted logging for SMB honeypot with multiple log files"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.sensor_name = config['honeypot'].get('sensor_name', 'nexus-smb-honeypot')
        
        # Create log directory
        log_file = Path(config['honeypot'].get('log_file', '../../logs/smb_log.log'))
        self.log_dir = log_file.parent
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize rich console if available
        self.console = Console() if RICH_AVAILABLE else None
        self.rich_enabled = RICH_AVAILABLE and config['logging'].getboolean('rich_console', True)
        
        # Setup loggers
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Setup multiple loggers for different log types"""
        log_level = getattr(logging, self.config['logging'].get('log_level', 'INFO'))
        
        # Main logger
        self.logger = logging.getLogger('smb_honeypot')
        self.logger.setLevel(log_level)
        self.logger.handlers.clear()
        
        # Connection logger
        self.connection_logger = self._create_logger(
            'smb_connections',
            self.config['logging'].get('connection_log', '../../logs/smb_connections.log')
        )
        
        # Authentication logger
        self.auth_logger = self._create_logger(
            'smb_auth',
            self.config['logging'].get('auth_log', '../../logs/smb_auth.log')
        )
        
        # File operations logger
        self.file_ops_logger = self._create_logger(
            'smb_file_ops',
            self.config['logging'].get('file_ops_log', '../../logs/smb_file_ops.log')
        )
        
        # Attack logger
        self.attack_logger = self._create_logger(
            'smb_attacks',
            self.config['logging'].get('attack_log', '../../logs/smb_attacks.log')
        )
        
        # LLM logger
        self.llm_logger = self._create_logger(
            'smb_llm',
            self.config['logging'].get('llm_log', '../../logs/smb_llm.log')
        )
        
        # Add rich console handler to main logger if enabled
        if self.rich_enabled:
            rich_handler = RichHandler(
                console=self.console,
                rich_tracebacks=True,
                tracebacks_show_locals=True
            )
            rich_handler.setLevel(log_level)
            self.logger.addHandler(rich_handler)
    
    def _create_logger(self, name: str, log_file: str) -> logging.Logger:
        """Create a logger with JSON formatter and rotation"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()
        logger.propagate = False
        
        # Resolve log file path
        log_path = Path(log_file)
        if not log_path.is_absolute():
            log_path = Path(__file__).parent / log_file
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Add rotating file handler
        rotation_size = self.config['logging'].getint('log_rotation_size', 100) * 1024 * 1024
        backup_count = self.config['logging'].getint('log_backup_count', 10)
        
        handler = RotatingFileHandler(
            log_path,
            maxBytes=rotation_size,
            backupCount=backup_count
        )
        handler.setFormatter(SMBJSONFormatter(self.sensor_name))
        logger.addHandler(handler)
        
        return logger
    
    def log_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                      event: str, **kwargs):
        """Log connection event"""
        log_data = {
            'event': event,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            **kwargs
        }
        self.connection_logger.info(f"Connection {event}", extra=log_data)
        
        if self.rich_enabled:
            self._rich_log_connection(event, src_ip, src_port, **kwargs)
    
    def log_authentication(self, username: str, success: bool, auth_type: str,
                          src_ip: str, **kwargs):
        """Log authentication attempt"""
        log_data = {
            'event': 'authentication',
            'username': username,
            'success': success,
            'auth_type': auth_type,
            'src_ip': src_ip,
            **kwargs
        }
        
        level = logging.INFO if success else logging.WARNING
        self.auth_logger.log(
            level,
            f"Authentication {'successful' if success else 'failed'} for {username}",
            extra=log_data
        )
        
        if self.rich_enabled:
            self._rich_log_authentication(username, success, auth_type, src_ip)
    
    def log_file_operation(self, operation: str, path: str, username: str,
                          src_ip: str, **kwargs):
        """Log file operation"""
        log_data = {
            'event': 'file_operation',
            'operation': operation,
            'path': path,
            'username': username,
            'src_ip': src_ip,
            **kwargs
        }
        self.file_ops_logger.info(f"File {operation}: {path}", extra=log_data)
        
        if self.rich_enabled:
            self._rich_log_file_operation(operation, path, username, src_ip)
    
    def log_attack_detection(self, analysis: Dict[str, Any], src_ip: str, **kwargs):
        """Log attack detection"""
        log_data = {
            'event': 'attack_detection',
            'src_ip': src_ip,
            'attack_types': analysis.get('attack_types', []),
            'severity': analysis.get('severity', 'low'),
            'threat_score': analysis.get('threat_score', 0),
            'indicators': analysis.get('indicators', []),
            'vulnerabilities': analysis.get('vulnerabilities', []),
            **kwargs
        }
        
        level = logging.CRITICAL if analysis.get('severity') == 'critical' else \
                logging.ERROR if analysis.get('severity') == 'high' else \
                logging.WARNING
        
        self.attack_logger.log(
            level,
            f"Attack detected: {', '.join(analysis.get('attack_types', []))}",
            extra=log_data
        )
        
        if self.rich_enabled:
            self._rich_log_attack(analysis, src_ip)
    
    def log_llm_interaction(self, prompt_type: str, prompt: str, response: str,
                           username: str, src_ip: str, **kwargs):
        """Log LLM interaction"""
        log_data = {
            'event': 'llm_interaction',
            'prompt_type': prompt_type,
            'prompt': prompt[:500],  # Truncate long prompts
            'response': response[:1000],  # Truncate long responses
            'username': username,
            'src_ip': src_ip,
            **kwargs
        }
        self.llm_logger.info(f"LLM {prompt_type}", extra=log_data)
        
        if self.rich_enabled and self.config['logging'].getboolean('log_llm_interactions', False):
            self._rich_log_llm(prompt_type, prompt, response)
    
    def _rich_log_connection(self, event: str, src_ip: str, src_port: int, **kwargs):
        """Rich console output for connection"""
        if event == 'established':
            self.console.print(f"[green]✓[/green] Connection from {src_ip}:{src_port}")
        elif event == 'closed':
            self.console.print(f"[yellow]✗[/yellow] Connection closed {src_ip}:{src_port}")
    
    def _rich_log_authentication(self, username: str, success: bool, auth_type: str, src_ip: str):
        """Rich console output for authentication"""
        if success:
            self.console.print(
                f"[green]✓[/green] Auth success: [bold]{username}[/bold] "
                f"from {src_ip} ({auth_type})"
            )
        else:
            self.console.print(
                f"[red]✗[/red] Auth failed: [bold]{username}[/bold] "
                f"from {src_ip} ({auth_type})"
            )
    
    def _rich_log_file_operation(self, operation: str, path: str, username: str, src_ip: str):
        """Rich console output for file operation"""
        op_icons = {
            'read': '📖',
            'write': '✍️',
            'create': '📝',
            'delete': '🗑️',
            'list': '📋',
            'open': '📂'
        }
        icon = op_icons.get(operation.lower(), '📄')
        self.console.print(
            f"{icon} {operation.upper()}: [cyan]{path}[/cyan] by {username} ({src_ip})"
        )
    
    def _rich_log_attack(self, analysis: Dict[str, Any], src_ip: str):
        """Rich console output for attack detection"""
        severity = analysis.get('severity', 'low')
        severity_colors = {
            'low': 'yellow',
            'medium': 'orange1',
            'high': 'red',
            'critical': 'red bold'
        }
        color = severity_colors.get(severity, 'yellow')
        
        attack_types = ', '.join(analysis.get('attack_types', []))
        threat_score = analysis.get('threat_score', 0)
        
        self.console.print(
            f"[{color}]⚠️  ATTACK DETECTED[/{color}] from {src_ip}\n"
            f"   Types: {attack_types}\n"
            f"   Severity: {severity.upper()} (Score: {threat_score})"
        )
    
    def _rich_log_llm(self, prompt_type: str, prompt: str, response: str):
        """Rich console output for LLM interaction"""
        self.console.print(
            f"[magenta]🤖 LLM {prompt_type}[/magenta]\n"
            f"   Prompt: {prompt[:100]}...\n"
            f"   Response: {response[:100]}..."
        )


class SMBSessionTracker:
    """Track comprehensive session information"""
    
    def __init__(self, session_id: str, session_dir: Path):
        self.session_id = session_id
        self.session_dir = session_dir
        self.session_file = session_dir / f"session_{session_id}.json"
        
        self.session_data = {
            'session_id': session_id,
            'start_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'commands': [],
            'file_operations': [],
            'authentication_attempts': [],
            'attack_analysis': [],
            'llm_interactions': [],
            'client_info': {}
        }
    
    def track_command(self, command: str, response: str, **kwargs):
        """Track SMB command"""
        self.session_data['commands'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'command': command,
            'response': response,
            **kwargs
        })
        self._save()
    
    def track_file_access(self, path: str, operation: str, **kwargs):
        """Track file access"""
        self.session_data['file_operations'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'path': path,
            'operation': operation,
            **kwargs
        })
        self._save()
    
    def track_authentication(self, username: str, success: bool, **kwargs):
        """Track authentication attempt"""
        self.session_data['authentication_attempts'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'username': username,
            'success': success,
            **kwargs
        })
        self._save()
    
    def track_attack(self, analysis: Dict[str, Any]):
        """Track attack detection"""
        self.session_data['attack_analysis'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **analysis
        })
        self._save()
    
    def track_llm_interaction(self, prompt_type: str, prompt: str, response: str, **kwargs):
        """Track LLM interaction"""
        self.session_data['llm_interactions'].append({
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'prompt_type': prompt_type,
            'prompt': prompt,
            'response': response,
            **kwargs
        })
        self._save()
    
    def set_client_info(self, info: Dict[str, Any]):
        """Set client information"""
        self.session_data['client_info'].update(info)
        self._save()
    
    def generate_session_summary(self) -> Dict[str, Any]:
        """Generate session summary"""
        return {
            'session_id': self.session_id,
            'duration': self._calculate_duration(),
            'total_commands': len(self.session_data['commands']),
            'total_file_operations': len(self.session_data['file_operations']),
            'authentication_attempts': len(self.session_data['authentication_attempts']),
            'successful_auth': sum(1 for a in self.session_data['authentication_attempts'] if a['success']),
            'attacks_detected': len(self.session_data['attack_analysis']),
            'llm_interactions': len(self.session_data['llm_interactions']),
            'client_info': self.session_data['client_info']
        }
    
    def _calculate_duration(self) -> float:
        """Calculate session duration in seconds"""
        start = datetime.datetime.fromisoformat(self.session_data['start_time'])
        end = datetime.datetime.now(datetime.timezone.utc)
        return (end - start).total_seconds()
    
    def _save(self):
        """Save session data to file"""
        with open(self.session_file, 'w') as f:
            json.dump(self.session_data, f, indent=2)
    
    def close(self):
        """Close session and save final data"""
        self.session_data['end_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.session_data['summary'] = self.generate_session_summary()
        self._save()
