#!/usr/bin/env python3
"""
NEXUS Honeypot Log Viewer - Comprehensive protocol analysis with command timelines,
session summaries, attack detection, ML anomaly detection, and detailed protocol specifics

Supports: SSH, FTP, HTTP, MySQL
Features: Command/request timelines, session summaries, protocol details, attack analysis,
ML-based anomaly detection, text and JSON output formats
"""

import json
import os
import sys
import argparse
import datetime
from base64 import b64decode
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

# Import ML components
try:
    sys.path.append(str(Path(__file__).parent.parent))
    from ai.detectors import MLDetector
    from ai.config import MLConfig
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    MLDetector = None
    MLConfig = None


class ProtocolAnalyzer:
    """Base class for protocol-specific analysis"""
    
    def __init__(self, service: str):
        self.service = service
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract protocol-specific details from log entry"""
        return {}
    
    def categorize_entry(self, message: str, log_entry: Dict[str, Any]) -> str:
        """Categorize log entry (command, response, attack, other)"""
        if 'attack' in message.lower():
            return 'attack'
        elif 'command' in message.lower() or 'User input' in message:
            return 'command'
        elif 'response' in message.lower() or 'LLM response' in message:
            return 'response'
        return 'other'
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format protocol-specific command details"""
        return ""


class SSHAnalyzer(ProtocolAnalyzer):
    """SSH Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SSH-specific details"""
        details = {
            'username': log_entry.get('username', 'unknown'),
            'command': log_entry.get('command', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
            'interactive': log_entry.get('interactive', False),
        }
        
        # Attack details
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
            details['indicators'] = log_entry.get('indicators', [])
        
        # Threat intelligence
        if 'threat_signatures_loaded' in log_entry:
            details['threat_signatures'] = log_entry.get('threat_signatures_loaded', 0)
            details['attack_patterns'] = log_entry.get('attack_patterns_loaded', 0)
        
        # Geolocation & Reputation
        if 'geolocation' in log_entry:
            details['geolocation'] = log_entry['geolocation']
            details['reputation'] = log_entry.get('reputation', {})
            details['ai_features'] = log_entry.get('ai_features_enabled', {})
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format SSH command details"""
        pd = entry.get('protocol_details', {})
        cmd = pd.get('command', 'N/A')
        user = pd.get('username', 'unknown')
        return f"  {user}@localhost: {cmd}"


class FTPAnalyzer(ProtocolAnalyzer):
    """FTP Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract FTP-specific details"""
        details = {
            'username': log_entry.get('username', 'anonymous'),
            'command': log_entry.get('command', ''),
            'path': log_entry.get('path', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
        }
        
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format FTP command details"""
        pd = entry.get('protocol_details', {})
        cmd = pd.get('command', 'N/A')
        path = pd.get('path', '')
        return f"  FTP {cmd} {path}"


class HTTPAnalyzer(ProtocolAnalyzer):
    """HTTP Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract HTTP-specific details"""
        details = {
            'method': log_entry.get('method', 'GET'),
            'path': log_entry.get('path', '/'),
            'url': log_entry.get('url', ''),
            'status_code': log_entry.get('status_code'),
            'user_agent': log_entry.get('user_agent', ''),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
        }
        
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
            details['indicators'] = log_entry.get('indicators', [])
        
        return details
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format HTTP request details"""
        pd = entry.get('protocol_details', {})
        method = pd.get('method', 'GET')
        path = pd.get('path', '/')
        status = pd.get('status_code', '?')
        return f"  {method} {path} ({status})"


class MySQLAnalyzer(ProtocolAnalyzer):
    """MySQL Protocol specific analyzer"""
    
    def extract_protocol_details(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract MySQL-specific details"""
        details = {
            'username': log_entry.get('username', 'unknown'),
            'query': log_entry.get('query', ''),
            'database': log_entry.get('database', ''),
            'client_ip': log_entry.get('client_ip', log_entry.get('src_ip', 'unknown')),
            'src_port': log_entry.get('src_port'),
            'dst_port': log_entry.get('dst_port'),
            'session_id': log_entry.get('session_id', ''),
            'query_type': log_entry.get('query_type', ''),
        }
        
        # Extract LLM response details
        if 'llm_response' in log_entry:
            details['llm_response'] = log_entry['llm_response']
            details['model'] = log_entry.get('model', '')
        
        # Extract ML analysis details
        if 'ml_anomaly_score' in log_entry:
            details['ml_anomaly_score'] = log_entry['ml_anomaly_score']
            details['ml_labels'] = log_entry.get('ml_labels', [])
            details['ml_reason'] = log_entry.get('ml_reason', '')
        
        # Extract attack details
        if 'attack_types' in log_entry:
            details['attack_types'] = log_entry['attack_types']
            details['severity'] = log_entry.get('severity', 'unknown')
            details['threat_score'] = log_entry.get('threat_score', 0)
            details['indicators'] = log_entry.get('indicators', [])
        
        # Extract vulnerability details
        if 'vulnerability_id' in log_entry:
            details['vulnerability_id'] = log_entry['vulnerability_id']
            details['vuln_name'] = log_entry.get('vuln_name', '')
            details['cvss_score'] = log_entry.get('cvss_score', 0)
        
        return details
    
    def categorize_entry(self, message: str, log_entry: Dict[str, Any]) -> str:
        """Categorize MySQL log entry (command, response, attack, other)"""
        message_lower = message.lower()
        
        # Attack patterns
        if 'attack' in message_lower or 'vulnerability' in message_lower:
            return 'attack'
        
        # Query received = command (the attacker's input)
        if 'query received' in message_lower or 'query_debug' in message_lower:
            return 'command'
        
        # Responses from honeypot
        if 'llm response' in message_lower or 'response' in message_lower:
            return 'response'
        if 'fallback response' in message_lower:
            return 'response'
        if 'query completed' in message_lower:
            return 'response'
        if 'setup failed' in message_lower:
            return 'response'
        
        return 'other'
    
    def format_command_details(self, entry: Dict[str, Any]) -> str:
        """Format MySQL query details with full query text"""
        pd = entry.get('protocol_details', {})
        query = pd.get('query', '')
        
        if not query:
            return ""
        
        # Show full query (up to 100 chars) - truncate only if very long
        query_display = query.strip()
        if len(query_display) > 100:
            query_display = query_display[:97] + '...'
        
        return f"  {query_display}"


class SessionReader:
    """Helper class to read session data from session directories"""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize SessionReader with optional base directory"""
        self.base_dir = base_dir or Path(__file__).parent.parent
    
    def get_session_directories(self, service: str) -> List[Path]:
        """Get session directories for a specific service"""
        try:
            session_base = self.base_dir / 'sessions' / service
            if session_base.exists():
                return [d for d in session_base.iterdir() if d.is_dir()]
        except Exception:
            pass
        return []
    
    def read_session_summary(self, session_dir: Path) -> Optional[Dict[str, Any]]:
        """Read session summary JSON if available"""
        try:
            summary_file = session_dir / 'summary.json'
            if summary_file.exists():
                with open(summary_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return None
    
    def read_session_replay(self, replay_file: str) -> Optional[Dict[str, Any]]:
        """Read session replay JSON if available"""
        try:
            with open(replay_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
        return None 


class LogViewer:
    """Unified log viewer supporting all protocols"""
    
    ANALYZERS = {
        'ssh': SSHAnalyzer,
        'ftp': FTPAnalyzer,
        'http': HTTPAnalyzer,
        'mysql': MySQLAnalyzer,
    }
    
    def __init__(self, service: str):
        self.service = service
        self.base_dir = Path(__file__).parent.parent
        self.session_reader = SessionReader(self.base_dir)
        self.analyzer = self.ANALYZERS.get(service, ProtocolAnalyzer)(service)
        
        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE and MLDetector and MLConfig:
            try:
                ml_config = MLConfig(service)
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector(service, ml_config)
            except Exception:
                pass
        
    def parse_logs(self, log_file: str, session_id: str = "", decode: bool = False,
                   filter_type: str = 'all') -> Dict[str, Any]:
        """Universal log parser - supports all protocols"""
        conversations = {}
        
        if not os.path.exists(log_file):
            return {}
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    task_name = log_entry.get('task_name', 'unknown')
                    message = log_entry.get('message', '')
                    
                    if session_id and session_id not in task_name:
                        continue
                    
                    # Initialize session
                    if task_name not in conversations:
                        conversations[task_name] = {
                            'session_id': task_name,
                            'src_ip': log_entry.get('src_ip', 'unknown'),
                            'dst_ip': log_entry.get('dst_ip', 'unknown'),
                            'src_port': log_entry.get('src_port'),
                            'dst_port': log_entry.get('dst_port'),
                            'protocol_details': {},
                            'entries': [],
                            'commands': [],
                            'responses': [],
                            'attacks': [],
                            'statistics': {
                                'total_entries': 0,
                                'total_commands': 0,
                                'total_responses': 0,
                                'total_attacks': 0,
                            }
                        }
                    
                    # Extract protocol-specific details
                    protocol_details = self.analyzer.extract_protocol_details(log_entry)
                    
                    # Build entry
                    entry = {
                        'timestamp': log_entry.get('timestamp', ''),
                        'message': message,
                        'level': log_entry.get('level', 'INFO'),
                        'raw': log_entry,
                        'protocol_details': protocol_details,
                    }
                    
                    # Decode base64 if requested
                    if decode and 'details' in log_entry:
                        try:
                            decoded = b64decode(log_entry['details']).decode('utf-8')
                            entry['decoded_details'] = decoded
                        except:
                            entry['decoded_details'] = 'Failed to decode'
                    
                    # Categorize entry
                    category = self.analyzer.categorize_entry(message, log_entry)
                    
                    if category == 'command':
                        conversations[task_name]['commands'].append(entry)
                    elif category == 'response':
                        conversations[task_name]['responses'].append(entry)
                    elif category == 'attack':
                        conversations[task_name]['attacks'].append(entry)
                    
                    conversations[task_name]['entries'].append(entry)
                    
                    # Update session-level details
                    if 'username' in protocol_details and 'username' not in conversations[task_name]['protocol_details']:
                        conversations[task_name]['protocol_details']['username'] = protocol_details['username']
                    
                except (json.JSONDecodeError, Exception):
                    continue
        
        # Calculate statistics
        for task_name, conv in conversations.items():
            conv['statistics']['total_entries'] = len(conv['entries'])
            conv['statistics']['total_commands'] = len(conv['commands'])
            conv['statistics']['total_responses'] = len(conv['responses'])
            conv['statistics']['total_attacks'] = len(conv['attacks'])
        
        return conversations
    
    def parse_ssh_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse SSH logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_ftp_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                      filter_type: str = 'all') -> Dict[str, Any]:
        """Parse FTP logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_http_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                       filter_type: str = 'all') -> Dict[str, Any]:
        """Parse HTTP logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def parse_mysql_logs(self, log_file: str, session_id: str = "", decode: bool = False, 
                        filter_type: str = 'all') -> Dict[str, Any]:
        """Parse MySQL logs (backward compatibility)"""
        return self.parse_logs(log_file, session_id, decode, filter_type)
    
    def get_ml_insights(self, conversations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ML insights from conversations with comprehensive analysis"""
        if not self.ml_detector:
            return {'ml_available': False}
        
        insights = {
            'ml_available': True,
            'service': self.service,
            'timestamp': datetime.datetime.now().isoformat(),
            'total_sessions': len(conversations),
            'anomalies': [],
            'risk_summary': {'high': 0, 'medium': 0, 'low': 0},
            'attack_patterns': {},  # Track attack patterns detected
            'metrics': {
                'entries_analyzed': 0,
                'anomalies_detected': 0,
                'avg_anomaly_score': 0.0,
                'max_anomaly_score': 0.0,
            }
        }
        
        all_scores = []
        
        for session_id, conv in conversations.items():
            for entry in conv['entries']:
                insights['metrics']['entries_analyzed'] += 1
                ml_result = self.analyze_log_entry_ml(entry)
                
                # Track attack patterns from entry data
                raw = entry.get('raw', {})
                attack_types = raw.get('attack_types', [])
                for attack_type in attack_types:
                    insights['attack_patterns'][attack_type] = insights['attack_patterns'].get(attack_type, 0) + 1
                
                if ml_result and 'ml_anomaly_score' in ml_result:
                    anomaly_score = ml_result['ml_anomaly_score']
                    all_scores.append(anomaly_score)
                    
                    if anomaly_score > 0.7:
                        risk_level = 'high' if anomaly_score > 0.9 else 'medium'
                        insights['risk_summary'][risk_level] += 1
                        insights['metrics']['anomalies_detected'] += 1
                        
                        # Store anomaly details
                        insights['anomalies'].append({
                            'session_id': session_id,
                            'anomaly_score': anomaly_score,
                            'risk_level': risk_level,
                            'message': entry.get('message', '')[:100],
                            'timestamp': entry.get('timestamp', ''),
                            'ml_labels': ml_result.get('labels', []),
                        })
                    else:
                        insights['risk_summary']['low'] += 1
        
        # Calculate aggregate metrics
        if all_scores:
            insights['metrics']['avg_anomaly_score'] = sum(all_scores) / len(all_scores)
            insights['metrics']['max_anomaly_score'] = max(all_scores)
        
        # Sort anomalies by score descending
        insights['anomalies'].sort(key=lambda x: x['anomaly_score'], reverse=True)
        
        return insights
    
    def analyze_log_entry_ml(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze single log entry with ML"""
        if not self.ml_detector:
            return {}
        try:
            ml_data = self._extract_ml_features(entry)
            if not ml_data:
                return {}
            return self.ml_detector.score(ml_data)
        except Exception:
            return {}
    
    def _extract_ml_features(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract ML features from entry"""
        pd = entry.get('protocol_details', {})
        
        if self.service == 'ssh':
            cmd = pd.get('command', '')
            return {'command': cmd} if cmd else None
        elif self.service == 'http':
            path = pd.get('path', '/')
            return {'method': pd.get('method', 'GET'), 'path': path} if path else None
        elif self.service == 'mysql':
            query = pd.get('query', '')
            return {'query': query} if query else None
        elif self.service == 'ftp':
            cmd = pd.get('command', '')
            return {'command': cmd, 'path': pd.get('path', '')} if cmd else None
        
        return None
    
    def format_text(self, conversations: Dict[str, Any], include_ml: bool = False,
                   show_full: bool = False) -> str:
        """Format as human-readable text with enhanced professional styling"""
        output = []
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Unicode box drawing characters for modern look
        BOX_TOP = "╔" + "═" * 118 + "╗"
        BOX_MID = "╠" + "═" * 118 + "╣"
        BOX_BOT = "╚" + "═" * 118 + "╝"
        BOX_EDGE = "║"
        SECTION_DIV = "├" + "─" * 118 + "┤"
        
        # Header
        output.append(BOX_TOP)
        title = f"NEXUS {self.service.upper()} HONEYPOT - COMPREHENSIVE SESSION ANALYSIS"
        output.append(f"{BOX_EDGE}  {title:^114}  {BOX_EDGE}")
        output.append(f"{BOX_EDGE}  Generated: {timestamp:^102}  {BOX_EDGE}")
        output.append(BOX_MID)
        
        # Summary Statistics
        total_sessions = len(conversations)
        total_entries = sum(len(c['entries']) for c in conversations.values())
        total_commands = sum(len(c['commands']) for c in conversations.values())
        total_responses = sum(len(c['responses']) for c in conversations.values())
        total_attacks = sum(len(c['attacks']) for c in conversations.values())
        
        output.append(f"{BOX_EDGE}  {'SUMMARY STATISTICS':^114}  {BOX_EDGE}")
        output.append(SECTION_DIV)
        output.append(f"{BOX_EDGE}    Protocol: {self.service.upper():<20} Sessions: {total_sessions:<15} Total Entries: {total_entries:<20}  {BOX_EDGE}")
        output.append(f"{BOX_EDGE}    Commands: {total_commands:<20} Responses: {total_responses:<15} Attacks Detected: {total_attacks:<20}  {BOX_EDGE}")
        
        # ML Summary if enabled
        if include_ml:
            output.append(SECTION_DIV)
            if self.ml_detector:
                output.append(f"{BOX_EDGE}  {'ML ANALYSIS STATUS: ENABLED':^114}  {BOX_EDGE}")
                ml_insights = self.get_ml_insights(conversations)
                if ml_insights.get('ml_available'):
                    metrics = ml_insights.get('metrics', {})
                    risk = ml_insights.get('risk_summary', {})
                    output.append(f"{BOX_EDGE}    Entries Analyzed: {metrics.get('entries_analyzed', 0):<15} Anomalies: {metrics.get('anomalies_detected', 0):<15}                            {BOX_EDGE}")
                    output.append(f"{BOX_EDGE}    Risk Levels -> High: {risk.get('high', 0)}  |  Medium: {risk.get('medium', 0)}  |  Low: {risk.get('low', 0):<50}  {BOX_EDGE}")
            else:
                output.append(f"{BOX_EDGE}  {'ML ANALYSIS: Not Available (ML components not loaded)':^114}  {BOX_EDGE}")
        
        output.append(BOX_MID)
        
        # Session Details
        for idx, (session_id, conv) in enumerate(conversations.items(), 1):
            # Session Header
            output.append(f"{BOX_EDGE}  SESSION {idx}/{total_sessions}: {session_id[:90]:<90}  {BOX_EDGE}")
            output.append(SECTION_DIV)
            
            # Connection Info
            src = conv['src_ip']
            src_port = conv.get('src_port', '?')
            dst = conv['dst_ip']
            dst_port = conv.get('dst_port', '?')
            output.append(f"{BOX_EDGE}    Connection: {src}:{src_port} --> {dst}:{dst_port:<65}  {BOX_EDGE}")
            
            # Protocol Details
            if conv['protocol_details']:
                proto_details = []
                for key, value in conv['protocol_details'].items():
                    if isinstance(value, (dict, list)):
                        proto_details.append(f"{key}: {...}")
                    else:
                        proto_details.append(f"{key}: {value}")
                proto_str = " | ".join(proto_details[:4])  # First 4 details
                output.append(f"{BOX_EDGE}    Details: {proto_str[:105]:<105}  {BOX_EDGE}")
            
            # Statistics Bar
            stats = conv['statistics']
            output.append(f"{BOX_EDGE}    Stats: {stats['total_entries']} entries | {stats['total_commands']} commands | {stats['total_responses']} responses | {stats['total_attacks']} attacks{' '*30}  {BOX_EDGE}")
            
            # Command Timeline - only show commands with actual query/command content
            commands_with_content = [cmd for cmd in conv['commands'] 
                                     if cmd.get('protocol_details', {}).get('query', '').strip()]
            if commands_with_content:
                output.append(SECTION_DIV)
                output.append(f"{BOX_EDGE}    QUERY TIMELINE ({len(commands_with_content)} queries):{' '*70}  {BOX_EDGE}")
                for i, cmd in enumerate(commands_with_content, 1):
                    ts = cmd.get('timestamp', '')[:19]
                    pd = cmd.get('protocol_details', {})
                    query = pd.get('query', '').strip()
                    query_type = pd.get('query_type', '')
                    
                    # Show query with type indicator
                    if len(query) > 90:
                        query = query[:87] + '...'
                    
                    # Detect attack indicator from ML or attack types
                    attack_indicator = ""
                    if pd.get('attack_types'):
                        attack_indicator = " [!ATTACK]"
                    elif pd.get('severity') in ['critical', 'high']:
                        attack_indicator = " [!]"
                    
                    line = f"      {i:>3}. [{ts}] {query}{attack_indicator}"
                    output.append(f"{BOX_EDGE}{line[:116]:<116}  {BOX_EDGE}")
                    
                    # Show ML analysis if present
                    if show_full and pd.get('ml_anomaly_score'):
                        ml_line = f"           ML Score: {pd['ml_anomaly_score']:.3f} | Labels: {', '.join(pd.get('ml_labels', []))}"
                        output.append(f"{BOX_EDGE}{ml_line[:116]:<116}  {BOX_EDGE}")
            
            # Responses - show with LLM response content
            if conv['responses']:
                output.append(SECTION_DIV)
                # Filter to only show meaningful responses (LLM responses or query completed with data)
                meaningful_responses = [r for r in conv['responses'] 
                                        if 'llm response' in r.get('message', '').lower() 
                                        or r.get('protocol_details', {}).get('llm_response')]
                
                if meaningful_responses:
                    output.append(f"{BOX_EDGE}    LLM RESPONSES ({len(meaningful_responses)} total):{' '*70}  {BOX_EDGE}")
                    for i, resp in enumerate(meaningful_responses, 1):
                        ts = resp.get('timestamp', '')[:19]
                        pd = resp.get('protocol_details', {})
                        llm_resp = pd.get('llm_response', '')
                        model = pd.get('model', '')
                        query = pd.get('query', '')[:40]
                        
                        # First line - query and model
                        line = f"      {i:>3}. [{ts}] Query: {query}"
                        if model:
                            line += f" (Model: {model})"
                        output.append(f"{BOX_EDGE}{line[:116]:<116}  {BOX_EDGE}")
                        
                        # Show LLM response preview
                        if llm_resp:
                            resp_preview = llm_resp.replace('\n', ' ')[:100]
                            if len(llm_resp) > 100:
                                resp_preview += '...'
                            line2 = f"           Response: {resp_preview}"
                            output.append(f"{BOX_EDGE}{line2[:116]:<116}  {BOX_EDGE}")
                else:
                    # Show all responses if no LLM responses
                    output.append(f"{BOX_EDGE}    RESPONSES ({len(conv['responses'])} total):{' '*77}  {BOX_EDGE}")
                    for i, resp in enumerate(conv['responses'][:20], 1):  # Limit to 20
                        ts = resp.get('timestamp', '')[:19]
                        msg = resp.get('message', '')[:80]
                        line = f"      {i:>3}. [{ts}] {msg}"
                        output.append(f"{BOX_EDGE}{line[:116]:<116}  {BOX_EDGE}")
                    
                    if len(conv['responses']) > 20:
                        output.append(f"{BOX_EDGE}           ... and {len(conv['responses']) - 20} more responses{' '*70}  {BOX_EDGE}")
                    
                    # Show decoded details if available and full mode enabled
                    if show_full:
                        for resp in conv['responses'][:5]:
                            if resp.get('decoded_details'):
                                decoded_lines = resp['decoded_details'][:200].split('\n')
                                for dl in decoded_lines[:3]:
                                    output.append(f"{BOX_EDGE}           {dl[:104]:<104}  {BOX_EDGE}")
            
            # Attacks (FULL with severity indicators)
            if conv['attacks']:
                output.append(SECTION_DIV)
                severity_icons = {'critical': '!!!', 'high': '!! ', 'medium': '!  ', 'low': '.  ', 'unknown': '?  '}
                output.append(f"{BOX_EDGE}    DETECTED ATTACKS ({len(conv['attacks'])} total):{' '*70}  {BOX_EDGE}")
                for i, attack in enumerate(conv['attacks'], 1):
                    ts = attack.get('timestamp', '')[:19]
                    msg = attack.get('message', '')[:60]
                    raw = attack.get('raw', {})
                    types = raw.get('attack_types', [])
                    severity = raw.get('severity', 'unknown')
                    sev_icon = severity_icons.get(severity, '?  ')
                    
                    line = f"      {sev_icon} [{ts}] {msg}"
                    output.append(f"{BOX_EDGE}{line[:116]:<116}  {BOX_EDGE}")
                    if types:
                        types_str = f"           Types: {', '.join(types[:5])} | Severity: {severity.upper()}"
                        output.append(f"{BOX_EDGE}{types_str[:116]:<116}  {BOX_EDGE}")
                    
                    # Show indicators if available
                    indicators = raw.get('indicators', [])
                    if indicators:
                        ind_str = f"           Indicators: {', '.join(str(ind) for ind in indicators[:3])}"
                        output.append(f"{BOX_EDGE}{ind_str[:116]:<116}  {BOX_EDGE}")
            
            # ML Analysis for session if enabled
            if include_ml and self.ml_detector:
                session_ml = self.get_ml_insights({session_id: conv})
                if session_ml.get('metrics', {}).get('anomalies_detected', 0) > 0:
                    output.append(SECTION_DIV)
                    output.append(f"{BOX_EDGE}    ML ANALYSIS:{' '*99}  {BOX_EDGE}")
                    metrics = session_ml.get('metrics', {})
                    risk = session_ml.get('risk_summary', {})
                    ml_line = f"           Anomalies: {metrics.get('anomalies_detected', 0)} | High: {risk.get('high', 0)} | Medium: {risk.get('medium', 0)} | Low: {risk.get('low', 0)}"
                    output.append(f"{BOX_EDGE}{ml_line[:116]:<116}  {BOX_EDGE}")
            
            output.append(BOX_MID)
        
        # Footer
        output.append(f"{BOX_EDGE}  {'END OF ANALYSIS REPORT':^114}  {BOX_EDGE}")
        output.append(f"{BOX_EDGE}  {'Generated by nexus honeypot platform':^114}  {BOX_EDGE}")
        output.append(BOX_BOT)
        
        return "\n".join(output)
    
    def format_json(self, conversations: Dict[str, Any], include_ml: bool = False) -> str:
        """Format as JSON"""
        data = {
            'service': self.service,
            'timestamp': datetime.datetime.now().isoformat(),
            'summary': {
                'total_sessions': len(conversations),
                'total_entries': sum(len(c['entries']) for c in conversations.values()),
                'total_commands': sum(len(c['commands']) for c in conversations.values()),
                'total_responses': sum(len(c['responses']) for c in conversations.values()),
                'total_attacks': sum(len(c['attacks']) for c in conversations.values()),
            },
            'sessions': {}
        }
        
        for session_id, conv in conversations.items():
            session_data = {
                'session_id': session_id,
                'source': {
                    'ip': conv['src_ip'],
                    'port': conv.get('src_port'),
                },
                'destination': {
                    'ip': conv['dst_ip'],
                    'port': conv.get('dst_port'),
                },
                'protocol_details': conv['protocol_details'],
                'statistics': conv['statistics'],
                'entries': [
                    {
                        'timestamp': e['timestamp'],
                        'message': e['message'],
                        'level': e['level'],
                        'protocol_details': e['protocol_details'],
                        'decoded_details': e.get('decoded_details'),
                    }
                    for e in conv['entries']
                ],
                'commands': [
                    {
                        'timestamp': c.get('timestamp'),
                        'query': c.get('protocol_details', {}).get('query', ''),
                        'query_type': c.get('protocol_details', {}).get('query_type', ''),
                        'username': c.get('protocol_details', {}).get('username', ''),
                    }
                    for c in conv['commands']
                ],
                'responses': [
                    {
                        'timestamp': r.get('timestamp'),
                        'message': r.get('message', ''),
                        'llm_response': r.get('protocol_details', {}).get('llm_response', ''),
                        'model': r.get('protocol_details', {}).get('model', ''),
                    }
                    for r in conv['responses']
                ],
                'attacks': [
                    {
                        'timestamp': a.get('timestamp'),
                        'message': a.get('message'),
                        'query': a.get('protocol_details', {}).get('query', ''),
                        'attack_types': a.get('raw', {}).get('attack_types', []),
                        'severity': a.get('raw', {}).get('severity'),
                        'threat_score': a.get('raw', {}).get('threat_score', 0),
                        'indicators': a.get('raw', {}).get('indicators', []),
                        'vulnerability_id': a.get('protocol_details', {}).get('vulnerability_id', ''),
                        'cvss_score': a.get('protocol_details', {}).get('cvss_score', 0),
                    }
                    for a in conv['attacks']
                ]
            }
            
            if include_ml:
                ml_insights = self.get_ml_insights({session_id: conv})
                session_data['ml_insights'] = ml_insights
            
            data['sessions'][session_id] = session_data
        
        if include_ml:
            data['ml_summary'] = self.get_ml_insights(conversations)
        
        return json.dumps(data, indent=2, default=str)
    
    def format_conversation(self, conversations: Dict[str, Any], format_type: str = 'text',
                          show_full: bool = False, include_ml: bool = False) -> str:
        """Format conversations (backward compatibility) - 'both' returns text format for display"""
        if format_type == 'json':
            return self.format_json(conversations, include_ml)
        else:
            # For 'both', return text for display - JSON saved separately
            return self.format_text(conversations, include_ml, show_full)
    
    def save_conversation(self, content: str, output_file: str, format_type: str = 'text',
                         conversations: Dict[str, Any] = None, include_ml: bool = False) -> Dict[str, str]:
        """
        Save to file(s). For 'both' format, saves both text and JSON files.
        
        Args:
            content: The text content to save
            output_file: Base output path
            format_type: 'text', 'json', or 'both'
            conversations: Required for 'both' format to generate JSON
            include_ml: Include ML insights in output
            
        Returns:
            Dictionary with 'text' and/or 'json' paths
        """
        output_path = Path(output_file)
        
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        saved_files = {}
        
        if format_type == 'both':
            # Save both formats
            base_name = output_path.stem
            base_dir = output_path.parent
            
            # Save text file
            text_path = base_dir / f"{base_name}.txt"
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(content)
            saved_files['text'] = str(text_path.resolve())
            
            # Save JSON file
            if conversations:
                json_path = base_dir / f"{base_name}.json"
                json_content = self.format_json(conversations, include_ml)
                with open(json_path, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                saved_files['json'] = str(json_path.resolve())
        else:
            # Single format save
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            saved_files[format_type] = str(output_path.resolve())
        
        return saved_files

def main():
    parser = argparse.ArgumentParser(description='NEXUS Honeypot Log Viewer with ML Analysis')
    parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql'],
                       help='Service to view logs for')
    parser.add_argument('--log-file', '-f', help='Log file path')
    parser.add_argument('--session-id', '-i', help='Specific session ID')
    parser.add_argument('--decode', '-d', action='store_true', help='Decode base64 details')
    parser.add_argument('--conversation', '-c', action='store_true', help='Show full conversation')
    parser.add_argument('--save', '-s', help='Save to file')
    parser.add_argument('--format', choices=['text', 'json', 'both'], default='text', help='Output format (both saves as text and json)')
    parser.add_argument('--filter', choices=['all', 'commands', 'responses', 'attacks', 'anomalies'],
                       default='all', help='Filter entries')
    
    # ML Analysis options
    parser.add_argument('--ml-analysis', '--ml', action='store_true', 
                       help='Enable ML-based anomaly detection and analysis')
    parser.add_argument('--anomaly-threshold', type=float, default=0.7,
                       help='Anomaly detection threshold (0.0-1.0, default: 0.7)')
    parser.add_argument('--ml-insights', action='store_true',
                       help='Show detailed ML insights and statistics')
    parser.add_argument('--high-risk-only', action='store_true',
                       help='Show only high-risk sessions (anomaly score > 0.9)')
    
    args = parser.parse_args()
    
    if args.service not in ['ssh', 'ftp', 'http', 'mysql']:
        print(f"Error: Log viewing for {args.service} not implemented")
        return 1
    
    # Default log file location - check both new and old locations
    if not args.log_file:
        base_dir = Path(__file__).parent.parent
        new_log_path = None
        old_log_path = None
        if args.service == 'ssh':
            new_log_path = base_dir / 'logs' / 'ssh_log.log'
            old_log_path = base_dir / 'service_emulators' / 'SSH' / 'ssh_log.log'
        elif args.service == 'ftp':
            new_log_path = base_dir / 'logs' / 'ftp_log.log'
            old_log_path = base_dir / 'service_emulators' / 'FTP' / 'ftp_log.log'
        elif args.service == 'http':
            new_log_path = base_dir / 'logs' / 'http_log.log'
            old_log_path = base_dir / 'service_emulators' / 'HTTP' / 'http_log.log'
        elif args.service == 'mysql':
            new_log_path = base_dir / 'logs' / 'mysql_log.log'
            old_log_path = base_dir / 'service_emulators' / 'MySQL' / 'mysql_log.log'
        
        if new_log_path and new_log_path.exists():
            args.log_file = str(new_log_path)
        elif old_log_path and old_log_path.exists():
            args.log_file = str(old_log_path)
        elif new_log_path:
            args.log_file = str(new_log_path)  # Default to new location
    
    try:
        viewer = LogViewer(args.service)
        conversations = {}
        if args.service == 'ssh':
            conversations = viewer.parse_ssh_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'ftp':
            conversations = viewer.parse_ftp_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'http':
            conversations = viewer.parse_http_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        elif args.service == 'mysql':
            conversations = viewer.parse_mysql_logs(
                args.log_file, args.session_id, args.decode, args.filter
            )
        if not conversations:
            print("No conversations found")
            return 1
        
        # Apply ML filtering if requested
        if args.ml_analysis or args.ml_insights:
            if not ML_AVAILABLE:
                print(" Error: ML analysis requested but ML components not available")
                return 1
            
            # Get ML insights first
            ml_insights = viewer.get_ml_insights(conversations)
            
            # Filter high-risk sessions if requested
            if args.high_risk_only:
                high_risk_sessions = {}
                for session_id, conv in conversations.items():
                    if conv.get('ml_risk_score', 0) > 0.9:
                        high_risk_sessions[session_id] = conv
                conversations = high_risk_sessions
                
                if not conversations:
                    print("No high-risk sessions found")
                    return 1
            
            # Filter anomalies if requested
            if args.filter == 'anomalies':
                anomaly_sessions = {}
                for session_id, conv in conversations.items():
                    if conv.get('ml_anomalies', []):
                        anomaly_sessions[session_id] = conv
                conversations = anomaly_sessions
                
                if not conversations:
                    print("No sessions with anomalies found")
                    return 1
            
            # Show detailed ML insights if requested
            if args.ml_insights:
                print("\n" + "=" * 80)
                print(" DETAILED ML INSIGHTS")
                print("=" * 80)
                
                if ml_insights.get('ml_available'):
                    print(f" Service: {ml_insights['service'].upper()}")
                    print(f" Analysis Time: {ml_insights.get('timestamp', 'N/A')}")
                    print(f" Total Sessions: {ml_insights['total_sessions']}")
                    metrics = ml_insights.get('metrics', {})
                    print(f" Entries Analyzed: {metrics.get('entries_analyzed', 0)}")
                    print(f" Anomalies Detected: {metrics.get('anomalies_detected', 0)}")
                    print(f" Average Anomaly Score: {metrics.get('avg_anomaly_score', 0):.3f}")
                    print(f" Maximum Anomaly Score: {metrics.get('max_anomaly_score', 0):.3f}")
                    
                    # Risk breakdown
                    risk_summary = ml_insights.get('risk_summary', {})
                    print(f"\n RISK BREAKDOWN:")
                    print(f"    High Risk: {risk_summary.get('high', 0)}")
                    print(f"    Medium Risk: {risk_summary.get('medium', 0)}")
                    print(f"    Low Risk: {risk_summary.get('low', 0)}")
                    
                    # Attack patterns
                    attack_patterns = ml_insights.get('attack_patterns', {})
                    if attack_patterns:
                        print(f"\n ATTACK PATTERNS DETECTED:")
                        for pattern, count in sorted(attack_patterns.items(), key=lambda x: x[1], reverse=True):
                            print(f"   • {pattern}: {count} occurrences")
                    
                    # Top anomalies
                    anomalies = ml_insights.get('anomalies', [])
                    if anomalies:
                        print(f"\n TOP ANOMALIES:")
                        for i, anomaly in enumerate(anomalies[:5], 1):
                            risk_emoji = "High" if anomaly.get('risk_level') == 'high' else "Medium" if anomaly.get('risk_level') == 'medium' else "Low"
                            print(f"   {i}. {risk_emoji} Score: {anomaly.get('anomaly_score', 0):.3f} | Session: {anomaly.get('session_id', 'N/A')}")
                            print(f"       {anomaly.get('message', 'N/A')}")
                            ml_labels = anomaly.get('ml_labels', [])
                            if ml_labels:
                                print(f"      Labels: {', '.join(ml_labels)}")
                else:
                    print(" ML analysis not available")
                
                print("=" * 80)
        
        # Enable ML analysis in output if requested
        include_ml = args.ml_analysis or args.ml_insights
        output = viewer.format_conversation(conversations, args.format, args.conversation, include_ml)
        
        if args.save:
            saved_paths = viewer.save_conversation(
                output, args.save, 
                format_type=args.format,
                conversations=conversations if args.format == 'both' else None,
                include_ml=include_ml
            )
            # Print saved paths
            for fmt, path in saved_paths.items():
                print(f"[SAVED] {fmt.upper()} file: {path}")
        else:
            # Handle encoding issues on Windows
            try:
                print(output)
            except UnicodeEncodeError:
                # Fallback to UTF-8 encoding
                import sys
                sys.stdout.buffer.write(output.encode('utf-8'))
                sys.stdout.buffer.write(b'\n')
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())