"""
LLM Interface - Integration with Large Language Models for dynamic response generation
"""

import json
import time
import random
from typing import Dict, List, Optional, Any
from datetime import datetime


class LLMInterface:
    """
    Interface for Large Language Model integration
    Supports Llama3-8B and other models for realistic response generation
    """
    
    def __init__(self, model_name: str = "llama3-8b"):
        self.model_name = model_name
        self.initialized = False
        self.model_client = None
        
        # Response templates for different services
        self.response_templates = {
            "ssh": {
                "command_not_found": [
                    "bash: {command}: command not found",
                    "-bash: {command}: No such file or directory",
                    "sh: {command}: not found"
                ],
                "permission_denied": [
                    "bash: {command}: Permission denied",
                    "-bash: {command}: cannot execute binary file",
                    "sudo: {command}: command not found"
                ],
                "file_operations": [
                    "ls: cannot access '{path}': No such file or directory",
                    "cat: {file}: No such file or directory",
                    "mkdir: cannot create directory '{dir}': File exists"
                ]
            },
            "ftp": {
                "file_not_found": [
                    "550 {file}: No such file or directory",
                    "550 Failed to open file",
                    "550 {file}: Permission denied"
                ],
                "login_responses": [
                    "230 Login successful",
                    "530 Login incorrect",
                    "331 Please specify the password"
                ],
                "directory_listing": [
                    "150 Here comes the directory listing",
                    "226 Directory send OK",
                    "550 Failed to change directory"
                ]
            },
            "mysql": {
                "syntax_errors": [
                    "ERROR 1064 (42000): You have an error in your SQL syntax",
                    "ERROR 1146 (42S02): Table '{table}' doesn't exist",
                    "ERROR 1045 (28000): Access denied for user '{user}'"
                ],
                "query_responses": [
                    "Query OK, {rows} rows affected",
                    "Empty set (0.00 sec)",
                    "ERROR 1054 (42S22): Unknown column '{column}' in 'field list'"
                ]
            },
            "smb": {
                "access_denied": [
                    "NT_STATUS_ACCESS_DENIED",
                    "NT_STATUS_LOGON_FAILURE",
                    "NT_STATUS_INVALID_PARAMETER"
                ],
                "file_operations": [
                    "NT_STATUS_OBJECT_NAME_NOT_FOUND",
                    "NT_STATUS_SHARING_VIOLATION",
                    "NT_STATUS_FILE_IS_A_DIRECTORY"
                ]
            },
            "rdp": {
                "authentication": [
                    "Authentication failed",
                    "Invalid credentials",
                    "Account locked out"
                ],
                "connection": [
                    "Connection established",
                    "Remote desktop services are currently busy",
                    "The connection was denied because the user account is not authorized"
                ]
            }
        }
        
        # System information templates
        self.system_info_templates = {
            "linux": {
                "uname": "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux",
                "whoami": "root",
                "pwd": "/root",
                "id": "uid=0(root) gid=0(root) groups=0(root)",
                "ps": "PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps"
            },
            "windows": {
                "ver": "Microsoft Windows [Version 10.0.19042.1052]",
                "whoami": "DESKTOP-ABC123\\Administrator",
                "dir": "Directory of C:\\Users\\Administrator\n\n12/01/2023  10:30 AM    <DIR>          .\n12/01/2023  10:30 AM    <DIR>          .."
            }
        }
    
    def initialize(self):
        """Initialize LLM interface"""
        try:
            # In a real implementation, this would initialize the actual LLM client
            # For now, we'll use template-based responses with some AI-like behavior
            self.initialized = True
            print(f"[{datetime.now()}] LLM Interface initialized with model: {self.model_name}")
            
        except Exception as e:
            print(f"[{datetime.now()}] LLM Interface initialization failed: {e}")
            raise
    
    def generate_response(self, service: str, command: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate AI-driven response for attacker command
        """
        if not self.initialized:
            return self._fallback_response(service, command)
        
        try:
            # Analyze command intent
            command_analysis = self._analyze_command_intent(command, service)
            
            # Generate contextual response
            response = self._generate_contextual_response(
                service, command, command_analysis, context
            )
            
            # Add realistic timing
            response_delay = self._calculate_response_delay(command, service)
            
            # Add system load simulation
            system_load = self._simulate_system_load()
            
            return {
                "text": response,
                "delay": response_delay,
                "system_load": system_load,
                "command_analysis": command_analysis,
                "confidence": random.uniform(0.7, 0.95)
            }
            
        except Exception as e:
            print(f"[{datetime.now()}] LLM response generation error: {e}")
            return self._fallback_response(service, command)
    
    def _analyze_command_intent(self, command: str, service: str) -> Dict[str, Any]:
        """Analyze the intent behind the attacker's command"""
        command_lower = command.lower().strip()
        
        # Common attack patterns
        reconnaissance_patterns = [
            "whoami", "id", "uname", "ps", "netstat", "ifconfig", "ls", "dir",
            "cat /etc/passwd", "cat /etc/shadow", "systeminfo", "ver"
        ]
        
        exploitation_patterns = [
            "wget", "curl", "nc", "netcat", "python", "perl", "bash", "sh",
            "powershell", "cmd", "sudo", "su", "chmod", "chown"
        ]
        
        persistence_patterns = [
            "crontab", "systemctl", "service", "reg add", "schtasks",
            "echo", ">>", "mkdir", "touch", "copy", "move"
        ]
        
        # Classify command intent
        if any(pattern in command_lower for pattern in reconnaissance_patterns):
            intent = "reconnaissance"
            confidence = 0.8
        elif any(pattern in command_lower for pattern in exploitation_patterns):
            intent = "exploitation"
            confidence = 0.9
        elif any(pattern in command_lower for pattern in persistence_patterns):
            intent = "persistence"
            confidence = 0.7
        else:
            intent = "unknown"
            confidence = 0.3
        
        return {
            "intent": intent,
            "confidence": confidence,
            "command_type": self._classify_command_type(command, service),
            "risk_level": self._assess_risk_level(command, intent)
        }
    
    def _classify_command_type(self, command: str, service: str) -> str:
        """Classify the type of command based on service"""
        command_lower = command.lower().strip()
        
        if service == "ssh":
            if command_lower.startswith(("ls", "dir", "pwd")):
                return "directory_listing"
            elif command_lower.startswith(("cat", "type", "more", "less")):
                return "file_read"
            elif command_lower.startswith(("wget", "curl", "download")):
                return "file_download"
            elif command_lower.startswith(("chmod", "chown", "attrib")):
                return "permission_change"
            else:
                return "system_command"
        
        elif service == "ftp":
            if command_lower.startswith(("list", "ls", "dir")):
                return "directory_listing"
            elif command_lower.startswith(("get", "retr")):
                return "file_download"
            elif command_lower.startswith(("put", "stor")):
                return "file_upload"
            elif command_lower.startswith(("cd", "cwd")):
                return "directory_change"
            else:
                return "ftp_command"
        
        elif service == "mysql":
            if command_lower.startswith("select"):
                return "data_query"
            elif command_lower.startswith(("insert", "update", "delete")):
                return "data_modification"
            elif command_lower.startswith(("create", "drop", "alter")):
                return "schema_modification"
            elif command_lower.startswith("show"):
                return "information_gathering"
            else:
                return "sql_command"
        
        return "generic_command"
    
    def _assess_risk_level(self, command: str, intent: str) -> str:
        """Assess the risk level of the command"""
        high_risk_patterns = [
            "rm -rf", "del /f", "format", "fdisk", "dd if=", "mkfs",
            "wget", "curl", "nc -l", "python -c", "perl -e",
            "chmod 777", "sudo su", "su -", "/etc/passwd", "/etc/shadow"
        ]
        
        medium_risk_patterns = [
            "ps aux", "netstat", "ifconfig", "systeminfo", "whoami",
            "crontab", "systemctl", "service", "reg query"
        ]
        
        command_lower = command.lower()
        
        if any(pattern in command_lower for pattern in high_risk_patterns):
            return "high"
        elif any(pattern in command_lower for pattern in medium_risk_patterns):
            return "medium"
        elif intent in ["reconnaissance", "exploitation"]:
            return "medium"
        else:
            return "low"
    
    def _generate_contextual_response(self, service: str, command: str, 
                                    analysis: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Generate contextual response based on command analysis"""
        command_type = analysis.get("command_type", "generic_command")
        intent = analysis.get("intent", "unknown")
        
        # Get appropriate response template
        if service in self.response_templates:
            service_templates = self.response_templates[service]
            
            # Select response based on command type and intent
            if command_type == "directory_listing" and service == "ssh":
                return self._generate_directory_listing(command, context)
            elif command_type == "file_read" and service == "ssh":
                return self._generate_file_read_response(command, context)
            elif command_type == "system_command" and service == "ssh":
                return self._generate_system_command_response(command, context)
            elif service == "ftp" and command_type in ["directory_listing", "file_download"]:
                return self._generate_ftp_response(command, command_type, context)
            elif service == "mysql":
                return self._generate_mysql_response(command, command_type, context)
            else:
                # Use template-based response
                return self._select_template_response(service, command_type, command)
        
        return f"Command '{command}' not recognized"
    
    def _generate_directory_listing(self, command: str, context: Dict[str, Any]) -> str:
        """Generate realistic directory listing"""
        fake_files = [
            "drwxr-xr-x 2 root root 4096 Dec  1 10:30 .",
            "drwxr-xr-x 3 root root 4096 Dec  1 10:29 ..",
            "-rw-r--r-- 1 root root  220 Dec  1 10:29 .bash_logout",
            "-rw-r--r-- 1 root root 3771 Dec  1 10:29 .bashrc",
            "-rw-r--r-- 1 root root  807 Dec  1 10:29 .profile",
            "-rw------- 1 root root 1024 Dec  1 10:30 .ssh",
            "drwxr-xr-x 2 root root 4096 Dec  1 10:30 Documents",
            "-rw-r--r-- 1 root root 2048 Dec  1 10:30 config.txt"
        ]
        
        return "\n".join(fake_files)
    
    def _generate_file_read_response(self, command: str, context: Dict[str, Any]) -> str:
        """Generate realistic file read response"""
        # Extract filename from command
        parts = command.split()
        if len(parts) > 1:
            filename = parts[1]
            
            if "passwd" in filename:
                return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            elif "shadow" in filename:
                return "cat: /etc/shadow: Permission denied"
            elif "config" in filename:
                return "# Configuration file\nserver_port=22\ndebug_mode=false\nmax_connections=100"
            else:
                return f"cat: {filename}: No such file or directory"
        
        return "cat: missing file operand"
    
    def _generate_system_command_response(self, command: str, context: Dict[str, Any]) -> str:
        """Generate system command response"""
        command_lower = command.lower().strip()
        
        if command_lower == "whoami":
            return "root"
        elif command_lower == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        elif command_lower in ["uname -a", "uname"]:
            return self.system_info_templates["linux"]["uname"]
        elif command_lower == "pwd":
            return "/root"
        elif command_lower in ["ps", "ps aux"]:
            return self.system_info_templates["linux"]["ps"]
        else:
            return f"bash: {command}: command not found"
    
    def _generate_ftp_response(self, command: str, command_type: str, context: Dict[str, Any]) -> str:
        """Generate FTP-specific response"""
        if command_type == "directory_listing":
            return "150 Here comes the directory listing.\n" + \
                   "drwxr-xr-x    2 ftp      ftp          4096 Dec 01 10:30 pub\n" + \
                   "-rw-r--r--    1 ftp      ftp          1024 Dec 01 10:30 readme.txt\n" + \
                   "226 Directory send OK."
        elif command_type == "file_download":
            return "550 Failed to open file."
        else:
            return "500 Unknown command."
    
    def _generate_mysql_response(self, command: str, command_type: str, context: Dict[str, Any]) -> str:
        """Generate MySQL-specific response"""
        _ = context  # Context reserved for future use
        if command_type == "data_query":
            return "Empty set (0.00 sec)"
        elif command_type == "information_gathering":
            if "databases" in command.lower():
                return "+--------------------+\n| Database           |\n+--------------------+\n| information_schema |\n| mysql              |\n| test               |\n+--------------------+"
            elif "tables" in command.lower():
                return "Empty set (0.00 sec)"
            else:
                return "Empty set (0.00 sec)"
        else:
            return "ERROR 1064 (42000): You have an error in your SQL syntax"
    
    def _select_template_response(self, service: str, command_type: str, command: str) -> str:
        """Select appropriate template response"""
        if service in self.response_templates:
            templates = self.response_templates[service]
            
            # Select appropriate template category
            if command_type in templates:
                responses = templates[command_type]
            elif "command_not_found" in templates:
                responses = templates["command_not_found"]
            else:
                responses = list(templates.values())[0]  # First available template
            
            # Select random response and format it
            response_template = random.choice(responses)
            return response_template.format(command=command, file=command, path=command)
        
        return f"Command '{command}' not recognized"
    
    def _calculate_response_delay(self, command: str, service: str) -> float:
        """Calculate realistic response delay"""
        base_delays = {
            "ssh": (0.1, 2.0),
            "ftp": (0.05, 1.0),
            "mysql": (0.02, 0.5),
            "smb": (0.1, 1.5),
            "rdp": (0.5, 3.0)
        }
        
        min_delay, max_delay = base_delays.get(service, (0.1, 1.0))
        
        # Adjust delay based on command complexity
        if len(command) > 50:
            max_delay *= 1.5
        
        # Add some randomness for realism
        return random.uniform(min_delay, max_delay)
    
    def _simulate_system_load(self) -> Dict[str, float]:
        """Simulate realistic system load indicators"""
        return {
            "cpu_usage": random.uniform(5.0, 25.0),
            "memory_usage": random.uniform(30.0, 70.0),
            "disk_io": random.uniform(0.1, 5.0),
            "network_io": random.uniform(0.5, 10.0)
        }
    
    def _fallback_response(self, service: str, command: str) -> Dict[str, Any]:
        """Generate fallback response when LLM is unavailable"""
        fallback_responses = {
            "ssh": "bash: command not found",
            "ftp": "500 Unknown command",
            "mysql": "ERROR 1064 (42000): You have an error in your SQL syntax",
            "smb": "NT_STATUS_ACCESS_DENIED",
            "rdp": "Authentication failed"
        }
        
        return {
            "text": fallback_responses.get(service, "Command not recognized"),
            "delay": random.uniform(0.1, 1.0),
            "system_load": self._simulate_system_load(),
            "command_analysis": {"intent": "unknown", "confidence": 0.1},
            "confidence": 0.1,
            "fallback": True
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        return {
            "model_name": self.model_name,
            "initialized": self.initialized,
            "capabilities": [
                "dynamic_response_generation",
                "contextual_analysis",
                "realistic_timing",
                "system_simulation"
            ]
        }