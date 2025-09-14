"""
Response Generator - AI-driven dynamic response generation with adaptive behavior
"""

import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class ResponseContext:
    """Context for response generation"""
    service: str
    command: str
    attack_type: str
    risk_level: float
    attacker_ip: str
    session_duration: float
    previous_commands: List[str]


class ResponseGenerator:
    """
    Generates dynamic, contextual responses using AI techniques
    to maintain realistic interaction with attackers
    """
    
    def __init__(self):
        self.llm_interface = None
        self.response_cache = {}
        self.adaptive_policies = {}
        self.initialized = False
        
        # Response strategy configurations
        self.response_strategies = {
            "deceptive": {
                "description": "Provide misleading but believable responses",
                "engagement_level": 0.8,
                "information_leakage": 0.3
            },
            "minimal": {
                "description": "Provide minimal responses to maintain connection",
                "engagement_level": 0.3,
                "information_leakage": 0.1
            },
            "interactive": {
                "description": "Engage actively to gather more intelligence",
                "engagement_level": 0.9,
                "information_leakage": 0.6
            },
            "honeytrap": {
                "description": "Lead attacker into revealing more information",
                "engagement_level": 0.95,
                "information_leakage": 0.8
            }
        }
    
    def initialize(self, llm_interface):
        """Initialize response generator with LLM interface"""
        self.llm_interface = llm_interface
        self.load_response_templates()
        self.initialized = True
        print(f"[{datetime.now()}] Response Generator initialized")
    
    def generate_response(self, service: str, command: str, attack_context, 
                         behavior_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate AI-driven response based on context and analysis
        """
        if not self.initialized:
            return self._fallback_response(service, command)
        
        try:
            # Create response context
            response_context = self._create_response_context(
                service, command, attack_context, behavior_analysis
            )
            
            # Select response strategy
            strategy = self._select_response_strategy(response_context, behavior_analysis)
            
            # Generate base response using LLM
            if self.llm_interface is None:
                return self._fallback_response(service, command)
            
            base_response = self.llm_interface.generate_response(
                service, command, {
                    "attack_context": attack_context,
                    "behavior_analysis": behavior_analysis,
                    "strategy": strategy
                }
            )
            
            # Apply adaptive modifications
            adaptive_response = self._apply_adaptive_modifications(
                base_response, response_context, strategy
            )
            
            # Add deception elements if needed
            final_response = self._add_deception_elements(
                adaptive_response, response_context, strategy
            )
            
            # Calculate effectiveness score
            effectiveness = self._calculate_response_effectiveness(
                final_response, response_context, behavior_analysis
            )
            
            return {
                "text": final_response["text"],
                "delay": final_response["delay"],
                "strategy": strategy,
                "effectiveness": effectiveness,
                "system_load": final_response.get("system_load", {}),
                "deception_level": strategy.get("information_leakage", 0.5),
                "engagement_score": strategy.get("engagement_level", 0.5)
            }
            
        except Exception as e:
            print(f"[{datetime.now()}] Response generation error: {e}")
            return self._fallback_response(service, command)
    
    def _create_response_context(self, service: str, command: str, 
                                attack_context, behavior_analysis: Dict[str, Any]) -> ResponseContext:
        """Create comprehensive response context"""
        return ResponseContext(
            service=service,
            command=command,
            attack_type=behavior_analysis.get("attack_type", "unknown"),
            risk_level=behavior_analysis.get("risk_score", 0.0),
            attacker_ip=attack_context.attacker_ip if attack_context else "unknown",
            session_duration=self._calculate_session_duration(attack_context),
            previous_commands=attack_context.commands if attack_context else []
        )
    
    def _calculate_session_duration(self, attack_context) -> float:
        """Calculate session duration in minutes"""
        if not attack_context:
            return 0.0
        
        start_time = attack_context.start_time
        current_time = datetime.now()
        duration = (current_time - start_time).total_seconds() / 60.0
        return duration
    
    def _select_response_strategy(self, context: ResponseContext, 
                                 behavior_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Select appropriate response strategy based on context and analysis
        """
        attack_type = context.attack_type
        risk_level = context.risk_level
        session_duration = context.session_duration
        
        # Strategy selection logic
        if attack_type == "reconnaissance" and risk_level < 0.5:
            # For low-risk reconnaissance, use deceptive strategy
            strategy_name = "deceptive"
        elif attack_type == "brute_force":
            # For brute force, use minimal responses to slow them down
            strategy_name = "minimal"
        elif attack_type == "exploitation" and risk_level > 0.7:
            # For high-risk exploitation, use honeytrap to gather intelligence
            strategy_name = "honeytrap"
        elif session_duration > 10:  # Long session
            # For long sessions, increase engagement
            strategy_name = "interactive"
        else:
            # Default to deceptive strategy
            strategy_name = "deceptive"
        
        # Get base strategy and apply adaptive modifications
        base_strategy = self.response_strategies[strategy_name].copy()
        
        # Adaptive modifications based on context
        if len(context.previous_commands) > 10:
            # Increase engagement for persistent attackers
            base_strategy["engagement_level"] = min(base_strategy["engagement_level"] + 0.1, 1.0)
        
        if context.service == "mysql" and "injection" in attack_type:
            # Reduce information leakage for SQL injection attempts
            base_strategy["information_leakage"] = max(base_strategy["information_leakage"] - 0.2, 0.1)
        
        base_strategy["name"] = strategy_name
        return base_strategy
    
    def _apply_adaptive_modifications(self, base_response: Dict[str, Any], 
                                    context: ResponseContext, 
                                    strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply adaptive modifications to base response
        """
        modified_response = base_response.copy()
        
        # Adjust response delay based on strategy and context
        base_delay = modified_response.get("delay", 1.0)
        
        if strategy["name"] == "minimal":
            # Increase delay for minimal strategy to slow down attackers
            modified_response["delay"] = base_delay * random.uniform(1.5, 3.0)
        elif strategy["name"] == "interactive":
            # Reduce delay for interactive strategy to encourage engagement
            modified_response["delay"] = base_delay * random.uniform(0.5, 1.0)
        elif context.attack_type == "brute_force":
            # Significantly increase delay for brute force attacks
            modified_response["delay"] = base_delay * random.uniform(2.0, 5.0)
        
        # Modify response content based on engagement level
        engagement_level = strategy["engagement_level"]
        
        if engagement_level > 0.8:
            # High engagement: Add helpful but misleading information
            modified_response = self._enhance_response_engagement(modified_response, context)
        elif engagement_level < 0.4:
            # Low engagement: Make response more terse
            modified_response = self._reduce_response_engagement(modified_response, context)
        
        return modified_response
    
    def _enhance_response_engagement(self, response: Dict[str, Any], 
                                   context: ResponseContext) -> Dict[str, Any]:
        """
        Enhance response to increase attacker engagement
        """
        enhanced_response = response.copy()
        base_text = enhanced_response.get("text", "")
        
        # Add contextual enhancements based on service
        if context.service == "ssh":
            if "command not found" in base_text.lower():
                # Suggest alternative commands to keep attacker engaged
                suggestions = [
                    "Did you mean 'ls'?",
                    "Try 'help' for available commands",
                    "Use 'which' to locate commands"
                ]
                enhanced_response["text"] = f"{base_text}\n{random.choice(suggestions)}"
            
            elif context.command.lower() in ["ls", "dir"]:
                # Add fake interesting files to directory listings
                fake_files = [
                    "backup.tar.gz",
                    "passwords.txt.bak",
                    "config.old",
                    "database_dump.sql"
                ]
                if random.random() < 0.3:  # 30% chance to add fake files
                    enhanced_response["text"] += f"\n-rw-r--r-- 1 root root 1024 Dec  1 10:30 {random.choice(fake_files)}"
        
        elif context.service == "mysql":
            if "error" in base_text.lower():
                # Provide hints that might lead to more attempts
                hints = [
                    "Check your syntax near 'SELECT'",
                    "Table name might be case sensitive",
                    "Try using backticks around table names"
                ]
                enhanced_response["text"] += f"\nHint: {random.choice(hints)}"
        
        elif context.service == "ftp":
            if "directory listing" in base_text.lower():
                # Add fake interesting directories
                fake_dirs = [
                    "drwxr-xr-x 2 ftp ftp 4096 Dec  1 10:30 confidential",
                    "drwxr-xr-x 2 ftp ftp 4096 Dec  1 10:30 backups",
                    "drwxr-xr-x 2 ftp ftp 4096 Dec  1 10:30 admin_files"
                ]
                if random.random() < 0.4:  # 40% chance to add fake directories
                    enhanced_response["text"] += f"\n{random.choice(fake_dirs)}"
        
        return enhanced_response
    
    def _reduce_response_engagement(self, response: Dict[str, Any], 
                                  context: ResponseContext) -> Dict[str, Any]:
        """
        Reduce response engagement to discourage further interaction
        """
        reduced_response = response.copy()
        base_text = reduced_response.get("text", "")
        
        # Make responses more terse and less helpful
        terse_responses = {
            "ssh": {
                "command not found": "Command not found",
                "permission denied": "Access denied",
                "file not found": "No such file"
            },
            "ftp": {
                "file not found": "550 Not found",
                "permission denied": "550 Access denied",
                "command error": "500 Error"
            },
            "mysql": {
                "syntax error": "ERROR 1064: Syntax error",
                "access denied": "ERROR 1045: Access denied",
                "table not found": "ERROR 1146: No such table"
            }
        }
        
        # Replace verbose responses with terse ones
        if context.service in terse_responses:
            service_responses = terse_responses[context.service]
            for key, terse_response in service_responses.items():
                if key.replace("_", " ") in base_text.lower():
                    reduced_response["text"] = terse_response
                    break
        
        return reduced_response
    
    def _add_deception_elements(self, response: Dict[str, Any], 
                               context: ResponseContext, 
                               strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add deception elements based on strategy
        """
        deceptive_response = response.copy()
        information_leakage = strategy.get("information_leakage", 0.5)
        
        # Only add deception if information leakage is significant
        if information_leakage < 0.4:
            return deceptive_response
        
        # Add service-specific deception elements
        if context.service == "ssh" and context.attack_type == "reconnaissance":
            deceptive_response = self._add_ssh_deception(deceptive_response, context)
        elif context.service == "mysql" and "injection" in context.attack_type:
            deceptive_response = self._add_mysql_deception(deceptive_response, context)
        elif context.service == "ftp":
            deceptive_response = self._add_ftp_deception(deceptive_response, context)
        
        return deceptive_response
    
    def _add_ssh_deception(self, response: Dict[str, Any], context: ResponseContext) -> Dict[str, Any]:
        """Add SSH-specific deception elements"""
        deceptive_response = response.copy()
        
        # Add fake system information
        if context.command.lower() in ["whoami"]:
            fake_users = ["admin", "backup", "service", "oracle"]
            if random.random() < 0.3:
                deceptive_response["text"] = random.choice(fake_users)
        
        elif context.command.lower() in ["ps", "ps aux"]:
            # Add fake interesting processes
            fake_processes = [
                "1234 ?        Ss     0:01 /usr/sbin/sshd -D",
                "5678 ?        S      0:00 /usr/bin/mysql --defaults-file=/etc/mysql/my.cnf",
                "9012 ?        Sl     0:02 /opt/backup/backup_daemon"
            ]
            if random.random() < 0.4:
                deceptive_response["text"] += f"\n{random.choice(fake_processes)}"
        
        return deceptive_response
    
    def _add_mysql_deception(self, response: Dict[str, Any], context: ResponseContext) -> Dict[str, Any]:
        """Add MySQL-specific deception elements"""
        deceptive_response = response.copy()
        
        if "show databases" in context.command.lower():
            # Add fake interesting databases
            fake_databases = [
                "| customer_data     |",
                "| financial_records |",
                "| user_credentials  |",
                "| backup_db         |"
            ]
            if random.random() < 0.5:
                deceptive_response["text"] += f"\n{random.choice(fake_databases)}"
        
        elif "show tables" in context.command.lower():
            # Add fake interesting tables
            fake_tables = [
                "| users           |",
                "| passwords       |",
                "| credit_cards    |",
                "| admin_accounts  |"
            ]
            if random.random() < 0.4:
                deceptive_response["text"] += f"\n{random.choice(fake_tables)}"
        
        return deceptive_response
    
    def _add_ftp_deception(self, response: Dict[str, Any], context: ResponseContext) -> Dict[str, Any]:
        """Add FTP-specific deception elements"""
        deceptive_response = response.copy()
        
        # Add fake files that might interest attackers
        if "list" in context.command.lower() or "ls" in context.command.lower():
            fake_files = [
                "-rw-r--r-- 1 ftp ftp 2048 Dec  1 10:30 database_backup.sql",
                "-rw-r--r-- 1 ftp ftp 1024 Dec  1 10:30 server_config.txt",
                "-rw-r--r-- 1 ftp ftp 4096 Dec  1 10:30 user_export.csv"
            ]
            if random.random() < 0.3:
                deceptive_response["text"] += f"\n{random.choice(fake_files)}"
        
        return deceptive_response
    
    def _calculate_response_effectiveness(self, response: Dict[str, Any], 
                                        context: ResponseContext, 
                                        behavior_analysis: Dict[str, Any]) -> float:
        """
        Calculate the effectiveness of the generated response
        """
        effectiveness = 0.5  # Base effectiveness
        
        # Factors that increase effectiveness
        if response.get("strategy", {}).get("name") == "honeytrap" and context.attack_type == "exploitation":
            effectiveness += 0.2  # Good strategy match
        
        if len(context.previous_commands) > 5:
            effectiveness += 0.1  # Sustained engagement
        
        if context.session_duration > 5:
            effectiveness += 0.15  # Long session indicates good engagement
        
        # Factors that decrease effectiveness
        if context.attack_type == "brute_force" and response.get("delay", 0) < 2.0:
            effectiveness -= 0.1  # Should slow down brute force more
        
        if behavior_analysis.get("risk_score", 0) > 0.8 and response.get("deception_level", 0) < 0.5:
            effectiveness -= 0.15  # High-risk attacks need more deception
        
        return max(0.1, min(effectiveness, 1.0))
    
    def _fallback_response(self, service: str, command: str) -> Dict[str, Any]:
        """Generate fallback response when AI generation fails"""
        fallback_responses = {
            "ssh": "bash: command not found",
            "ftp": "500 Unknown command",
            "mysql": "ERROR 1064: You have an error in your SQL syntax",
            "smb": "NT_STATUS_ACCESS_DENIED",
            "rdp": "Authentication failed"
        }
        
        return {
            "text": fallback_responses.get(service, "Command not recognized"),
            "delay": random.uniform(0.5, 2.0),
            "strategy": {"name": "fallback", "engagement_level": 0.1},
            "effectiveness": 0.1,
            "system_load": {},
            "deception_level": 0.1,
            "engagement_score": 0.1,
            "fallback": True
        }
    
    def load_response_templates(self):
        """Load response templates for different scenarios"""
        # This would typically load from a database or configuration file
        self.response_templates = {
            "engagement_enhancers": {
                "ssh": [
                    "Try 'help' for available commands",
                    "Use 'man command' for help",
                    "Check /usr/local/bin for additional tools"
                ],
                "mysql": [
                    "Use 'SHOW DATABASES;' to list databases",
                    "Try 'DESCRIBE table_name;' for table structure",
                    "Use 'EXPLAIN query;' for query analysis"
                ],
                "ftp": [
                    "Use 'HELP' for available commands",
                    "Try 'PASSIVE' mode if having connection issues",
                    "Use 'BINARY' mode for file transfers"
                ]
            },
            "deception_elements": {
                "fake_files": [
                    "backup.tar.gz", "config.old", "passwords.txt.bak",
                    "database_dump.sql", "admin_notes.txt", "server_keys.pem"
                ],
                "fake_processes": [
                    "backup_daemon", "mysql_monitor", "log_analyzer",
                    "security_scanner", "data_sync", "admin_tools"
                ],
                "fake_databases": [
                    "customer_data", "financial_records", "user_accounts",
                    "audit_logs", "backup_db", "temp_storage"
                ]
            }
        }
    
    def update_adaptive_policy(self, service: str, policy_updates: Dict[str, Any]):
        """Update adaptive response policies"""
        if service not in self.adaptive_policies:
            self.adaptive_policies[service] = {}
        
        self.adaptive_policies[service].update(policy_updates)
        
        print(f"[{datetime.now()}] Updated adaptive policy for {service}: {policy_updates}")
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """Get response generation statistics"""
        return {
            "total_responses_generated": len(self.response_cache),
            "strategies_used": list(self.response_strategies.keys()),
            "adaptive_policies": len(self.adaptive_policies),
            "template_categories": len(self.response_templates) if hasattr(self, 'response_templates') else 0
        }