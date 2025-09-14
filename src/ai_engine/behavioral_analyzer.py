"""
Behavioral Analyzer - AI-powered analysis of attacker behavior patterns
"""

import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field

from .patterns.sequence_patterns import (
    BehaviorPattern, CommandSequence, SequencePatternMatcher
)
from .scoring.threat_scorer import ThreatScorer, ThreatMetrics


class BehavioralAnalyzer:
    """
    Analyzes attacker behavior patterns using AI techniques
    for attack classification and prediction
    """
    
    def __init__(self):
        # Pattern recognition components
        self.pattern_matcher = SequencePatternMatcher()
        self.known_patterns: Dict[str, BehaviorPattern] = {}
        self.pattern_sequences: Dict[str, List[CommandSequence]] = defaultdict(list)
        
        # Attack tracking
        self.attack_signatures: Dict[str, Dict[str, Any]] = {}
        self.behavioral_cache: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.command_frequencies: Dict[str, Counter] = defaultdict(Counter)
        
        # Real-time detection
        self.detection_thresholds = {
            "pattern_confidence": 0.8,
            "sequence_similarity": 0.85,
            "anomaly_threshold": 0.7
        }
        
        self.initialized = False
        
        # Load attack pattern definitions
        self.load_attack_patterns()
        
        # Initialize threat scorer
        self.threat_scorer = ThreatScorer()
    
    def initialize(self):
        """Initialize behavioral analyzer with pattern recognition"""
        try:
            # Initialize pattern matcher
            self.pattern_matcher.initialize()
            
            # Load pre-trained patterns and signatures
            self.load_behavioral_models()
            
            # Initialize pattern recognition system
            self._init_pattern_recognition()
            
            self.initialized = True
            print(f"[{datetime.now()}] Behavioral Analyzer initialized with pattern recognition")
            
        except Exception as e:
            print(f"[{datetime.now()}] Behavioral Analyzer initialization failed: {e}")
            raise
    
    def _init_pattern_recognition(self):
        """Initialize pattern recognition components"""
        # Load known attack patterns
        try:
            with open("data/attack_patterns.json", "r") as f:
                patterns = json.load(f)
                for pattern in patterns:
                    self.known_patterns[pattern["id"]] = BehaviorPattern(**pattern)
        except FileNotFoundError:
            print(f"[{datetime.now()}] No pre-existing patterns found, starting fresh")
        
        # Initialize detection thresholds from config
        try:
            with open("config/detection_thresholds.json", "r") as f:
                self.detection_thresholds.update(json.load(f))
        except FileNotFoundError:
            print(f"[{datetime.now()}] Using default detection thresholds")
    
    def analyze_command(self, command: str, service: str, attack_context) -> Dict[str, Any]:
        """
        Analyze individual command using enhanced pattern recognition
        """
        if not self.initialized:
            return self._fallback_analysis(command, service)
        
        analysis = {
            "command": command,
            "service": service,
            "timestamp": datetime.now().isoformat(),
            "attack_type": "unknown",
            "confidence": 0.0,
            "risk_score": 0.0,
            "patterns_detected": [],
            "behavioral_indicators": [],
            "sequence_matches": [],
            "anomaly_score": 0.0
        }
        
        try:
            # Pattern recognition
            current_sequence = [command]
            if attack_context and hasattr(attack_context, 'commands'):
                current_sequence = attack_context.commands[-5:] + [command]
            
            # Match patterns
            pattern_matches = self.pattern_matcher.match_sequence(current_sequence, service)
            analysis["patterns_detected"] = pattern_matches
            
            # Update behavioral cache
            self.behavioral_cache[service].append({
                "command": command,
                "timestamp": datetime.now(),
                "patterns": pattern_matches
            })
            if len(self.behavioral_cache[service]) > 1000:
                self.behavioral_cache[service] = self.behavioral_cache[service][-1000:]
            
            # Update command frequencies
            self.command_frequencies[service][command] += 1
            
            # Real-time pattern detection
            realtime_patterns = self._detect_realtime_patterns(
                command, service, pattern_matches
            )
            analysis["behavioral_indicators"] = realtime_patterns
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                pattern_matches, realtime_patterns, service
            )
            analysis["risk_score"] = risk_score
            
            # Anomaly detection with pattern context
            anomaly_score = self._detect_pattern_anomalies(
                command, pattern_matches, service
            )
            analysis["anomaly_score"] = anomaly_score
            
            # Classify attack type using pattern information
            attack_type = self._classify_attack_with_patterns(
                pattern_matches, realtime_patterns, risk_score
            )
            analysis.update(attack_type)
            
            # Learn from this interaction
            self._update_pattern_learning(command, service, analysis)
            
            # Calculate threat score
            threat_metrics = ThreatMetrics(
                attack_type=analysis["attack_type"],
                pattern_confidence=analysis["confidence"],
                complexity=self.analyze_command_complexity(command)["complexity_score"],
                service_risk=self.threat_scorer.service_risk_levels.get(service, 0.5),
                behavioral_risk=analysis["risk_score"],
                frequency=self.command_frequencies[service][command],
                first_seen=datetime.now(),  # This will be updated if pattern exists
                last_seen=datetime.now()
            )
            
            # Update temporal metrics if we have history
            pattern_key = f"{service}:{command}"
            if pattern_key in self.known_patterns:
                pattern = self.known_patterns[pattern_key]
                threat_metrics.first_seen = pattern.first_seen
                threat_metrics.last_seen = pattern.last_seen
                
                # Calculate progression rate from pattern history
                progression = self.threat_scorer.analyze_threat_progression(pattern_key)
                threat_metrics.progression_rate = progression["progression_rate"]
            
            # Calculate complete threat score
            threat_score = self.threat_scorer.calculate_threat_score(threat_metrics)
            
            # Add threat information to analysis
            analysis["threat_score"] = {
                "total_score": threat_score.total_score,
                "base_score": threat_score.base_score,
                "temporal_score": threat_score.temporal_score,
                "impact_score": threat_score.impact_score,
                "threat_level": threat_score.threat_level.name,
                "confidence": threat_score.confidence
            }
            
            # Update threat history
            self.threat_scorer.update_threat_history(pattern_key, threat_score)
            
        except Exception as e:
            print(f"[{datetime.now()}] Enhanced pattern analysis error: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _detect_realtime_patterns(self, command: str, service: str, 
                                pattern_matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect patterns in real-time"""
        indicators = []
        
        # Check for high-confidence patterns
        for match in pattern_matches:
            if match["confidence"] >= self.detection_thresholds["pattern_confidence"]:
                indicators.append({
                    "type": "high_confidence_pattern",
                    "pattern": match["pattern"] if "pattern" in match else match["command"],
                    "confidence": match["confidence"]
                })
        
        # Check command frequency
        cmd_freq = self.command_frequencies[service][command]
        if cmd_freq > 10:  # Arbitrary threshold
            indicators.append({
                "type": "high_frequency_command",
                "frequency": cmd_freq,
                "confidence": min(1.0, cmd_freq / 100)
            })
        
        # Recent behavior analysis
        recent_behavior = self.behavioral_cache[service][-10:]
        if recent_behavior:
            # Check for rapid command sequences
            time_diffs = []
            for i in range(1, len(recent_behavior)):
                diff = (recent_behavior[i]["timestamp"] - 
                       recent_behavior[i-1]["timestamp"]).total_seconds()
                time_diffs.append(diff)
            
            if time_diffs and any(d < 0.1 for d in time_diffs):  # Very rapid commands
                indicators.append({
                    "type": "rapid_command_sequence",
                    "avg_delay": sum(time_diffs) / len(time_diffs),
                    "confidence": 0.9
                })
        
        return indicators
    
    def _calculate_risk_score(self, pattern_matches: List[Dict[str, Any]],
                            behavioral_indicators: List[Dict[str, Any]],
                            service: str) -> float:
        """Calculate risk score based on patterns"""
        risk_score = 0.0
        
        # Pattern-based scoring
        if pattern_matches:
            pattern_score = max(match["confidence"] for match in pattern_matches)
            risk_score += pattern_score * 0.4
        
        # Behavioral indicator scoring
        if behavioral_indicators:
            indicator_scores = [ind["confidence"] for ind in behavioral_indicators 
                              if "confidence" in ind]
            if indicator_scores:
                risk_score += max(indicator_scores) * 0.3
        
        # Service-specific risk factors
        service_risk_weights = {
            "ssh": 1.0,  # Highest risk
            "rdp": 0.9,
            "smb": 0.8,
            "ftp": 0.7,
            "mysql": 0.6
        }
        risk_score += service_risk_weights.get(service, 0.5) * 0.3
        
        return min(1.0, risk_score)
    
    def _detect_pattern_anomalies(self, command: str, 
                                pattern_matches: List[Dict[str, Any]],
                                service: str) -> float:
        """Detect anomalies in command patterns"""
        anomaly_score = 0.0
        
        # Check pattern match confidence
        if pattern_matches:
            avg_confidence = sum(m["confidence"] for m in pattern_matches) / len(pattern_matches)
            if avg_confidence < self.detection_thresholds["pattern_confidence"]:
                anomaly_score += (1 - avg_confidence) * 0.4
        else:
            anomaly_score += 0.4  # No pattern matches
        
        # Check command frequency anomalies
        cmd_freq = self.command_frequencies[service][command]
        total_cmds = sum(self.command_frequencies[service].values())
        if total_cmds > 0:
            freq_ratio = cmd_freq / total_cmds
            if freq_ratio < 0.01:  # Rare command
                anomaly_score += 0.3
        
        # Check sequence timing
        recent_behavior = self.behavioral_cache[service][-5:]
        if len(recent_behavior) > 1:
            time_diffs = []
            for i in range(1, len(recent_behavior)):
                diff = (recent_behavior[i]["timestamp"] - 
                       recent_behavior[i-1]["timestamp"]).total_seconds()
                time_diffs.append(diff)
            
            if time_diffs:
                avg_diff = sum(time_diffs) / len(time_diffs)
                if avg_diff < 0.1:  # Unusually fast
                    anomaly_score += 0.3
                elif avg_diff > 10:  # Unusually slow
                    anomaly_score += 0.2
        
        return min(1.0, anomaly_score)
    
    def _classify_attack_with_patterns(self, pattern_matches: List[Dict[str, Any]],
                                     behavioral_indicators: List[Dict[str, Any]],
                                     risk_score: float) -> Dict[str, Any]:
        """Classify attack type using pattern information"""
        classification = {
            "attack_type": "unknown",
            "confidence": 0.0,
            "sub_types": []
        }
        
        # Pattern-based classification
        if pattern_matches:
            pattern_types = [self._infer_attack_type(match) for match in pattern_matches]
            if pattern_types:
                # Get most common attack type
                attack_type_counts = Counter(pattern_types)
                most_common = attack_type_counts.most_common(1)[0]
                classification["attack_type"] = most_common[0]
                classification["confidence"] = most_common[1] / len(pattern_types)
                
                # Add sub-types if there are multiple patterns
                if len(attack_type_counts) > 1:
                    classification["sub_types"] = [
                        {"type": t, "count": c}
                        for t, c in attack_type_counts.most_common()[1:]
                    ]
        
        # Adjust confidence based on risk score
        classification["confidence"] = (
            classification["confidence"] * 0.7 + risk_score * 0.3
        )
        
        return classification
    
    def _infer_attack_type(self, pattern_match: Dict[str, Any]) -> str:
        """Infer attack type from pattern match"""
        # Simple pattern-based inference
        command = pattern_match.get("command", "").lower()
        pattern = pattern_match.get("pattern", "").lower()
        
        if any(word in command or word in pattern 
               for word in ["password", "pass", "login", "auth"]):
            return "brute_force"
        elif any(word in command or word in pattern 
                for word in ["select", "union", "insert", "exec"]):
            return "sql_injection"
        elif any(word in command or word in pattern 
                for word in ["dir", "ls", "list", "enum"]):
            return "reconnaissance"
        elif any(word in command or word in pattern 
                for word in ["wget", "curl", "download"]):
            return "malware_download"
        else:
            return "unknown"
    
    def _fallback_analysis(self, command: str, service: str) -> Dict[str, Any]:
        """Generate fallback analysis when analyzer is not initialized"""
        return {
            "command": command,
            "service": service,
            "timestamp": datetime.now().isoformat(),
            "attack_type": "unknown",
            "confidence": 0.1,
            "risk_score": 0.5,
            "patterns_detected": [],
            "behavioral_indicators": [],
            "sequence_matches": [],
            "anomaly_score": 0.0,
            "fallback": True
        }
    
    def _update_pattern_learning(self, command: str, service: str, 
                               analysis: Dict[str, Any]) -> None:
        """Update pattern learning from analysis"""
        # Create command sequence
        sequence = CommandSequence(
            commands=[command],
            service=service,
            timestamp=datetime.now()
        )
        
        # Update pattern sequences
        self.pattern_sequences[service].append(sequence)
        if len(self.pattern_sequences[service]) > 1000:
            self.pattern_sequences[service] = self.pattern_sequences[service][-1000:]
        
        # Update or create patterns
        for match in analysis["patterns_detected"]:
            pattern_key = f"{service}:{match['command']}"
            if pattern_key not in self.known_patterns:
                self.known_patterns[pattern_key] = BehaviorPattern(
                    pattern_id=pattern_key,
                    pattern_type=self._infer_attack_type(match),
                    commands=[command],
                    service=service
                )
            
            pattern = self.known_patterns[pattern_key]
            pattern.update(command)  # This will update frequency and confidence
            
        # Save patterns periodically
        if len(self.pattern_sequences[service]) % 100 == 0:
            self._save_patterns()
    
    def _save_patterns(self) -> None:
        """Save learned patterns to storage"""
        try:
            patterns_data = {
                "timestamp": datetime.now().isoformat(),
                "patterns": {
                    pattern_id: {
                        "pattern_type": pattern.pattern_type,
                        "commands": pattern.commands,
                        "service": pattern.service,
                        "frequency": pattern.frequency,
                        "confidence": pattern.confidence,
                        "first_seen": pattern.first_seen.isoformat(),
                        "last_seen": pattern.last_seen.isoformat()
                    }
                    for pattern_id, pattern in self.known_patterns.items()
                }
            }
            
            with open("data/learned_patterns.json", "w") as f:
                json.dump(patterns_data, f, indent=2)
                
        except Exception as e:
            print(f"[{datetime.now()}] Error saving patterns: {e}")
    
    def classify_attack_type(self, commands: List[str], service: str) -> Dict[str, Any]:
        """
        Classify attack type based on command patterns
        """
        if not commands:
            return {"type": "unknown", "confidence": 0.0}
        
        # Combine all commands for analysis
        command_text = " ".join(commands).lower()
        
        # Attack type patterns
        attack_patterns = {
            "brute_force": {
                "patterns": [
                    r"(login|auth|password|passwd|user)",
                    r"(ssh|ftp|rdp|mysql).*login",
                    r"(admin|root|administrator|guest)"
                ],
                "weight": 0.8
            },
            "reconnaissance": {
                "patterns": [
                    r"(whoami|id|uname|ps|netstat|ifconfig)",
                    r"(ls|dir|cat|type|more|less)",
                    r"(systeminfo|ver|version|env)",
                    r"(/etc/passwd|/etc/shadow|config)"
                ],
                "weight": 0.9
            },
            "exploitation": {
                "patterns": [
                    r"(wget|curl|download|nc|netcat)",
                    r"(python|perl|bash|sh|cmd|powershell)",
                    r"(chmod|chown|sudo|su|runas)",
                    r"(exploit|payload|shell|reverse)"
                ],
                "weight": 0.95
            },
            "persistence": {
                "patterns": [
                    r"(crontab|systemctl|service|startup)",
                    r"(reg add|schtasks|task|schedule)",
                    r"(echo.*>>|mkdir|touch|copy|move)",
                    r"(backdoor|persistence|maintain)"
                ],
                "weight": 0.85
            },
            "lateral_movement": {
                "patterns": [
                    r"(ssh.*@|rdp.*connect|smb.*share)",
                    r"(net use|mount|smbclient)",
                    r"(psexec|wmic|winrm)",
                    r"(pivot|tunnel|proxy)"
                ],
                "weight": 0.8
            },
            "data_exfiltration": {
                "patterns": [
                    r"(tar|zip|rar|compress|archive)",
                    r"(scp|sftp|rsync|copy.*remote)",
                    r"(base64|encode|encrypt)",
                    r"(exfil|steal|dump|extract)"
                ],
                "weight": 0.9
            }
        }
        
        # Calculate scores for each attack type
        scores = {}
        for attack_type, config in attack_patterns.items():
            score = 0.0
            matches = 0
            
            for pattern in config["patterns"]:
                if re.search(pattern, command_text):
                    matches += 1
                    score += config["weight"]
            
            if matches > 0:
                scores[attack_type] = score / len(config["patterns"])
        
        # Determine best match
        if not scores:
            return {"type": "unknown", "confidence": 0.1}
        
        best_type = max(scores.keys(), key=lambda k: scores[k])
        confidence = min(scores[best_type], 0.95)
        
        # Adjust confidence based on command sequence
        if len(commands) > 1:
            sequence_bonus = min(0.1 * len(commands), 0.3)
            confidence = min(confidence + sequence_bonus, 0.98)
        
        return {
            "type": best_type,
            "confidence": confidence,
            "scores": scores,
            "command_count": len(commands)
        }
    
    def analyze_command_patterns(self, command: str, service: str) -> Dict[str, Any]:
        """
        Analyze individual command for behavioral patterns
        """
        indicators = []
        risk_score = 0.0
        
        command_lower = command.lower().strip()
        
        # Suspicious command patterns
        suspicious_patterns = {
            "system_info_gathering": {
                "patterns": [r"whoami", r"id", r"uname", r"systeminfo", r"ver"],
                "risk": 0.3,
                "description": "System information gathering"
            },
            "file_system_exploration": {
                "patterns": [r"ls", r"dir", r"find", r"locate", r"tree"],
                "risk": 0.2,
                "description": "File system exploration"
            },
            "privilege_escalation": {
                "patterns": [r"sudo", r"su", r"runas", r"chmod 777", r"chown"],
                "risk": 0.8,
                "description": "Privilege escalation attempt"
            },
            "network_reconnaissance": {
                "patterns": [r"netstat", r"ifconfig", r"arp", r"route", r"nslookup"],
                "risk": 0.4,
                "description": "Network reconnaissance"
            },
            "malicious_downloads": {
                "patterns": [r"wget", r"curl", r"download", r"invoke-webrequest"],
                "risk": 0.9,
                "description": "Potential malicious download"
            },
            "reverse_shell": {
                "patterns": [r"nc -l", r"netcat", r"bash -i", r"python.*socket"],
                "risk": 0.95,
                "description": "Reverse shell attempt"
            },
            "credential_access": {
                "patterns": [r"/etc/passwd", r"/etc/shadow", r"sam", r"ntds.dit"],
                "risk": 0.85,
                "description": "Credential access attempt"
            }
        }
        
        # Check for suspicious patterns
        for pattern_name, config in suspicious_patterns.items():
            for pattern in config["patterns"]:
                if re.search(pattern, command_lower):
                    indicators.append({
                        "type": pattern_name,
                        "description": config["description"],
                        "risk": config["risk"],
                        "matched_pattern": pattern
                    })
                    risk_score = max(risk_score, config["risk"])
        
        # Service-specific analysis
        service_analysis = self.analyze_service_specific_patterns(command, service)
        indicators.extend(service_analysis["indicators"])
        risk_score = max(risk_score, service_analysis["risk_score"])
        
        # Command complexity analysis
        complexity_analysis = self.analyze_command_complexity(command)
        if complexity_analysis["is_complex"]:
            indicators.append({
                "type": "complex_command",
                "description": "Complex or obfuscated command",
                "risk": complexity_analysis["risk"],
                "details": complexity_analysis["details"]
            })
            risk_score = max(risk_score, complexity_analysis["risk"])
        
        return {
            "indicators": indicators,
            "risk_score": risk_score,
            "pattern_matches": len(indicators)
        }
    
    def analyze_service_specific_patterns(self, command: str, service: str) -> Dict[str, Any]:
        """
        Analyze patterns specific to each service
        """
        indicators = []
        risk_score = 0.0
        
        command_lower = command.lower().strip()
        
        if service == "ssh":
            ssh_patterns = {
                "config_access": [r"/etc/ssh", r"sshd_config", r"authorized_keys"],
                "tunnel_creation": [r"ssh.*-L", r"ssh.*-R", r"ssh.*-D"],
                "key_operations": [r"ssh-keygen", r"ssh-copy-id", r"id_rsa"]
            }
            
            for pattern_type, patterns in ssh_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, command_lower):
                        indicators.append({
                            "type": f"ssh_{pattern_type}",
                            "description": f"SSH {pattern_type.replace('_', ' ')}",
                            "risk": 0.6,
                            "service": "ssh"
                        })
                        risk_score = max(risk_score, 0.6)
        
        elif service == "ftp":
            ftp_patterns = {
                "binary_transfer": [r"binary", r"type i"],
                "passive_mode": [r"pasv", r"passive"],
                "directory_traversal": [r"\.\.", r"\.\.\/", r"\.\.\\"]
            }
            
            for pattern_type, patterns in ftp_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, command_lower):
                        indicators.append({
                            "type": f"ftp_{pattern_type}",
                            "description": f"FTP {pattern_type.replace('_', ' ')}",
                            "risk": 0.4,
                            "service": "ftp"
                        })
                        risk_score = max(risk_score, 0.4)
        
        elif service == "mysql":
            mysql_patterns = {
                "information_schema": [r"information_schema", r"show databases", r"show tables"],
                "union_injection": [r"union.*select", r"union.*all"],
                "file_operations": [r"load_file", r"into outfile", r"into dumpfile"],
                "user_enumeration": [r"mysql.user", r"show grants", r"current_user"]
            }
            
            for pattern_type, patterns in mysql_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, command_lower):
                        risk = 0.8 if "injection" in pattern_type or "file" in pattern_type else 0.5
                        indicators.append({
                            "type": f"mysql_{pattern_type}",
                            "description": f"MySQL {pattern_type.replace('_', ' ')}",
                            "risk": risk,
                            "service": "mysql"
                        })
                        risk_score = max(risk_score, risk)
        
        return {
            "indicators": indicators,
            "risk_score": risk_score
        }
    
    def analyze_command_complexity(self, command: str) -> Dict[str, Any]:
        """
        Analyze command complexity and potential obfuscation
        """
        complexity_indicators = {
            "length": len(command) > 100,
            "special_chars": len(re.findall(r'[^a-zA-Z0-9\s]', command)) > 20,
            "base64_like": bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', command)),
            "hex_encoding": bool(re.search(r'\\x[0-9a-fA-F]{2}', command)),
            "multiple_pipes": command.count('|') > 2,
            "multiple_redirects": command.count('>') + command.count('<') > 3,
            "nested_quotes": bool(re.search(r'["\'][^"\']*["\'][^"\']*["\']', command))
        }
        
        complexity_score = sum(complexity_indicators.values()) / len(complexity_indicators)
        is_complex = complexity_score > 0.3
        
        risk = min(complexity_score * 0.7, 0.8) if is_complex else 0.1
        
        return {
            "is_complex": is_complex,
            "complexity_score": complexity_score,
            "risk": risk,
            "details": {k: v for k, v in complexity_indicators.items() if v}
        }
    
    def analyze_command_sequence(self, commands: List[str], service: str) -> Dict[str, Any]:
        """
        Analyze sequence of commands for behavioral patterns
        """
        if len(commands) < 2:
            return {"sequence_type": "single_command", "risk_progression": 0.0}
        
        # Analyze command progression
        risk_progression = []
        for i, command in enumerate(commands):
            analysis = self.analyze_command_patterns(command, service)
            risk_progression.append(analysis["risk_score"])
        
        # Detect sequence patterns
        sequence_patterns = {
            "escalating_reconnaissance": self._detect_escalating_recon(commands),
            "exploitation_chain": self._detect_exploitation_chain(commands),
            "persistence_setup": self._detect_persistence_setup(commands),
            "data_collection": self._detect_data_collection(commands)
        }
        
        # Determine dominant sequence type
        detected_patterns = [k for k, v in sequence_patterns.items() if v["detected"]]
        
        if detected_patterns:
            primary_pattern = max(detected_patterns, 
                                key=lambda k: sequence_patterns[k]["confidence"])
        else:
            primary_pattern = "random_commands"
        
        return {
            "sequence_type": primary_pattern,
            "risk_progression": risk_progression,
            "average_risk": sum(risk_progression) / len(risk_progression),
            "max_risk": max(risk_progression),
            "detected_patterns": detected_patterns,
            "command_count": len(commands)
        }
    
    def _detect_escalating_recon(self, commands: List[str]) -> Dict[str, Any]:
        """Detect escalating reconnaissance pattern"""
        recon_stages = [
            ["whoami", "id", "uname"],  # Basic info
            ["ps", "netstat", "ifconfig"],  # System state
            ["ls", "find", "locate"],  # File system
            ["cat", "/etc/passwd", "config"]  # Sensitive files
        ]
        
        stage_matches = [0] * len(recon_stages)
        
        for command in commands:
            command_lower = command.lower()
            for i, stage_patterns in enumerate(recon_stages):
                if any(pattern in command_lower for pattern in stage_patterns):
                    stage_matches[i] += 1
        
        # Check for progression through stages
        progression_score = 0
        for i in range(len(stage_matches) - 1):
            if stage_matches[i] > 0 and stage_matches[i + 1] > 0:
                progression_score += 1
        
        detected = progression_score >= 2
        confidence = min(progression_score / (len(recon_stages) - 1), 1.0)
        
        return {
            "detected": detected,
            "confidence": confidence,
            "stage_matches": stage_matches,
            "progression_score": progression_score
        }
    
    def _detect_exploitation_chain(self, commands: List[str]) -> Dict[str, Any]:
        """Detect exploitation chain pattern"""
        exploit_indicators = [
            "download", "wget", "curl", "nc", "netcat",
            "python", "perl", "bash", "sh", "powershell",
            "chmod", "chown", "sudo", "su"
        ]
        
        exploit_matches = 0
        command_text = " ".join(commands).lower()
        
        for indicator in exploit_indicators:
            if indicator in command_text:
                exploit_matches += 1
        
        detected = exploit_matches >= 3
        confidence = min(exploit_matches / len(exploit_indicators), 1.0)
        
        return {
            "detected": detected,
            "confidence": confidence,
            "exploit_matches": exploit_matches
        }
    
    def _detect_persistence_setup(self, commands: List[str]) -> Dict[str, Any]:
        """Detect persistence setup pattern"""
        persistence_indicators = [
            "crontab", "systemctl", "service", "startup",
            "reg add", "schtasks", "mkdir", "echo.*>>",
            "copy", "move", "touch"
        ]
        
        persistence_matches = 0
        command_text = " ".join(commands).lower()
        
        for indicator in persistence_indicators:
            if re.search(indicator, command_text):
                persistence_matches += 1
        
        detected = persistence_matches >= 2
        confidence = min(persistence_matches / len(persistence_indicators), 1.0)
        
        return {
            "detected": detected,
            "confidence": confidence,
            "persistence_matches": persistence_matches
        }
    
    def _detect_data_collection(self, commands: List[str]) -> Dict[str, Any]:
        """Detect data collection pattern"""
        collection_indicators = [
            "find", "locate", "grep", "search",
            "tar", "zip", "compress", "archive",
            "cat", "type", "more", "less",
            "copy", "scp", "rsync"
        ]
        
        collection_matches = 0
        command_text = " ".join(commands).lower()
        
        for indicator in collection_indicators:
            if indicator in command_text:
                collection_matches += 1
        
        detected = collection_matches >= 3
        confidence = min(collection_matches / len(collection_indicators), 1.0)
        
        return {
            "detected": detected,
            "confidence": confidence,
            "collection_matches": collection_matches
        }
    
    def detect_anomalies(self, command: str, service: str) -> float:
        """
        Detect anomalous behavior using statistical analysis
        """
        # Simple anomaly detection based on command characteristics
        anomaly_score = 0.0
        
        # Length-based anomaly
        avg_length = 20  # Assumed average command length
        length_deviation = abs(len(command) - avg_length) / avg_length
        if length_deviation > 2.0:  # More than 2x average
            anomaly_score += 0.3
        
        # Character distribution anomaly
        alpha_ratio = len(re.findall(r'[a-zA-Z]', command)) / max(len(command), 1)
        if alpha_ratio < 0.3:  # Too few alphabetic characters
            anomaly_score += 0.2
        
        # Special character anomaly
        special_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', command)) / max(len(command), 1)
        if special_ratio > 0.5:  # Too many special characters
            anomaly_score += 0.4
        
        # Service-specific anomalies
        if service == "mysql" and not any(keyword in command.lower() 
                                        for keyword in ["select", "insert", "update", "delete", "show", "create"]):
            anomaly_score += 0.3
        
        return min(anomaly_score, 1.0)
    
    def update_behavioral_learning(self, command: str, service: str, analysis: Dict[str, Any]):
        """
        Update behavioral learning models with new data
        """
        # Store command pattern for future analysis
        pattern_key = f"{service}_{analysis['attack_type']}"
        
        # Create command sequence
        sequence = CommandSequence(
            commands=[command],
            service=service,
            timestamp=datetime.now()
        )
        
        # Update pattern sequences
        self.pattern_sequences[pattern_key].append(sequence)
        
        # Keep only recent patterns (last 1000 per type)
        if len(self.pattern_sequences[pattern_key]) > 1000:
            self.pattern_sequences[pattern_key] = self.pattern_sequences[pattern_key][-1000:]
    
    def load_attack_patterns(self):
        """Load known attack patterns and signatures"""
        # This would typically load from a database or file
        # For now, we'll use hardcoded patterns
        attack_patterns = {
            "common_exploits": {
                "patterns": [
                    "wget http://",
                    "curl -o",
                    "nc -l",
                    "python -c",
                    "bash -i",
                    "powershell -enc"
                ],
                "risk": 0.9
            },
            "reconnaissance": {
                "patterns": [
                    "whoami",
                    "id", 
                    "uname -a",
                    "ps aux",
                    "netstat -an",
                    "ifconfig"
                ],
                "risk": 0.7
            },
            "privilege_escalation": {
                "patterns": [
                    "sudo su",
                    "su -",
                    "chmod 777",
                    "chown root"
                ],
                "risk": 0.95
            }
        }
        
        # Convert to proper signature format
        self.attack_signatures = {
            category: {
                "patterns": config["patterns"],
                "risk": config["risk"],
                "description": f"{category.replace('_', ' ').title()} attempt"
            }
            for category, config in attack_patterns.items()
        }
    
    def load_behavioral_models(self):
        """Load pre-trained behavioral models"""
        try:
            with open("data/behavioral_models.json", "r") as f:
                models = json.load(f)
                self.known_patterns.update(models.get("patterns", {}))
        except FileNotFoundError:
            pass  # No pre-trained models available
    
    def compile_pattern_matchers(self):
        """Compile regex patterns for efficient matching"""
        # Compile frequently used patterns
        self.compiled_patterns = {}
        
        for category, patterns in self.attack_signatures.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
    
    def get_behavioral_summary(self) -> Dict[str, Any]:
        """Get summary of behavioral analysis"""
        total_patterns = sum(len(sequences) for sequences in self.pattern_sequences.values())
        
        return {
            "total_analyzed_commands": total_patterns,
            "pattern_categories": len(self.pattern_sequences),
            "known_attack_signatures": len(self.attack_signatures),
            "behavioral_models_loaded": len(self.known_patterns)
        }