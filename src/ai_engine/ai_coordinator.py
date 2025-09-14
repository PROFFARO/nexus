"""
AI Coordinator - Central AI engine for dynamic response generation and behavioral analysis
"""

import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
import threading
from collections import defaultdict, deque
import hashlib

from .llm_interface import LLMInterface
from .behavioral_analyzer import BehavioralAnalyzer
from .response_generator import ResponseGenerator
from .correlation.correlation_engine import CorrelationEngine, ServiceEvent


@dataclass
class ServiceInteraction:
    """Detailed tracking of service interactions"""
    service: str
    attacker_ip: str
    command: str
    timestamp: datetime
    context: Dict[str, Any]
    response: Optional[Dict[str, Any]] = None
    interaction_id: str = field(init=False)
    
    def __post_init__(self):
        """Generate unique interaction ID"""
        interaction_string = f"{self.service}:{self.attacker_ip}:{self.command}:{self.timestamp.isoformat()}"
        self.interaction_id = hashlib.sha256(interaction_string.encode()).hexdigest()[:16]


@dataclass
class InteractionPattern:
    """Pattern extracted from service interactions"""
    pattern_id: str
    service: str
    commands: List[str]
    context_features: Dict[str, Any]
    frequency: int = 0
    last_seen: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    associated_ips: Set[str] = field(default_factory=set)
    
    def update_frequency(self, attacker_ip: str):
        """Update pattern frequency and metadata"""
        self.frequency += 1
        self.last_seen = datetime.now()
        self.associated_ips.add(attacker_ip)
        
    def calculate_confidence(self) -> float:
        """Calculate pattern confidence based on frequency and recency"""
        time_factor = 1.0
        age_hours = (datetime.now() - self.last_seen).total_seconds() / 3600
        if age_hours > 24:
            time_factor = max(0.5, 1.0 - (age_hours - 24) / 168)  # Decay over a week
        
        ip_factor = min(1.0, len(self.associated_ips) / 10)  # Scale with unique IPs, max at 10
        
        self.confidence = (0.4 * time_factor + 0.3 * ip_factor + 0.3 * min(1.0, self.frequency / 100))
        return self.confidence


@dataclass
class AttackContext:
    """Enhanced context information for ongoing attacks"""
    attacker_ip: str
    service: str
    commands: List[str]
    start_time: datetime
    last_activity: datetime
    attack_type: str
    confidence: float
    interaction_patterns: List[str] = field(default_factory=list)  # Pattern IDs
    threat_score: float = 0.0
    session_id: str = field(init=False)
    correlated_sessions: List[List[str]] = field(default_factory=list)
    correlation_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Generate unique session ID"""
        session_string = f"{self.service}:{self.attacker_ip}:{self.start_time.isoformat()}"
        self.session_id = hashlib.sha256(session_string.encode()).hexdigest()[:16]


class AICoordinator:
    """
    Central AI coordinator that manages dynamic responses,
    behavioral analysis, and adaptive policy changes
    """
    
    def __init__(self):
        self.llm_interface = LLMInterface()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.response_generator = ResponseGenerator()
        self.correlation_engine = CorrelationEngine()
        
        # Enhanced attack tracking
        self.active_attacks: Dict[str, AttackContext] = {}
        self.attack_history = deque(maxlen=1000)
        
        # Interaction tracking
        self.recent_interactions: Dict[str, List[ServiceInteraction]] = defaultdict(list)
        self.interaction_patterns: Dict[str, InteractionPattern] = {}
        self.pattern_frequency: Dict[str, int] = defaultdict(int)
        
        # Learning and adaptation
        self.learned_patterns = defaultdict(list)
        self.adaptive_policies = {}
        
        # Performance metrics
        self.response_times = deque(maxlen=100)
        self.accuracy_scores = deque(maxlen=100)
        self.pattern_matches = defaultdict(int)
        
        # Cache for quick pattern lookup
        self.pattern_cache: Dict[str, List[str]] = {}  # service -> pattern_ids
        self.ip_pattern_cache: Dict[str, Set[str]] = defaultdict(set)  # ip -> pattern_ids
        
        self.initialized = False
        self.lock = threading.Lock()
    
    def initialize(self):
        """Initialize AI engine components"""
        if self.initialized:
            return
        
        try:
            # Initialize LLM interface
            self.llm_interface.initialize()
            
            # Load pre-trained models and patterns
            self.load_learned_patterns()
            
            # Initialize behavioral analyzer
            self.behavioral_analyzer.initialize()
            
            # Initialize response generator
            self.response_generator.initialize(self.llm_interface)
            
            self.initialized = True
            
            print(f"[{datetime.now()}] AI Coordinator initialized successfully")
            
        except Exception as e:
            print(f"[{datetime.now()}] AI Coordinator initialization failed: {e}")
            raise
    
    def process_interaction(self, service: str, attacker_ip: str, 
                          command: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process attacker interaction and generate AI-driven response with enhanced pattern matching
        """
        if not self.initialized:
            return self._fallback_response(service, command)
        
        start_time = time.time()
        response = None
        
        try:
            with self.lock:
                # Create and store interaction record
                interaction = ServiceInteraction(
                    service=service,
                    attacker_ip=attacker_ip,
                    command=command,
                    timestamp=datetime.now(),
                    context=context
                )
                self.recent_interactions[attacker_ip].append(interaction)
                
                # Update attack context with pattern matching
                attack_context = self._update_attack_context(
                    service, attacker_ip, command, context
                )
                
                # Analyze behavior and get threat assessment
                behavior_analysis = self.behavioral_analyzer.analyze_command(
                    command, service, attack_context
                )
                
                # Create correlation event
                correlation_event = ServiceEvent(
                    timestamp=datetime.now(),
                    service=service,
                    source_ip=attacker_ip,
                    command=command,
                    session_id=attack_context.session_id,
                    attack_type=behavior_analysis["attack_type"],
                    threat_score=behavior_analysis["threat_score"]["total_score"],
                    confidence=behavior_analysis["threat_score"]["confidence"],
                    patterns=behavior_analysis["patterns_detected"],
                    behavioral_data={
                        "indicators": behavior_analysis["behavioral_indicators"],
                        "risk_score": behavior_analysis["risk_score"],
                        "anomaly_score": behavior_analysis["anomaly_score"]
                    }
                )
                
                # Process correlation
                correlation_results = self.correlation_engine.process_event(correlation_event)
                
                # Update attack context with correlation results
                if correlation_results:
                    attack_context.correlated_sessions = [
                        r.session_ids for r in correlation_results
                    ]
                    attack_context.correlation_data = {
                        "results": [
                            {
                                "type": r.correlation_type,
                                "score": r.score,
                                "confidence": r.confidence,
                                "evidence": r.evidence
                            }
                            for r in correlation_results
                        ]
                    }
                
                # Extract and analyze patterns
                self._analyze_interaction_patterns(interaction, attack_context)
                
                # Update threat assessment
                self._update_threat_assessment(attack_context, interaction)
                
                # Generate response based on analysis
                response = self._generate_response(interaction, attack_context)
                interaction.response = response
                
                # Update metrics
                self.response_times.append(time.time() - start_time)
                
                return response
                
        except Exception as e:
            print(f"[{datetime.now()}] AI processing error: {e}")
            return self._fallback_response(service, command)
    
    def _generate_response(self, interaction: ServiceInteraction, 
                         attack_context: AttackContext) -> Dict[str, Any]:
        """Generate appropriate response based on interaction analysis"""
        response = {
            "allow_interaction": True,
            "response_type": "normal",
            "delay_ms": 0,
            "block_ip": False,
            "log_level": "INFO"
        }
        
        # Adjust response based on threat score
        if attack_context.threat_score > 0.8:
            response.update({
                "allow_interaction": False,
                "block_ip": True,
                "log_level": "CRITICAL",
                "reason": "High threat score detected"
            })
        elif attack_context.threat_score > 0.6:
            response.update({
                "response_type": "deceptive",
                "delay_ms": 500,
                "log_level": "WARNING"
            })
        elif attack_context.threat_score > 0.4:
            response.update({
                "response_type": "evasive",
                "delay_ms": 200,
                "log_level": "WARNING"
            })
        
        # Add context for response generation
        response["context"] = {
            "threat_score": attack_context.threat_score,
            "patterns": attack_context.interaction_patterns,
            "service": interaction.service,
            "command": interaction.command
        }
        
        return response
                
    def _analyze_interaction_patterns(self, interaction: ServiceInteraction, 
                                    attack_context: AttackContext) -> None:
        """Analyze and extract patterns from interaction"""
        # Get recent interactions for this IP
        ip_interactions = self.recent_interactions[interaction.attacker_ip][-10:]
        
        # Extract command sequence pattern
        commands = [i.command for i in ip_interactions]
        pattern_key = f"{interaction.service}:{'|'.join(commands[-3:])}"
        
        # Create or update pattern
        if pattern_key not in self.interaction_patterns:
            pattern = InteractionPattern(
                pattern_id=hashlib.sha256(pattern_key.encode()).hexdigest()[:16],
                service=interaction.service,
                commands=commands[-3:],
                context_features=self._extract_context_features(interaction.context)
            )
            self.interaction_patterns[pattern_key] = pattern
        
        pattern = self.interaction_patterns[pattern_key]
        pattern.update_frequency(interaction.attacker_ip)
        
        # Update pattern caches
        if pattern.pattern_id not in self.pattern_cache.get(interaction.service, []):
            self.pattern_cache.setdefault(interaction.service, []).append(pattern.pattern_id)
        self.ip_pattern_cache[interaction.attacker_ip].add(pattern.pattern_id)
        
        # Update attack context
        if pattern.pattern_id not in attack_context.interaction_patterns:
            attack_context.interaction_patterns.append(pattern.pattern_id)
    
    def _update_threat_assessment(self, attack_context: AttackContext, 
                                interaction: ServiceInteraction):
        """Update threat assessment based on patterns and behavior"""
        # Base threat score
        threat_score = 0.0
        
        # Pattern-based scoring
        for pattern_id in attack_context.interaction_patterns:
            if pattern_id in self.interaction_patterns:
                pattern = self.interaction_patterns[pattern_id]
                pattern_confidence = pattern.calculate_confidence()
                threat_score += pattern_confidence * 0.3
        
        # Frequency-based scoring
        ip_interactions = self.recent_interactions[interaction.attacker_ip]
        interaction_rate = len(ip_interactions) / max(1, (datetime.now() - 
            ip_interactions[0].timestamp).total_seconds() / 60)  # interactions per minute
        threat_score += min(0.3, interaction_rate * 0.1)
        
        # Service correlation scoring
        unique_services = len(set(i.service for i in ip_interactions))
        threat_score += min(0.2, unique_services * 0.05)
        
        # Command complexity scoring
        command_complexity = len(interaction.command.split()) / 10
        threat_score += min(0.2, command_complexity * 0.1)
        
        # Update attack context
        attack_context.threat_score = min(1.0, threat_score)
    
    def _extract_context_features(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant features from interaction context"""
        features = {}
        
        # Extract common features
        if "authenticated" in context:
            features["authenticated"] = context["authenticated"]
        
        if "username" in context:
            features["has_username"] = bool(context["username"])
            
        if "session_data" in context:
            session = context["session_data"]
            features["has_session"] = True
            features["session_length"] = len(str(session))
        
        return features

    
    def _update_attack_context(self, service: str, attacker_ip: str, 
                              command: str, context: Dict[str, Any]) -> AttackContext:
        """Update or create attack context for attacker"""
        attack_key = f"{attacker_ip}:{service}"
        current_time = datetime.now()
        
        if attack_key in self.active_attacks:
            # Update existing attack context
            attack_context = self.active_attacks[attack_key]
            attack_context.commands.append(command)
            attack_context.last_activity = current_time
            
            # Re-analyze attack type based on new command
            attack_type = self.behavioral_analyzer.classify_attack_type(
                attack_context.commands, service
            )
            attack_context.attack_type = attack_type["type"]
            attack_context.confidence = attack_type["confidence"]
            
        else:
            # Create new attack context
            attack_type = self.behavioral_analyzer.classify_attack_type([command], service)
            
            attack_context = AttackContext(
                attacker_ip=attacker_ip,
                service=service,
                commands=[command],
                start_time=current_time,
                last_activity=current_time,
                attack_type=attack_type["type"],
                confidence=attack_type["confidence"]
            )
            
            self.active_attacks[attack_key] = attack_context
        
        return attack_context
    
    def _learn_from_interaction(self, service: str, command: str, 
                               behavior_analysis: Dict, response: Dict):
        """Learn from attacker interactions to improve future responses"""
        learning_data = {
            "service": service,
            "command": command,
            "attack_type": behavior_analysis.get("attack_type", "unknown"),
            "response_effectiveness": response.get("effectiveness", 0.5),
            "timestamp": datetime.now().isoformat()
        }
        
        # Store learning pattern
        pattern_key = f"{service}:{behavior_analysis.get('attack_type', 'unknown')}"
        self.learned_patterns[pattern_key].append(learning_data)
        
        # Update adaptive policies if needed
        self._update_adaptive_policies(service, behavior_analysis, response)
    
    def _update_adaptive_policies(self, service: str, behavior_analysis: Dict, response: Dict):
        """Update adaptive policies based on learning"""
        policy_key = f"{service}_policy"
        
        if policy_key not in self.adaptive_policies:
            self.adaptive_policies[policy_key] = {
                "response_delay": {"min": 0.5, "max": 3.0},
                "deception_level": 0.7,
                "interaction_depth": 0.8,
                "last_updated": datetime.now().isoformat()
            }
        
        policy = self.adaptive_policies[policy_key]
        
        # Adapt based on attack type
        attack_type = behavior_analysis.get("attack_type", "unknown")
        
        if attack_type == "brute_force":
            # Increase response delay for brute force attacks
            policy["response_delay"]["min"] = max(1.0, policy["response_delay"]["min"])
            policy["response_delay"]["max"] = max(5.0, policy["response_delay"]["max"])
        elif attack_type == "reconnaissance":
            # Provide more deceptive information for reconnaissance
            policy["deception_level"] = min(0.9, policy["deception_level"] + 0.1)
        elif attack_type == "exploitation":
            # Increase interaction depth for exploitation attempts
            policy["interaction_depth"] = min(1.0, policy["interaction_depth"] + 0.1)
        
        policy["last_updated"] = datetime.now().isoformat()
    
    def _fallback_response(self, service: str, command: str) -> Dict[str, Any]:
        """Generate fallback response when AI processing fails"""
        fallback_responses = {
            "ssh": {
                "response": "bash: command not found",
                "delay": random.uniform(0.5, 2.0)
            },
            "ftp": {
                "response": "550 File not found",
                "delay": random.uniform(0.3, 1.5)
            },
            "mysql": {
                "response": "ERROR 1064 (42000): You have an error in your SQL syntax",
                "delay": random.uniform(0.2, 1.0)
            },
            "smb": {
                "response": "NT_STATUS_ACCESS_DENIED",
                "delay": random.uniform(0.5, 2.0)
            },
            "rdp": {
                "response": "Authentication failed",
                "delay": random.uniform(1.0, 3.0)
            }
        }
        
        default_response = {
            "response": "Command not recognized",
            "delay": random.uniform(0.5, 2.0)
        }
        
        return {
            "response": fallback_responses.get(service, default_response),
            "behavior_analysis": {"attack_type": "unknown", "confidence": 0.1},
            "attack_context": None,
            "response_time": 0.1,
            "ai_confidence": 0.1,
            "fallback": True
        }
    
    def generate_behavioral_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive behavioral analysis report"""
        current_time = datetime.now()
        
        # Clean up old attack contexts
        self._cleanup_old_attacks(current_time)
        
        # Analyze current attack patterns
        attack_summary = self._analyze_attack_patterns()
        
        # Generate threat intelligence
        threat_intel = self._generate_threat_intelligence()
        
        # Performance metrics
        performance = self._get_performance_metrics()
        
        return {
            "timestamp": current_time.isoformat(),
            "active_attacks": len(self.active_attacks),
            "attack_summary": attack_summary,
            "threat_intelligence": threat_intel,
            "performance_metrics": performance,
            "learned_patterns": len(self.learned_patterns),
            "adaptive_policies": self.adaptive_policies
        }
    
    def _cleanup_old_attacks(self, current_time: datetime):
        """Remove old inactive attack contexts"""
        timeout_threshold = current_time - timedelta(minutes=30)
        
        expired_attacks = [
            key for key, context in self.active_attacks.items()
            if context.last_activity < timeout_threshold
        ]
        
        for key in expired_attacks:
            # Move to history before removing
            self.attack_history.append(self.active_attacks[key])
            del self.active_attacks[key]
    
    def _analyze_attack_patterns(self) -> Dict[str, Any]:
        """Analyze current attack patterns"""
        if not self.active_attacks:
            return {"total_attacks": 0, "attack_types": {}, "top_targets": []}
        
        attack_types = defaultdict(int)
        service_targets = defaultdict(int)
        
        for context in self.active_attacks.values():
            attack_types[context.attack_type] += 1
            service_targets[context.service] += 1
        
        return {
            "total_attacks": len(self.active_attacks),
            "attack_types": dict(attack_types),
            "top_targets": sorted(service_targets.items(), key=lambda x: x[1], reverse=True)[:5]
        }
    
    def _generate_threat_intelligence(self) -> Dict[str, Any]:
        """Generate threat intelligence from learned patterns"""
        threat_intel = {
            "high_risk_ips": [],
            "common_attack_vectors": [],
            "emerging_patterns": []
        }
        
        # Analyze high-risk IPs
        ip_activity = defaultdict(int)
        for context in self.active_attacks.values():
            ip_activity[context.attacker_ip] += len(context.commands)
        
        threat_intel["high_risk_ips"] = [
            {"ip": ip, "activity_score": score}
            for ip, score in sorted(ip_activity.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Analyze common attack vectors
        attack_vectors = defaultdict(int)
        for patterns in self.learned_patterns.values():
            for pattern in patterns[-10:]:  # Recent patterns
                attack_vectors[pattern["attack_type"]] += 1
        
        threat_intel["common_attack_vectors"] = [
            {"type": attack_type, "frequency": freq}
            for attack_type, freq in sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        return threat_intel
    
    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get AI engine performance metrics"""
        if not self.response_times:
            return {"avg_response_time": 0, "accuracy": 0, "throughput": 0}
        
        avg_response_time = sum(self.response_times) / len(self.response_times)
        accuracy = sum(self.accuracy_scores) / len(self.accuracy_scores) if self.accuracy_scores else 0
        
        return {
            "avg_response_time": round(avg_response_time, 3),
            "accuracy": round(accuracy, 3),
            "throughput": len(self.response_times),
            "total_interactions": len(self.learned_patterns)
        }
    
    def load_learned_patterns(self):
        """Load previously learned patterns from storage"""
        try:
            with open("data/learned_patterns.json", "r") as f:
                data = json.load(f)
                self.learned_patterns.update(data.get("patterns", {}))
                self.adaptive_policies.update(data.get("policies", {}))
        except FileNotFoundError:
            pass  # No previous patterns to load
    
    def save_learned_patterns(self):
        """Save learned patterns to storage"""
        import os
        os.makedirs("data", exist_ok=True)
        
        data = {
            "patterns": dict(self.learned_patterns),
            "policies": self.adaptive_policies,
            "timestamp": datetime.now().isoformat()
        }
        
        with open("data/learned_patterns.json", "w") as f:
            json.dump(data, f, indent=2)
    
    def generate_final_report(self) -> Dict[str, Any]:
        """Generate final comprehensive report"""
        final_report = self.generate_behavioral_analysis()
        
        # Add historical data
        final_report["historical_attacks"] = len(self.attack_history)
        final_report["total_learned_patterns"] = sum(len(patterns) for patterns in self.learned_patterns.values())
        
        # Save learned patterns
        self.save_learned_patterns()
        
        return final_report
    
    def get_status(self) -> Dict[str, Any]:
        """Get current AI coordinator status"""
        return {
            "initialized": self.initialized,
            "active_attacks": len(self.active_attacks),
            "learned_patterns": len(self.learned_patterns),
            "adaptive_policies": len(self.adaptive_policies),
            "avg_response_time": sum(self.response_times) / len(self.response_times) if self.response_times else 0
        }