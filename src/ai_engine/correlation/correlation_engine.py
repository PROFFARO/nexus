"""
Correlation Engine - Core system for cross-service attack correlation
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict
import json
import logging
import ipaddress

@dataclass
class ServiceEvent:
    """Represents a single event from a service"""
    timestamp: datetime
    service: str
    source_ip: str
    command: str
    session_id: str
    attack_type: str
    threat_score: float
    confidence: float
    patterns: List[Dict[str, Any]]
    behavioral_data: Dict[str, Any]

@dataclass
class SessionData:
    """Tracks data for a correlated session"""
    session_id: str
    source_ip: str
    start_time: datetime
    services: Set[str] = field(default_factory=set)
    events: List[ServiceEvent] = field(default_factory=list)
    attack_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    threat_scores: List[float] = field(default_factory=list)
    behavioral_patterns: Dict[str, Any] = field(default_factory=dict)
    correlation_score: float = 0.0
    confidence: float = 0.0
    is_active: bool = True
    last_update: datetime = field(default_factory=datetime.now)

@dataclass
class CorrelationResult:
    """Result of a correlation analysis"""
    session_ids: List[str]
    correlation_type: str
    confidence: float
    score: float
    evidence: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)

class CorrelationEngine:
    """
    Manages cross-service correlation of attack patterns and behaviors
    """
    
    def __init__(self):
        self.logger = logging.getLogger("correlation_engine")
        
        # Active sessions by ID and IP
        self.sessions: Dict[str, SessionData] = {}
        self.ip_sessions: Dict[str, Set[str]] = defaultdict(set)
        
        # Correlation tracking
        self.correlations: Dict[str, CorrelationResult] = {}
        self.behavioral_patterns: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.config = {
            "session_timeout": 3600,  # 1 hour
            "correlation_threshold": 0.7,
            "pattern_similarity_threshold": 0.8,
            "behavioral_similarity_threshold": 0.75,
            "min_confidence": 0.6
        }
    
    def process_event(self, event: ServiceEvent) -> List[CorrelationResult]:
        """
        Process a new service event and update correlations
        
        Args:
            event: The service event to process
        
        Returns:
            List of new correlation results
        """
        # Update session tracking
        session = self._update_session_tracking(event)
        
        # Update behavioral patterns
        self._update_behavioral_patterns(session, event)
        
        # Find correlations
        new_correlations = self._find_correlations(session)
        
        # Clean up old sessions
        self._cleanup_old_sessions()
        
        return new_correlations
    
    def _update_session_tracking(self, event: ServiceEvent) -> SessionData:
        """Update session tracking with new event"""
        # Try to find existing session
        session = self.sessions.get(event.session_id)
        
        if not session:
            # Create new session
            session = SessionData(
                session_id=event.session_id,
                source_ip=event.source_ip,
                start_time=event.timestamp
            )
            self.sessions[event.session_id] = session
            self.ip_sessions[event.source_ip].add(event.session_id)
        
        # Update session data
        session.services.add(event.service)
        session.events.append(event)
        session.attack_types[event.attack_type] += 1
        session.threat_scores.append(event.threat_score)
        session.last_update = event.timestamp
        
        # Update correlation score
        if len(session.services) > 1:
            session.correlation_score = self._calculate_correlation_score(session)
            session.confidence = self._calculate_correlation_confidence(session)
        
        return session
    
    def _update_behavioral_patterns(self, session: SessionData, event: ServiceEvent):
        """Update behavioral patterns for the session"""
        behavior_key = f"{session.session_id}:{event.service}"
        
        # Extract behavioral patterns
        patterns = {
            "command_patterns": event.patterns,
            "attack_sequence": [e.command for e in session.events[-5:]],
            "service_interaction": list(session.services),
            "threat_progression": session.threat_scores[-5:],
            "attack_types": dict(session.attack_types)
        }
        
        # Store patterns
        session.behavioral_patterns[event.service] = patterns
        self.behavioral_patterns[behavior_key] = patterns
    
    def _find_correlations(self, session: SessionData) -> List[CorrelationResult]:
        """Find correlations with other sessions"""
        new_correlations = []
        
        # Only look for correlations if we have multiple services
        if len(session.services) <= 1:
            return new_correlations
        
        # Check IP-based correlations
        ip_correlations = self._find_ip_correlations(session)
        new_correlations.extend(ip_correlations)
        
        # Check pattern-based correlations
        pattern_correlations = self._find_pattern_correlations(session)
        new_correlations.extend(pattern_correlations)
        
        # Check behavioral correlations
        behavioral_correlations = self._find_behavioral_correlations(session)
        new_correlations.extend(behavioral_correlations)
        
        # Store new correlations
        for correlation in new_correlations:
            correlation_key = ":".join(sorted(correlation.session_ids))
            self.correlations[correlation_key] = correlation
        
        return new_correlations
    
    def _find_ip_correlations(self, session: SessionData) -> List[CorrelationResult]:
        """Find correlations based on IP address"""
        correlations = []
        
        # Get all sessions from this IP
        ip_session_ids = self.ip_sessions[session.source_ip]
        
        if len(ip_session_ids) > 1:
            # Calculate correlation metrics
            related_sessions = [
                self.sessions[sid] for sid in ip_session_ids 
                if sid != session.session_id and self.sessions[sid].is_active
            ]
            
            for related in related_sessions:
                # Check for service overlap
                common_services = session.services.intersection(related.services)
                if not common_services:
                    continue
                
                # Calculate correlation scores
                correlation_score = self._calculate_ip_correlation_score(
                    session, related, common_services
                )
                
                if correlation_score >= self.config["correlation_threshold"]:
                    evidence = {
                        "common_services": list(common_services),
                        "ip_address": session.source_ip,
                        "attack_patterns": {
                            "session": dict(session.attack_types),
                            "related": dict(related.attack_types)
                        }
                    }
                    
                    correlations.append(CorrelationResult(
                        session_ids=[session.session_id, related.session_id],
                        correlation_type="ip_based",
                        confidence=min(session.confidence, related.confidence),
                        score=correlation_score,
                        evidence=evidence
                    ))
        
        return correlations
    
    def _find_pattern_correlations(self, session: SessionData) -> List[CorrelationResult]:
        """Find correlations based on attack patterns"""
        correlations = []
        
        # Compare patterns with other active sessions
        for other_id, other in self.sessions.items():
            if (other_id == session.session_id or 
                not other.is_active or
                not self._sessions_worth_comparing(session, other)):
                continue
            
            # Compare patterns across services
            pattern_score = self._calculate_pattern_similarity(session, other)
            
            if pattern_score >= self.config["pattern_similarity_threshold"]:
                # Get common patterns
                common_patterns = []
                for service in session.services.intersection(other.services):
                    if (service in session.behavioral_patterns and 
                        service in other.behavioral_patterns):
                        patterns1 = session.behavioral_patterns[service].get("command_patterns", [])
                        patterns2 = other.behavioral_patterns[service].get("command_patterns", [])
                        common = [p for p in patterns1 if any(
                            p.get("type") == p2.get("type") for p2 in patterns2
                        )]
                        common_patterns.extend(common)
                
                evidence = {
                    "pattern_similarity": pattern_score,
                    "common_patterns": common_patterns,
                    "attack_sequence_similarity": self._compare_attack_sequences(
                        [e.command for e in session.events[-5:]],
                        [e.command for e in other.events[-5:]]
                    )
                }
                
                correlations.append(CorrelationResult(
                    session_ids=[session.session_id, other_id],
                    correlation_type="pattern_based",
                    confidence=pattern_score,
                    score=pattern_score,
                    evidence=evidence
                ))
        
        return correlations
    
    def _find_behavioral_correlations(self, session: SessionData) -> List[CorrelationResult]:
        """Find correlations based on behavioral analysis"""
        correlations = []
        
        # Compare behavior with other active sessions
        for other_id, other in self.sessions.items():
            if (other_id == session.session_id or 
                not other.is_active or
                not self._sessions_worth_comparing(session, other)):
                continue
            
            # Calculate behavioral similarity
            behavior_score = self._calculate_behavioral_similarity(session, other)
            
            if behavior_score >= self.config["behavioral_similarity_threshold"]:
                evidence = {
                    "behavioral_similarity": behavior_score,
                    "threat_progression": {
                        "session": session.threat_scores[-5:],
                        "other": other.threat_scores[-5:]
                    },
                    "attack_type_overlap": self._calculate_attack_type_similarity(
                        session.attack_types, other.attack_types
                    )
                }
                
                correlations.append(CorrelationResult(
                    session_ids=[session.session_id, other_id],
                    correlation_type="behavioral",
                    confidence=behavior_score,
                    score=behavior_score,
                    evidence=evidence
                ))
        
        return correlations
    
    def _calculate_correlation_score(self, session: SessionData) -> float:
        """Calculate correlation score for a session"""
        if len(session.services) <= 1:
            return 0.0
        
        factors = [
            self._calculate_service_correlation(session),
            self._calculate_temporal_correlation(session),
            self._calculate_pattern_correlation(session),
            self._calculate_threat_correlation(session)
        ]
        
        return sum(factors) / len(factors)
    
    def _calculate_correlation_confidence(self, session: SessionData) -> float:
        """Calculate confidence in correlation score"""
        factors = [
            len(session.events) / 10,  # More events = higher confidence
            len(session.services) / 5,  # More services = higher confidence
            sum(session.threat_scores) / len(session.threat_scores),  # Average threat score
            0.5 + (len(session.attack_types) / 10)  # Variety of attack types
        ]
        
        return min(sum(factors) / len(factors), 1.0)
    
    def _calculate_ip_correlation_score(self, session1: SessionData, 
                                      session2: SessionData,
                                      common_services: Set[str]) -> float:
        """Calculate correlation score between two sessions from same IP"""
        factors = []
        
        # Service overlap score
        service_overlap = len(common_services) / max(
            len(session1.services), len(session2.services)
        )
        factors.append(service_overlap)
        
        # Temporal proximity score
        time_diff = abs((session1.last_update - session2.last_update).total_seconds())
        temporal_score = 1.0 - min(time_diff / self.config["session_timeout"], 1.0)
        factors.append(temporal_score)
        
        # Attack type similarity
        attack_similarity = self._calculate_attack_type_similarity(
            session1.attack_types, session2.attack_types
        )
        factors.append(attack_similarity)
        
        # Threat score correlation
        threat_correlation = self._calculate_threat_score_correlation(
            session1.threat_scores, session2.threat_scores
        )
        factors.append(threat_correlation)
        
        return sum(factors) / len(factors)
    
    def _calculate_pattern_similarity(self, session1: SessionData, 
                                    session2: SessionData) -> float:
        """Calculate pattern similarity between two sessions"""
        if not session1.behavioral_patterns or not session2.behavioral_patterns:
            return 0.0
        
        similarities = []
        
        # Compare patterns for each common service
        common_services = session1.services.intersection(session2.services)
        for service in common_services:
            if (service in session1.behavioral_patterns and 
                service in session2.behavioral_patterns):
                
                patterns1 = session1.behavioral_patterns[service]
                patterns2 = session2.behavioral_patterns[service]
                
                # Compare command patterns
                cmd_similarity = self._compare_command_patterns(
                    patterns1.get("command_patterns", []),
                    patterns2.get("command_patterns", [])
                )
                similarities.append(cmd_similarity)
                
                # Compare attack sequences
                seq_similarity = self._compare_attack_sequences(
                    patterns1.get("attack_sequence", []),
                    patterns2.get("attack_sequence", [])
                )
                similarities.append(seq_similarity)
        
        return sum(similarities) / len(similarities) if similarities else 0.0
    
    def _calculate_behavioral_similarity(self, session1: SessionData, 
                                      session2: SessionData) -> float:
        """Calculate behavioral similarity between two sessions"""
        factors = []
        
        # Compare attack type distributions
        attack_similarity = self._calculate_attack_type_similarity(
            session1.attack_types, session2.attack_types
        )
        factors.append(attack_similarity)
        
        # Compare threat score progressions
        threat_correlation = self._calculate_threat_score_correlation(
            session1.threat_scores, session2.threat_scores
        )
        factors.append(threat_correlation)
        
        # Compare service interaction patterns
        service_similarity = len(
            session1.services.intersection(session2.services)
        ) / max(len(session1.services), len(session2.services))
        factors.append(service_similarity)
        
        # Compare temporal patterns
        temporal_similarity = self._calculate_temporal_similarity(session1, session2)
        factors.append(temporal_similarity)
        
        return sum(factors) / len(factors)
    
    def _calculate_service_correlation(self, session: SessionData) -> float:
        """Calculate correlation score based on service interaction patterns"""
        if len(session.services) <= 1:
            return 0.0
        
        # Analyze service interaction sequence
        service_sequence = [event.service for event in session.events[-10:]]
        unique_transitions = set()
        
        for i in range(len(service_sequence) - 1):
            transition = (service_sequence[i], service_sequence[i + 1])
            if transition[0] != transition[1]:
                unique_transitions.add(transition)
        
        # More unique transitions = higher correlation
        transition_score = min(len(unique_transitions) / 5, 1.0)
        
        # Consider time between service switches
        time_diffs = []
        for i in range(len(session.events) - 1):
            if session.events[i].service != session.events[i + 1].service:
                diff = (session.events[i + 1].timestamp - 
                       session.events[i].timestamp).total_seconds()
                time_diffs.append(diff)
        
        time_score = 0.0
        if time_diffs:
            avg_diff = sum(time_diffs) / len(time_diffs)
            time_score = 1.0 - min(avg_diff / 300, 1.0)  # Lower times = higher score
        
        return (transition_score + time_score) / 2
    
    def _calculate_temporal_correlation(self, session: SessionData) -> float:
        """Calculate correlation score based on temporal patterns"""
        if len(session.events) < 2:
            return 0.0
        
        # Analyze time differences between events
        time_diffs = []
        for i in range(len(session.events) - 1):
            diff = (session.events[i + 1].timestamp - 
                   session.events[i].timestamp).total_seconds()
            time_diffs.append(diff)
        
        if not time_diffs:
            return 0.0
        
        # Calculate temporal pattern score
        avg_diff = sum(time_diffs) / len(time_diffs)
        consistency_score = 1.0 - min(
            abs(max(time_diffs) - min(time_diffs)) / 300, 1.0
        )
        
        return consistency_score
    
    def _calculate_pattern_correlation(self, session: SessionData) -> float:
        """Calculate correlation score based on attack patterns"""
        if not session.attack_types:
            return 0.0
        
        # Calculate pattern diversity
        pattern_diversity = len(session.attack_types) / 5  # Normalize to max 5 types
        
        # Calculate pattern consistency
        total_attacks = sum(session.attack_types.values())
        pattern_consistency = max(session.attack_types.values()) / total_attacks
        
        return (pattern_diversity + pattern_consistency) / 2
    
    def _calculate_threat_correlation(self, session: SessionData) -> float:
        """Calculate correlation score based on threat progression"""
        if len(session.threat_scores) < 2:
            return 0.0
        
        # Calculate threat score progression
        progression = (session.threat_scores[-1] - session.threat_scores[0])
        progression_score = min(abs(progression), 1.0)
        
        # Calculate threat consistency
        avg_score = sum(session.threat_scores) / len(session.threat_scores)
        consistency = 1.0 - min(
            abs(max(session.threat_scores) - min(session.threat_scores)), 1.0
        )
        
        return (progression_score + consistency) / 2
    
    def _sessions_worth_comparing(self, session1: SessionData, 
                                session2: SessionData) -> bool:
        """Determine if two sessions are worth comparing"""
        # Check temporal proximity
        time_diff = abs(
            (session1.last_update - session2.last_update).total_seconds()
        )
        if time_diff > self.config["session_timeout"]:
            return False
        
        # Check if they have any services in common
        if not session1.services.intersection(session2.services):
            return False
        
        # Check if they have enough events
        if len(session1.events) < 2 or len(session2.events) < 2:
            return False
        
        return True
    
    def _compare_command_patterns(self, patterns1: List[Dict[str, Any]],
                                patterns2: List[Dict[str, Any]]) -> float:
        """Compare command patterns between two sessions"""
        if not patterns1 or not patterns2:
            return 0.0
        
        # Extract pattern types
        types1 = {p.get("type", "") for p in patterns1}
        types2 = {p.get("type", "") for p in patterns2}
        
        # Calculate Jaccard similarity
        intersection = len(types1.intersection(types2))
        union = len(types1.union(types2))
        
        return intersection / union if union > 0 else 0.0
    
    def _compare_attack_sequences(self, seq1: List[str], seq2: List[str]) -> float:
        """Compare attack command sequences"""
        if not seq1 or not seq2:
            return 0.0
        
        # Use longest common subsequence
        lcs_length = self._longest_common_subsequence(seq1, seq2)
        max_length = max(len(seq1), len(seq2))
        
        return lcs_length / max_length
    
    def _longest_common_subsequence(self, seq1: List[str], seq2: List[str]) -> int:
        """Calculate length of longest common subsequence"""
        m, n = len(seq1), len(seq2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i-1] == seq2[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
        
        return dp[m][n]
    
    def _calculate_attack_type_similarity(self, types1: Dict[str, int],
                                        types2: Dict[str, int]) -> float:
        """Calculate similarity between attack type distributions"""
        all_types = set(types1.keys()).union(types2.keys())
        if not all_types:
            return 0.0
        
        # Calculate cosine similarity
        dot_product = sum(types1.get(t, 0) * types2.get(t, 0) for t in all_types)
        norm1 = sum(v*v for v in types1.values()) ** 0.5
        norm2 = sum(v*v for v in types2.values()) ** 0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def _calculate_threat_score_correlation(self, scores1: List[float],
                                         scores2: List[float]) -> float:
        """Calculate correlation between threat score sequences"""
        if not scores1 or not scores2:
            return 0.0
        
        # Get last 5 scores from each
        scores1 = scores1[-5:]
        scores2 = scores2[-5:]
        
        # Calculate trend similarity
        trend1 = [scores1[i] - scores1[i-1] for i in range(1, len(scores1))]
        trend2 = [scores2[i] - scores2[i-1] for i in range(1, len(scores2))]
        
        if not trend1 or not trend2:
            return 0.0
        
        # Compare trends using sign correlation
        matches = sum(1 for t1, t2 in zip(trend1, trend2) 
                     if (t1 > 0 and t2 > 0) or (t1 < 0 and t2 < 0))
        
        return matches / min(len(trend1), len(trend2))
    
    def _calculate_temporal_similarity(self, session1: SessionData,
                                    session2: SessionData) -> float:
        """Calculate similarity in temporal patterns"""
        # Compare event timing patterns
        time_diffs1 = []
        time_diffs2 = []
        
        for i in range(1, len(session1.events)):
            diff = (session1.events[i].timestamp - 
                   session1.events[i-1].timestamp).total_seconds()
            time_diffs1.append(diff)
        
        for i in range(1, len(session2.events)):
            diff = (session2.events[i].timestamp - 
                   session2.events[i-1].timestamp).total_seconds()
            time_diffs2.append(diff)
        
        if not time_diffs1 or not time_diffs2:
            return 0.0
        
        # Compare average time differences
        avg1 = sum(time_diffs1) / len(time_diffs1)
        avg2 = sum(time_diffs2) / len(time_diffs2)
        
        return 1.0 - min(abs(avg1 - avg2) / 300, 1.0)
    
    def _cleanup_old_sessions(self):
        """Clean up expired sessions"""
        current_time = datetime.now()
        
        # Find expired sessions
        expired = []
        for session_id, session in self.sessions.items():
            if ((current_time - session.last_update).total_seconds() > 
                self.config["session_timeout"]):
                expired.append(session_id)
                
                # Remove from IP tracking
                self.ip_sessions[session.source_ip].remove(session_id)
                if not self.ip_sessions[session.source_ip]:
                    del self.ip_sessions[session.source_ip]
        
        # Remove expired sessions
        for session_id in expired:
            del self.sessions[session_id]
    
    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary of current correlations"""
        return {
            "active_sessions": len(self.sessions),
            "total_correlations": len(self.correlations),
            "correlation_types": self._get_correlation_type_summary(),
            "service_stats": self._get_service_stats()
        }
    
    def _get_correlation_type_summary(self) -> Dict[str, int]:
        """Get summary of correlation types"""
        summary = defaultdict(int)
        for correlation in self.correlations.values():
            summary[correlation.correlation_type] += 1
        return dict(summary)
    
    def _get_service_stats(self) -> Dict[str, Any]:
        """Get statistics about service correlations"""
        service_stats = defaultdict(lambda: {
            "total_events": 0,
            "correlated_sessions": 0,
            "avg_threat_score": 0.0
        })
        
        for session in self.sessions.values():
            for event in session.events:
                stats = service_stats[event.service]
                stats["total_events"] += 1
                if len(session.services) > 1:
                    stats["correlated_sessions"] += 1
                stats["avg_threat_score"] = (
                    (stats["avg_threat_score"] * (stats["total_events"] - 1) + 
                     event.threat_score) / stats["total_events"]
                )
        
        return dict(service_stats)