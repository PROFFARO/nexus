"""
Threat Scoring System - Calculates and manages threat scores for attack patterns
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

@dataclass
class ThreatMetrics:
    """Metrics used to calculate threat scores"""
    # Base metrics
    attack_type: str
    pattern_confidence: float
    complexity: float
    service_risk: float
    behavioral_risk: float
    
    # Temporal metrics
    frequency: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    progression_rate: float = 0.0
    
    # Impact metrics
    data_impact: float = 0.0
    system_impact: float = 0.0
    access_impact: float = 0.0

@dataclass
class ThreatScore:
    """Complete threat score with all components"""
    base_score: float
    temporal_score: float
    impact_score: float
    total_score: float
    threat_level: ThreatLevel
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)

class ThreatScorer:
    """
    Calculates threat scores based on various metrics and patterns
    """
    
    def __init__(self):
        # Scoring weights
        self.weights = {
            "pattern_confidence": 0.3,
            "complexity": 0.2,
            "service_risk": 0.2,
            "behavioral_risk": 0.3,
            "temporal": 0.25,
            "impact": 0.25
        }
        
        # Service risk levels
        self.service_risk_levels = {
            "ssh": 1.0,    # Highest risk
            "rdp": 0.9,
            "smb": 0.8,
            "ftp": 0.7,
            "mysql": 0.6
        }
        
        # Attack type base risks
        self.attack_type_risks = {
            "brute_force": 0.7,
            "sql_injection": 0.9,
            "reconnaissance": 0.5,
            "malware_download": 0.95,
            "privilege_escalation": 0.9,
            "persistence": 0.8,
            "lateral_movement": 0.85,
            "data_exfiltration": 0.8
        }
        
        # Historical data
        self.threat_history: Dict[str, List[ThreatScore]] = {}
    
    def calculate_threat_score(self, metrics: ThreatMetrics) -> ThreatScore:
        """Calculate complete threat score from metrics"""
        # Calculate component scores
        base_score = self._calculate_base_score(metrics)
        temporal_score = self._calculate_temporal_score(metrics)
        impact_score = self._calculate_impact_score(metrics)
        
        # Calculate total weighted score
        total_score = (
            base_score * (1 - self.weights["temporal"] - self.weights["impact"]) +
            temporal_score * self.weights["temporal"] +
            impact_score * self.weights["impact"]
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(total_score)
        
        # Calculate confidence based on metrics reliability
        confidence = self._calculate_confidence(metrics)
        
        return ThreatScore(
            base_score=base_score,
            temporal_score=temporal_score,
            impact_score=impact_score,
            total_score=total_score,
            threat_level=threat_level,
            confidence=confidence
        )
    
    def _calculate_base_score(self, metrics: ThreatMetrics) -> float:
        """Calculate base threat score"""
        # Get attack type base risk
        attack_risk = self.attack_type_risks.get(metrics.attack_type, 0.5)
        
        # Calculate weighted score components
        weighted_scores = [
            metrics.pattern_confidence * self.weights["pattern_confidence"],
            metrics.complexity * self.weights["complexity"],
            metrics.service_risk * self.weights["service_risk"],
            metrics.behavioral_risk * self.weights["behavioral_risk"],
            attack_risk * 0.2  # Additional weight for attack type
        ]
        
        # Combine scores with normalization
        base_score = sum(weighted_scores) / sum(self.weights.values())
        
        return min(1.0, base_score)
    
    def _calculate_temporal_score(self, metrics: ThreatMetrics) -> float:
        """Calculate temporal threat score based on historical patterns"""
        temporal_score = 0.0
        
        # Frequency impact
        if metrics.frequency > 0:
            freq_score = min(metrics.frequency / 100, 1.0)  # Normalize frequency
            temporal_score += freq_score * 0.4
        
        # Progression rate impact
        temporal_score += metrics.progression_rate * 0.4
        
        # Recency impact
        time_since_first = (datetime.now() - metrics.first_seen).total_seconds()
        time_since_last = (datetime.now() - metrics.last_seen).total_seconds()
        
        if time_since_last < 3600:  # Within last hour
            temporal_score += 0.2
        elif time_since_last < 86400:  # Within last day
            temporal_score += 0.1
        
        return min(1.0, temporal_score)
    
    def _calculate_impact_score(self, metrics: ThreatMetrics) -> float:
        """Calculate potential impact score"""
        impact_weights = {
            "data": 0.4,
            "system": 0.3,
            "access": 0.3
        }
        
        impact_score = (
            metrics.data_impact * impact_weights["data"] +
            metrics.system_impact * impact_weights["system"] +
            metrics.access_impact * impact_weights["access"]
        )
        
        return min(1.0, impact_score)
    
    def _determine_threat_level(self, total_score: float) -> ThreatLevel:
        """Map total score to threat level"""
        if total_score >= 0.9:
            return ThreatLevel.CRITICAL
        elif total_score >= 0.7:
            return ThreatLevel.HIGH
        elif total_score >= 0.5:
            return ThreatLevel.MEDIUM
        elif total_score >= 0.3:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def _calculate_confidence(self, metrics: ThreatMetrics) -> float:
        """Calculate confidence score for the threat assessment"""
        confidence_factors = [
            metrics.pattern_confidence,
            min(metrics.frequency / 10, 1.0) if metrics.frequency > 0 else 0.1,
            0.8 if (datetime.now() - metrics.last_seen).total_seconds() < 3600 else 0.5,
            metrics.behavioral_risk
        ]
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def update_threat_history(self, threat_id: str, score: ThreatScore):
        """Update historical threat data"""
        if threat_id not in self.threat_history:
            self.threat_history[threat_id] = []
        
        self.threat_history[threat_id].append(score)
        
        # Keep only recent history (last 1000 scores)
        if len(self.threat_history[threat_id]) > 1000:
            self.threat_history[threat_id] = self.threat_history[threat_id][-1000:]
    
    def analyze_threat_progression(self, threat_id: str) -> Dict[str, Any]:
        """Analyze how a threat has progressed over time"""
        if threat_id not in self.threat_history or not self.threat_history[threat_id]:
            return {
                "trend": "unknown",
                "progression_rate": 0.0,
                "confidence": 0.1
            }
        
        history = self.threat_history[threat_id]
        
        # Calculate score progression
        scores = [score.total_score for score in history]
        if len(scores) < 2:
            return {
                "trend": "insufficient_data",
                "progression_rate": 0.0,
                "confidence": 0.3
            }
        
        # Calculate trend
        score_diff = scores[-1] - scores[0]
        time_diff = (history[-1].timestamp - history[0].timestamp).total_seconds()
        
        if time_diff == 0:
            progression_rate = 0.0
        else:
            progression_rate = score_diff / (time_diff / 3600)  # Change per hour
        
        # Determine trend
        if progression_rate > 0.1:
            trend = "escalating"
        elif progression_rate < -0.1:
            trend = "decreasing"
        else:
            trend = "stable"
        
        # Calculate confidence based on history size
        confidence = min(len(history) / 10, 1.0)
        
        return {
            "trend": trend,
            "progression_rate": progression_rate,
            "confidence": confidence,
            "data_points": len(history),
            "time_span": time_diff,
            "current_score": scores[-1],
            "initial_score": scores[0]
        }
    
    def get_threat_statistics(self, threat_id: str) -> Dict[str, Any]:
        """Get statistical analysis of threat scores"""
        if threat_id not in self.threat_history or not self.threat_history[threat_id]:
            return {"error": "No history available"}
        
        history = self.threat_history[threat_id]
        scores = [score.total_score for score in history]
        
        return {
            "count": len(scores),
            "average_score": sum(scores) / len(scores),
            "max_score": max(scores),
            "min_score": min(scores),
            "latest_score": scores[-1],
            "threat_level": history[-1].threat_level.name,
            "confidence": history[-1].confidence
        }