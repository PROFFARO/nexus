"""
Sequence Pattern Recognition System for Behavioral Analysis
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re
from collections import defaultdict


@dataclass
class CommandSequence:
    """Represents a sequence of commands"""
    commands: List[str]
    service: str
    timestamp: datetime
    sequence_id: str = field(init=False)
    
    def __post_init__(self):
        """Generate unique sequence ID"""
        seq_str = f"{self.service}:{'|'.join(self.commands)}:{self.timestamp.isoformat()}"
        self.sequence_id = hashlib.sha256(seq_str.encode()).hexdigest()[:16]


@dataclass
class BehaviorPattern:
    """Represents a detected behavior pattern"""
    pattern_id: str
    pattern_type: str
    commands: List[str]
    service: str
    frequency: int = 0
    confidence: float = 0.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    associated_ips: Set[str] = field(default_factory=set)
    features: Dict[str, Any] = field(default_factory=dict)
    
    def update(self, attacker_ip: str):
        """Update pattern statistics"""
        self.frequency += 1
        self.last_seen = datetime.now()
        self.associated_ips.add(attacker_ip)
        self._calculate_confidence()
    
    def _calculate_confidence(self):
        """Calculate pattern confidence score"""
        # Time-based factor
        time_factor = 1.0
        age_hours = (datetime.now() - self.first_seen).total_seconds() / 3600
        if age_hours > 24:
            time_factor = max(0.5, 1.0 - (age_hours - 24) / 168)  # Decay over a week
        
        # Frequency factor
        freq_factor = min(1.0, self.frequency / 100)
        
        # IP diversity factor
        ip_factor = min(1.0, len(self.associated_ips) / 10)
        
        self.confidence = (0.4 * time_factor + 0.3 * freq_factor + 0.3 * ip_factor)


class SequencePatternMatcher:
    """Pattern matching engine for command sequences"""
    
    def __init__(self):
        self.patterns: Dict[str, BehaviorPattern] = {}
        self.sequence_cache: Dict[str, List[CommandSequence]] = defaultdict(list)
        self.pattern_matchers = {}
        self.initialized = False
    
    def initialize(self):
        """Initialize pattern matching engine"""
        try:
            # Load predefined patterns
            self.load_predefined_patterns()
            
            # Initialize pattern matchers
            self._init_pattern_matchers()
            
            self.initialized = True
            
        except Exception as e:
            print(f"[{datetime.now()}] Pattern matcher initialization failed: {e}")
            raise
    
    def load_predefined_patterns(self):
        """Load predefined attack patterns"""
        try:
            with open("data/attack_patterns.json", "r") as f:
                patterns = json.load(f)
                for p in patterns:
                    pattern = BehaviorPattern(
                        pattern_id=p["id"],
                        pattern_type=p["type"],
                        commands=p["commands"],
                        service=p["service"],
                        features=p.get("features", {})
                    )
                    self.patterns[pattern.pattern_id] = pattern
        except FileNotFoundError:
            print(f"[{datetime.now()}] No predefined patterns found, starting fresh")
    
    def _init_pattern_matchers(self):
        """Initialize pattern matching algorithms"""
        for service in ["ssh", "ftp", "rdp", "smb", "mysql"]:
            self.pattern_matchers[service] = {
                "exact": set(),  # Exact command matches
                "regex": [],     # Regular expression patterns
                "fuzzy": []      # Fuzzy matching patterns
            }
        
        for pattern in self.patterns.values():
            for cmd in pattern.commands:
                if '*' in cmd or '?' in cmd:
                    self.pattern_matchers[pattern.service]["fuzzy"].append(cmd)
                elif any(c in cmd for c in '.[]{}()\\+'):
                    self.pattern_matchers[pattern.service]["regex"].append(cmd)
                else:
                    self.pattern_matchers[pattern.service]["exact"].add(cmd)
    
    def match_sequence(self, commands: List[str], service: str) -> List[Dict[str, Any]]:
        """Match command sequence against known patterns"""
        matches = []
        sequence = CommandSequence(commands, service, datetime.now())
        
        # Update sequence cache
        self.sequence_cache[service].append(sequence)
        if len(self.sequence_cache[service]) > 1000:
            self.sequence_cache[service] = self.sequence_cache[service][-1000:]
        
        # Exact matches
        for cmd in commands:
            if cmd in self.pattern_matchers[service]["exact"]:
                matches.append({
                    "type": "exact",
                    "command": cmd,
                    "confidence": 1.0
                })
        
        # Regex matches
        for pattern in self.pattern_matchers[service]["regex"]:
            for cmd in commands:
                try:
                    if re.match(pattern, cmd):
                        matches.append({
                            "type": "regex",
                            "command": cmd,
                            "pattern": pattern,
                            "confidence": 0.9
                        })
                except re.error:
                    continue
        
        # Fuzzy matches
        for pattern in self.pattern_matchers[service]["fuzzy"]:
            for cmd in commands:
                similarity = self._calculate_similarity(cmd, pattern)
                if similarity > 0.8:
                    matches.append({
                        "type": "fuzzy",
                        "command": cmd,
                        "pattern": pattern,
                        "confidence": similarity
                    })
        
        return matches
    
    def _calculate_similarity(self, cmd: str, pattern: str) -> float:
        """Calculate string similarity score"""
        if not cmd or not pattern:
            return 0.0
        
        # Convert glob patterns to regex
        if '*' in pattern or '?' in pattern:
            pattern = pattern.replace('*', '.*').replace('?', '.')
            try:
                if re.match(pattern, cmd):
                    return 0.9
            except re.error:
                return 0.0
        
        # Simple Levenshtein-based similarity
        dist = self._levenshtein_distance(cmd, pattern)
        max_len = max(len(cmd), len(pattern))
        return 1 - (dist / max_len)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]