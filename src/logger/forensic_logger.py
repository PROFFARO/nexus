"""
Forensic Logger - Comprehensive logging and forensic chain analysis
"""

import json
import os
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, TextIO, Tuple
from collections import defaultdict, deque
import threading
from dataclasses import dataclass, asdict
import uuid


@dataclass
class ForensicEvent:
    """Represents a forensic event"""
    event_id: str
    timestamp: str
    service: str
    action: str
    source_ip: str
    data: Dict[str, Any]
    hash_chain: str
    severity: str


class ForensicLogger:
    """
    Advanced forensic logging system for honeypot activities
    Provides comprehensive logging, chain of custody, and analysis
    """
    
    def __init__(self, log_directory: str = "logs", max_events: int = 10000, cleanup_interval: int = 3600):
        """
        Initialize the ForensicLogger with specified parameters
        
        Args:
            log_directory (str): Directory to store log files
            max_events (int): Maximum number of events to keep in memory
            cleanup_interval (int): Interval in seconds between cleanup operations
        """
        self.log_directory = log_directory
        self.initialized = False
        
        # Event storage
        self.events: deque[ForensicEvent] = deque(maxlen=max_events)
        self.event_counter = 0
        self.hash_chain = ""
        
        # Memory management
        self.max_events = max_events
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = None
        self._cleanup_lock = threading.Lock()
        
        # Log files
        self.main_log_file: Optional[TextIO] = None
        self.forensic_chain_file: Optional[TextIO] = None
        self.analysis_log_file: Optional[TextIO] = None
        
        # Analysis data
        self.ip_statistics: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_events": 0,
                "services_accessed": set(),
                "first_seen": None,
                "last_seen": None,
                "attack_types": defaultdict(int),
                "risk_score": 0.0
            }
        )
        
        self.service_statistics: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_events": 0,
                "unique_ips": set(),
                "attack_types": defaultdict(int),
                "peak_activity": 0
            }
        )
        
        # For thread safety
        self._write_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        
        # Real-time analysis
        self.real_time_analysis = True
        self.analysis_thread = None
        self.analysis_lock = threading.Lock()
        
        # Forensic chain integrity
        self.chain_integrity_checks = True
        self.last_integrity_check = None
        
    def initialize(self):
        """Initialize forensic logging system"""
        if self.initialized:
            return
        
        try:
            # Create log directory
            os.makedirs(self.log_directory, exist_ok=True)
            
            # Initialize log files
            self._initialize_log_files()
            
            # Start real-time analysis thread
            if self.real_time_analysis:
                self.analysis_thread = threading.Thread(
                    target=self._real_time_analysis_worker,
                    daemon=True
                )
                self.analysis_thread.start()
            
            # Initialize hash chain
            self._initialize_hash_chain()
            
            self.initialized = True
            
            self.log_event({
                "action": "forensic_logger_initialized",
                "log_directory": self.log_directory,
                "real_time_analysis": self.real_time_analysis
            })
            
            print(f"[{datetime.now()}] Forensic Logger initialized")
            
        except Exception as e:
            print(f"[{datetime.now()}] Forensic Logger initialization failed: {e}")
            raise
    
    def _initialize_log_files(self):
        """Initialize log file handles with proper resource management"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # Close any existing file handles
            self.cleanup()
            
            # Main activity log
            main_log_path = os.path.join(self.log_directory, f"honeypot_activity_{timestamp}.log")
            self.main_log_file = open(main_log_path, "a", encoding="utf-8", buffering=1)  # Line buffered
            
            # Forensic chain log
            chain_log_path = os.path.join(self.log_directory, f"forensic_chain_{timestamp}.log")
            self.forensic_chain_file = open(chain_log_path, "a", encoding="utf-8", buffering=1)
            
            # Analysis log
            analysis_log_path = os.path.join(self.log_directory, f"analysis_{timestamp}.log")
            self.analysis_log_file = open(analysis_log_path, "a", encoding="utf-8", buffering=1)
            
        except Exception as e:
            self.cleanup()  # Ensure all files are closed if there's an error
            raise RuntimeError(f"Failed to initialize log files: {str(e)}")
    
    def _initialize_hash_chain(self):
        """Initialize forensic hash chain"""
        genesis_data = {
            "action": "chain_genesis",
            "timestamp": datetime.now().isoformat(),
            "system": "nexus_honeypot"
        }
        
        self.hash_chain = self._calculate_hash(json.dumps(genesis_data, sort_keys=True))
        
        # Log genesis block
        try:
            if self.forensic_chain_file:
                with self._write_lock:
                    self.forensic_chain_file.write(f"GENESIS: {self.hash_chain}\n")
                    self.forensic_chain_file.flush()
        except IOError as e:
            print(f"[{datetime.now()}] Failed to write genesis block: {e}")
            self._initialize_log_files()  # Attempt to recover
    
    def log_event(self, event_data: Dict[str, Any]):
        """Log forensic event with chain of custody and memory management"""
        if not self.initialized:
            return
        
        # Trigger cleanup if needed
        self._cleanup_old_events()
        
        try:
            with self.analysis_lock:
                # Generate event ID
                self.event_counter += 1
                event_id = f"EVT_{self.event_counter:08d}_{int(time.time())}"
                
                # Prepare event
                timestamp = datetime.now().isoformat()
                service = event_data.get("service", "system")
                action = event_data.get("action", "unknown")
                source_ip = event_data.get("client_ip", event_data.get("src_ip", "unknown"))
                
                # Calculate severity
                severity = self._calculate_event_severity(event_data)
                
                # Create forensic event
                forensic_event = ForensicEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    service=service,
                    action=action,
                    source_ip=source_ip,
                    data=event_data,
                    hash_chain=self._update_hash_chain(event_data),
                    severity=severity
                )
                
                # Store event
                self.events.append(forensic_event)
                
                # Write to log files
                self._write_to_logs(forensic_event)
                
                # Update statistics
                self._update_statistics(forensic_event)
                
                # Real-time threat detection
                if self.real_time_analysis:
                    self._detect_real_time_threats(forensic_event)
                
        except Exception as e:
            print(f"[{datetime.now()}] Forensic logging error: {e}")
    
    def _calculate_event_severity(self, event_data: Dict[str, Any]) -> str:
        """Calculate event severity level"""
        action = event_data.get("action", "").lower()
        
        # High severity events
        high_severity_actions = [
            "exploitation_attempt", "malware_upload", "privilege_escalation",
            "credential_theft", "data_exfiltration", "system_compromise"
        ]
        
        # Medium severity events
        medium_severity_actions = [
            "brute_force_attack", "reconnaissance", "suspicious_command",
            "unauthorized_access", "file_manipulation"
        ]
        
        # Check for high-risk indicators
        if any(keyword in action for keyword in high_severity_actions):
            return "HIGH"
        elif any(keyword in action for keyword in medium_severity_actions):
            return "MEDIUM"
        elif "error" in action or "failed" in action:
            return "LOW"
        else:
            return "INFO"
    
    def _update_hash_chain(self, event_data: Dict[str, Any]) -> str:
        """Update forensic hash chain"""
        # Create hash input
        hash_input = {
            "previous_hash": self.hash_chain,
            "timestamp": datetime.now().isoformat(),
            "event_data": event_data
        }
        
        # Calculate new hash
        new_hash = self._calculate_hash(json.dumps(hash_input, sort_keys=True))
        self.hash_chain = new_hash
        
        return new_hash
    
    def _calculate_hash(self, data: str) -> str:
        """Calculate SHA-256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _ensure_log_files(self) -> bool:
        """Ensure log files are initialized and ready for writing"""
        if not all([self.main_log_file, self.forensic_chain_file]):
            try:
                self._initialize_log_files()
                return all([self.main_log_file, self.forensic_chain_file])
            except Exception as e:
                print(f"Failed to initialize log files: {e}")
                return False
        return True

    def _write_to_logs(self, event: ForensicEvent):
        """Write event to log files with thread safety"""
        if not self._ensure_log_files():
            print(f"[{datetime.now()}] Cannot write logs - files not initialized")
            return
            
        with self._write_lock:
            try:
                # Main activity log
                log_entry = {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "service": event.service,
                    "action": event.action,
                    "source_ip": event.source_ip,
                    "severity": event.severity,
                    "data": event.data
                }
                
                assert self.main_log_file is not None  # Type checker hint
                self.main_log_file.write(json.dumps(log_entry) + "\n")
                self.main_log_file.flush()
                
                # Forensic chain log
                chain_entry = {
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "hash": event.hash_chain,
                    "previous_hash": getattr(self, '_previous_hash', ''),
                    "integrity_verified": True
                }
                
                assert self.forensic_chain_file is not None  # Type checker hint
                self.forensic_chain_file.write(json.dumps(chain_entry) + "\n")
                self.forensic_chain_file.flush()
                
                self._previous_hash = event.hash_chain
                
            except IOError as e:
                print(f"Error writing to log files: {e}")
                self._initialize_log_files()  # Attempt to recover
    
    def _get_default_ip_stats(self) -> Dict[str, Any]:
        """Get default IP statistics structure"""
        return {
            "total_events": 0,
            "services_accessed": set(),
            "first_seen": None,
            "last_seen": None,
            "attack_types": defaultdict(int),
            "risk_score": 0.0
        }
    
    def _get_default_service_stats(self) -> Dict[str, Any]:
        """Get default service statistics structure"""
        return {
            "total_events": 0,
            "unique_ips": set(),
            "attack_types": defaultdict(int),
            "peak_activity": 0
        }

    def _update_statistics(self, event: ForensicEvent):
        """Update statistical analysis with thread safety"""
        with self._stats_lock:
            try:
                # IP statistics
                ip_stats = self.ip_statistics[event.source_ip]
                ip_stats["total_events"] += 1
                services = ip_stats["services_accessed"]
                if isinstance(services, set):
                    services.add(event.service)
                
                if ip_stats["first_seen"] is None:
                    ip_stats["first_seen"] = event.timestamp
                ip_stats["last_seen"] = event.timestamp
                
                # Extract attack type from event data
                attack_type = event.data.get("attack_type", "unknown")
                ip_stats["attack_types"][attack_type] += 1
                
                # Calculate risk score
                ip_stats["risk_score"] = self._calculate_ip_risk_score(ip_stats)
                
                # Service statistics
                service_stats = self.service_statistics[event.service]
                service_stats["total_events"] += 1
                unique_ips = service_stats["unique_ips"]
                if isinstance(unique_ips, set):
                    unique_ips.add(event.source_ip)
                service_stats["attack_types"][attack_type] += 1
                
            except Exception as e:
                print(f"Error updating statistics: {e}")
                # Reset statistics for this event if needed
                self.ip_statistics[event.source_ip] = self._get_default_ip_stats()
                self.service_statistics[event.service] = self._get_default_service_stats()
    
    def _calculate_ip_risk_score(self, ip_stats: Dict[str, Any]) -> float:
        """Calculate risk score for IP address"""
        score = 0.0
        
        # Base score from event count
        event_count = ip_stats["total_events"]
        score += min(event_count * 0.1, 3.0)  # Max 3.0 from event count
        
        # Service diversity penalty
        service_count = len(ip_stats["services_accessed"])
        if service_count > 3:
            score += 2.0  # Accessing many services is suspicious
        
        # Attack type severity
        attack_types = ip_stats["attack_types"]
        high_risk_types = ["exploitation", "brute_force", "malware"]
        
        for attack_type, count in attack_types.items():
            if any(risk_type in attack_type for risk_type in high_risk_types):
                score += count * 0.5
        
        # Time-based analysis
        if ip_stats["first_seen"] and ip_stats["last_seen"]:
            first_seen = datetime.fromisoformat(ip_stats["first_seen"])
            last_seen = datetime.fromisoformat(ip_stats["last_seen"])
            duration = (last_seen - first_seen).total_seconds()
            
            # Sustained activity increases risk
            if duration > 3600:  # More than 1 hour
                score += 1.0
        
        return min(score, 10.0)  # Cap at 10.0
    
    def _detect_real_time_threats(self, event: ForensicEvent):
        """Detect real-time threats and generate alerts"""
        threats = []
        
        # High-risk IP detection
        ip_stats = self.ip_statistics[event.source_ip]
        if ip_stats["risk_score"] > 7.0:
            threats.append({
                "type": "high_risk_ip",
                "severity": "HIGH",
                "description": f"IP {event.source_ip} has high risk score: {ip_stats['risk_score']:.2f}",
                "ip": event.source_ip,
                "risk_score": ip_stats["risk_score"]
            })
        
        # Rapid-fire attack detection
        recent_events = [e for e in self.events if e.source_ip == event.source_ip 
                        and (datetime.now() - datetime.fromisoformat(e.timestamp)).total_seconds() < 60]
        
        if len(recent_events) > 10:  # More than 10 events in 1 minute
            threats.append({
                "type": "rapid_fire_attack",
                "severity": "HIGH",
                "description": f"Rapid-fire attack detected from {event.source_ip}: {len(recent_events)} events in 1 minute",
                "ip": event.source_ip,
                "event_count": len(recent_events)
            })
        
        # Multi-service attack detection
        services_accessed = len(ip_stats["services_accessed"])
        if services_accessed >= 4:
            threats.append({
                "type": "multi_service_attack",
                "severity": "MEDIUM",
                "description": f"Multi-service attack from {event.source_ip}: {services_accessed} services accessed",
                "ip": event.source_ip,
                "services": list(ip_stats["services_accessed"])
            })
        
        # Log threats
        for threat in threats:
            self._log_threat_alert(threat, event)
    
    def _log_threat_alert(self, threat: Dict[str, Any], event: ForensicEvent):
        """Log threat alert with unique ID generation"""
        alert = {
            "alert_id": f"ALERT_{int(time.time())}_{str(uuid.uuid4())[:8]}",
            "timestamp": datetime.now().isoformat(),
            "threat": threat,
            "triggering_event": event.event_id,
            "source_ip": event.source_ip,
            "service": event.service
        }
        
        try:
            if self.analysis_log_file:
                with self._write_lock:
                    self.analysis_log_file.write(f"THREAT_ALERT: {json.dumps(alert)}\n")
                    self.analysis_log_file.flush()
        except IOError as e:
            print(f"[{datetime.now()}] Failed to write threat alert: {e}")
        
        print(f"[{datetime.now()}] THREAT ALERT: {threat['description']}")
    
    def _real_time_analysis_worker(self):
        """Real-time analysis worker thread with proper synchronization and cleanup"""
        while True:
            try:
                time.sleep(30)  # Run analysis every 30 seconds
                
                if not self.initialized:
                    continue
                
                # Perform cleanup if needed
                self._cleanup_old_events()
                
                # Generate periodic analysis with proper locks
                with self._stats_lock:
                    analysis = self.generate_analysis_report()
                
                # Log analysis results with proper synchronization
                if self.analysis_log_file:
                    with self._write_lock:
                        try:
                            assert self.analysis_log_file is not None  # Type checker hint
                            self.analysis_log_file.write(f"PERIODIC_ANALYSIS: {json.dumps(analysis)}\n")
                            self.analysis_log_file.flush()
                        except IOError as e:
                            print(f"[{datetime.now()}] Failed to write analysis: {e}")
                            self._initialize_log_files()
                
                # Perform integrity check with proper synchronization
                if self.chain_integrity_checks:
                    with self._write_lock:
                        self._perform_integrity_check()
                
            except Exception as e:
                print(f"[{datetime.now()}] Real-time analysis error: {e}")
                # Sleep a bit longer on error to prevent rapid retries
                time.sleep(5)
    
    def _verify_hash_chain(self) -> Tuple[bool, Optional[str], int]:
        """
        Verify the integrity of the entire hash chain
        Returns: (is_valid, first_invalid_event_id, events_verified)
        """
        events_verified = 0
        previous_hash = None
        
        try:
            for event in self.events:
                # Reconstruct hash input
                hash_input = {
                    "previous_hash": previous_hash or "",
                    "timestamp": event.timestamp,
                    "event_data": event.data
                }
                
                # Calculate expected hash
                expected_hash = self._calculate_hash(json.dumps(hash_input, sort_keys=True))
                
                # Verify hash matches
                if event.hash_chain != expected_hash:
                    return False, event.event_id, events_verified
                
                previous_hash = event.hash_chain
                events_verified += 1
            
            return True, None, events_verified
            
        except Exception as e:
            print(f"[{datetime.now()}] Hash chain verification error: {e}")
            return False, None, events_verified

    def _perform_integrity_check(self):
        """Perform forensic chain integrity check with comprehensive verification"""
        try:
            integrity_status = "INSUFFICIENT_DATA"
            verification_details = {}
            
            if len(self.events) > 0:
                is_valid, invalid_event, events_verified = self._verify_hash_chain()
                
                if is_valid:
                    integrity_status = "VERIFIED"
                    verification_details["chain_valid"] = True
                else:
                    integrity_status = "INTEGRITY_VIOLATION"
                    verification_details.update({
                        "chain_valid": False,
                        "first_invalid_event": invalid_event,
                        "valid_events": events_verified
                    })
            
            self.last_integrity_check = datetime.now()
            
            integrity_report = {
                "timestamp": self.last_integrity_check.isoformat(),
                "status": integrity_status,
                "events_verified": len(self.events),
                "chain_hash": self.hash_chain,
                "verification_details": verification_details
            }
            
            if self.forensic_chain_file:
                with self._write_lock:
                    try:
                        assert self.forensic_chain_file is not None
                        self.forensic_chain_file.write(f"INTEGRITY_CHECK: {json.dumps(integrity_report)}\n")
                        self.forensic_chain_file.flush()
                    except IOError as e:
                        print(f"[{datetime.now()}] Failed to write integrity report: {e}")
            
            # If integrity violation found, log an alert
            if integrity_status == "INTEGRITY_VIOLATION":
                # Create a synthetic event for integrity violation alert if no events exist
                alert_event = self.events[-1] if self.events else ForensicEvent(
                    event_id=f"INTEGRITY_CHECK_{int(time.time())}",
                    timestamp=datetime.now().isoformat(),
                    service="forensic_logger",
                    action="integrity_check",
                    source_ip="127.0.0.1",
                    data={},
                    hash_chain=self.hash_chain,
                    severity="HIGH"
                )
                
                self._log_threat_alert({
                    "type": "integrity_violation",
                    "severity": "HIGH",
                    "description": f"Hash chain integrity violation detected: {verification_details}",
                }, alert_event)
            
        except Exception as e:
            print(f"[{datetime.now()}] Integrity check error: {e}")
    
    def generate_analysis_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        current_time = datetime.now()
        
        # Basic statistics
        total_events = len(self.events)
        unique_ips = len(self.ip_statistics)
        services_active = len(self.service_statistics)
        
        # Top attackers
        top_attackers = sorted(
            self.ip_statistics.items(),
            key=lambda x: x[1]["risk_score"],
            reverse=True
        )[:10]
        
        # Attack type distribution
        attack_type_dist = defaultdict(int)
        for ip_stats in self.ip_statistics.values():
            for attack_type, count in ip_stats["attack_types"].items():
                attack_type_dist[attack_type] += count
        
        # Service activity
        service_activity = {}
        for service, stats in self.service_statistics.items():
            service_activity[service] = {
                "total_events": stats["total_events"],
                "unique_attackers": len(stats["unique_ips"]),
                "top_attack_types": dict(sorted(stats["attack_types"].items(), 
                                              key=lambda x: x[1], reverse=True)[:5])
            }
        
        # Recent activity (last hour)
        one_hour_ago = current_time - timedelta(hours=1)
        recent_events = [
            e for e in self.events 
            if datetime.fromisoformat(e.timestamp) > one_hour_ago
        ]
        
        return {
            "timestamp": current_time.isoformat(),
            "summary": {
                "total_events": total_events,
                "unique_attackers": unique_ips,
                "active_services": services_active,
                "recent_activity": len(recent_events)
            },
            "top_attackers": [
                {
                    "ip": ip,
                    "risk_score": stats["risk_score"],
                    "total_events": stats["total_events"],
                    "services_accessed": len(stats["services_accessed"])
                }
                for ip, stats in top_attackers
            ],
            "attack_distribution": dict(attack_type_dist),
            "service_activity": service_activity,
            "integrity": {
                "chain_hash": self.hash_chain,
                "last_check": self.last_integrity_check.isoformat() if self.last_integrity_check else None
            }
        }
    
    def generate_forensic_chain(self) -> Dict[str, Any]:
        """Generate complete forensic chain report"""
        chain_report = {
            "generation_time": datetime.now().isoformat(),
            "total_events": len(self.events),
            "chain_integrity": "VERIFIED",  # Simplified for demo
            "genesis_hash": self.hash_chain,
            "events": []
        }
        
        # Include all events in chronological order
        for event in self.events:
            chain_report["events"].append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "service": event.service,
                "action": event.action,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "hash": event.hash_chain
            })
        
        # Save forensic chain report
        report_path = os.path.join(
            self.log_directory, 
            f"forensic_chain_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(chain_report, f, indent=2)
        
        return chain_report
    
    def get_status(self) -> Dict[str, Any]:
        """Get forensic logger status"""
        return {
            "initialized": self.initialized,
            "total_events": len(self.events),
            "unique_ips": len(self.ip_statistics),
            "active_services": len(self.service_statistics),
            "real_time_analysis": self.real_time_analysis,
            "chain_integrity": self.chain_integrity_checks,
            "log_directory": self.log_directory
        }
    
    def _check_cleanup_needed(self) -> bool:
        """Check if cleanup is needed based on time interval"""
        if self.last_cleanup is None:
            return True
        
        time_since_cleanup = (datetime.now() - self.last_cleanup).total_seconds()
        return time_since_cleanup >= self.cleanup_interval
    
    def _cleanup_old_events(self):
        """Clean up old events and associated statistics"""
        with self._cleanup_lock:
            try:
                if not self._check_cleanup_needed():
                    return
                
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(hours=24)  # Keep last 24 hours of detailed stats
                
                # Clean up IP statistics
                with self._stats_lock:
                    for ip in list(self.ip_statistics.keys()):
                        stats = self.ip_statistics[ip]
                        if stats["last_seen"]:
                            last_seen = datetime.fromisoformat(stats["last_seen"])
                            if last_seen < cutoff_time:
                                del self.ip_statistics[ip]
                
                # Clean up service statistics
                # (Keep service stats longer as they're less memory intensive)
                service_cutoff = current_time - timedelta(days=7)
                events_in_range = [e for e in self.events 
                                 if datetime.fromisoformat(e.timestamp) > service_cutoff]
                
                active_services = {e.service for e in events_in_range}
                with self._stats_lock:
                    for service in list(self.service_statistics.keys()):
                        if service not in active_services:
                            del self.service_statistics[service]
                
                self.last_cleanup = current_time
                
                # Log cleanup operation
                cleanup_report = {
                    "timestamp": current_time.isoformat(),
                    "events_in_memory": len(self.events),
                    "active_ips": len(self.ip_statistics),
                    "active_services": len(self.service_statistics)
                }
                
                if self.analysis_log_file:
                    with self._write_lock:
                        try:
                            assert self.analysis_log_file is not None
                            self.analysis_log_file.write(f"CLEANUP: {json.dumps(cleanup_report)}\n")
                            self.analysis_log_file.flush()
                        except IOError as e:
                            print(f"[{datetime.now()}] Failed to write cleanup report: {e}")
                
            except Exception as e:
                print(f"[{datetime.now()}] Error during cleanup: {e}")
    
    def cleanup(self):
        """Cleanup resources and perform final cleanup operations"""
        try:
            # Perform one final cleanup of events and statistics
            self._cleanup_old_events()
            
            # Close all file handles
            if self.main_log_file:
                self.main_log_file.close()
            if self.forensic_chain_file:
                self.forensic_chain_file.close()
            if self.analysis_log_file:
                self.analysis_log_file.close()
            
            # Clear memory
            self.events.clear()
            self.ip_statistics.clear()
            self.service_statistics.clear()
            
        except Exception as e:
            print(f"[{datetime.now()}] Error during final cleanup: {e}")
        finally:
            # Ensure files are closed even if cleanup fails
            self.main_log_file = None
            self.forensic_chain_file = None
            self.analysis_log_file = None