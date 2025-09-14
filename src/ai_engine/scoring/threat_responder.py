"""
Threat Response Actions - Manages automated responses to detected threats
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import json
import logging

class ActionType(Enum):
    """Types of response actions available"""
    ALERT = "alert"              # Send alerts/notifications
    BLOCK = "block"              # Block IP/user/session
    RESTRICT = "restrict"        # Restrict access/capabilities
    MONITOR = "monitor"          # Enhanced monitoring
    DISCONNECT = "disconnect"    # Force disconnect
    LOG = "log"                  # Enhanced logging
    INVESTIGATE = "investigate"  # Trigger investigation

@dataclass
class ActionConfig:
    """Configuration for a response action"""
    action_type: ActionType
    threshold: float             # Score threshold to trigger
    confidence_required: float   # Minimum confidence required
    cooldown: int               # Cooldown period in seconds
    conditions: Dict[str, Any]   # Additional conditions

@dataclass
class ActionResult:
    """Result of an executed action"""
    action_type: ActionType
    success: bool
    timestamp: datetime
    details: Dict[str, Any]
    error: Optional[str] = None

class ThreatResponder:
    """
    Manages and executes threat response actions based on threat scores
    """
    
    def __init__(self):
        self.logger = logging.getLogger("threat_responder")
        
        # Action configurations
        self.action_configs: Dict[str, ActionConfig] = {}
        
        # Action history
        self.action_history: Dict[str, List[ActionResult]] = {}
        
        # Action handlers
        self.action_handlers: Dict[ActionType, Callable] = {
            ActionType.ALERT: self._handle_alert,
            ActionType.BLOCK: self._handle_block,
            ActionType.RESTRICT: self._handle_restrict,
            ActionType.MONITOR: self._handle_monitor,
            ActionType.DISCONNECT: self._handle_disconnect,
            ActionType.LOG: self._handle_log,
            ActionType.INVESTIGATE: self._handle_investigate
        }
        
        # Load default configurations
        self._load_default_configs()
    
    def _load_default_configs(self):
        """Load default action configurations"""
        default_configs = {
            "critical_alert": ActionConfig(
                action_type=ActionType.ALERT,
                threshold=0.9,
                confidence_required=0.7,
                cooldown=300,  # 5 minutes
                conditions={
                    "min_impact_score": 0.8,
                    "requires_progression": True
                }
            ),
            "high_block": ActionConfig(
                action_type=ActionType.BLOCK,
                threshold=0.8,
                confidence_required=0.85,
                cooldown=600,  # 10 minutes
                conditions={
                    "min_base_score": 0.7,
                    "min_temporal_score": 0.6
                }
            ),
            "medium_restrict": ActionConfig(
                action_type=ActionType.RESTRICT,
                threshold=0.6,
                confidence_required=0.6,
                cooldown=300,
                conditions={
                    "min_risk_score": 0.5
                }
            ),
            "enhanced_monitoring": ActionConfig(
                action_type=ActionType.MONITOR,
                threshold=0.5,
                confidence_required=0.4,
                cooldown=900,  # 15 minutes
                conditions={
                    "anomaly_score_threshold": 0.6
                }
            ),
            "forced_disconnect": ActionConfig(
                action_type=ActionType.DISCONNECT,
                threshold=0.95,
                confidence_required=0.9,
                cooldown=60,  # 1 minute
                conditions={
                    "requires_critical": True,
                    "min_impact_score": 0.9
                }
            )
        }
        
        self.action_configs.update(default_configs)
    
    def evaluate_actions(self, threat_data: Dict[str, Any], 
                        context: Dict[str, Any]) -> List[ActionResult]:
        """
        Evaluate and execute appropriate actions based on threat data
        
        Args:
            threat_data: Complete threat analysis data including scores
            context: Additional context about the threat/session
        """
        results = []
        current_time = datetime.now()
        
        # Check each action configuration
        for action_name, config in self.action_configs.items():
            # Skip if in cooldown
            if not self._check_cooldown(action_name, config, current_time):
                continue
            
            # Check if action should be triggered
            if self._should_trigger_action(config, threat_data, context):
                # Execute action
                result = self._execute_action(config, threat_data, context)
                results.append(result)
                
                # Record action
                self._record_action(action_name, result)
        
        return results
    
    def _check_cooldown(self, action_name: str, config: ActionConfig, 
                       current_time: datetime) -> bool:
        """Check if action is in cooldown period"""
        if action_name in self.action_history and self.action_history[action_name]:
            last_action = self.action_history[action_name][-1]
            time_diff = (current_time - last_action.timestamp).total_seconds()
            return time_diff > config.cooldown
        return True
    
    def _should_trigger_action(self, config: ActionConfig, 
                             threat_data: Dict[str, Any],
                             context: Dict[str, Any]) -> bool:
        """Determine if an action should be triggered"""
        # Check base requirements
        if threat_data["threat_score"]["total_score"] < config.threshold:
            return False
        
        if threat_data["threat_score"]["confidence"] < config.confidence_required:
            return False
        
        # Check additional conditions
        conditions_met = True
        
        for condition, value in config.conditions.items():
            if condition == "min_impact_score":
                if threat_data["threat_score"]["impact_score"] < value:
                    conditions_met = False
            elif condition == "requires_progression":
                if not threat_data.get("progression", {}).get("trend") == "escalating":
                    conditions_met = False
            elif condition == "min_base_score":
                if threat_data["threat_score"]["base_score"] < value:
                    conditions_met = False
            elif condition == "min_temporal_score":
                if threat_data["threat_score"]["temporal_score"] < value:
                    conditions_met = False
            elif condition == "min_risk_score":
                if threat_data.get("risk_score", 0) < value:
                    conditions_met = False
            elif condition == "anomaly_score_threshold":
                if threat_data.get("anomaly_score", 0) < value:
                    conditions_met = False
            elif condition == "requires_critical":
                if threat_data["threat_score"]["threat_level"] != "CRITICAL":
                    conditions_met = False
        
        return conditions_met
    
    def _execute_action(self, config: ActionConfig, 
                       threat_data: Dict[str, Any],
                       context: Dict[str, Any]) -> ActionResult:
        """Execute the specified action"""
        handler = self.action_handlers.get(config.action_type)
        if not handler:
            return ActionResult(
                action_type=config.action_type,
                success=False,
                timestamp=datetime.now(),
                details={},
                error=f"No handler for action type {config.action_type}"
            )
        
        try:
            result = handler(threat_data, context)
            return ActionResult(
                action_type=config.action_type,
                success=True,
                timestamp=datetime.now(),
                details=result
            )
        except Exception as e:
            return ActionResult(
                action_type=config.action_type,
                success=False,
                timestamp=datetime.now(),
                details={},
                error=str(e)
            )
    
    def _record_action(self, action_name: str, result: ActionResult):
        """Record an executed action in history"""
        if action_name not in self.action_history:
            self.action_history[action_name] = []
        
        self.action_history[action_name].append(result)
        
        # Trim history if needed
        if len(self.action_history[action_name]) > 1000:
            self.action_history[action_name] = self.action_history[action_name][-1000:]
        
        # Log the action
        self._log_action(action_name, result)
    
    def _log_action(self, action_name: str, result: ActionResult):
        """Log action execution details"""
        log_data = {
            "timestamp": result.timestamp.isoformat(),
            "action_name": action_name,
            "action_type": result.action_type.value,
            "success": result.success,
            "details": result.details
        }
        
        if result.error:
            log_data["error"] = result.error
            self.logger.error(f"Action {action_name} failed: {json.dumps(log_data)}")
        else:
            self.logger.info(f"Action {action_name} executed: {json.dumps(log_data)}")
    
    # Action Handlers
    def _handle_alert(self, threat_data: Dict[str, Any], 
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle alert action"""
        alert_data = {
            "severity": threat_data["threat_score"]["threat_level"],
            "score": threat_data["threat_score"]["total_score"],
            "confidence": threat_data["threat_score"]["confidence"],
            "attack_type": threat_data.get("attack_type", "unknown"),
            "source": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "timestamp": datetime.now().isoformat()
        }
        
        # TODO: Integrate with alert system
        self.logger.warning(f"THREAT ALERT: {json.dumps(alert_data)}")
        
        return alert_data
    
    def _handle_block(self, threat_data: Dict[str, Any], 
                     context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle block action"""
        block_data = {
            "ip": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "duration": 3600,  # 1 hour default
            "reason": f"Threat score {threat_data['threat_score']['total_score']:.2f}"
        }
        
        # TODO: Integrate with firewall/blocking system
        self.logger.warning(f"BLOCKING SOURCE: {json.dumps(block_data)}")
        
        return block_data
    
    def _handle_restrict(self, threat_data: Dict[str, Any], 
                        context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle restrict action"""
        restrict_data = {
            "target": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "level": "limited",
            "duration": 1800  # 30 minutes default
        }
        
        # TODO: Integrate with access control system
        self.logger.warning(f"RESTRICTING ACCESS: {json.dumps(restrict_data)}")
        
        return restrict_data
    
    def _handle_monitor(self, threat_data: Dict[str, Any], 
                       context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle enhanced monitoring action"""
        monitor_data = {
            "target": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "level": "enhanced",
            "duration": 7200  # 2 hours default
        }
        
        # TODO: Integrate with monitoring system
        self.logger.info(f"ENHANCED MONITORING: {json.dumps(monitor_data)}")
        
        return monitor_data
    
    def _handle_disconnect(self, threat_data: Dict[str, Any], 
                         context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle forced disconnect action"""
        disconnect_data = {
            "target": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "session": context.get("session_id", "unknown"),
            "reason": "Critical threat detected"
        }
        
        # TODO: Integrate with service management system
        self.logger.warning(f"FORCING DISCONNECT: {json.dumps(disconnect_data)}")
        
        return disconnect_data
    
    def _handle_log(self, threat_data: Dict[str, Any], 
                   context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle enhanced logging action"""
        log_data = {
            "target": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "level": "detailed",
            "duration": 3600  # 1 hour default
        }
        
        # TODO: Integrate with logging system
        self.logger.info(f"ENHANCED LOGGING: {json.dumps(log_data)}")
        
        return log_data
    
    def _handle_investigate(self, threat_data: Dict[str, Any], 
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle investigation action"""
        investigate_data = {
            "target": context.get("source", "unknown"),
            "service": context.get("service", "unknown"),
            "priority": "high" if threat_data["threat_score"]["total_score"] > 0.8 else "medium",
            "attack_type": threat_data.get("attack_type", "unknown")
        }
        
        # TODO: Integrate with investigation system
        self.logger.info(f"INVESTIGATION TRIGGERED: {json.dumps(investigate_data)}")
        
        return investigate_data