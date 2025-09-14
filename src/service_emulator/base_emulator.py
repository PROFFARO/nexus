"""
Base Service Emulator - Common functionality for all service emulators
"""

import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod


class BaseServiceEmulator(ABC):
    """
    Base class for all service emulators in the honeypot system
    Provides common functionality and AI integration interface
    """
    
    def __init__(self, service_name: str, port: int, 
                 ai_coordinator=None, forensic_logger=None, 
                 adaptive_responses: bool = True, **kwargs):
        
        self.service_name = service_name
        self.port = port
        self.bind_ip = kwargs.get("bind_ip", "0.0.0.0")
        
        # AI and logging components
        self.ai_coordinator = ai_coordinator
        self.forensic_logger = forensic_logger
        self.adaptive_responses = adaptive_responses
        
        # Service state
        self.running = False
        self.server_socket = None
        self.start_time = None
        
        # Statistics
        self.connection_count = 0
        self.total_interactions = 0
        self.blocked_ips = set()
        
        # Configuration
        self.config = kwargs.get("config", {})
        self.max_connections = kwargs.get("max_connections", 100)
        self.connection_timeout = kwargs.get("connection_timeout", 300)  # 5 minutes
        
    @abstractmethod
    def start_service(self):
        """Start the service emulator - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    def _handle_client_connection(self, client_socket: socket.socket, client_address: tuple):
        """Handle individual client connection - must be implemented by subclasses"""
        pass
    
    def start(self):
        """Start the service emulator"""
        if self.running:
            return
        
        self.running = True
        self.start_time = datetime.now()
        
        # Start service in separate thread
        service_thread = threading.Thread(target=self.start_service, daemon=True)
        service_thread.start()
        
        self.log_event({
            "action": "service_started",
            "service": self.service_name,
            "port": self.port,
            "timestamp": self.start_time.isoformat()
        })
    
    def stop(self):
        """Stop the service emulator"""
        self.stop_service()
    
    def stop_service(self):
        """Stop the service emulator"""
        if not self.running:
            return
        
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        self.log_event({
            "action": "service_stopped",
            "service": self.service_name,
            "uptime": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            "total_connections": self.connection_count,
            "total_interactions": self.total_interactions
        })
    
    def log_event(self, event_data: Dict[str, Any]):
        """Log event using forensic logger"""
        event_data.update({
            "service": self.service_name,
            "timestamp": datetime.now().isoformat()
        })
        
        if self.forensic_logger:
            self.forensic_logger.log_event(event_data)
        else:
            # Fallback logging
            print(f"[{event_data['timestamp']}] {self.service_name}: {event_data}")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP address is blocked"""
        return ip in self.blocked_ips
    
    def block_ip(self, ip: str, reason: str = "suspicious_activity"):
        """Block IP address"""
        self.blocked_ips.add(ip)
        self.log_event({
            "action": "ip_blocked",
            "ip": ip,
            "reason": reason
        })
    
    def unblock_ip(self, ip: str):
        """Unblock IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.log_event({
                "action": "ip_unblocked",
                "ip": ip
            })
    
    def update_policy(self, policy_updates: Dict[str, Any]):
        """Update adaptive policies"""
        self.config.update(policy_updates)
        
        self.log_event({
            "action": "policy_updated",
            "updates": policy_updates
        })
        
        # Notify AI coordinator of policy changes
        if self.ai_coordinator:
            self.ai_coordinator.update_adaptive_policy(self.service_name, policy_updates)
    
    def is_healthy(self) -> bool:
        """Check if service is healthy"""
        return self.running and self.server_socket is not None
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            "service": self.service_name,
            "port": self.port,
            "running": self.running,
            "uptime": uptime,
            "connection_count": self.connection_count,
            "total_interactions": self.total_interactions,
            "blocked_ips": len(self.blocked_ips),
            "ai_enabled": self.ai_coordinator is not None,
            "adaptive_responses": self.adaptive_responses
        }
    
    def process_with_ai(self, interaction_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process interaction using AI coordinator"""
        if not self.ai_coordinator:
            return {"ai_processed": False, "fallback": True}
        
        try:
            ai_response = self.ai_coordinator.process_interaction(
                service=self.service_name,
                attacker_ip=data.get("client_ip", "unknown"),
                command=data.get("command", ""),
                context=data
            )
            
            self.total_interactions += 1
            return ai_response
            
        except Exception as e:
            self.log_event({
                "action": "ai_processing_error",
                "error": str(e),
                "interaction_type": interaction_type
            })
            return {"ai_processed": False, "error": str(e)}
    
    def validate_client_connection(self, client_address: tuple) -> bool:
        """Validate if client connection should be accepted"""
        client_ip = client_address[0]
        
        # Check if IP is blocked
        if self.is_ip_blocked(client_ip):
            self.log_event({
                "action": "connection_blocked",
                "client_ip": client_ip,
                "reason": "ip_blocked"
            })
            return False
        
        # Check connection limits
        if self.connection_count >= self.max_connections:
            self.log_event({
                "action": "connection_rejected",
                "client_ip": client_ip,
                "reason": "max_connections_reached"
            })
            return False
        
        return True
    
    def handle_client_connection(self, client_socket: socket.socket, client_address: tuple):
        """Handle client connection with common preprocessing"""
        client_ip, client_port = client_address
        
        # Validate connection
        if not self.validate_client_connection(client_address):
            try:
                client_socket.close()
            except:
                pass
            return
        
        self.connection_count += 1
        
        try:
            # Set socket timeout
            client_socket.settimeout(self.connection_timeout)
            
            # Log connection
            self.log_event({
                "action": "connection_accepted",
                "client_ip": client_ip,
                "client_port": client_port
            })
            
            # Handle service-specific connection
            self._handle_client_connection(client_socket, client_address)
            
        except Exception as e:
            self.log_event({
                "action": "connection_error",
                "client_ip": client_ip,
                "error": str(e)
            })
        finally:
            self.connection_count -= 1
            try:
                client_socket.close()
            except:
                pass
    
    def create_realistic_delay(self, base_delay: float = 0.5, 
                             command_complexity: float = 1.0) -> float:
        """Create realistic response delay"""
        import random
        
        # Base delay with some randomness
        delay = base_delay * random.uniform(0.7, 1.3)
        
        # Adjust for command complexity
        delay *= command_complexity
        
        # Add system load simulation
        system_load = random.uniform(0.8, 1.2)
        delay *= system_load
        
        return max(0.1, min(delay, 10.0))  # Clamp between 0.1 and 10 seconds
    
    def simulate_system_resources(self) -> Dict[str, float]:
        """Simulate realistic system resource usage"""
        import random
        
        return {
            "cpu_usage": random.uniform(5.0, 30.0),
            "memory_usage": random.uniform(20.0, 80.0),
            "disk_io": random.uniform(0.1, 10.0),
            "network_io": random.uniform(0.5, 15.0),
            "load_average": random.uniform(0.1, 2.0)
        }
    
    def __str__(self):
        return f"{self.service_name}:{self.port}"
    
    def __repr__(self):
        return f"<{self.__class__.__name__}(service='{self.service_name}', port={self.port}, running={self.running})>"