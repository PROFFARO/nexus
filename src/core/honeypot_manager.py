"""
Honeypot Manager - Core orchestration component for AI-based adaptive honeypot system
"""

import threading
import time
import json
from datetime import datetime
from dataclasses import dataclass

from ai_engine.ai_coordinator import AICoordinator
from logger.forensic_logger import ForensicLogger
from container.docker_manager import DockerManager


@dataclass
class ServiceConfig:
    """Service configuration structure"""
    name: str
    port: int
    enabled: bool
    ai_enabled: bool
    adaptive_responses: bool


class HoneypotManager:
    """
    Core honeypot manager that orchestrates all service emulators,
    AI engine, logging, and containerization
    """
    
    def __init__(self, config_path: str = "config/honeypot.json"):
        self.config_path = config_path
        self.services = {}
        self.threads = {}
        self.running = False
        
        # Core components
        self.ai_coordinator = AICoordinator()
        self.forensic_logger = ForensicLogger()
        self.docker_manager = DockerManager()
        
        # Service configurations
        self.service_configs = {
            "ssh": ServiceConfig("ssh", 22, True, True, True),
            "ftp": ServiceConfig("ftp", 21, True, True, True),
            "smb": ServiceConfig("smb", 445, True, True, True),
            "rdp": ServiceConfig("rdp", 3389, True, True, True),
            "mysql": ServiceConfig("mysql", 3306, True, True, True)
        }
        
        self.load_configuration()
    
    def load_configuration(self):
        """Load honeypot configuration"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                self.update_service_configs(config)
        except FileNotFoundError:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        default_config = {
            "services": {
                "ssh": {"port": 22, "enabled": True, "ai_enabled": True},
                "ftp": {"port": 21, "enabled": True, "ai_enabled": True},
                "smb": {"port": 445, "enabled": True, "ai_enabled": True},
                "rdp": {"port": 3389, "enabled": True, "ai_enabled": True},
                "mysql": {"port": 3306, "enabled": True, "ai_enabled": True}
            },
            "ai_engine": {
                "model": "llama3-8b",
                "response_delay": {"min": 0.5, "max": 3.0},
                "adaptive_learning": True
            },
            "logging": {
                "level": "INFO",
                "forensic_chain": True,
                "real_time_analysis": True
            },
            "container": {
                "enabled": True,
                "isolation_level": "high"
            }
        }
        
        import os
        os.makedirs("config", exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
    
    def update_service_configs(self, config: dict):
        """Update service configurations from loaded config"""
        services_config = config.get("services", {})
        for service_name, service_config in services_config.items():
            if service_name in self.service_configs:
                self.service_configs[service_name].port = service_config.get("port", self.service_configs[service_name].port)
                self.service_configs[service_name].enabled = service_config.get("enabled", True)
                self.service_configs[service_name].ai_enabled = service_config.get("ai_enabled", True)
    
    def initialize_services(self):
        """Initialize all enabled service emulators"""
        from service_emulator.ssh_emulator import SSHEmulator
        from service_emulator.mysql_emulator import MySQLEmulator
        from service_emulator.base_emulator import BaseServiceEmulator
        
        # Create placeholder classes for services not yet implemented
        class FTPEmulator(BaseServiceEmulator):
            def __init__(self, *args, **kwargs):
                super().__init__("ftp", kwargs.get('port', 21), *args, **kwargs)
            def start_service(self): pass
            def _handle_client_connection(self, client_socket, client_address): pass
        
        class SMBEmulator(BaseServiceEmulator):
            def __init__(self, *args, **kwargs):
                super().__init__("smb", kwargs.get('port', 445), *args, **kwargs)
            def start_service(self): pass
            def _handle_client_connection(self, client_socket, client_address): pass
        
        class RDPEmulator(BaseServiceEmulator):
            def __init__(self, *args, **kwargs):
                super().__init__("rdp", kwargs.get('port', 3389), *args, **kwargs)
            def start_service(self): pass
            def _handle_client_connection(self, client_socket, client_address): pass
        
        service_classes = {
            "ssh": SSHEmulator,
            "ftp": FTPEmulator,
            "smb": SMBEmulator,
            "rdp": RDPEmulator,
            "mysql": MySQLEmulator
        }
        
        for service_name, config in self.service_configs.items():
            if config.enabled and service_name in service_classes:
                service_class = service_classes[service_name]
                
                # Initialize service with AI integration
                service_instance = service_class(
                    port=config.port,
                    ai_coordinator=self.ai_coordinator if config.ai_enabled else None,
                    forensic_logger=self.forensic_logger,
                    adaptive_responses=config.adaptive_responses
                )
                
                self.services[service_name] = service_instance
                
                self.forensic_logger.log_event({
                    "action": "service_initialized",
                    "service": service_name,
                    "port": config.port,
                    "ai_enabled": config.ai_enabled,
                    "timestamp": datetime.now().isoformat()
                })
    
    def start_service_threads(self):
        """Start all service emulators in separate threads"""
        for service_name, service in self.services.items():
            thread = threading.Thread(
                target=self._run_service,
                args=(service_name, service),
                daemon=True
            )
            thread.start()
            self.threads[service_name] = thread
            
            self.forensic_logger.log_event({
                "action": "service_started",
                "service": service_name,
                "thread_id": thread.ident,
                "timestamp": datetime.now().isoformat()
            })
    
    def _run_service(self, service_name: str, service):
        """Run individual service emulator"""
        try:
            service.start()
        except Exception as e:
            self.forensic_logger.log_event({
                "action": "service_error",
                "service": service_name,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
    
    def start_honeypot(self):
        """Start the complete honeypot system"""
        if self.running:
            return
        
        self.running = True
        
        # Initialize AI engine
        self.ai_coordinator.initialize()
        
        # Initialize forensic logging
        self.forensic_logger.initialize()
        
        # Initialize container environment
        if self.docker_manager.is_enabled():
            self.docker_manager.setup_containers()
        
        # Initialize and start services
        self.initialize_services()
        self.start_service_threads()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        monitor_thread.start()
        
        self.forensic_logger.log_event({
            "action": "honeypot_started",
            "services": list(self.services.keys()),
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"[{datetime.now()}] Nexus Honeypot System Started")
        print(f"Active Services: {', '.join(self.services.keys())}")
    
    def _monitor_system(self):
        """Monitor system health and performance"""
        while self.running:
            try:
                # Check service health
                for service_name, service in self.services.items():
                    if hasattr(service, 'is_healthy') and not service.is_healthy():
                        self.forensic_logger.log_event({
                            "action": "service_unhealthy",
                            "service": service_name,
                            "timestamp": datetime.now().isoformat()
                        })
                
                # Generate periodic reports
                self.ai_coordinator.generate_behavioral_analysis()
                
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                self.forensic_logger.log_event({
                    "action": "monitor_error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
    
    def stop_honeypot(self):
        """Stop the honeypot system gracefully"""
        if not self.running:
            return
        
        self.running = False
        
        # Stop all services
        for service_name, service in self.services.items():
            try:
                if hasattr(service, 'stop'):
                    service.stop()
            except Exception as e:
                self.forensic_logger.log_event({
                    "action": "service_stop_error",
                    "service": service_name,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
        
        # Generate final reports
        self.ai_coordinator.generate_final_report()
        self.forensic_logger.generate_forensic_chain()
        
        # Cleanup containers
        if self.docker_manager.is_enabled():
            self.docker_manager.cleanup_containers()
        
        self.forensic_logger.log_event({
            "action": "honeypot_stopped",
            "timestamp": datetime.now().isoformat()
        })
        
        print(f"[{datetime.now()}] Nexus Honeypot System Stopped")
    
    def get_system_status(self) -> dict:
        """Get current system status"""
        return {
            "running": self.running,
            "services": {
                name: {
                    "enabled": config.enabled,
                    "port": config.port,
                    "ai_enabled": config.ai_enabled,
                    "status": "running" if name in self.services else "stopped"
                }
                for name, config in self.service_configs.items()
            },
            "ai_engine": self.ai_coordinator.get_status(),
            "logging": self.forensic_logger.get_status(),
            "containers": self.docker_manager.get_status() if self.docker_manager.is_enabled() else None
        }
    
    def update_adaptive_policy(self, service_name: str, policy_updates: dict):
        """Update adaptive policies for specific service"""
        if service_name in self.services:
            service = self.services[service_name]
            if hasattr(service, 'update_policy'):
                service.update_policy(policy_updates)
                
                self.forensic_logger.log_event({
                    "action": "policy_updated",
                    "service": service_name,
                    "updates": policy_updates,
                    "timestamp": datetime.now().isoformat()
                })


if __name__ == "__main__":
    import signal
    import sys
    
    honeypot = HoneypotManager()
    
    def signal_handler(sig, frame):
        print("\nShutting down honeypot system...")
        honeypot.stop_honeypot()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        honeypot.start_honeypot()
        
        # Keep main thread alive
        while honeypot.running:
            time.sleep(1)
            
    except KeyboardInterrupt:
        honeypot.stop_honeypot()