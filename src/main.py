#!/usr/bin/env python3
"""
Nexus Development - AI-Based Adaptive Honeypot System
Main Entry Point

This is the main entry point for the Nexus honeypot system that orchestrates
all service emulators with AI-driven dynamic responses and comprehensive logging.
"""

import sys
import signal
import argparse
import json
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.honeypot_manager import HoneypotManager


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Nexus AI-Based Adaptive Honeypot System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Start with default configuration
  python main.py --config custom.json    # Use custom configuration
  python main.py --services ssh,ftp      # Start only SSH and FTP services
  python main.py --no-ai                 # Disable AI features
  python main.py --container             # Force container mode
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config/honeypot.json",
        help="Configuration file path (default: config/honeypot.json)"
    )
    
    parser.add_argument(
        "--services", "-s",
        type=str,
        help="Comma-separated list of services to enable (ssh,ftp,smb,rdp,mysql)"
    )
    
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI features"
    )
    
    parser.add_argument(
        "--no-container",
        action="store_true",
        help="Disable container support"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Log directory path (default: logs)"
    )
    
    parser.add_argument(
        "--bind-ip",
        type=str,
        default="0.0.0.0",
        help="IP address to bind services (default: 0.0.0.0)"
    )
    
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run in test mode (limited functionality)"
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="Nexus Honeypot System v1.0.0"
    )
    
    return parser.parse_args()


def setup_signal_handlers(honeypot_manager):
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down honeypot system...")
        honeypot_manager.stop_honeypot()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Windows-specific signals
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, signal_handler)


def validate_configuration(config_path: str) -> bool:
    """Validate configuration file"""
    config_file = Path(config_path)
    
    if not config_file.exists():
        print(f"Error: Configuration file not found: {config_path}")
        return False
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        # Basic validation
        required_sections = ["services", "ai_engine", "logging"]
        for section in required_sections:
            if section not in config:
                print(f"Error: Missing required configuration section: {section}")
                return False
        
        return True
        
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        return False
    except Exception as e:
        print(f"Error: Failed to validate configuration: {e}")
        return False


def print_banner():
    """Print system banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗                              ║
║    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝                              ║
║    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗                              ║
║    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║                              ║
║    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║                              ║
║    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                              ║
║                                                                               ║
║              AI-Based Adaptive Honeypot System v1.0.0                        ║
║                                                                               ║
║  🔒 Medium Interaction Honeypot with AI-Driven Dynamic Responses             ║
║  🤖 Behavioral Analysis & Attack Pattern Recognition                          ║
║  📊 Comprehensive Forensic Logging & Chain of Custody                        ║
║  🐳 Containerized Service Isolation & Orchestration                          ║
║                                                                               ║
║  Services: SSH(22) | FTP(21) | SMB(445) | RDP(3389) | MySQL(3306)          ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Print banner
        print_banner()
        
        # Validate configuration
        if not validate_configuration(args.config):
            sys.exit(1)
        
        # Create honeypot manager with configuration
        honeypot_config = {
            "config_path": args.config,
            "log_level": args.log_level,
            "log_dir": args.log_dir,
            "bind_ip": args.bind_ip,
            "ai_enabled": not args.no_ai,
            "container_enabled": not args.no_container,
            "test_mode": args.test
        }
        
        # Override services if specified
        if args.services:
            enabled_services = [s.strip().lower() for s in args.services.split(",")]
            honeypot_config["enabled_services"] = enabled_services
        
        # Initialize honeypot manager
        honeypot_manager = HoneypotManager(**honeypot_config)
        
        # Setup signal handlers
        setup_signal_handlers(honeypot_manager)
        
        # Start honeypot system
        print("Starting Nexus Honeypot System...")
        print("=" * 80)
        
        honeypot_manager.start_honeypot()
        
        # Print status information
        status = honeypot_manager.get_system_status()
        print("\nSystem Status:")
        print(f"  Running: {status['running']}")
        print(f"  AI Engine: {'Enabled' if status['ai_engine']['initialized'] else 'Disabled'}")
        print(f"  Logging: {'Active' if status['logging']['initialized'] else 'Inactive'}")
        print(f"  Containers: {'Enabled' if status.get('containers') else 'Disabled'}")
        
        print("\nActive Services:")
        for service_name, service_info in status['services'].items():
            if service_info['enabled']:
                ai_status = "AI-Enhanced" if service_info['ai_enabled'] else "Standard"
                print(f"  {service_name.upper():>6}: Port {service_info['port']} ({ai_status})")
        
        print("\n" + "=" * 80)
        print("Honeypot system is running. Press Ctrl+C to stop.")
        print("Monitor logs in real-time or check the dashboard for activity.")
        
        # Keep main thread alive
        while honeypot_manager.running:
            try:
                import time
                time.sleep(1)
            except KeyboardInterrupt:
                break
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        print("\nNexus Honeypot System stopped")


if __name__ == "__main__":
    main()