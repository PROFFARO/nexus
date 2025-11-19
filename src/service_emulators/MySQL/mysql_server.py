#!/usr/bin/env python3
"""
NEXUS MySQL Honeypot Server
Comprehensive MySQL service emulator with AI-based dynamic response generation,
attack pattern recognition, forensic logging, and session management.
"""

import asyncio
import datetime
import hashlib
import json
import logging
import os
import re
import socket
import struct
import sys
import threading
import time
import traceback
import uuid
from base64 import b64decode, b64encode
from configparser import ConfigParser
from operator import itemgetter
from pathlib import Path
from typing import Any, Dict, List, Optional

# LLM imports
from langchain_aws import ChatBedrock, ChatBedrockConverse
from langchain_core.chat_history import (
    BaseChatMessageHistory,
    InMemoryChatMessageHistory,
)
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableConfig, RunnablePassthrough
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openai import AzureChatOpenAI, ChatOpenAI

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")

# Import ML components with robust path handling
ML_AVAILABLE = False
MLDetector = None
MLConfig = None

try:
    from ...ai.config import MLConfig
    from ...ai.detectors import MLDetector
    ML_AVAILABLE = True
except ImportError:
    try:
        ai_path = Path(__file__).parent.parent.parent / "ai"
        if ai_path.exists() and str(ai_path) not in sys.path:
            sys.path.insert(0, str(ai_path.parent))
        from ai.config import MLConfig
        from ai.detectors import MLDetector
        ML_AVAILABLE = True
    except ImportError as e:
        ML_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Thread-local storage for request context
thread_local = threading.local()

# Global configuration
config = {}


class AttackAnalyzer:
    """AI-based attack behavior analyzer with integrated JSON patterns and ML detection"""

    def __init__(self):
        """Initialize attack analyzer with pattern and signature loading"""
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()
        
        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE and MLConfig is not None and MLDetector is not None:
            try:
                ml_config = MLConfig("mysql")
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector("mysql", ml_config)
                    logging.info("ML detector initialized for MySQL service")
            except Exception as e:
                logging.warning(f"Failed to initialize ML detector: {e}")
                self.ml_detector = None

    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load attack patterns from JSON configuration"""
        try:
            patterns_file = Path(__file__).parent / "attack_patterns.json"
            with open(patterns_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load attack patterns: {e}")
            return {
                "sql_injection": {
                    "patterns": [r"'\s*or\s*1=1", r"union.*select", r"drop\s*table"],
                    "severity": "critical",
                },
                "reconnaissance": {
                    "patterns": [r"show\s*databases", r"show\s*tables", r"select.*information_schema"],
                    "severity": "medium",
                },
            }

    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures from JSON configuration"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load vulnerability signatures: {e}")
            return {}

    def analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyze a SQL query for attack patterns"""
        analysis = {
            "query": query,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attack_types": [],
            "severity": "low",
            "indicators": [],
            "vulnerabilities": [],
            "pattern_matches": [],
        }

        if not config.get("ai_features", {}).get("attack_pattern_recognition", True):
            return analysis

        # Check attack patterns
        for attack_type, attack_data in self.attack_patterns.items():
            patterns = attack_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    analysis["attack_types"].append(attack_type)
                    analysis["indicators"].extend(attack_data.get("indicators", []))
                    analysis["pattern_matches"].append({
                        "type": attack_type,
                        "pattern": pattern,
                        "severity": attack_data.get("severity", "medium"),
                    })

        # Check vulnerability signatures
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    analysis["vulnerabilities"].append({
                        "id": vuln_id,
                        "name": vuln_data.get("name", vuln_id),
                        "severity": vuln_data.get("severity", "medium"),
                        "cvss_score": vuln_data.get("cvss_score", 0.0),
                        "pattern_matched": pattern,
                    })

        # Determine severity
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = "low"

        for match in analysis["pattern_matches"]:
            if severity_scores.get(match["severity"], 1) > severity_scores[max_severity]:
                max_severity = match["severity"]

        for vuln in analysis["vulnerabilities"]:
            if severity_scores.get(vuln["severity"], 1) > severity_scores[max_severity]:
                max_severity = vuln["severity"]

        analysis["severity"] = max_severity

        # ML-based analysis
        if self.ml_detector:
            try:
                ml_results = self.ml_detector.score({
                    "query": query,
                    "timestamp": analysis["timestamp"],
                    "attack_types": analysis["attack_types"],
                    "severity": analysis["severity"],
                })

                if isinstance(ml_results, dict):
                    analysis["ml_anomaly_score"] = ml_results.get("ml_anomaly_score", 0.0)
                    analysis["ml_labels"] = ml_results.get("ml_labels", [])
                    analysis["ml_confidence"] = ml_results.get("ml_confidence", 0.0)
            except Exception as e:
                logging.error(f"ML analysis failed: {e}")

        return analysis

    def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate threat score from analysis"""
        score = 0
        severity_scores = {"low": 10, "medium": 30, "high": 60, "critical": 90}
        
        score += severity_scores.get(analysis["severity"], 0)
        score += len(analysis["attack_types"]) * 5
        score += len(analysis["vulnerabilities"]) * 15
        
        ml_score = analysis.get("ml_anomaly_score", 0)
        if ml_score > 0:
            score += int(ml_score * 30)
            
        return min(score, 100)


class VulnerabilityLogger:
    """Log and analyze vulnerability exploitation attempts"""

    def __init__(self):
        """Initialize vulnerability logger"""
        self.vulnerability_signatures = self._load_vulnerability_signatures()

    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load vulnerability signatures: {e}")
            return {}

    def analyze_for_vulnerabilities(self, query: str) -> List[Dict[str, Any]]:
        """Analyze query for vulnerability exploitation"""
        vulnerabilities = []

        if not config.get("ai_features", {}).get("vulnerability_detection", True):
            return vulnerabilities

        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    vulnerabilities.append({
                        "vulnerability_id": vuln_id,
                        "name": vuln_data.get("name", vuln_id),
                        "description": vuln_data.get("description", ""),
                        "pattern_matched": pattern,
                        "query": query,
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "severity": vuln_data.get("severity", "medium"),
                        "cvss_score": vuln_data.get("cvss_score", 0.0),
                    })

        return vulnerabilities


class ForensicChainLogger:
    """Generate forensic chain of custody for attacks"""

    def __init__(self, session_dir: str):
        """Initialize forensic logger"""
        self.session_dir = Path(session_dir)
        self.chain_file = self.session_dir / "forensic_chain.json"
        self.chain_data = {
            "session_id": str(uuid.uuid4()),
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "events": [],
            "evidence": [],
        }

    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log forensic event"""
        if not config.get("forensics", {}).get("chain_of_custody", True):
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data,
            "hash": hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest(),
        }

        self.chain_data["events"].append(event)
        self._save_chain()

    def add_evidence(self, evidence_type: str, file_path: str, description: str):
        """Add evidence to forensic chain"""
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()

            evidence = {
                "evidence_id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": evidence_type,
                "file_path": file_path,
                "file_hash": hashlib.sha256(content).hexdigest(),
                "file_size": len(content),
                "description": description,
            }

            self.chain_data["evidence"].append(evidence)
            self._save_chain()

    def _save_chain(self):
        """Save forensic chain to file"""
        with open(self.chain_file, "w") as f:
            json.dump(self.chain_data, f, indent=2)


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for logging"""
    
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "src_ip": getattr(record, "src_ip", "-"),
            "src_port": getattr(record, "src_port", "-"),
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "mysql",
        }
        for key, value in record.__dict__.items():
            if key not in log_record and key != "args" and key != "msg":
                log_record[key] = value
        return json.dumps(log_record)


class MySQLHoneypot:
    """MySQL Honeypot Server with comprehensive attack detection and AI responses"""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, config_file: Optional[str] = None):
        """Initialize MySQL honeypot"""
        global config
        
        self.host = host or str(config.get("mysql", {}).get("host", "0.0.0.0"))
        self.port = int(port or config.get("mysql", {}).get("port", 3326))
        self.server = None
        self.running = False
        
        # Initialize components
        self.attack_analyzer = AttackAnalyzer()
        self.vuln_logger = VulnerabilityLogger()
        
        # Session management
        self.sessions = {}
        self.session_dir = Path(config.get("honeypot", {}).get("sessions_dir", "sessions"))
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # LLM initialization
        self.llm = self._initialize_llm()
        self.chat_history = {}
        
        logger.info(f"MySQL Honeypot initialized: {self.host}:{self.port}")

    def _setup_logging(self):
        """Setup JSON logging"""
        sensor_name = config.get("honeypot", {}).get("sensor_name", "nexus-mysql")
        log_file = config.get("honeypot", {}).get("log_file", "mysql_log.log")
        
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        handler = logging.FileHandler(log_file)
        formatter = JSONFormatter(sensor_name)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    def _initialize_llm(self):
        """Initialize LLM provider based on configuration"""
        llm_provider = config.get("llm", {}).get("llm_provider", "ollama").lower()
        model_name = config.get("llm", {}).get("model_name", "llama3.2")
        temperature = float(config.get("llm", {}).get("temperature", 0.2))

        try:
            if llm_provider == "openai":
                return ChatOpenAI(
                    model=model_name,
                    temperature=temperature,
                )
            elif llm_provider == "azure":
                return AzureChatOpenAI(
                    model=model_name,
                    temperature=temperature,
                    api_version=config.get("llm", {}).get("azure_api_version", "2024-02-01"),
                    azure_endpoint=config.get("llm", {}).get("azure_endpoint"),
                )
            elif llm_provider == "aws":
                return ChatBedrock(
                    model_id=model_name,
                    region_name=config.get("llm", {}).get("aws_region", "us-east-1"),
                    temperature=temperature,
                )
            elif llm_provider == "gemini":
                return ChatGoogleGenerativeAI(
                    model=model_name,
                    temperature=temperature,
                )
            else:  # ollama or default
                base_url = config.get("llm", {}).get("base_url", "http://localhost:11434")
                return ChatOllama(
                    model=model_name,
                    base_url=base_url,
                    temperature=temperature,
                )
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {e}")
            return None

    def _get_llm_response(self, query: str, session_id: str) -> str:
        """Get LLM response for query"""
        if not self.llm:
            return self._get_fallback_response(query)

        try:
            # Get or create chat history
            if session_id not in self.chat_history:
                self.chat_history[session_id] = InMemoryChatMessageHistory()

            # Build prompt
            system_prompt = config.get("llm", {}).get("system_prompt", "You are a MySQL 8.0 server")
            
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=query)
            ]

            # Get response
            response = self.llm.invoke(messages)
            
            # Extract content safely
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = str(content)
            
            # Store in history
            self.chat_history[session_id].add_user_message(query)
            self.chat_history[session_id].add_ai_message(str(content))
            
            return str(content)
        except Exception as e:
            logger.error(f"LLM response failed: {e}")
            return self._get_fallback_response(query)

    def _get_fallback_response(self, query: str) -> str:
        """Get fallback response when LLM unavailable"""
        query_upper = query.strip().upper()
        
        if "SHOW DATABASES" in query_upper:
            return json.dumps([
                {"Database": "information_schema"},
                {"Database": "mysql"},
                {"Database": "performance_schema"},
                {"Database": "nexus_gamedev"},
            ])
        elif "SHOW TABLES" in query_upper:
            return json.dumps([
                {"Tables_in_nexus_gamedev": "users"},
                {"Tables_in_nexus_gamedev": "games"},
                {"Tables_in_nexus_gamedev": "players"},
                {"Tables_in_nexus_gamedev": "scores"},
            ])
        elif "SELECT" in query_upper and "@@version" in query_upper:
            return json.dumps([{"@@version": "8.0.32-0ubuntu0.20.04.2"}])
        elif "SHOW VARIABLES" in query_upper:
            return json.dumps([
                {"Variable_name": "version", "Value": "8.0.32"},
                {"Variable_name": "datadir", "Value": "/var/lib/mysql/"},
            ])
        else:
            return json.dumps([])

    async def handle_connection(self, reader, writer):
        """Handle incoming MySQL client connection"""
        peername = writer.get_extra_info("peername")
        src_ip, src_port = peername if peername else ("unknown", 0)
        
        # Create session
        session_id = f"session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{src_ip.replace('.', '_')}"
        session_dir = self.session_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        session_data = {
            "session_id": session_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "username": None,
            "authenticated": False,
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "queries": [],
            "attack_analysis": [],
            "vulnerabilities": [],
        }
        
        forensic_logger = ForensicChainLogger(str(session_dir))
        
        try:
            # Send MySQL greeting
            server_version = config.get("mysql", {}).get("server_version", "8.0.32-0ubuntu0.20.04.2")
            greeting = self._build_greeting(server_version)
            writer.write(greeting)
            await writer.drain()
            
            forensic_logger.log_event("connection_established", {
                "src_ip": src_ip,
                "src_port": src_port,
            })
            
            logger.info("MySQL connection received", extra={
                "src_ip": src_ip,
                "src_port": src_port,
                "session_id": session_id,
            })
            
            # Handle authentication and queries
            while True:
                data = await reader.readexactly(1)
                if not data:
                    break
                
                # Parse packet header
                try:
                    packet_length = int.from_bytes(data[:3], "little")
                    if packet_length == 0:
                        continue
                    
                    # Read full packet
                    packet_data = await reader.readexactly(packet_length + 1)
                    command = packet_data[0]
                    
                    if command == 0x03:  # Query command
                        query = packet_data[1:].decode("utf-8", errors="ignore").strip()
                        
                        # Analyze query
                        attack_analysis = self.attack_analyzer.analyze_query(query)
                        vulnerabilities = self.vuln_logger.analyze_for_vulnerabilities(query)
                        
                        session_data["queries"].append({
                            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "query": query,
                            "attack_analysis": attack_analysis,
                            "vulnerabilities": vulnerabilities,
                        })
                        
                        # Log threats
                        if attack_analysis.get("attack_types"):
                            logger.warning("Attack pattern detected", extra={
                                "attack_types": attack_analysis["attack_types"],
                                "severity": attack_analysis["severity"],
                                "query": query,
                                "session_id": session_id,
                            })
                            forensic_logger.log_event("attack_detected", attack_analysis)
                        
                        if vulnerabilities:
                            logger.critical("Vulnerability exploitation attempt", extra={
                                "vulnerabilities": vulnerabilities,
                                "query": query,
                                "session_id": session_id,
                            })
                            for vuln in vulnerabilities:
                                forensic_logger.log_event("vulnerability_exploit", vuln)
                        
                        # Get response
                        response = self._get_llm_response(query, session_id)
                        writer.write(self._build_result_packet(response))
                        await writer.drain()
                        
                        logger.info("Query processed", extra={
                            "query": query,
                            "session_id": session_id,
                        })
                        
                except Exception as e:
                    logger.error(f"Packet parsing error: {e}")
                    break
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Connection error: {e}", extra={
                "src_ip": src_ip,
                "session_id": session_id,
            })
        finally:
            # Save session data
            session_data["end_time"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            session_file = session_dir / "session_summary.json"
            with open(session_file, "w") as f:
                json.dump(session_data, f, indent=2)
            
            forensic_logger.log_event("connection_closed", {
                "reason": "normal_closure",
            })
            forensic_logger.add_evidence("session_summary", str(session_file), "Complete session summary")
            
            writer.close()
            logger.info("Connection closed", extra={"session_id": session_id})

    def _build_greeting(self, server_version: str) -> bytes:
        """Build MySQL server greeting packet"""
        # Protocol version (10 for MySQL 3.21+)
        packet = bytearray([0x0a])
        
        # Server version string
        packet.extend(server_version.encode() + b"\x00")
        
        # Connection ID
        packet.extend(struct.pack("<I", 1))
        
        # Auth plugin data part 1
        packet.extend(b"12345678")
        
        # Filler (always 0)
        packet.append(0x00)
        
        # Capability flags (lower 2 bytes)
        packet.extend(struct.pack("<H", 0x0202))
        
        # Character set
        packet.append(33)  # utf8
        
        # Status flags
        packet.extend(struct.pack("<H", 0x0002))
        
        # Capability flags (upper 2 bytes)
        packet.extend(struct.pack("<H", 0x0000))
        
        # Add header
        header = struct.pack("<I", len(packet))[:-1]
        return header + bytes(packet)

    def _build_result_packet(self, result: str) -> bytes:
        """Build MySQL result packet"""
        result_bytes = result.encode("utf-8")
        length = len(result_bytes)
        header = struct.pack("<I", length)[:-1]
        return header + bytes([0x00]) + result_bytes

    async def start(self):
        """Start MySQL honeypot server"""
        try:
            server = await asyncio.start_server(
                self.handle_connection,
                self.host,
                self.port
            )
            self.server = server
            self.running = True
            logger.info(f"MySQL Honeypot started on {self.host}:{self.port}")
            
            async with server:
                await server.serve_forever()
        except Exception as e:
            logger.error(f"Server startup failed: {e}")
            self.running = False

    def stop(self):
        """Stop MySQL honeypot server"""
        if self.server:
            self.server.close()
            self.running = False
            logger.info("MySQL Honeypot stopped")


def load_config(config_file: Optional[str] = None):
    """Load configuration from mysql_config.ini"""
    global config
    
    if config_file is None:
        config_file = str(Path(__file__).parent.parent.parent.parent / "configs" / "mysql_config.ini")
    
    config_parser = ConfigParser()
    config_parser.read(config_file)
    
    # Convert ConfigParser to dict
    config = {}
    for section in config_parser.sections():
        config[section] = dict(config_parser.items(section))
    
    logger.info(f"Configuration loaded from {config_file}")
    return config


def get_user_accounts() -> dict:
    """Load user accounts from config"""
    user_accounts = {}
    if "user_accounts" in config:
        user_accounts = dict(config["user_accounts"])
    return user_accounts


def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    """Choose and initialize LLM provider"""
    if llm_provider is None:
        llm_provider = config.get("llm", {}).get("llm_provider", "ollama")
    if llm_provider:
        llm_provider = str(llm_provider).lower()
    else:
        llm_provider = "ollama"
    
    if model_name is None:
        model_name = config.get("llm", {}).get("model_name", "llama3.2")
    if model_name:
        model_name = str(model_name)
    else:
        model_name = "llama3.2"
    
    temperature = float(config.get("llm", {}).get("temperature", 0.2))

    try:
        if llm_provider == "openai":
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
            )
        elif llm_provider == "azure":
            return AzureChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_version=str(config.get("llm", {}).get("azure_api_version", "2024-02-01")),
                azure_endpoint=str(config.get("llm", {}).get("azure_endpoint", "")),
            )
        elif llm_provider == "aws":
            return ChatBedrock(
                model_id=model_name,
                region_name=str(config.get("llm", {}).get("aws_region", "us-east-1")),
                temperature=temperature,
            )
        elif llm_provider == "gemini":
            return ChatGoogleGenerativeAI(
                model=model_name,
                temperature=temperature,
            )
        else:  # ollama or default
            base_url = str(config.get("llm", {}).get("base_url", "http://localhost:11434"))
            return ChatOllama(
                model=model_name,
                base_url=base_url,
                temperature=temperature,
            )
    except Exception as e:
        logger.error(f"Failed to initialize LLM: {e}")
        return None


class ContextFilter(logging.Filter):
    """Add context to log records"""
    def filter(self, record):
        record.src_ip = getattr(thread_local, "src_ip", "-")
        record.src_port = getattr(thread_local, "src_port", "-")
        return True


# Global session storage for chat history
_session_storage: Dict[str, BaseChatMessageHistory] = {}


def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    """Get or create session chat history"""
    global _session_storage
    
    if session_id not in _session_storage:
        _session_storage[session_id] = InMemoryChatMessageHistory()
    
    return _session_storage[session_id]


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NEXUS MySQL Honeypot")
    parser.add_argument("--config", help="Configuration file path", default=None)
    parser.add_argument("--host", help="Listening host", default=None)
    parser.add_argument("--port", type=int, help="Listening port", default=None)
    
    args = parser.parse_args()
    
    # Load config
    load_config(args.config)
    
    # Print configuration info
    logger.info("="*60)
    logger.info("NEXUS MySQL Honeypot Configuration")
    logger.info("="*60)
    logger.info(f"LLM Provider: {config.get('llm', {}).get('llm_provider', 'ollama')}")
    logger.info(f"Model: {config.get('llm', {}).get('model_name', 'llama3.2')}")
    logger.info(f"Attack Pattern Recognition: {config.get('ai_features', {}).get('attack_pattern_recognition', True)}")
    logger.info(f"Vulnerability Detection: {config.get('ai_features', {}).get('vulnerability_detection', True)}")
    logger.info(f"Real-time Analysis: {config.get('ai_features', {}).get('real_time_analysis', True)}")
    logger.info(f"User Accounts: {len(get_user_accounts())} accounts configured")
    logger.info("="*60)
    
    # Create and start honeypot
    honeypot = MySQLHoneypot(
        host=args.host,
        port=args.port,
        config_file=args.config
    )
    
    try:
        await honeypot.start()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
        honeypot.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
