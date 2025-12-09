#!/usr/bin/env python3

import argparse
import asyncio
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
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

from langchain_aws import ChatBedrock, ChatBedrockConverse
from langchain_core.chat_history import (
    BaseChatMessageHistory,
    InMemoryChatMessageHistory,
)
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openai import AzureChatOpenAI, ChatOpenAI

# Initialize logger at module level
logger = logging.getLogger(__name__)

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    print(
        "Warning: python-dotenv not installed. Install with: pip install python-dotenv"
    )
    print("Environment variables will be loaded from system environment only.")

# Import ML components with robust path handling
ML_AVAILABLE = False
MLDetector = None
MLConfig = None

# Import FTP honeypot modules
try:
    from virtual_filesystem import VirtualFilesystem, FileNode
    from command_executor import FTPCommandExecutor
    from llm_guard import LLMGuard
    VFS_AVAILABLE = True
except ImportError:
    try:
        from .virtual_filesystem import VirtualFilesystem, FileNode
        from .command_executor import FTPCommandExecutor
        from .llm_guard import LLMGuard
        VFS_AVAILABLE = True
    except ImportError as e:
        VFS_AVAILABLE = False
        if __name__ == "__main__":
            print(f"Warning: VFS modules not available: {e}")

try:
    # Try relative imports first
    from ...ai.config import MLConfig
    from ...ai.detectors import MLDetector

    ML_AVAILABLE = True
except ImportError:
    try:
        # Try absolute imports with path adjustment
        import sys
        from pathlib import Path

        ai_path = Path(__file__).parent.parent.parent / "ai"
        if ai_path.exists() and str(ai_path) not in sys.path:
            sys.path.insert(0, str(ai_path.parent))

        from ai.config import MLConfig
        from ai.detectors import MLDetector

        ML_AVAILABLE = True
    except ImportError as e:
        ML_AVAILABLE = False
        # Only print warning if running directly, not during imports
        if __name__ == "__main__":
            print(f"Warning: ML components not available: {e}")


class AttackAnalyzer:
    """AI-based attack behavior analyzer with integrated JSON patterns and ML detection"""

    def __init__(self):
        # Load attack patterns from JSON file
        self.attack_patterns = self._load_attack_patterns()
        # Load vulnerability signatures from JSON file
        self.vulnerability_signatures = self._load_vulnerability_signatures()

        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE:
            try:
                ml_config = MLConfig("ftp")
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector("ftp", ml_config)
                    logging.info("ML detector initialized for FTP service")
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
            # Fallback to basic patterns
            return {
                "reconnaissance": {
                    "patterns": [r"LIST", r"NLST", r"PWD", r"SYST"],
                    "severity": "medium",
                },
                "privilege_escalation": {
                    "patterns": [r"SITE.*CHMOD", r"SITE.*EXEC"],
                    "severity": "high",
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

    def analyze_command(self, command: str) -> Dict[str, Any]:
        """Analyze an FTP command for attack patterns using integrated JSON data"""
        analysis = {
            "command": command,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attack_types": [],
            "severity": "low",
            "indicators": [],
            "vulnerabilities": [],
            "pattern_matches": [],
        }

        # Check if attack pattern recognition is enabled
        if not config["ai_features"].getboolean("attack_pattern_recognition", True):
            return analysis

        # Check attack patterns from JSON
        for attack_type, attack_data in self.attack_patterns.items():
            patterns = attack_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    analysis["attack_types"].append(attack_type)
                    analysis["indicators"].extend(attack_data.get("indicators", []))
                    analysis["pattern_matches"].append(
                        {
                            "type": attack_type,
                            "pattern": pattern,
                            "severity": attack_data.get("severity", "medium"),
                        }
                    )

        # Check vulnerability signatures
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    analysis["vulnerabilities"].append(
                        {
                            "id": vuln_id,
                            "name": vuln_data.get("name", vuln_id),
                            "severity": vuln_data.get("severity", "medium"),
                            "cvss_score": vuln_data.get("cvss_score", 0.0),
                            "pattern_matched": pattern,
                        }
                    )

        # Determine overall severity based on patterns and vulnerabilities
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = "low"

        # Check attack pattern severities
        for match in analysis["pattern_matches"]:
            if (
                severity_scores.get(match["severity"], 1)
                > severity_scores[max_severity]
            ):
                max_severity = match["severity"]

        # Check vulnerability severities
        for vuln in analysis["vulnerabilities"]:
            if severity_scores.get(vuln["severity"], 1) > severity_scores[max_severity]:
                max_severity = vuln["severity"]

        # Apply sensitivity level adjustment
        sensitivity = (
            config["attack_detection"].get("sensitivity_level", "medium").lower()
        )
        if sensitivity == "high" and max_severity == "low":
            max_severity = "medium"
        elif sensitivity == "low" and max_severity == "medium":
            max_severity = "low"

        analysis["severity"] = max_severity

        # Calculate threat score if enabled
        if config["attack_detection"].getboolean("threat_scoring", True):
            threat_score = self._calculate_threat_score(analysis)
            analysis["threat_score"] = threat_score

            # Check alert threshold
            alert_threshold = config["attack_detection"].getint("alert_threshold", 70)
            analysis["alert_triggered"] = threat_score >= alert_threshold

        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                # Prepare comprehensive ML data
                ml_data = {
                    "command": command,
                    "timestamp": analysis["timestamp"],
                    "attack_types": analysis["attack_types"],
                    "severity": analysis["severity"],
                    "indicators": analysis["indicators"],
                    "vulnerabilities": analysis["vulnerabilities"],
                    "pattern_matches": analysis["pattern_matches"],
                }

                # Get ML scoring results
                ml_results = self.ml_detector.score(ml_data)

                # Integrate ML results into analysis

                # Ensure ml_results is a dictionary
                if not isinstance(ml_results, dict):
                    logging.warning(
                        f"ML detector returned non-dict result: {type(ml_results)}"
                    )
                    ml_results = {
                        "ml_anomaly_score": 0.0,
                        "ml_labels": ["ml_error"],
                        "ml_cluster": -1,
                        "ml_reason": f"Invalid ML result type: {type(ml_results)}",
                        "ml_confidence": 0.0,
                        "ml_inference_time_ms": 0,
                    }
                analysis["ml_anomaly_score"] = ml_results.get("ml_anomaly_score", 0.0)
                analysis["ml_labels"] = ml_results.get("ml_labels", [])
                analysis["ml_cluster"] = ml_results.get("ml_cluster", -1)
                analysis["ml_reason"] = ml_results.get("ml_reason", "No ML analysis")
                analysis["ml_confidence"] = ml_results.get("ml_confidence", 0.0)
                analysis["ml_risk_score"] = ml_results.get("ml_risk_score", 0.0)
                analysis["ml_inference_time_ms"] = ml_results.get(
                    "ml_inference_time_ms", 0
                )

                # Calculate risk level using new ML method
                ml_score = ml_results.get("ml_anomaly_score", 0)
                risk_info = self.ml_detector.calculate_risk_level(
                    ml_score,
                    attack_types=analysis["attack_types"],
                    severity=analysis["severity"]
                )
                analysis["ml_risk_level"] = risk_info["risk_level"]
                analysis["ml_threat_score"] = risk_info["threat_score"]
                analysis["ml_risk_color"] = risk_info["color"]
                
                # Detect attack vectors using new ML method
                attack_vectors = self.ml_detector.detect_attack_vectors(ml_data, ml_results)
                analysis["attack_vectors"] = attack_vectors

                # Enhance severity based on ML anomaly score
                ml_score = ml_results.get("ml_anomaly_score", 0)
                if ml_score > 0.8:
                    if analysis["severity"] in ["low", "medium"]:
                        analysis["severity"] = "high"
                        analysis["attack_types"].append("ml_anomaly_high")
                elif ml_score > 0.6:
                    if analysis["severity"] == "low":
                        analysis["severity"] = "medium"
                        analysis["attack_types"].append("ml_anomaly_medium")

                # Add ML-specific indicators
                if "anomaly" in ml_results.get("ml_labels", []):
                    analysis["indicators"].append(
                        f"ML Anomaly Detection: {ml_results.get('ml_reason', 'Unknown')}"
                    )

                # Add attack vector indicators
                if attack_vectors:
                    for vector in attack_vectors:
                        analysis["indicators"].append(
                            f"Attack Vector: {vector['technique']} (MITRE {vector['mitre_id']}) - Confidence: {vector['confidence']:.2f}"
                        )

                logging.info(
                    f"FTP ML Analysis: Score={ml_score:.3f}, Risk={risk_info['risk_level']}, "
                    f"Vectors={len(attack_vectors)}, Labels={ml_results.get('ml_labels', [])}"
                )

            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                # Add ML error information to analysis
                analysis["ml_error"] = str(e)
                analysis["ml_anomaly_score"] = 0.0
                analysis["ml_labels"] = ["ml_error"]
                analysis["attack_vectors"] = []
                if not config.get("ml", {}).get("fallback_on_error", True):
                    raise

        return analysis

    def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate threat score based on analysis"""
        score = 0
        severity_scores = {"low": 10, "medium": 30, "high": 60, "critical": 90}

        # Base score from severity
        score += severity_scores.get(analysis["severity"], 0)

        # Add points for multiple attack types
        score += len(analysis["attack_types"]) * 5

        # Add points for vulnerabilities
        score += len(analysis["vulnerabilities"]) * 15

        # Add ML-based scoring
        ml_score = analysis.get("ml_anomaly_score", 0)
        if ml_score > 0:
            # ML score contributes up to 30 points
            ml_contribution = int(ml_score * 30)
            score += ml_contribution

            # Bonus for high confidence ML detection
            ml_confidence = analysis.get("ml_confidence", 0)
            if ml_confidence > 0.8 and ml_score > 0.7:
                score += 10  # High confidence bonus

        return min(score, 100)  # Cap at 100


class FileTransferHandler:
    """Handle file uploads and downloads with forensic logging"""

    def __init__(self, session_dir: str):
        self.session_dir = Path(session_dir)
        # Use configured directories or defaults
        downloads_dirname = config["features"].get("downloads_dir", "downloads")
        uploads_dirname = config["features"].get("uploads_dir", "uploads")
        self.downloads_dir = self.session_dir / downloads_dirname
        self.uploads_dir = self.session_dir / uploads_dirname
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)

    def handle_download(
        self, filename: str, content: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Handle file download requests (RETR command)"""
        download_info = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "filename": filename,
            "type": "download",
            "status": "attempted",
        }

        # Check if file monitoring is enabled
        if not config["forensics"].getboolean("file_monitoring", True):
            return download_info

        # Generate fake file content if not provided
        if content is None:
            content = self._generate_fake_file_content(filename)

        file_path = self.downloads_dir / filename

        # Save download if enabled
        if config["forensics"].getboolean("save_downloads", True):
            with open(file_path, "wb") as f:
                f.write(content)

        download_info.update(file_size=str(len(content)), status="completed")

        # Only add file_path if downloads are being saved
        if config["forensics"].getboolean("save_downloads", True):
            download_info["file_path"] = str(file_path)

        # Add file hash analysis if enabled
        if config["forensics"].getboolean("file_hash_analysis", True):
            download_info["file_hash"] = hashlib.sha256(content).hexdigest()
            # amazonq-ignore-next-line
            # amazonq-ignore-next-line
            download_info["md5_hash"] = hashlib.md5(content).hexdigest()

        # Add malware detection if enabled
        if config["forensics"].getboolean("malware_detection", True):
            download_info["malware_detected"] = str(
                self._detect_malware(filename, content)
            )
            download_info["file_type"] = self._identify_file_type(filename, content)

        return download_info

    def _generate_fake_file_content(self, filename: str) -> bytes:
        """Generate realistic fake file content based on file type"""
        filename_lower = filename.lower()

        if filename_lower.endswith((".txt", ".log", ".conf", ".cfg")):
            # Text configuration files
            content = f"""# Configuration file for NexusGames Studio
# Generated: {datetime.datetime.now()}
# This is a honeypot simulation

server_name=nexus-ftp-01
max_connections=100
allow_anonymous=false
local_enable=true
write_enable=true
local_umask=022
dirmessage_enable=true
use_localtime=true
xferlog_enable=true
connect_from_port_20=true
chroot_local_user=true
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=false
""".encode()
        elif filename_lower.endswith((".sh", ".bash")):
            # Shell scripts
            content = f"""#!/bin/bash
# NexusGames Studio deployment script
# This is a honeypot simulation

echo "Starting game server deployment..."
echo "Connecting to production servers..."
echo "Deploying build artifacts..."
echo "Updating configuration files..."
echo "Restarting services..."
echo "Deployment complete!"
""".encode()
        elif filename_lower.endswith((".py", ".python")):
            # Python scripts
            content = f"""#!/usr/bin/env python3
# NexusGames Studio automation script
# This is a honeypot simulation

import os
import sys
import time

def deploy_game_build():
    print("Deploying game build...")
    print("Validating assets...")
    print("Uploading to CDN...")
    print("Updating database...")
    print("Build deployed successfully!")

if __name__ == "__main__":
    deploy_game_build()
""".encode()
        elif filename_lower.endswith((".sql", ".db")):
            # Database files
            content = f"""-- NexusGames Studio Database Schema
-- This is a honeypot simulation

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    created_at TIMESTAMP
);

CREATE TABLE games (
    id INT PRIMARY KEY,
    title VARCHAR(100),
    genre VARCHAR(50),
    release_date DATE
);

INSERT INTO users VALUES (1, 'admin', 'admin@nexusgames.com', NOW());
INSERT INTO games VALUES (1, 'Stellar Conquest', 'Strategy', '2024-12-01');
""".encode()
        else:
            # Generic file
            content = f"""NexusGames Studio File: {filename}
Created: {datetime.datetime.now()}
This is a honeypot simulation file.

File contains sensitive game development data.
Access restricted to authorized personnel only.
""".encode()

        return content

    def _detect_malware(self, filename: str, content: bytes) -> bool:
        """Simple malware detection based on patterns"""
        malware_patterns = [
            b"malware",
            b"virus",
            b"trojan",
            b"backdoor",
            b"payload",
            b"exploit",
        ]
        filename_lower = filename.lower()

        # Check filename patterns
        if any(
            pattern in filename_lower
            for pattern in [
                "malware",
                "virus",
                "trojan",
                "backdoor",
                "payload",
                "exploit",
            ]
        ):
            return True

        # Check content patterns
        for pattern in malware_patterns:
            if pattern in content.lower():
                return True

        return False

    def _identify_file_type(self, filename: str, content: bytes) -> str:
        """Identify file type based on extension and content"""
        filename_lower = filename.lower()

        if filename_lower.endswith((".txt", ".log", ".conf", ".cfg")):
            return "text_file"
        elif filename_lower.endswith((".sh", ".bash")):
            return "shell_script"
        elif filename_lower.endswith((".py", ".python")):
            return "python_script"
        elif filename_lower.endswith((".sql", ".db")):
            return "database_file"
        elif b"#!/bin/bash" in content[:100]:
            return "shell_script"
        elif b"#!/usr/bin/env python" in content[:100]:
            return "python_script"
        else:
            return "unknown"

    def handle_upload(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Handle file uploads via STOR command"""
        upload_info = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "filename": filename,
            "type": "upload",
            "file_size": len(content),
        }

        # Check if file monitoring is enabled
        if not config["forensics"].getboolean("file_monitoring", True):
            return upload_info

        # Save upload if enabled
        if config["forensics"].getboolean("save_uploads", True):
            file_path = self.uploads_dir / filename
            with open(file_path, "wb") as f:
                f.write(content)
            upload_info["file_path"] = str(file_path)

        # Add file hash analysis if enabled
        if config["forensics"].getboolean("file_hash_analysis", True):
            upload_info["file_hash"] = hashlib.sha256(content).hexdigest()
            upload_info["md5_hash"] = hashlib.md5(content).hexdigest()

        # Add malware detection if enabled
        if config["forensics"].getboolean("malware_detection", True):
            upload_info["malware_detected"] = str(
                self._detect_malware(filename, content)
            )
            upload_info["file_type"] = self._identify_file_type(filename, content)

        upload_info["status"] = "completed"
        return upload_info


class VulnerabilityLogger:
    """Log and analyze vulnerability exploitation attempts using integrated JSON data"""

    def __init__(self):
        # Load vulnerability signatures from JSON file (shared with AttackAnalyzer)
        self.vulnerability_signatures = self._load_vulnerability_signatures()

    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures from JSON configuration"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load vulnerability signatures: {e}")
            # Fallback patterns
            return {
                "FTP_BOUNCE_ATTACK": {
                    "patterns": [r"PORT.*127\.0\.0\.1", r"PORT.*localhost"],
                    "severity": "high",
                },
                "DIRECTORY_TRAVERSAL": {
                    "patterns": [r"\.\./\.\./\.\./", r"\.\.\\\.\.\\\.\.\\"],
                    "severity": "critical",
                },
            }

    def analyze_for_vulnerabilities(
        self, command: str, headers: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        """Analyze FTP command for vulnerability exploitation attempts using JSON data"""
        vulnerabilities = []

        # Check if vulnerability detection is enabled
        if not config["ai_features"].getboolean("vulnerability_detection", True):
            return vulnerabilities

        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    vulnerabilities.append(
                        {
                            "vulnerability_id": vuln_id,
                            "name": vuln_data.get("name", vuln_id),
                            "description": vuln_data.get("description", ""),
                            "pattern_matched": pattern,
                            "input": command,
                            "timestamp": datetime.datetime.now(
                                datetime.timezone.utc
                            ).isoformat(),
                            "severity": vuln_data.get("severity", "medium"),
                            "cvss_score": vuln_data.get("cvss_score", 0.0),
                            "indicators": vuln_data.get("indicators", []),
                        }
                    )

        return vulnerabilities


class ForensicChainLogger:
    """Generate forensic chain of custody for attacks"""

    def __init__(self, session_dir: str):
        # amazonq-ignore-next-line
        self.session_dir = Path(session_dir)
        self.chain_file = self.session_dir / "forensic_chain.json"
        self.chain_data = {
            "session_id": str(uuid.uuid4()),
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "events": [],
            "evidence": [],
            "attack_timeline": [],
        }

    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log forensic event"""
        # Check if chain of custody is enabled
        if not config["forensics"].getboolean("chain_of_custody", True):
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data,
            "hash": hashlib.sha256(
                json.dumps(data, sort_keys=True).encode()
            ).hexdigest(),
        }

        self.chain_data["events"].append(event)
        self._save_chain()

    def add_evidence(self, evidence_type: str, file_path: str, description: str):
        """Add evidence to forensic chain"""
        # Check if chain of custody is enabled
        if not config["forensics"].getboolean("chain_of_custody", True):
            return

        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                content = f.read()

            evidence = {
                "evidence_id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": evidence_type,
                "file_path": file_path,
                "file_size": len(content),
                "description": description,
            }

            # Add file hash analysis if enabled
            if config["forensics"].getboolean("file_hash_analysis", True):
                evidence["file_hash"] = hashlib.sha256(content).hexdigest()
                evidence["md5_hash"] = hashlib.md5(content).hexdigest()

            self.chain_data["evidence"].append(evidence)
            self._save_chain()

    def _save_chain(self):
        """Save forensic chain to file"""
        with open(self.chain_file, "w") as f:
            json.dump(self.chain_data, f, indent=2)


class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": getattr(record, "task_name", "-"),
            "src_ip": getattr(record, "src_ip", "-"),
            "src_port": getattr(record, "src_port", "-"),
            "dst_ip": getattr(record, "dst_ip", "-"),
            "dst_port": getattr(record, "dst_port", "-"),
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "ftp",
        }
        if hasattr(record, "interactive"):
            log_record["interactive"] = getattr(record, "interactive", True)
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key not in [
                "args",
                "msg",
                "exc_info",
                "exc_text",
                "stack_info",
                "pathname",
                "filename",
                "module",
                "funcName",
                "lineno",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
            ]:
                log_record[key] = value
        return json.dumps(log_record)


class FTPSession:
    """Represents an FTP session with AI-enhanced responses"""

    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server
        self.authenticated = False
        self.username = None
        self.current_directory = "/home/ftp"
        self.transfer_mode = "ASCII"
        self.data_connection = None
        self.data_writer = None
        self.data_reader = None
        self.passive_mode = False
        self.active_mode_address = None

        # Create unique LLM session ID for this FTP session
        self.llm_session_id = f"ftp-{uuid.uuid4().hex[:12]}"

        self.session_data = {
            "commands": [],
            "files_uploaded": [],
            "files_downloaded": [],
            "vulnerabilities": [],
            "attack_analysis": [],
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        # Initialize virtual filesystem (VFS) for hybrid honeypot mode
        self.filesystem = None
        self.command_executor = None
        self.llm_guard = None
        
        # Legacy seed filesystem for fallback
        self.seed_fs = self._load_seed_filesystem()

        # Initialize session recording if enabled
        self.session_recording = config["features"].getboolean(
            "session_recording", True
        )
        self.save_replay = config["features"].getboolean("save_replay", True)
        self.session_transcript = [] if self.session_recording else None

        # Initialize components
        self._initialize_components(server)

    def _load_seed_filesystem(self) -> Dict[str, Any]:
        """Load seed filesystem from configured directory"""
        seed_dir = config["honeypot"].get("seed_fs_dir", "")
        if not seed_dir or not os.path.exists(seed_dir):
            return {}

        try:
            seed_fs = {}
            for root, dirs, files in os.walk(seed_dir):
                rel_path = os.path.relpath(root, seed_dir)
                if rel_path == ".":
                    rel_path = "/home/ftp"
                else:
                    rel_path = f"/home/ftp/{rel_path.replace(os.sep, '/')}"

                seed_fs[rel_path] = {"dirs": dirs[:], "files": files[:]}
            return seed_fs
        except Exception as e:
            logger.error(f"Failed to load seed filesystem: {e}")
            return {}

    def _initialize_components(self, server):
        """Initialize integrated components including VFS and command execution"""
        try:
            self.attack_analyzer = AttackAnalyzer()
            self.file_handler = (
                FileTransferHandler(str(server.session_dir))
                if config["forensics"].getboolean("file_monitoring", True)
                else None
            )
            self.vuln_logger = VulnerabilityLogger()
            self.forensic_logger = (
                ForensicChainLogger(str(server.session_dir))
                if config["forensics"].getboolean("chain_of_custody", True)
                else None
            )
            
            # Initialize VFS-based hybrid honeypot components
            if VFS_AVAILABLE:
                try:
                    self.filesystem = VirtualFilesystem(username="ftp")
                    self.command_executor = FTPCommandExecutor(self.filesystem)
                    self.llm_guard = LLMGuard()
                    
                    # Try to load persisted VFS state
                    vfs_state_path = str(server.session_dir / "filesystem_state.json")
                    if os.path.exists(vfs_state_path):
                        self.filesystem.load_state(vfs_state_path)
                        logger.info(f"Loaded VFS state from {vfs_state_path}")
                    
                    logger.info("Hybrid honeypot VFS initialized successfully")
                except Exception as ve:
                    logger.error(f"Failed to initialize VFS components: {ve}")
                    self.filesystem = None
                    self.command_executor = None
                    self.llm_guard = None
            else:
                logger.warning("VFS modules not available, using LLM-only mode")
                
        except Exception as e:
            logger.error(f"Failed to initialize FTP session components: {e}")
            self.attack_analyzer = None
            self.file_handler = None
            self.vuln_logger = None
            self.forensic_logger = None
            self.filesystem = None
            self.command_executor = None
            self.llm_guard = None

    async def send_response(self, code: int, message: str):
        """Send FTP response to client"""
        response = f"{code} {message}\r\n"
        self.writer.write(response.encode())
        await self.writer.drain()

        # Record response in session transcript if enabled
        if self.session_recording and self.session_transcript is not None:
            self.session_transcript.append(
                {
                    "timestamp": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                    "type": "output",
                    "content": response.strip(),
                    "code": code,
                    "message": message,
                }
            )

        # Log response
        logger.info(
            "FTP response",
            extra={
                "details": b64encode(response.encode("utf-8")).decode("utf-8"),
                "response_code": code,
                "response_message": message,
            },
        )

    async def handle_command(self, command_line: str):
        """Handle FTP command with AI analysis"""
        command_line = command_line.strip()
        if not command_line:
            return

        # Handle special case where user just types password after USER command
        if (
            not command_line.upper().startswith(
                (
                    "USER",
                    "PASS",
                    "QUIT",
                    "HELP",
                    "LIST",
                    "NLST",
                    "PWD",
                    "CWD",
                    "SYST",
                    "PORT",
                    "PASV",
                    "TYPE",
                    "RETR",
                    "STOR",
                    "NOOP",
                    "CDUP",
                    "LS",
                    "DIR",
                )
            )
            and self.username
            and not self.authenticated
        ):
            # Treat as password
            command = "PASS"
            args = command_line
        else:
            # Parse command normally
            parts = command_line.split(" ", 1)
            command = parts[0].upper()
            # Handle telnet aliases
            if command == "LS" or command == "DIR":
                command = "LIST"
            args = parts[1] if len(parts) > 1 else ""

        # Record session transcript if enabled
        if self.session_recording and self.session_transcript is not None:
            self.session_transcript.append(
                {
                    "timestamp": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                    "type": "input",
                    "content": command_line,
                    "command": command,
                    "args": args,
                }
            )

        # Log command
        logger.info(
            "FTP command",
            extra={
                "details": b64encode(command_line.encode("utf-8")).decode("utf-8"),
                "command": command,
                "command_args": args,
                "username": self.username,
            },
        )

        # Analyze command for attacks if real-time analysis is enabled
        attack_analysis = {
            "command": command_line,
            "attack_types": [],
            "severity": "low",
        }
        vulnerabilities = []

        if self.attack_analyzer and config["ai_features"].getboolean(
            "real_time_analysis", True
        ):
            try:
                attack_analysis = self.attack_analyzer.analyze_command(command_line)
                self.session_data["attack_analysis"].append(attack_analysis)
            except Exception as e:
                logger.error(f"Attack analysis failed: {e}")

        if self.vuln_logger and config["ai_features"].getboolean(
            "vulnerability_detection", True
        ):
            try:
                vulnerabilities = self.vuln_logger.analyze_for_vulnerabilities(
                    command_line
                )
                self.session_data["vulnerabilities"].extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Vulnerability analysis failed: {e}")

        # Log attack analysis if threats detected
        if attack_analysis.get("attack_types"):
            log_extra = {
                "attack_types": attack_analysis["attack_types"],
                "severity": attack_analysis["severity"],
                "indicators": attack_analysis.get("indicators", []),
                "command": command_line,
            }

            # Add threat score if available
            if "threat_score" in attack_analysis:
                log_extra["threat_score"] = attack_analysis["threat_score"]

            # Check if alert should be triggered
            if attack_analysis.get("alert_triggered", False):
                logger.critical("High-threat FTP attack detected", extra=log_extra)
            else:
                logger.warning("FTP attack pattern detected", extra=log_extra)

            if self.forensic_logger:
                try:
                    self.forensic_logger.log_event("attack_detected", attack_analysis)
                except Exception as e:
                    logger.error(f"Forensic logging failed: {e}")

        # Log vulnerabilities with enhanced context
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = dict(vuln)
                enhanced_vuln["related_attack_types"] = attack_analysis.get(
                    "attack_types", []
                )
                enhanced_vuln["overall_severity"] = attack_analysis.get(
                    "severity", "low"
                )
                enhanced_vuln["threat_score"] = attack_analysis.get("threat_score", 0)

                # Rename "name" to "vuln_name" to avoid LogRecord attribute conflict
                if "name" in enhanced_vuln:
                    enhanced_vuln["vuln_name"] = enhanced_vuln.pop("name")

                # Check alert threshold for vulnerabilities
                alert_threshold = config["attack_detection"].getint(
                    "alert_threshold", 70
                )
                if enhanced_vuln["threat_score"] >= alert_threshold:
                    logger.critical(
                        "Critical FTP vulnerability exploitation attempt",
                        extra=enhanced_vuln,
                    )
                else:
                    logger.critical(
                        "FTP vulnerability exploitation attempt", extra=enhanced_vuln
                    )

                if self.forensic_logger:
                    self.forensic_logger.log_event(
                        "vulnerability_exploit", enhanced_vuln
                    )
            except Exception as e:
                logger.error(f"Vulnerability logging failed: {e}")

        # Store command in session data
        self.session_data["commands"].append(
            {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "command": command_line,
                "attack_analysis": attack_analysis,
                "vulnerabilities": vulnerabilities,
            }
        )

        # Handle specific FTP commands
        result = await self.handle_ftp_command(command, args, attack_analysis)
        return result if result is not None else True

    async def handle_ftp_command(
        self, command: str, args: str, attack_analysis: Dict[str, Any]
    ):
        """Handle FTP commands with 3-layer dispatch: VFS, error simulation, LLM fallback"""

        # ===== Authentication commands (handled manually, not by dispatcher) =====
        if command == "USER":
            self.username = args
            # Set filesystem user context if available
            if self.filesystem:
                self.filesystem.set_user(args if args else "ftp")
            await self.send_response(331, f"Password required for {args}")
            return True
        elif command == "PASS":
            if not self.username:
                await self.send_response(503, "Login with USER first")
                return True
            if self.username in accounts and (
                args == accounts[self.username] or accounts[self.username] == "*"
            ):
                self.authenticated = True
                # Set filesystem user context on successful auth
                if self.filesystem:
                    self.filesystem.set_user(self.username)
                    
                    # Load per-user VFS state for persistence
                    sessions_dir = Path(config["honeypot"].get("sessions_dir", "sessions"))
                    user_state_dir = sessions_dir / "user_states" / self.username
                    user_state_dir.mkdir(parents=True, exist_ok=True)
                    user_state_path = user_state_dir / "filesystem_state.json"
                    
                    if user_state_path.exists():
                        if self.filesystem.load_state(str(user_state_path)):
                            logger.info(f"Loaded persisted VFS state for user {self.username}")
                    
                    # Set initial directory based on user
                    self.current_directory = "/var/ftp/pub"
                    
                await self.send_response(230, f"User {self.username} logged in")
                logger.info(
                    "FTP authentication success",
                    extra={"username": self.username, "password": args},
                )
            else:
                await self.send_response(530, "Login incorrect")
                logger.info(
                    "FTP authentication failed",
                    extra={"username": self.username, "password": args},
                )
            return True
        elif command == "QUIT":
            # Save VFS state to per-user location before quitting
            if self.filesystem and self.username:
                try:
                    sessions_dir = Path(config["honeypot"].get("sessions_dir", "sessions"))
                    user_state_dir = sessions_dir / "user_states" / self.username
                    user_state_dir.mkdir(parents=True, exist_ok=True)
                    user_state_path = user_state_dir / "filesystem_state.json"
                    
                    self.filesystem.save_state(str(user_state_path))
                    logger.info(f"Saved VFS state for user {self.username} to {user_state_path}")
                except Exception as e:
                    logger.error(f"Failed to save VFS state: {e}")
            await self.send_response(221, "Goodbye")
            return False
        elif command == "PORT":
            await self.handle_active_mode(args)
            return True
        elif command == "PASV":
            await self.handle_passive_mode()
            return True

        # ===== 3-Layer Dispatch using CommandExecutor =====
        if self.command_executor:
            # Use the hybrid honeypot dispatch system
            result = self.command_executor.execute(
                command=command,
                args=args,
                current_dir=self.current_directory,
                username=self.username or "anonymous",
                authenticated=self.authenticated,
            )
            
            route = result.get("route")
            
            # Layer 1 & 2: VFS execution or error response
            if route in ("vfs", "error"):
                code = result.get("code", 500)
                message = result.get("message", "Error")
                
                # Handle directory change commands
                if result.get("new_dir"):
                    self.current_directory = result["new_dir"]
                
                # Handle transfer type changes
                if result.get("transfer_type"):
                    self.transfer_mode = result["transfer_type"]
                
                # Handle data transfer commands (LIST, RETR, MLSD)
                if result.get("data") is not None:
                    await self.send_response(code, message)
                    
                    # Send data via data connection or control connection
                    data = result["data"]
                    if hasattr(self, "data_writer") and self.data_writer:
                        try:
                            if isinstance(data, str):
                                self.data_writer.write(data.encode() + b"\r\n")
                            else:
                                self.data_writer.write(data)
                            await self.data_writer.drain()
                            self.data_writer.close()
                            await self.data_writer.wait_closed()
                            self.data_writer = None
                        except Exception as e:
                            logger.error(f"Data connection error: {e}")
                            # Fall back to control connection
                            for line in str(data).split("\n"):
                                if line.strip():
                                    self.writer.write(f"{line}\r\n".encode())
                                    await self.writer.drain()
                    else:
                        # Send via control connection for telnet clients
                        for line in str(data).split("\n"):
                            if line.strip():
                                self.writer.write(f"{line}\r\n".encode())
                                await self.writer.drain()
                    
                    # Send completion message if provided
                    if result.get("data_complete_code"):
                        await asyncio.sleep(0.1)  # Simulate transfer delay
                        await self.send_response(
                            result["data_complete_code"],
                            result.get("data_complete_message", "Transfer complete")
                        )
                    
                    # Log the data transfer
                    logger.info(
                        "FTP data transfer",
                        extra={
                            "command": command,
                            "directory": self.current_directory,
                            "bytes": len(str(data)),
                        },
                    )
                
                # Handle STOR command (file upload)
                elif result.get("stor_path"):
                    await self.send_response(code, message)
                    
                    # Read data from data connection
                    uploaded_content = b""
                    if hasattr(self, "data_reader") and self.data_reader:
                        try:
                            uploaded_content = await asyncio.wait_for(
                                self.data_reader.read(10 * 1024 * 1024),  # Max 10MB
                                timeout=30.0
                            )
                        except asyncio.TimeoutError:
                            logger.warning("File upload timed out")
                        except Exception as e:
                            logger.error(f"Error reading upload data: {e}")
                    
                    # Store the file in VFS
                    if uploaded_content:
                        if result.get("append"):
                            success = self.command_executor.complete_appe(
                                result["stor_path"],
                                uploaded_content.decode('utf-8', errors='replace'),
                                result.get("stor_username", self.username or "ftp")
                            )
                        else:
                            success = self.command_executor.complete_stor(
                                result["stor_path"],
                                uploaded_content.decode('utf-8', errors='replace'),
                                result.get("stor_username", self.username or "ftp")
                            )
                        
                        if success:
                            await self.send_response(226, "Transfer complete")
                            # Track upload in session
                            if self.file_handler:
                                upload_info = self.file_handler.handle_upload(
                                    result["stor_path"].split("/")[-1],
                                    uploaded_content
                                )
                                self.session_data["files_uploaded"].append(upload_info)
                        else:
                            await self.send_response(550, "Upload failed")
                    else:
                        await self.send_response(226, "Transfer complete (empty file)")
                
                # Standard response (no data connection)
                else:
                    await self.send_response(code, message)
                
                return True
            
            # Layer 3: LLM fallback
            elif route == "llm":
                return await self._handle_llm_fallback(command, args, attack_analysis, result)
        
        # ===== Legacy LLM-only mode (if VFS not available) =====
        else:
            return await self._handle_llm_legacy(command, args, attack_analysis)

        return True

    async def _handle_llm_fallback(
        self, command: str, args: str, attack_analysis: Dict[str, Any], dispatch_result: Dict
    ):
        """Handle commands via LLM with context injection"""
        full_command = f"{command} {args}".strip()
        
        # Build enhanced prompt with VFS context
        if self.llm_guard and self.filesystem:
            ai_prompt = self.llm_guard.enhance_prompt(
                command, args, self.filesystem, self.current_directory, self.username or "anonymous"
            )
        else:
            ai_prompt = dispatch_result.get("llm_prompt", f"FTP Command: {full_command}")
        
        # Add attack context
        if config["ai_features"].getboolean("dynamic_responses", True) and attack_analysis.get("attack_types"):
            ai_prompt += f"\n[ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"
        
        try:
            # Get AI response with timeout
            llm_response = await asyncio.wait_for(
                with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=ai_prompt)],
                        "username": self.username or "anonymous",
                        "interactive": True,
                    },
                    config={"configurable": {"session_id": self.llm_session_id}},
                ),
                timeout=30.0,
            )
            
            ai_output = llm_response.content.strip() if llm_response else ""
            
            # Validate LLM output
            if self.llm_guard:
                validation = self.llm_guard.validate_output(
                    ai_output, command, args, self.filesystem, self.current_directory
                )
                
                if not validation["is_valid"]:
                    logger.warning(f"LLM output validation failed: {validation['reason']}")
                    fallback = self.llm_guard.get_fallback_response(command, validation["reason"])
                    await self.send_response(fallback["code"], fallback["message"])
                    return True
                
                # Use validated/cleaned response
                code = validation.get("code", 200)
                message = validation.get("message", "OK")
                await self.send_response(code, message)
            else:
                # Parse response without validation
                if ai_output and len(ai_output) >= 3 and ai_output[:3].isdigit():
                    code = int(ai_output[:3])
                    message = ai_output[4:] if len(ai_output) > 4 else "OK"
                    await self.send_response(code, message)
                else:
                    await self.send_response(200, ai_output if ai_output else "OK")
            
            logger.info(
                "LLM FTP response",
                extra={"command": full_command, "ai_response": ai_output, "username": self.username},
            )
            
        except asyncio.TimeoutError:
            logger.warning(f"LLM command processing timed out for '{full_command}'")
            await self.send_response(200, "Command okay")
        except Exception as e:
            logger.error(f"LLM command processing failed for '{full_command}': {e}", exc_info=True)
            await self.send_response(502, f"Command not implemented: {command}")
        
        return True

    async def _handle_llm_legacy(self, command: str, args: str, attack_analysis: Dict[str, Any]):
        """Legacy LLM-only handling when VFS is not available"""
        # Check authentication for protected commands
        if (
            command in ["LIST", "NLST", "RETR", "STOR", "CWD", "PWD", "CDUP", 
                        "MKD", "RMD", "DELE", "SIZE", "MDTM"]
            and not self.authenticated
        ):
            await self.send_response(530, "Please login with USER and PASS")
            return True

        # Use legacy LIST handler
        if command == "LIST" or command == "NLST":
            await self.handle_list_command(command, args, attack_analysis)
            return True

        # Let LLM handle other commands
        full_command = f"{command} {args}".strip()
        ai_prompt = f"""FTP Command: {full_command}
Current Directory: {self.current_directory}
Username: {self.username}
Authenticated: {self.authenticated}

You are an FTP server. Respond with a proper FTP response code (3 digits) followed by a message.
Examples:
- "200 Command okay"
- "215 UNIX Type: L8"
- "257 "/home/user" is current directory"
- "226 Transfer complete"
- "550 File not found"

Important: Start your response with a 3-digit FTP code."""

        try:
            llm_response = await asyncio.wait_for(
                with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=ai_prompt)],
                        "username": self.username or "anonymous",
                        "interactive": True,
                    },
                    config={"configurable": {"session_id": self.llm_session_id}},
                ),
                timeout=30.0,
            )

            ai_output = llm_response.content.strip() if llm_response else ""
            
            if not ai_output:
                await self.send_response(502, "Command not implemented")
                return True

            # Parse FTP response
            lines = ai_output.strip().split("\n")
            first_line = lines[0].strip()

            if len(first_line) >= 3 and first_line[:3].isdigit():
                ftp_code = int(first_line[:3])
                ftp_message = first_line[4:] if len(first_line) > 4 else "OK"
                await self.send_response(ftp_code, ftp_message)
            else:
                await self.send_response(200, first_line)

        except asyncio.TimeoutError:
            await self.send_response(200, "Command okay")
        except Exception as e:
            logger.error(f"LLM command processing failed: {e}")
            await self.send_response(502, f"Command not implemented: {command}")

        return True


    async def handle_list_command(
        self, command: str, args: str, attack_analysis: Dict[str, Any]
    ):
        """Handle LIST/NLST commands with LLM-generated directory listings"""

        await self.send_response(
            150, "Opening ASCII mode data connection for file list"
        )

        # Get LLM to generate realistic directory listing
        directory_listing = None

        # Build detailed prompt for directory listing
        ai_prompt = f"""FTP {command} Command
Current Directory: {self.current_directory}
User: {self.username}
Authenticated: {self.authenticated}
Arguments: {args if args else "(none)"}

Generate a realistic Unix-style directory listing for an FTP server at a game development company.
Show files and directories that would exist in: {self.current_directory}

Format each line as:
drwxr-xr-x  2 ftp  ftp   4096 Jan 15 14:30 directoryname
-rw-r--r--  1 ftp  ftp  12345 Jan 15 14:30 filename.ext

Include realistic game development files (.fbx, .unity, .uasset, .zip, .png, .wav, etc.)
Include realistic directories (assets/, builds/, backups/, config/, games/, etc.)

DO NOT include any FTP status codes (like 150, 226) in your response.
ONLY output the directory listing lines, one per line."""

        try:
            # Use persistent session for better context
            llm_response = await asyncio.wait_for(
                with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=ai_prompt)],
                        "username": self.username or "anonymous",
                        "interactive": True,
                    },
                    config={"configurable": {"session_id": self.llm_session_id}},
                ),
                timeout=10.0,  # Increased timeout for directory generation
            )

            if llm_response and llm_response.content:
                ai_text = llm_response.content.strip()

                # Clean up the response - remove any FTP status codes LLM might have included
                lines = []
                for line in ai_text.splitlines():
                    line = line.strip()
                    # Skip empty lines and FTP status codes
                    if line and not re.match(r"^[1-5]\d{2}\s", line):
                        lines.append(line)

                if lines:
                    directory_listing = "\n".join(lines)
                    logger.info(
                        "LLM generated directory listing",
                        extra={
                            "username": self.username,
                            "directory": self.current_directory,
                            "line_count": len(lines),
                        },
                    )
                else:
                    logger.warning(
                        "LLM returned empty directory listing, using fallback"
                    )
                    directory_listing = None

        except asyncio.TimeoutError:
            logger.warning(
                "LLM LIST request timed out, using fallback",
                extra={"username": self.username},
            )
            directory_listing = None
        except Exception as e:
            logger.error(
                f"LLM LIST generation failed: {e}", extra={"username": self.username}
            )
            directory_listing = None

        # Use fallback only if LLM failed
        if not directory_listing:
            directory_listing = self._generate_fallback_listing()

        # Send directory listing to client
        if directory_listing:
            # Send via data connection if available, otherwise via control connection
            if hasattr(self, "data_writer") and self.data_writer:
                try:
                    self.data_writer.write(directory_listing.encode() + b"\r\n")
                    await self.data_writer.drain()
                    self.data_writer.close()
                    await self.data_writer.wait_closed()
                    self.data_writer = None
                except Exception as e:
                    logger.error(f"Data connection error: {e}")
                    # Fall back to control connection
                    for line in directory_listing.split("\n"):
                        if line.strip():
                            self.writer.write(f"{line}\r\n".encode())
                            await self.writer.drain()
            else:
                # Send via control connection for telnet clients
                for line in directory_listing.split("\n"):
                    if line.strip():
                        self.writer.write(f"{line}\r\n".encode())
                        await self.writer.drain()

        # Simulate transfer delay
        await asyncio.sleep(0.1)

        # Send completion message
        await self.send_response(226, "Transfer complete")

        # Log the listing
        logger.info(
            "FTP directory listing sent",
            extra={
                "details": b64encode(directory_listing.encode("utf-8")).decode("utf-8"),
                "command": command,
                "directory": self.current_directory,
                "bytes": len(directory_listing),
            },
        )

    async def handle_download(self, filename: str, attack_analysis: Dict[str, Any]):
        """Handle file download (RETR command)"""

        if self.file_handler:
            try:
                download_info = self.file_handler.handle_download(filename)
                self.session_data["files_downloaded"].append(download_info)

                await self.send_response(150, f"Opening data connection for {filename}")
                await asyncio.sleep(0.2)  # Simulate transfer time
                await self.send_response(226, "Transfer complete")

                logger.info("FTP file download", extra=download_info)

                if self.forensic_logger:
                    self.forensic_logger.log_event("file_download", download_info)
                    if download_info.get("file_path"):
                        self.forensic_logger.add_evidence(
                            "downloaded_file",
                            download_info["file_path"],
                            f"File downloaded via FTP: {filename}",
                        )

            except Exception as e:
                logger.error(f"File download handling failed: {e}")
                await self.send_response(550, "File not found")
        else:
            await self.send_response(550, "File not found")

    async def handle_upload(self, filename: str, attack_analysis: Dict[str, Any]):
        """Handle file upload (STOR command)"""

        await self.send_response(150, f"Opening data connection for {filename}")

        # Simulate receiving file data
        fake_content = f"Uploaded file: {filename}\nTimestamp: {datetime.datetime.now()}\nThis is a honeypot simulation".encode()

        if self.file_handler:
            try:
                upload_info = self.file_handler.handle_upload(filename, fake_content)
                self.session_data["files_uploaded"].append(upload_info)

                await self.send_response(226, "Transfer complete")

                logger.info("FTP file upload", extra=upload_info)

                if self.forensic_logger:
                    self.forensic_logger.log_event("file_upload", upload_info)
                    if upload_info.get("file_path"):
                        self.forensic_logger.add_evidence(
                            "uploaded_file",
                            upload_info["file_path"],
                            f"File uploaded via FTP: {filename}",
                        )

            except Exception as e:
                logger.error(f"File upload handling failed: {e}")
                await self.send_response(550, "Upload failed")
        else:
            await self.send_response(550, "Upload failed")

    async def handle_passive_mode(self):
        """Handle PASV command"""
        # Generate fake passive mode response
        ip_parts = "192,168,1,100"  # Fake IP
        port_high = 20
        port_low = 21
        await self.send_response(
            227, f"Entering Passive Mode ({ip_parts},{port_high},{port_low})"
        )

    async def handle_active_mode(self, args: str):
        """Handle PORT command with proper data connection setup"""
        try:
            # Parse PORT command arguments
            parts = args.split(",")
            if len(parts) == 6:
                ip = ".".join(parts[:4])
                port = int(parts[4]) * 256 + int(parts[5])

                # Store data connection info
                self.data_ip = ip
                self.data_port = port

                # Try to establish data connection for next data transfer
                try:
                    reader, writer = await asyncio.open_connection(ip, port)
                    self.data_reader = reader
                    self.data_writer = writer
                    await self.send_response(
                        200,
                        "PORT command successful. Consider using PASV for better firewall compatibility.",
                    )
                    logger.info(
                        "FTP active mode", extra={"client_ip": ip, "client_port": port}
                    )
                except Exception as conn_error:
                    logger.warning(
                        f"Could not establish data connection to {ip}:{port}: {conn_error}"
                    )
                    await self.send_response(
                        200,
                        "PORT command successful. Consider using PASV for better firewall compatibility.",
                    )
            else:
                await self.send_response(501, "Syntax error in PORT command")
        except Exception as e:
            await self.send_response(501, "Syntax error in PORT command")

    async def handle_unknown_command(
        self, command: str, args: str, attack_analysis: Dict[str, Any]
    ):
        """Handle unknown FTP commands with AI response"""

        # Default response
        default_response = (502, "Command not implemented")

        try:
            if "with_message_history" in globals():
                enhanced_command = f"FTP command: {command} {args}. Respond with proper FTP status code and message."
                if attack_analysis.get("attack_types"):
                    enhanced_command += f" [ATTACK_DETECTED: {', '.join(attack_analysis['attack_types'])}]"

                llm_response = await with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=enhanced_command)],
                        "username": self.username,
                        "interactive": True,
                    },
                    config={"configurable": {"session_id": f"ftp-{uuid.uuid4()}"}},
                )

                # Parse AI response for FTP code and message
                if llm_response and llm_response.content:
                    response_text = llm_response.content.strip()
                    if (
                        response_text.startswith(("2", "3", "4", "5"))
                        and len(response_text) > 3
                    ):
                        code = int(response_text[:3])
                        message = response_text[4:]
                        await self.send_response(code, message)
                        return

        except Exception as e:
            logger.error(f"LLM request failed for unknown command: {e}")

        # Use default response
        await self.send_response(default_response[0], default_response[1])

    def _resolve_path(self, path: str) -> str:
        """Resolve path with security checks"""
        # Sanitize path to prevent traversal attacks
        path = path.replace("..", "").replace("\\", "/")

        if path.startswith("/"):
            # Ensure path stays within allowed root
            if not path.startswith("/home/ftp"):
                return "/home/ftp"
            return path
        else:
            resolved = f"{self.current_directory}/{path}".replace("//", "/")
            # Ensure resolved path stays within allowed root
            if not resolved.startswith("/home/ftp"):
                return "/home/ftp"
            return resolved

    def _generate_fallback_listing(self) -> str:
        """Generate fallback directory listing"""
        return """drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 assets
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 backups
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 builds
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 config
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 games
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 logs
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 pub
drwxr-xr-x    2 ftp      ftp          4096 Jan 15 14:30 uploads"""


class MyFTPServer:
    """FTP Server with AI-enhanced responses and comprehensive logging"""

    def __init__(self):
        self.sessions = {}

        # Create session directory
        session_id = f"ftp_session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        sessions_dir = Path(config["honeypot"].get("sessions_dir", "sessions"))
        self.session_dir = sessions_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)

    async def generate_session_summary(self, session):
        """Generate AI-powered session summary with comprehensive analysis"""
        try:
            # Collect session data
            commands = session.session_data.get("commands", [])
            command_list = [cmd.get("command", "") for cmd in commands][:50]  # Limit to 50 for prompt size
            
            attack_patterns = []
            for analysis in session.session_data.get("attack_analysis", []):
                if analysis.get("attack_types"):
                    attack_patterns.extend(analysis["attack_types"])
            attack_patterns = list(set(attack_patterns))  # Unique patterns
            
            vulnerabilities = [vuln.get("vulnerability_id", "") for vuln in session.session_data.get("vulnerabilities", [])]
            files_downloaded = [file.get("filename", "") for file in session.session_data.get("files_downloaded", [])]
            files_uploaded = [file.get("filename", "") for file in session.session_data.get("files_uploaded", [])]
            
            duration = session.session_data.get("duration", "unknown")
            username = session.username or "anonymous"
            
            # Build comprehensive analysis prompt
            prompt = f"""[SECURITY ANALYST MODE]
You are a cybersecurity analyst reviewing an FTP honeypot session. Analyze the following session data and provide a detailed security assessment.

=== SESSION DATA ===
Username: {username}
Duration: {duration}
Total Commands: {len(commands)}
Commands Executed: {', '.join(command_list[:30])}{'...' if len(command_list) > 30 else ''}

Attack Patterns Detected: {', '.join(attack_patterns) if attack_patterns else 'None'}
Vulnerability Exploits Attempted: {', '.join(vulnerabilities) if vulnerabilities else 'None'}

Files Downloaded: {', '.join(files_downloaded) if files_downloaded else 'None'}
Files Uploaded: {', '.join(files_uploaded) if files_uploaded else 'None'}

=== ANALYSIS REQUIRED ===
Provide a structured analysis with the following sections:

1. **Attack Stage Identification**
   - Reconnaissance, Initial Access, Execution, Persistence, Lateral Movement, Exfiltration, etc.

2. **Attacker Objectives**
   - What was the attacker trying to achieve based on the command patterns?

3. **Threat Level Assessment**
   - Severity rating with justification

4. **Key Indicators of Compromise (IOCs)**
   - List specific commands or patterns that indicate malicious intent

5. **Recommended Actions**
   - What security measures should be taken based on this session?

=== FINAL JUDGEMENT ===
End your analysis with exactly one of these judgements on a new line:
Judgement: BENIGN
Judgement: SUSPICIOUS  
Judgement: MALICIOUS

Remember: This is a honeypot session analysis. Do NOT respond as an FTP server. Provide security analysis only."""

            # Use a dedicated session ID for summaries (separate from command responses)
            summary_session_id = f"ftp-analysis-{uuid.uuid4().hex[:12]}"
            
            # Query LLM with timeout
            llm_response = await asyncio.wait_for(
                with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=prompt)],
                        "username": "security_analyst",
                        "interactive": False,  # Not interactive command mode
                    },
                    config={"configurable": {"session_id": summary_session_id}},
                ),
                timeout=60.0,  # Longer timeout for analysis
            )

            if not llm_response or not llm_response.content:
                logger.warning("LLM returned empty response for session summary")
                self._log_fallback_summary(session, "LLM returned empty response")
                return

            analysis_content = llm_response.content.strip()
            
            # Validate response looks like an analysis, not an FTP command
            if analysis_content.startswith(("220", "221", "230", "331", "500", "550")):
                logger.warning("LLM returned FTP response instead of analysis, using fallback")
                self._log_fallback_summary(session, "LLM broke character")
                return

            # Parse judgement from response
            judgement = "UNKNOWN"
            if "Judgement: BENIGN" in analysis_content or "JUDGEMENT: BENIGN" in analysis_content.upper():
                judgement = "BENIGN"
            elif "Judgement: SUSPICIOUS" in analysis_content or "JUDGEMENT: SUSPICIOUS" in analysis_content.upper():
                judgement = "SUSPICIOUS"
            elif "Judgement: MALICIOUS" in analysis_content or "JUDGEMENT: MALICIOUS" in analysis_content.upper():
                judgement = "MALICIOUS"

            # Log the full analysis
            logger.info(
                "FTP session analysis complete",
                extra={
                    "analysis": analysis_content,
                    "judgement": judgement,
                    "session_commands": len(commands),
                    "attack_patterns_detected": len(attack_patterns),
                    "vulnerabilities_detected": len(vulnerabilities),
                    "files_downloaded": len(files_downloaded),
                    "files_uploaded": len(files_uploaded),
                    "username": username,
                    "duration": str(duration),
                },
            )
            
            # Also save analysis to session data
            session.session_data["ai_analysis"] = {
                "content": analysis_content,
                "judgement": judgement,
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

        except asyncio.TimeoutError:
            logger.warning("Session summary generation timed out after 60 seconds")
            self._log_fallback_summary(session, "Analysis timed out")
        except Exception as e:
            logger.error(f"Session summary generation failed: {e}", exc_info=True)
            self._log_fallback_summary(session, str(e))

    def _log_fallback_summary(self, session, reason: str):
        """Log a fallback summary when AI analysis fails"""
        commands = session.session_data.get("commands", [])
        attack_patterns = []
        for analysis in session.session_data.get("attack_analysis", []):
            if analysis.get("attack_types"):
                attack_patterns.extend(analysis["attack_types"])
        
        # Simple rule-based judgement as fallback
        judgement = "UNKNOWN"
        if len(attack_patterns) > 5:
            judgement = "MALICIOUS"
        elif len(attack_patterns) > 0:
            judgement = "SUSPICIOUS"
        elif len(commands) < 5:
            judgement = "BENIGN"

        logger.info(
            "FTP session summary (fallback)",
            extra={
                "analysis": f"Fallback analysis - {reason}",
                "judgement": judgement,
                "session_commands": len(commands),
                "attack_patterns_detected": len(attack_patterns),
                "username": session.username or "anonymous",
            },
        )


    async def handle_client(self, reader, writer):
        """Handle FTP client connection"""

        # Get connection details
        peername = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")

        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = "-", "-"

        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = "-", "-"

        # Store connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        # Create session
        session = FTPSession(reader, writer, self)
        task_uuid = f"ftp-session-{uuid.uuid4()}"

        # Set task name for logging
        current_task = asyncio.current_task()
        if current_task is not None and hasattr(current_task, "set_name"):
            current_task.set_name(task_uuid)

        # Log connection
        connection_info = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "session_id": task_uuid,
            "session_dir": str(self.session_dir),
        }

        # Add AI features status
        connection_info["ai_features_enabled"] = {
            "dynamic_responses": config["ai_features"].getboolean(
                "dynamic_responses", True
            ),
            "attack_pattern_recognition": config["ai_features"].getboolean(
                "attack_pattern_recognition", True
            ),
            "vulnerability_detection": config["ai_features"].getboolean(
                "vulnerability_detection", True
            ),
            "adaptive_banners": config["ai_features"].getboolean(
                "adaptive_banners", True
            ),
            "deception_techniques": config["ai_features"].getboolean(
                "deception_techniques", True
            ),
        }

        # Add forensics configuration status
        connection_info["file_monitoring_enabled"] = config["forensics"].getboolean(
            "file_monitoring", True
        )
        connection_info["chain_of_custody_enabled"] = config["forensics"].getboolean(
            "chain_of_custody", True
        )

        logger.info("FTP connection received", extra=connection_info)

        if session.forensic_logger:
            try:
                session.forensic_logger.log_event(
                    "connection_established", connection_info
                )
            except Exception as e:
                logger.error(f"Forensic logging failed: {e}")

        try:
            # Send welcome message with adaptive banner if enabled
            banner_message = "NexusGames Studio FTP Server Ready"

            # Apply adaptive banners if enabled
            if config["ai_features"].getboolean("adaptive_banners", True):
                # Modify banner based on source IP or attack patterns
                if src_ip != "unknown" and not src_ip.startswith("192.168."):
                    banner_message += f" (Last connection from {src_ip})"

            await session.send_response(220, banner_message)

            # Handle commands
            while True:
                try:
                    data = await reader.readline()
                    if not data:
                        break

                    command_line = data.decode("utf-8", errors="ignore").strip()
                    if not command_line:
                        continue

                    # Handle command
                    try:
                        continue_session = await session.handle_command(command_line)
                        if not continue_session:
                            break
                    except Exception as cmd_error:
                        logger.error(f"Command processing error: {cmd_error}")
                        await session.send_response(500, "Internal server error")
                        continue

                except asyncio.IncompleteReadError:
                    break
                except Exception as e:
                    logger.error(f"Error handling FTP command: {e}")
                    break

        except Exception as e:
            logger.error(f"FTP session error: {e}")
        finally:
            # Save session summary
            session.session_data["end_time"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            session.session_data["duration"] = str(
                datetime.datetime.fromisoformat(session.session_data["end_time"])
                - datetime.datetime.fromisoformat(session.session_data["start_time"])
            )

            # Save session data if forensic reports are enabled
            if config["forensics"].getboolean("forensic_reports", True):
                session_file = self.session_dir / "session_summary.json"
                with open(session_file, "w") as f:
                    json.dump(session.session_data, f, indent=2)

                # Save replay data if enabled
                if (
                    session.save_replay
                    and hasattr(session, "session_transcript")
                    and session.session_transcript
                ):
                    replay_file = self.session_dir / "session_replay.json"
                    with open(replay_file, "w") as f:
                        json.dump(
                            {
                                "session_id": task_uuid,
                                "start_time": session.session_data["start_time"],
                                "end_time": session.session_data["end_time"],
                                "transcript": session.session_transcript,
                            },
                            f,
                            indent=2,
                        )

                if session.forensic_logger:
                    try:
                        session.forensic_logger.add_evidence(
                            "session_summary",
                            str(session_file),
                            "Complete FTP session activity summary",
                        )
                        if (
                            session.save_replay
                            and hasattr(session, "session_transcript")
                            and session.session_transcript
                        ):
                            replay_file = self.session_dir / "session_replay.json"
                            session.forensic_logger.add_evidence(
                                "session_replay",
                                str(replay_file),
                                "Complete FTP session transcript for replay",
                            )
                        session.forensic_logger.log_event(
                            "connection_closed", {"reason": "normal_closure"}
                        )
                    except Exception as e:
                        logger.error(f"Forensic finalization failed: {e}")

            # Ensure downloads/uploads directories exist under the session dir
            try:
                downloads_dir = self.session_dir / "downloads"
                uploads_dir = self.session_dir / "uploads"
                downloads_dir.mkdir(parents=True, exist_ok=True)
                uploads_dir.mkdir(parents=True, exist_ok=True)

                # Write metadata file
                meta = {
                    "session_id": task_uuid,
                    "username": session.username,
                    "client_ip": thread_local.__dict__.get("src_ip", "-"),
                    "started": session.session_data.get("start_time"),
                    "ended": session.session_data.get("end_time"),
                }
                with open(self.session_dir / "meta.json", "w", encoding="utf-8") as mf:
                    json.dump(meta, mf, indent=2)
            except Exception as e:
                logger.error(f"Session finalization failed: {e}")

            # Generate session summary using AI if enabled
            if session.session_data.get("commands") and config[
                "ai_features"
            ].getboolean("ai_attack_summaries", True):
                try:
                    await self.generate_session_summary(session)
                except Exception as e:
                    logger.error(f"Session summary generation failed: {e}")

            logger.info("FTP connection closed")
            writer.close()
            await writer.wait_closed()


async def start_server():
    """Start the FTP server"""
    server_instance = MyFTPServer()

    host = config["ftp"].get("host", "0.0.0.0")
    port = config["ftp"].getint("port", 2121)

    server = await asyncio.start_server(
        server_instance.handle_client, host=host, port=port, reuse_address=True
    )

    llm_provider = config["llm"].get("llm_provider", "openai")
    model_name = config["llm"].get("model_name", "gpt-4o-mini")

    print(f"\n[+] FTP Honeypot Starting...")
    print(f"[*] Host: {host}")
    print(f"[*] Port: {port}")
    print(f"[*] LLM Provider: {llm_provider}")
    print(f"[*] Model: {model_name}")
    print(f"[*] Sensor: {sensor_name}")
    print(f"[*] Log File: {config['honeypot'].get('log_file', 'ftp_log.log')}")
    print(f"[!] Press Ctrl+C to stop\n")

    logger.info(f"FTP honeypot started on {host}:{port}")
    print(f"[+] FTP honeypot listening on {host}:{port}")
    print("[*] Ready for connections...")

    try:
        async with server:
            await server.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[-] FTP honeypot stopped by user")
        logger.info("FTP honeypot stopped by user")
        raise


class ContextFilter(logging.Filter):
    """Filter to add asyncio task name to log records"""

    def filter(self, record):
        try:
            task_name = getattr(asyncio.current_task(), "get_name", lambda: "-")()
        except RuntimeError:
            task_name = thread_local.__dict__.get("session_id", "-")

        record.src_ip = thread_local.__dict__.get("src_ip", "-")
        record.src_port = thread_local.__dict__.get("src_port", "-")
        record.dst_ip = thread_local.__dict__.get("dst_ip", "-")
        record.dst_port = thread_local.__dict__.get("dst_port", "-")
        record.task_name = task_name

        return True


def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]


def get_user_accounts() -> dict:
    if (not "user_accounts" in config) or (len(config.items("user_accounts")) == 0):
        raise ValueError("No user accounts found in configuration file.")

    accounts = dict()
    for k, v in config.items("user_accounts"):
        accounts[k] = v
    return accounts


def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    llm_provider_name = llm_provider or config["llm"].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = model_name or config["llm"].get("model_name", "gpt-4o-mini")

    temperature = config["llm"].getfloat("temperature", 0.2)
    base_kwargs = {"temperature": temperature}
    openai_kwargs = {**base_kwargs, "request_timeout": 30, "max_retries": 2}
    gemini_kwargs = {**base_kwargs, "timeout": 30}
    other_kwargs = {**base_kwargs, "request_timeout": 30, "max_retries": 2}

    if llm_provider_name == "openai":
        llm_model = ChatOpenAI(model=model_name, **openai_kwargs)
    elif llm_provider_name == "azure":
        llm_model = AzureChatOpenAI(
            azure_deployment=config["llm"].get("azure_deployment"),
            azure_endpoint=config["llm"].get("azure_endpoint"),
            api_version=config["llm"].get("azure_api_version"),
            model=config["llm"].get("model_name"),
            **openai_kwargs,
        )
    elif llm_provider_name == "ollama":
        base_url = config["llm"].get("base_url", "http://localhost:11434")
        llm_model = ChatOllama(model=model_name, base_url=base_url, **other_kwargs)
    elif llm_provider_name == "aws":
        llm_model = ChatBedrockConverse(
            model=model_name,
            region_name=config["llm"].get("aws_region", "us-east-1"),
            credentials_profile_name=config["llm"].get(
                "aws_credentials_profile", "default"
            ),
            **other_kwargs,
        )
    elif llm_provider_name == "gemini":
        llm_model = ChatGoogleGenerativeAI(model=model_name, **gemini_kwargs)
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    return llm_model


def get_prompts(prompt: Optional[str], prompt_file: Optional[str]) -> dict:
    system_prompt = config["llm"]["system_prompt"]
    if prompt is not None:
        if not prompt.strip():
            print("Error: The prompt text cannot be empty.", file=sys.stderr)
            sys.exit(1)
        user_prompt = prompt
    elif prompt_file:
        if not os.path.exists(prompt_file):
            print(
                f"Error: The specified prompt file '{prompt_file}' does not exist.",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(prompt_file, "r") as f:
            user_prompt = f.read()
    elif os.path.exists("prompt.txt"):
        with open("prompt.txt", "r") as f:
            user_prompt = f.read()
    else:
        raise ValueError("Either prompt or prompt_file must be provided.")
    return {"system_prompt": system_prompt, "user_prompt": user_prompt}


#### MAIN ####

try:
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Start the FTP honeypot server.")
    parser.add_argument(
        "-c", "--config", type=str, default=None, help="Path to the configuration file"
    )
    parser.add_argument(
        "-p", "--prompt", type=str, help="The entire text of the prompt"
    )
    parser.add_argument(
        "-f",
        "--prompt-file",
        type=str,
        default="prompt.txt",
        help="Path to the prompt file",
    )
    parser.add_argument(
        "-l", "--llm-provider", type=str, help="The LLM provider to use"
    )
    parser.add_argument("-m", "--model-name", type=str, help="The model name to use")
    parser.add_argument(
        "-t",
        "--trimmer-max-tokens",
        type=int,
        help="The maximum number of tokens to send to the LLM backend in a single request",
    )
    parser.add_argument(
        "-s", "--system-prompt", type=str, help="System prompt for the LLM"
    )
    parser.add_argument(
        "-r",
        "--temperature",
        type=float,
        help="Temperature parameter for controlling randomness in LLM responses (0.0-2.0)",
    )
    parser.add_argument(
        "-H", "--host", type=str, help="The host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)"
    )
    parser.add_argument(
        "-P", "--port", type=int, help="The port the FTP honeypot will listen on"
    )
    parser.add_argument(
        "-L",
        "--log-file",
        type=str,
        help="The name of the file you wish to write the honeypot log to",
    )
    parser.add_argument(
        "-S",
        "--sensor-name",
        type=str,
        help="The name of the sensor, used to identify this honeypot in the logs",
    )
    parser.add_argument(
        "-u",
        "--user-account",
        action="append",
        help="User account in the form username=password. Can be repeated.",
    )
    args = parser.parse_args()

    # Determine which config file to load
    config = ConfigParser()
    if args.config is not None:
        if not os.path.exists(args.config):
            print(
                f"Error: The specified config file '{args.config}' does not exist.",
                file=sys.stderr,
            )
            sys.exit(1)
        config.read(args.config)
    else:
        # Try multiple config file locations (relative to script dir)
        config_paths = [
            "config.ini",  # Current directory
            Path(__file__).parent / "config.ini",  # Same directory as script
        ]
        config_found = False
        for config_path in config_paths:
            if os.path.exists(config_path):
                config.read(config_path)
                config_found = True
                break
        
        if not config_found:
            # Use defaults when no config file found
            default_log_file = str(
                Path(__file__).parent.parent.parent / "logs" / "ftp_log.log"
            )
            config["honeypot"] = {
                "log_file": default_log_file,
                "sensor_name": socket.gethostname(),
            }
            config["ftp"] = {"host": "0.0.0.0", "port": "2121"}
            config["llm"] = {
                "llm_provider": "openai",
                "model_name": "gpt-3.5-turbo",
                "trimmer_max_tokens": "64000",
                "temperature": "0.7",
                "system_prompt": "",
            }
            config["user_accounts"] = {}

    # Override config values with command line arguments if provided
    if args.llm_provider:
        config["llm"]["llm_provider"] = args.llm_provider
    if args.model_name:
        config["llm"]["model_name"] = args.model_name
    if args.trimmer_max_tokens:
        config["llm"]["trimmer_max_tokens"] = str(args.trimmer_max_tokens)
    if args.system_prompt:
        config["llm"]["system_prompt"] = args.system_prompt
    if args.temperature is not None:
        config["llm"]["temperature"] = str(args.temperature)
    if args.host:
        config["ftp"]["host"] = args.host
    if args.port:
        config["ftp"]["port"] = str(args.port)
    if args.log_file:
        config["honeypot"]["log_file"] = args.log_file
    if args.sensor_name:
        config["honeypot"]["sensor_name"] = args.sensor_name

    # Merge command-line user accounts into the config
    if args.user_account:
        if "user_accounts" not in config:
            config["user_accounts"] = {}
        for account in args.user_account:
            if "=" in account:
                key, value = account.split("=", 1)
                config["user_accounts"][key.strip()] = value.strip()
            else:
                config["user_accounts"][account.strip()] = ""

    # Read the user accounts from the configuration
    accounts = get_user_accounts()

    # Always use UTC for logging
    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
            record.created, datetime.timezone.utc
        ).isoformat(sep="T", timespec="milliseconds")
    )

    # Get the sensor name from the config or use the system's hostname
    sensor_name = config["honeypot"].get("sensor_name", socket.gethostname())

    # Set up the honeypot logger with configurable log level
    logger = logging.getLogger(__name__)
    log_level = config["logging"].get("log_level", "INFO").upper()
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    log_file_handler = logging.FileHandler(
        config["honeypot"].get("log_file", "ftp_log.log")
    )
    logger.addHandler(log_file_handler)

    # Configure structured logging
    if config["logging"].getboolean("structured_logging", True):
        log_file_handler.setFormatter(JSONFormatter(sensor_name))
    else:
        log_file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )

    # Add console handler for real-time streaming if enabled
    if config["logging"].getboolean("real_time_streaming", True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        if config["logging"].getboolean("structured_logging", True):
            console_handler.setFormatter(JSONFormatter(sensor_name))
        else:
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
        logger.addHandler(console_handler)

    f = ContextFilter()
    logger.addFilter(f)

    # Now get access to the LLM
    prompts = get_prompts(args.prompt, args.prompt_file)
    llm_system_prompt = prompts["system_prompt"]
    llm_user_prompt = prompts["user_prompt"]

    llm = choose_llm(config["llm"].get("llm_provider"), config["llm"].get("model_name"))

    llm_sessions = dict()

    llm_trimmer = trim_messages(
        max_tokens=config["llm"].getint("trimmer_max_tokens", 64000),
        strategy="last",
        token_counter=llm,
        include_system=True,
        allow_partial=False,
        start_on="human",
    )

    llm_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", llm_system_prompt),
            ("system", llm_user_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    llm_chain = (
        RunnablePassthrough.assign(messages=(itemgetter("messages") | llm_trimmer))
        | llm_prompt
        | llm
    )

    with_message_history = RunnableWithMessageHistory(
        llm_chain, llm_get_session_history, input_messages_key="messages"
    )

    # Thread-local storage for connection details
    thread_local = threading.local()

    # Start the server
    # amazonq-ignore-next-line
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[-] FTP honeypot stopped by user")
        logger.info("FTP honeypot stopped by user")
    finally:
        try:
            loop.close()
        except (OSError, RuntimeError):
            pass

except (KeyboardInterrupt, asyncio.CancelledError):
    print("\n[-] FTP honeypot stopped by user")
    logger.info("FTP honeypot stopped by user")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
