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

import asyncssh
from asyncssh.misc import ConnectionLost
from command_formatter import CommandFormatter
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
        self.formatter = CommandFormatter()
        # Load attack patterns from JSON file
        self.attack_patterns = self._load_attack_patterns()
        # Load vulnerability signatures from JSON file
        self.vulnerability_signatures = self._load_vulnerability_signatures()

        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE:
            try:
                ml_config = MLConfig("ssh")
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector("ssh", ml_config)
                    logging.info("ML detector initialized for SSH service")
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
                    "patterns": [r"whoami", r"id", r"uname"],
                    "severity": "medium",
                },
                "privilege_escalation": {
                    "patterns": [r"sudo", r"su -"],
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
        """Analyze a command for attack patterns using integrated JSON data"""
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
                analysis["ml_inference_time_ms"] = ml_results.get(
                    "ml_inference_time_ms", 0
                )

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

                logging.info(
                    f"ML Analysis: Score={ml_score:.3f}, Labels={ml_results.get('ml_labels', [])}, Confidence={ml_results.get('ml_confidence', 0):.3f}"
                )

            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                # Add ML error information to analysis
                analysis["ml_error"] = str(e)
                analysis["ml_anomaly_score"] = 0.0
                analysis["ml_labels"] = ["ml_error"]
                if not config.get("ml", {}).get("fallback_on_error", True):
                    raise

        return analysis

    def _calculate_threat_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate threat score based on analysis including ML insights"""
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


class FileUploadHandler:
    """Handle file uploads and downloads with forensic logging"""

    def __init__(self, session_dir: str):
        self.session_dir = Path(session_dir)
        # Use configured downloads directory or default
        downloads_dirname = config["features"].get("downloads_dir", "downloads")
        self.downloads_dir = self.session_dir / downloads_dirname
        self.uploads_dir = self.session_dir / "uploads"
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)

    def handle_download(
        self, command: str, content: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Handle file download commands (wget, curl, etc.)"""
        download_info = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "command": command,
            "type": "download",
            "status": "attempted",
        }

        # Check if file monitoring is enabled
        if not config["forensics"].getboolean("file_monitoring", True):
            return download_info

        # Extract URL from command
        url_match = re.search(r"(https?://[^\s]+)", command)
        if url_match:
            url = url_match.group(1)
            download_info["url"] = url

            # Generate fake file
            filename = url.split("/")[-1] or "downloaded_file"
            if "?" in filename:
                filename = filename.split("?")[0]

            file_path = self.downloads_dir / filename

            # Create realistic fake malware content based on filename
            if content is None:
                content = self._generate_fake_malware_content(filename, url)

            # Save download if enabled
            if config["forensics"].getboolean("save_downloads", True):
                with open(file_path, "wb") as f:
                    f.write(content)

            download_info.update(
                filename=filename, file_size=str(len(content)), status="completed"
            )

            # Only add file_path if downloads are being saved
            if config["forensics"].getboolean("save_downloads", True):
                download_info["file_path"] = str(file_path)

            # Add file hash analysis if enabled
            if config["forensics"].getboolean("file_hash_analysis", True):
                download_info["file_hash"] = hashlib.sha256(content).hexdigest()
                download_info["md5_hash"] = hashlib.md5(content).hexdigest()

            # Add malware detection if enabled
            if config["forensics"].getboolean("malware_detection", True):
                download_info["malware_detected"] = str(
                    self._detect_malware(filename, content)
                )
                download_info["file_type"] = self._identify_file_type(filename, content)

        return download_info

    def _generate_fake_malware_content(self, filename: str, url: str) -> bytes:
        """Generate realistic fake malware content based on file type"""
        filename_lower = filename.lower()

        if "xmrig" in filename_lower or "miner" in filename_lower:
            # Fake cryptocurrency miner
            content = f"""#!/bin/bash
# XMRig Cryptocurrency Miner v6.18.0
# Downloaded from: {url}
# This is a honeypot simulation - no actual mining occurs

echo "XMRig 6.18.0"
echo "Mining pool: pool.minergate.com:45700"
echo "Algorithm: RandomX"
echo "Threads: 4"
echo "Hashrate: 1.2 KH/s"
echo "Status: Connected"

# Simulate mining activity
while true; do
    echo "[$(date)] Accepted share $(($RANDOM % 100))/100"
    sleep 30
done
""".encode()
        elif filename_lower.endswith((".sh", ".bash")):
            # Fake shell script
            content = f"""#!/bin/bash
# Malicious script downloaded from {url}
# This is a honeypot simulation

echo "Installing backdoor..."
echo "Creating persistence..."
echo "Connecting to C&C server..."
echo "Installation complete"
""".encode()
        elif filename_lower.endswith((".py", ".python")):
            # Fake Python malware
            content = f"""#!/usr/bin/env python3
# Malware downloaded from {url}
# This is a honeypot simulation

import os
import sys
import time

print("Initializing payload...")
print("Establishing connection...")
print("Payload deployed successfully")

while True:
    time.sleep(60)
    print("Heartbeat sent")
""".encode()
        elif filename_lower.endswith(".exe"):
            # Fake Windows executable (PE header simulation)
            content = (
                b"MZ\x90\x00"
                + b"\x00" * 60
                + b"PE\x00\x00"
                + f"Fake malware from {url}".encode()
                + b"\x00" * 1000
            )
        else:
            # Generic fake malware
            content = f"""# Malware file downloaded from {url}
# Downloaded at {datetime.datetime.now(datetime.timezone.utc)}
# This is a honeypot simulation - file contains no actual malware

echo "Malware payload activated"
echo "System compromised"
""".encode()

        return content

    def _detect_malware(self, filename: str, content: bytes) -> bool:
        """Simple malware detection based on patterns"""
        malware_patterns = [b"xmrig", b"miner", b"backdoor", b"payload", b"exploit"]
        filename_lower = filename.lower()

        # Check filename patterns
        if any(
            pattern in filename_lower
            for pattern in ["xmrig", "miner", "backdoor", "payload", "exploit"]
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

        if filename_lower.endswith((".sh", ".bash")):
            return "shell_script"
        elif filename_lower.endswith((".py", ".python")):
            return "python_script"
        elif filename_lower.endswith(".exe"):
            return "windows_executable"
        elif b"#!/bin/bash" in content[:100]:
            return "shell_script"
        elif b"#!/usr/bin/env python" in content[:100]:
            return "python_script"
        else:
            return "unknown"

    def handle_upload(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Handle file uploads via SCP, SFTP, etc."""
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
            # amazonq-ignore-next-line
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
        self.formatter = CommandFormatter()
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
                "CVE-2021-44228": {
                    "patterns": [r"\$\{jndi:", r"ldap://"],
                    "severity": "critical",
                },
                "COMMAND_INJECTION": {
                    "patterns": [r";.*rm.*-rf", r"&&.*cat"],
                    "severity": "critical",
                },
            }

    def analyze_for_vulnerabilities(
        self, command: str, headers: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        """Analyze command/input for vulnerability exploitation attempts using JSON data"""
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
            "sensor_protocol": "ssh",
        }
        if hasattr(record, "interactive"):
            log_record["interactive"] = getattr(record, "interactive", True)
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key != "args" and key != "msg":
                log_record[key] = value
        return json.dumps(log_record)


class MySSHServer(asyncssh.SSHServer):
    def __init__(self):
        self.formatter = CommandFormatter()
        super().__init__()
        self.summary_generated = False
        self.username = "guest"  # Will be set to actual username after authentication
        self.current_directory = "/home/guest"
        self.command_history = []  # Track command history for history command
        self.session_data = {
            "commands": [],
            "files_uploaded": [],
            "files_downloaded": [],
            "vulnerabilities": [],
            "attack_analysis": [],
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        # Initialize seed filesystem if configured
        self.seed_fs = self._load_seed_filesystem()
        self.seed_first_reply = config["honeypot"].getboolean("seed_first_reply", False)
        # Initialize session recording if enabled
        self.session_recording = config["features"].getboolean(
            "session_recording", True
        )
        self.save_replay = config["features"].getboolean("save_replay", True)
        self.session_transcript = [] if self.session_recording else None

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
                    rel_path = "/home/guest"
                else:
                    rel_path = f"/home/guest/{rel_path.replace(os.sep, '/')}"

                seed_fs[rel_path] = {"dirs": dirs[:], "files": files[:]}
            return seed_fs
        except Exception as e:
            logger.error(f"Failed to load seed filesystem: {e}")
            return {}

    def _analyze_geolocation(self, ip: str) -> Dict[str, str]:
        """Basic geolocation analysis (placeholder implementation)"""
        # This is a simplified implementation - in production, use a real geolocation service
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return {"country": "Local", "region": "Private Network", "city": "Internal"}
        elif ip.startswith("127."):
            return {"country": "Local", "region": "Localhost", "city": "Local"}
        else:
            # Placeholder for external IPs - would use real geolocation API
            return {"country": "Unknown", "region": "Unknown", "city": "Unknown"}

    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Basic IP reputation check (placeholder implementation)"""
        # This is a simplified implementation - in production, use real threat intelligence feeds
        known_bad_ranges = [
            "192.0.2.",
            "198.51.100.",
            "203.0.113.",
        ]  # RFC 5737 test ranges

        reputation = {
            "is_malicious": any(
                ip.startswith(bad_range) for bad_range in known_bad_ranges
            ),
            "threat_score": 0,
            "categories": [],
        }

        if reputation["is_malicious"]:
            reputation["threat_score"] = 85
            reputation["categories"] = ["test_range", "suspicious"]

        return reputation

    def format_command_output(self, command: str, output: str) -> str:
        """Format command output to look like real Unix shell output"""
        if not output or not output.strip():
            return ""

        # Remove ALL ANSI escape sequences thoroughly
        clean_output = re.sub(r"\x1b\[[0-9;]*[mK]", "", output)
        clean_output = re.sub(r"\[\d*;?\d*m", "", clean_output)
        clean_output = re.sub(r"\[0m", "", clean_output)
        clean_output = re.sub(r"\[01;34m", "", clean_output)

        # Remove any existing prompts from output
        clean_output = re.sub(r"guest@[^$]*\$\s*", "", clean_output)

        # Normalize whitespace
        clean_output = re.sub(r"\s+", " ", clean_output.strip())

        # Determine command type
        cmd_lower = command.lower().strip()

        if cmd_lower.startswith("ls"):
            # Additional cleaning for ls output to handle concatenated filenames
            if not "-l" in command:
                # Look for concatenated filenames and separate them
                clean_output = re.sub(
                    r"([a-zA-Z0-9_-]+\.[a-zA-Z0-9]{2,4})([A-Z][a-zA-Z0-9_-])",
                    r"\1 \2",
                    clean_output,
                )
                clean_output = re.sub(
                    r"([a-zA-Z0-9_-]+/)([A-Z][a-zA-Z0-9_-])", r"\1 \2", clean_output
                )
                clean_output = re.sub(r"([a-z])([A-Z][a-z])", r"\1 \2", clean_output)
            return self.formatter.format_ls_output(clean_output, command)
        elif cmd_lower.startswith("cd"):
            return self._handle_cd_command(command)
        elif cmd_lower.startswith("ps"):
            return self.formatter.format_ps_output(clean_output)
        elif cmd_lower.startswith("netstat"):
            return self.formatter.format_netstat_output(clean_output)
        elif cmd_lower.startswith("top"):
            return self.formatter.format_top_output(clean_output)
        elif cmd_lower.startswith("df"):
            return self.formatter.format_df_output(clean_output)
        elif cmd_lower.startswith("find"):
            return self.formatter.format_find_output(clean_output, command)
        elif cmd_lower.startswith("grep"):
            return self.formatter.format_grep_output(clean_output, command)
        elif cmd_lower.startswith("cat"):
            return self.formatter.format_cat_output(clean_output, command)
        elif cmd_lower.startswith("ifconfig"):
            return self.formatter.format_ifconfig_output(clean_output)
        elif cmd_lower.startswith("mount"):
            return self.formatter.format_mount_output(clean_output)
        else:
            return self.formatter.format_generic_output(clean_output)

    def _format_ls_output(self, output: str, command: str = "") -> str:
        """Format ls command output horizontally with proper spacing"""
        # Check if -l flag is used for long format
        if "-l" in command:
            return output

        # Use seed filesystem if available
        if self.seed_fs and self.current_directory in self.seed_fs:
            seed_data = self.seed_fs[self.current_directory]
            items = seed_data["dirs"] + seed_data["files"]
        else:
            # Split output and handle concatenated filenames
            items = []
            words = output.split()

            for word in words:
                # Check if word contains multiple filenames concatenated together
                # Look for patterns like "file1.txtfile2.txt" or "dir1/dir2/"
                if len(word) > 20 and ("." in word or "/" in word):
                    # Try to split on common file extensions and directory patterns
                    parts = re.split(
                        r"(\.[a-zA-Z0-9]{2,4}(?=[A-Z]|[a-z][A-Z])|/(?=[A-Z]|[a-z]))",
                        word,
                    )
                    current = ""
                    for part in parts:
                        if part:
                            current += part
                            # If this looks like a complete filename, add it
                            if (
                                part.endswith("/")
                                or re.match(r"\.[a-zA-Z0-9]{2,4}$", part)
                                or (len(current) > 3 and not part.startswith("."))
                            ):
                                items.append(current)
                                current = ""
                    if current:  # Add any remaining part
                        items.append(current)
                else:
                    items.append(word)

        if not items:
            return ""

        # Format horizontally with proper spacing
        formatted_items = []
        for item in items:
            # Color directories (items ending with / or common directory patterns)
            if item.endswith("/") or any(
                pattern in item.lower()
                for pattern in [
                    "docs",
                    "config",
                    "scripts",
                    "reports",
                    "projects",
                    "tools",
                    "admin",
                    "backup",
                    "logs",
                    "temp",
                ]
            ):
                formatted_items.append(f"{item:<20}")
            else:
                formatted_items.append(f"{item:<20}")

        # Arrange in rows of 4 items each
        rows = []
        for i in range(0, len(formatted_items), 4):
            row = formatted_items[i : i + 4]
            rows.append("".join(row).rstrip())

        return "\n".join(rows)

    def _handle_cd_command(self, command: str) -> str:
        """Handle cd command and update current directory"""
        parts = command.strip().split()
        if len(parts) < 2:
            return ""

        target_dir = parts[1].rstrip("/")

        if target_dir == "..":
            # Go back to parent directory
            username = getattr(self, "username", "guest")
            if self.current_directory != f"/home/{username}":
                path_parts = self.current_directory.split("/")
                if len(path_parts) > 3:  # /home/username/...
                    self.current_directory = "/".join(path_parts[:-1])
                else:
                    self.current_directory = f"/home/{username}"
            return ""
        elif target_dir == "~":
            username = getattr(self, "username", "guest")
            self.current_directory = f"/home/{username}"
            return ""
        elif target_dir == "" or target_dir == ".":
            # Stay in current directory
            return ""
        elif target_dir.startswith("~/"):
            # Handle ~/path format
            relative_path = target_dir[2:]  # Remove ~/
            username = getattr(self, "username", "guest")
            self.current_directory = f"/home/{username}/{relative_path}"
            return ""
        elif target_dir.startswith("/"):
            # Absolute path - validate it's within allowed range
            username = getattr(self, "username", "guest")
            if target_dir.startswith(f"/home/{username}"):
                self.current_directory = target_dir
            else:
                # amazonq-ignore-next-line
                return f"-bash: cd: {target_dir}: Permission denied"
            return ""
        else:
            # Relative path - prevent duplicate directory names
            username = getattr(self, "username", "guest")
            if self.current_directory == f"/home/{username}":
                self.current_directory = f"/home/{username}/{target_dir}"
            else:
                # Check if we're already in the target directory to prevent duplication
                current_basename = os.path.basename(self.current_directory)
                if current_basename == target_dir:
                    # Already in the target directory, don't duplicate
                    return ""
                else:
                    self.current_directory = f"{self.current_directory}/{target_dir}"
            return ""

    def _format_ps_output(self, output: str) -> str:
        """Format ps command output with proper columns"""
        formatted = "  PID TTY          TIME CMD\n"
        formatted += " 1234 pts/0    00:00:01 bash\n"
        formatted += " 5678 pts/0    00:00:00 ps\n"
        return formatted.rstrip()

    def _format_netstat_output(self, output: str) -> str:
        """Format netstat command output with proper columns"""
        lines = output.split("\n")
        if not lines:
            return output

        formatted = "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        for line in lines:
            if line.strip() and not line.startswith("Proto"):
                parts = line.split()
                if len(parts) >= 6:
                    proto = parts[0][:5].ljust(5)
                    recv_q = parts[1][:6].ljust(6)
                    send_q = parts[2][:6].ljust(6)
                    local = parts[3][:23].ljust(23)
                    foreign = parts[4][:23].ljust(23)
                    state = parts[5] if len(parts) > 5 else ""
                    formatted += (
                        f"{proto} {recv_q} {send_q} {local} {foreign} {state}\n"
                    )
        return formatted.rstrip()

    def _format_top_output(self, output: str) -> str:
        """Format top command output with proper structure"""
        lines = output.split("\n")
        if not lines:
            return output

        formatted = (
            "top - "
            + datetime.datetime.now().strftime("%H:%M:%S")
            + " up 1 day, 2:34, 1 user, load average: 0.15, 0.12, 0.08\n"
        )
        formatted += (
            "Tasks: 142 total,   1 running, 141 sleeping,   0 stopped,   0 zombie\n"
        )
        formatted += "%Cpu(s):  2.3 us,  1.2 sy,  0.0 ni, 96.2 id,  0.3 wa,  0.0 hi,  0.0 si,  0.0 st\n"
        formatted += "MiB Mem :   7982.4 total,   1234.5 free,   2345.6 used,   4402.3 buff/cache\n"
        formatted += "MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5234.8 avail Mem\n\n"
        formatted += "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"

        for i, line in enumerate(lines[:10]):
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    pid = str(1000 + i).rjust(5)
                    user = "guest"[:8].ljust(8)
                    pr = "20".rjust(3)
                    ni = "0".rjust(4)
                    virt = "123456".rjust(8)
                    res = "12345".rjust(7)
                    shr = "1234".rjust(7)
                    s = "S"
                    cpu = "0.3".rjust(6)
                    mem = "0.2".rjust(6)
                    time = "0:00.12".rjust(10)
                    cmd = parts[0] if parts else "bash"
                    formatted += f"{pid} {user} {pr} {ni} {virt} {res} {shr} {s} {cpu} {mem} {time} {cmd}\n"

        return formatted.rstrip()

    def _format_df_output(self, output: str) -> str:
        """Format df command output with proper columns"""
        formatted = "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        formatted += "/dev/sda1       20971520 8388608  12582912  40% /\n"
        formatted += "tmpfs            4096000       0   4096000   0% /dev/shm\n"
        formatted += "/dev/sda2       10485760 2097152   8388608  20% /home\n"
        return formatted

    def _format_find_output(self, output: str) -> str:
        """Format find command output with proper paths"""
        lines = output.split("\n")
        formatted_lines = []
        for line in lines:
            if line.strip() and not line.startswith("."):
                formatted_lines.append(f"./{line.strip()}")
        return "\n".join(formatted_lines)

    def _format_grep_output(self, output: str) -> str:
        """Format grep command output with highlighting"""
        lines = output.split("\n")
        formatted_lines = []
        for line in lines:
            if line.strip():
                formatted_lines.append(line.strip())
        return "\n".join(formatted_lines)

    def _format_cat_output(self, output: str) -> str:
        """Format cat command output as plain text"""
        return output.strip()

    def _format_ifconfig_output(self, output: str) -> str:
        """Format ifconfig command output with proper network interface structure"""
        formatted = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        formatted += "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        formatted += (
            "        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n"
        )
        formatted += "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n"
        formatted += "        RX packets 1234  bytes 567890 (554.5 KiB)\n"
        formatted += "        TX packets 987  bytes 123456 (120.5 KiB)\n\n"
        formatted += "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        formatted += "        inet 127.0.0.1  netmask 255.0.0.0\n"
        formatted += "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
        formatted += "        loop  txqueuelen 1000  (Local Loopback)\n"
        return formatted

    def _format_mount_output(self, output: str) -> str:
        """Format mount command output with proper filesystem structure"""
        formatted = "/dev/sda1 on / type ext4 (rw,relatime)\n"
        formatted += "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
        formatted += "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
        formatted += "tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n"
        return formatted

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        # Get the source and destination IPs and ports
        peername = conn.get_extra_info("peername")
        sockname = conn.get_extra_info("sockname")

        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = "-", "-"

        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = "-", "-"

        # Store the connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        # -- SAFE SESSION DIR NAME (Windows-safe) --
        # Build a session id including timestamp + sanitized client IP
        raw_ip_part = str(src_ip)
        # Replace anything that is not A-Z a-z 0-9 . _ - with underscore
        safe_ip_part = re.sub(r"[^A-Za-z0-9._-]", "_", raw_ip_part)
        # Keep it reasonably short
        safe_ip_part = safe_ip_part[:100]

        session_id = f"session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{safe_ip_part}"
        sessions_dir = Path(config["honeypot"].get("sessions_dir", "sessions"))
        self.session_dir = sessions_dir / session_id

        # Create the directory safely (parents=True, exist_ok=True)
        try:
            self.session_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # Fallback: generate a uuid-based session dir if filesystem still rejects name
            logger.warning(
                "Failed to create session_dir with sanitized name; falling back to uuid",
                extra={"path": str(self.session_dir), "error": str(e)},
            )
            safe_uuid = uuid.uuid4().hex
            self.session_dir = (
                sessions_dir
                / f"session_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{safe_uuid}"
            )
            self.session_dir.mkdir(parents=True, exist_ok=True)

        # Initialize integrated components with error handling
        try:
            self.attack_analyzer = AttackAnalyzer()
            self.file_handler = (
                FileUploadHandler(str(self.session_dir))
                if config["forensics"].getboolean("file_monitoring", True)
                else None
            )
            self.vuln_logger = VulnerabilityLogger()
            self.forensic_logger = (
                ForensicChainLogger(str(self.session_dir))
                if config["forensics"].getboolean("chain_of_custody", True)
                else None
            )

            # Cross-reference components for unified threat intelligence
            self._integrate_threat_intelligence()
        except Exception as e:
            logger.error(f"Failed to initialize honeypot components: {e}")
            # Initialize with minimal functionality
            self.attack_analyzer = None
            self.file_handler = None
            self.vuln_logger = None
            self.forensic_logger = None

        # Log connection with enhanced details
        connection_info = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "session_id": session_id,
            "session_dir": str(self.session_dir),
        }

        # Add threat intelligence info if available
        if self.attack_analyzer:
            connection_info["threat_signatures_loaded"] = len(
                getattr(self.attack_analyzer, "vulnerability_signatures", {})
            )
            connection_info["attack_patterns_loaded"] = len(
                getattr(self.attack_analyzer, "attack_patterns", {})
            )

        # Add geolocation analysis if enabled
        if config["attack_detection"].getboolean("geolocation_analysis", True):
            connection_info["geolocation"] = self._analyze_geolocation(src_ip)

        # Add reputation filtering if enabled
        if config["attack_detection"].getboolean("reputation_filtering", True):
            connection_info["reputation"] = self._check_ip_reputation(src_ip)

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

        logger.info("SSH connection received", extra=connection_info)

        if self.forensic_logger:
            try:
                self.forensic_logger.log_event(
                    "connection_established", connection_info
                )
            except Exception as e:
                logger.error(f"Forensic logging failed: {e}")

    def _integrate_threat_intelligence(self):
        """Integrate threat intelligence across all components"""
        try:
            # Share vulnerability signatures between components
            if (
                self.attack_analyzer
                and self.vuln_logger
                and hasattr(self.attack_analyzer, "vulnerability_signatures")
                and hasattr(self.vuln_logger, "vulnerability_signatures")
            ):
                # Ensure both components use the same vulnerability data
                shared_vulns = self.attack_analyzer.vulnerability_signatures
                self.vuln_logger.vulnerability_signatures = shared_vulns

            # Log integration status
            if self.attack_analyzer:
                logger.info(
                    "Threat intelligence integration completed",
                    extra={
                        "attack_patterns": len(
                            getattr(self.attack_analyzer, "attack_patterns", {})
                        ),
                        "vulnerability_signatures": len(
                            getattr(
                                self.attack_analyzer, "vulnerability_signatures", {}
                            )
                        ),
                        "components_integrated": [
                            "AttackAnalyzer",
                            "VulnerabilityLogger",
                            "FileUploadHandler",
                            "ForensicChainLogger",
                        ],
                    },
                )
        except Exception as e:
            logger.error(f"Failed to integrate threat intelligence: {e}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.error("SSH connection error", extra={"error": str(exc)})
            if not isinstance(exc, ConnectionLost):
                traceback.print_exception(exc)
        else:
            logger.info("SSH connection closed")

        # Save session summary and forensic data
        if hasattr(self, "session_data"):
            self.session_data["end_time"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            self.session_data["duration"] = str(
                datetime.datetime.fromisoformat(self.session_data["end_time"])
                - datetime.datetime.fromisoformat(self.session_data["start_time"])
            )

            # Save session data
            if hasattr(self, "session_dir"):
                session_file = self.session_dir / "session_summary.json"
                with open(session_file, "w") as f:
                    json.dump(self.session_data, f, indent=2)

                # Save replay data if enabled
                if (
                    self.save_replay
                    and hasattr(self, "session_transcript")
                    and self.session_transcript
                ):
                    replay_file = self.session_dir / "session_replay.json"
                    with open(replay_file, "w") as f:
                        json.dump(
                            {
                                "session_id": getattr(self, "session_id", "unknown"),
                                "start_time": self.session_data["start_time"],
                                "end_time": self.session_data["end_time"],
                                "transcript": self.session_transcript,
                            },
                            f,
                            indent=2,
                        )

                # Add session summary as evidence
                if hasattr(self, "forensic_logger") and self.forensic_logger:
                    try:
                        self.forensic_logger.add_evidence(
                            "session_summary",
                            str(session_file),
                            "Complete session activity summary",
                        )
                        if (
                            self.save_replay
                            and hasattr(self, "session_transcript")
                            and self.session_transcript
                        ):
                            replay_file = self.session_dir / "session_replay.json"
                            self.forensic_logger.add_evidence(
                                "session_replay",
                                str(replay_file),
                                "Complete session transcript for replay",
                            )
                        self.forensic_logger.log_event(
                            "connection_closed",
                            {"reason": str(exc) if exc else "normal_closure"},
                        )
                    except Exception as e:
                        logger.error(f"Final forensic logging failed: {e}")

        # Ensure session summary is called on connection loss if attributes are set
        if (
            hasattr(self, "_process")
            and hasattr(self, "_llm_config")
            and hasattr(self, "_session")
        ):
            try:
                asyncio.create_task(
                    session_summary(
                        self._process, self._llm_config, self._session, self
                    )
                )
            except Exception as e:
                logger.error(f"Failed to create session summary task: {e}")

    def begin_auth(self, username: str) -> bool:
        if accounts.get(username) != "":
            logger.info("User attempting to authenticate", extra={"username": username})
            return True
        else:
            logger.info(
                "Authentication success", extra={"username": username, "password": ""}
            )
            return False

    def password_auth_supported(self) -> bool:
        return True

    def host_based_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return False

    def kbdinit_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        pw = accounts.get(username, "*")

        if pw == "*" or (pw != "*" and password == pw):
            logger.info(
                "Authentication success",
                extra={"username": username, "password": password},
            )
            return True
        else:
            logger.info(
                "Authentication failed",
                extra={"username": username, "password": password},
            )
            return False


async def session_summary(
    process: asyncssh.SSHServerProcess,
    llm_config: Dict,
    session: RunnableWithMessageHistory,
    server: MySSHServer,
):
    # Check if the summary has already been generated
    if server.summary_generated:
        return

    try:
        # When the SSH session ends, ask the LLM to give a nice
        # summary of the attacker's actions and probable intent,
        # as well as a snap judgement about whether we should be
        # concerned or not.

        prompt = f"""
Analyze this SSH session for malicious activity. You have access to:
- Complete command history: {[cmd["command"] for cmd in server.session_data.get("commands", [])]}
- Attack patterns detected: {[analysis["attack_types"] for analysis in server.session_data.get("attack_analysis", []) if analysis.get("attack_types")]}
- Vulnerabilities exploited: {[vuln["vulnerability_id"] for vuln in server.session_data.get("vulnerabilities", [])]}
- Files downloaded: {[file["filename"] for file in server.session_data.get("files_downloaded", [])]}
- Files uploaded/created: {[file["filename"] for file in server.session_data.get("files_uploaded", [])]}
- Session duration: {server.session_data.get("duration", "unknown")}
- Username used: {process.get_extra_info("username")}

Provide a concise analysis covering:
1. Attack stage identification (reconnaissance, initial access, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, impact)
2. Primary attacker objectives based on command patterns
3. Threat level assessment

Key indicators to analyze:
- System enumeration commands (whoami, id, uname, ps, netstat, ifconfig)
- File system exploration (ls, find, cat sensitive files)
- Download attempts (wget, curl) especially for malware/tools
- Privilege escalation attempts (sudo, su, chmod +x)
- Persistence mechanisms (crontab, systemctl, rc files)
- Data collection (cat /etc/passwd, history, env)
- Network reconnaissance (ping, nmap, netstat)
- Process manipulation (kill, nohup, background processes)
- File modifications (echo >, vim, nano)

Classification criteria:
- BENIGN: Basic system navigation, help commands, normal user behavior
- SUSPICIOUS: System enumeration, reconnaissance, probing activities
- MALICIOUS: Malware downloads, exploitation attempts, persistence installation, data theft

End with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]" and specify the primary attack goal.
"""

        # Ask the LLM for its summary with rate limiting protection
        try:
            llm_response = await session.ainvoke(
                {
                    "messages": [HumanMessage(content=prompt)],
                    "username": process.get_extra_info("username"),
                    "interactive": True,  # Ensure interactive flag is passed
                },
                config=llm_config,
            )

            # Extract the judgement from the response
            judgement = "UNKNOWN"
            if "Judgement: BENIGN" in llm_response.content:
                judgement = "BENIGN"
            elif "Judgement: SUSPICIOUS" in llm_response.content:
                judgement = "SUSPICIOUS"
            elif "Judgement: MALICIOUS" in llm_response.content:
                judgement = "MALICIOUS"

            logger.info(
                "Session summary",
                extra={"details": llm_response.content, "judgement": judgement},
            )

        except Exception as e:
            logger.error(f"LLM session summary failed: {e}")
            # Generate enhanced fallback summary from session data
            commands = [
                cmd["command"] for cmd in server.session_data.get("commands", [])
            ]
            attack_patterns = [
                analysis
                for analysis in server.session_data.get("attack_analysis", [])
                if analysis.get("attack_types")
            ]
            downloads = server.session_data.get("files_downloaded", [])
            uploads = server.session_data.get("files_uploaded", [])

            # Analyze command patterns for fallback
            suspicious_commands = [
                cmd
                for cmd in commands
                if any(
                    pattern in cmd.lower()
                    for pattern in [
                        "wget",
                        "curl",
                        "chmod +x",
                        "sudo",
                        "su -",
                        "cat /etc/",
                        "find /",
                        "ps aux",
                        "netstat",
                        "uname -a",
                    ]
                )
            ]

            if downloads or any(
                "malware" in str(attack).lower() for attack in attack_patterns
            ):
                judgement = "MALICIOUS"
                summary = f"Malware download session with {len(commands)} commands, {len(downloads)} downloads, goal: malware deployment"
            elif suspicious_commands or attack_patterns:
                judgement = "SUSPICIOUS"
                summary = f"Reconnaissance session with {len(commands)} commands, {len(suspicious_commands)} suspicious activities, goal: system enumeration"
            else:
                judgement = "BENIGN"
                summary = f"Normal session with {len(commands)} basic commands, no threats detected"

            logger.info(
                "Session summary (fallback)",
                extra={"details": summary, "judgement": judgement},
            )

    except Exception as e:
        logger.error(f"Session summary generation failed: {e}")
    finally:
        server.summary_generated = True


# amazonq-ignore-next-line
async def handle_client(
    process: asyncssh.SSHServerProcess, server: MySSHServer
) -> None:
    # This is the main loop for handling SSH client connections.
    # Any user interaction should be done here.

    # Give each session a unique name
    task_uuid = f"session-{uuid.uuid4()}"
    current_task = asyncio.current_task()
    if current_task is not None and hasattr(current_task, "set_name"):
        current_task.set_name(task_uuid)

    llm_config = {"configurable": {"session_id": task_uuid}}

    # Store references for session summary
    server._process = process
    server._llm_config = llm_config
    server._session = with_message_history
    server.session_id = task_uuid

    # Store the authenticated username and update current directory
    authenticated_username = process.get_extra_info("username") or "guest"
    server.username = authenticated_username
    server.current_directory = f"/home/{authenticated_username}"

    try:
        if process.command:
            # Handle non-interactive command execution
            command = process.command

            # Enhanced logging and analysis
            await process_command(
                command, process, server, llm_config, interactive=False
            )
            try:
                await session_summary(process, llm_config, with_message_history, server)
            except Exception as e:
                logger.error(f"Session summary failed: {e}")
            process.exit(0)
        else:
            # Handle interactive session - show banner and MOTD
            banner = config["ssh"].get("banner", "")
            motd = config["ssh"].get("motd", "").replace("\\n", "\n")

            # Apply adaptive banners if enabled
            if config["ai_features"].getboolean("adaptive_banners", True) and banner:
                # Modify banner based on source IP or attack patterns
                src_ip = getattr(thread_local, "src_ip", "unknown")
                if src_ip != "unknown" and not src_ip.startswith("192.168."):
                    banner += f"\nLast failed login: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {src_ip}"

            if banner:
                process.stdout.write(f"{banner}\n")

            if motd:
                process.stdout.write(f"{motd}\n")

            # Handle seed first reply
            if server.seed_first_reply:
                try:
                    llm_response = await with_message_history.ainvoke(
                        {
                            "messages": [HumanMessage(content="login")],
                            "username": process.get_extra_info("username"),
                            "interactive": True,
                        },
                        config=llm_config,
                    )

                    formatted_content = server.format_command_output(
                        "login", llm_response.content
                    )
                    if formatted_content.strip():
                        process.stdout.write(f"{formatted_content}\n")
                    logger.info(
                        "LLM response",
                        extra={
                            "details": b64encode(
                                formatted_content.encode("utf-8")
                            ).decode("utf-8"),
                            "interactive": True,
                        },
                    )
                except Exception as e:
                    logger.error(f"Initial LLM request failed: {e}")

            process.stdout.write(get_prompt(server))

            while True:
                try:
                    async for line in process.stdin:
                        try:
                            line = line.rstrip("\n")

                            # Skip tab completion - let LLM handle everything
                            if "\t" in line:
                                line = line.replace("\t", "")
                                # Just continue with the command without tab completion

                            # Process command with enhanced analysis
                            response = await process_command(
                                line, process, server, llm_config, interactive=True
                            )

                            if response == "XXX-END-OF-SESSION-XXX":
                                # Run session summary in background without blocking exit
                                asyncio.create_task(
                                    session_summary(
                                        process,
                                        llm_config,
                                        with_message_history,
                                        server,
                                    )
                                )
                                process.exit(0)
                                return
                        except Exception as cmd_error:
                            logger.error(f"Command processing error: {cmd_error}")
                            # Continue processing other commands
                            continue
                    # If we reach here, stdin was closed
                    break
                except asyncssh.misc.TerminalSizeChanged:
                    # Handle terminal size changes gracefully and continue
                    logger.info("Terminal size changed, continuing session")
                    continue
                except asyncssh.BreakReceived:
                    # Handle Ctrl+C gracefully
                    logger.info("Break received, continuing session")
                    continue
                except (ConnectionResetError, asyncssh.misc.ConnectionLost):
                    # Handle connection issues
                    logger.info("Connection lost")
                    break
                except Exception as e:
                    logger.error(f"Session handling error: {e}")
                    # Continue on other errors
                    continue

    except asyncssh.BreakReceived:
        logger.info("Break received in main handler")
    except ConnectionResetError:
        logger.info("Connection reset in main handler")
    except Exception as e:
        logger.error(f"Client handling error: {e}")
    finally:
        try:
            if not server.summary_generated:
                await session_summary(process, llm_config, with_message_history, server)
        except Exception as e:
            logger.error(f"Final session summary failed: {e}")


def _check_blocked_commands(
    command: str, process: asyncssh.SSHServerProcess, server: MySSHServer
) -> bool:
    """Check if command should be blocked"""
    if not config["features"].getboolean("block_outbound", True):
        return False

    blocked_patterns = [
        r"ssh\s+\d+\.\d+\.\d+\.\d+",
        r"nmap\s+",
        r"ping\s+\d+\.\d+\.\d+\.\d+",
        r"telnet\s+\d+\.\d+\.\d+\.\d+",
    ]
    for pattern in blocked_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            process.stdout.write("Connection blocked by security policy\n")
            process.stdout.write(get_prompt(server))
            return True
    return False


def _perform_threat_analysis(command: str, server: MySSHServer) -> tuple:
    """Perform attack and vulnerability analysis"""
    attack_analysis = {
        "command": command,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "attack_types": [],
        "severity": "low",
        "indicators": [],
        "vulnerabilities": [],
    }
    vulnerabilities = []

    # Analyze command for attacks
    if server.attack_analyzer and config["ai_features"].getboolean(
        "real_time_analysis", True
    ):
        try:
            attack_analysis = server.attack_analyzer.analyze_command(command)
            server.session_data["attack_analysis"].append(attack_analysis)
        except Exception as e:
            logger.error(f"Attack analysis failed: {e}")

    # Check for vulnerabilities
    if server.vuln_logger and config["ai_features"].getboolean(
        "vulnerability_detection", True
    ):
        try:
            vulnerabilities = server.vuln_logger.analyze_for_vulnerabilities(command)
            server.session_data["vulnerabilities"].extend(vulnerabilities)

            # Cross-reference vulnerabilities with attack patterns
            if vulnerabilities and attack_analysis.get("vulnerabilities"):
                for vuln in vulnerabilities:
                    matching_attack_vulns = [
                        av
                        for av in attack_analysis["vulnerabilities"]
                        if av["id"] == vuln["vulnerability_id"]
                    ]
                    if matching_attack_vulns:
                        vuln["confirmed_by_attack_analyzer"] = True
                        vuln["attack_context"] = matching_attack_vulns[0]
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")

    return attack_analysis, vulnerabilities


def _log_threats(
    attack_analysis: dict, vulnerabilities: list, command: str, server: MySSHServer
):
    """Log detected threats"""
    # Log attack analysis
    if attack_analysis.get("attack_types"):
        log_extra = {
            "attack_types": attack_analysis["attack_types"],
            "severity": attack_analysis["severity"],
            "indicators": attack_analysis.get("indicators", []),
            "command": command,
        }

        if "threat_score" in attack_analysis:
            log_extra["threat_score"] = attack_analysis["threat_score"]

        if attack_analysis.get("alert_triggered", False):
            logger.critical("High-threat attack detected", extra=log_extra)
        else:
            logger.warning("Attack pattern detected", extra=log_extra)

        if server.forensic_logger:
            try:
                server.forensic_logger.log_event("attack_detected", attack_analysis)
            except Exception as e:
                logger.error(f"Forensic logging failed: {e}")

    # Log vulnerabilities
    for vuln in vulnerabilities:
        try:
            enhanced_vuln = dict(vuln)
            enhanced_vuln["related_attack_types"] = attack_analysis.get(
                "attack_types", []
            )
            enhanced_vuln["overall_severity"] = attack_analysis.get("severity", "low")
            enhanced_vuln["threat_score"] = attack_analysis.get("threat_score", 0)

            alert_threshold = config["attack_detection"].getint("alert_threshold", 70)
            if enhanced_vuln["threat_score"] >= alert_threshold:
                logger.critical(
                    "Critical vulnerability exploitation attempt", extra=enhanced_vuln
                )
            else:
                logger.critical(
                    "Vulnerability exploitation attempt", extra=enhanced_vuln
                )

            if server.forensic_logger:
                server.forensic_logger.log_event("vulnerability_exploit", enhanced_vuln)
        except Exception as e:
            logger.error(f"Vulnerability logging failed: {e}")


def _handle_file_operations(command: str, server: MySSHServer):
    """Handle file download operations"""
    if (
        re.search(r"wget|curl.*-o|scp.*:", command, re.IGNORECASE)
        and server.file_handler
    ):
        try:
            download_info = server.file_handler.handle_download(command)
            server.session_data["files_downloaded"].append(download_info)
            logger.info("File download attempt", extra=download_info)
            if server.forensic_logger:
                server.forensic_logger.log_event("file_download", download_info)

                if download_info.get("file_path"):
                    server.forensic_logger.add_evidence(
                        "downloaded_file",
                        download_info["file_path"],
                        f"File downloaded via: {command}",
                    )
        except Exception as e:
            logger.error(f"File handling failed: {e}")


async def _get_llm_response(
    command: str,
    attack_analysis: dict,
    process: asyncssh.SSHServerProcess,
    server: MySSHServer,
    llm_config: dict,
    interactive: bool,
) -> str:
    """Get LLM response with enhanced context"""
    enhanced_command = command

    # Apply dynamic responses if enabled
    if config["ai_features"].getboolean(
        "dynamic_responses", True
    ) and attack_analysis.get("attack_types"):
        enhanced_command += f" [HONEYPOT_CONTEXT: Detected {', '.join(attack_analysis['attack_types'])} behavior]"

    # Apply deception techniques if enabled
    if config["ai_features"].getboolean("deception_techniques", True):
        if "reconnaissance" in attack_analysis.get("attack_types", []):
            enhanced_command += (
                " [DECEPTION: Show realistic but controlled system information]"
            )
        elif "privilege_escalation" in attack_analysis.get("attack_types", []):
            enhanced_command += (
                " [DECEPTION: Simulate security resistance while logging attempts]"
            )

    try:
        llm_response = await with_message_history.ainvoke(
            {
                "messages": [HumanMessage(content=enhanced_command)],
                "username": process.get_extra_info("username"),
                "interactive": interactive,
            },
            config=llm_config,
        )
        return server.format_command_output(command, llm_response.content)
    except Exception as e:
        logger.error(f"LLM request failed: {e}")
        return _get_fallback_response(command, process, server)


def _get_fallback_response(
    command: str, process: asyncssh.SSHServerProcess, server: MySSHServer
) -> str:
    """Get fallback response when LLM fails"""
    cmd_lower = command.lower().strip()
    if cmd_lower == "ls":
        return None  # Let LLM handle ls command
    elif cmd_lower == "pwd":
        return server.current_directory if server else "/home/guest"
    elif cmd_lower == "whoami":
        return process.get_extra_info("username") or "guest"
    elif cmd_lower in ["help", "--help", "-h"]:
        return get_help_text()
    else:
        return f"bash: {command.split()[0] if command.split() else command}: command not found"


async def process_command(
    command: str,
    process: asyncssh.SSHServerProcess,
    server: MySSHServer,
    llm_config: dict,
    interactive: bool = True,
) -> str:
    """Process a command with comprehensive analysis and logging"""

    # Check for blocked commands
    if _check_blocked_commands(command, process, server):
        return "blocked"

    # Record session transcript
    if server.session_recording and server.session_transcript is not None:
        server.session_transcript.append(
            {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": "input",
                "content": command,
                "interactive": interactive,
            }
        )

    # Log user input
    logger.info(
        "User input",
        extra={
            "details": b64encode(command.encode("utf-8")).decode("utf-8"),
            "interactive": interactive,
            "command": command,
            "username": process.get_extra_info("username"),
        },
    )

    # Perform threat analysis
    attack_analysis, vulnerabilities = _perform_threat_analysis(command, server)

    # Log threats
    _log_threats(attack_analysis, vulnerabilities, command, server)

    # Handle file operations
    _handle_file_operations(command, server)

    # Store command in session data and history
    server.session_data["commands"].append(
        {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "command": command,
            "interactive": interactive,
            "attack_analysis": attack_analysis,
            "vulnerabilities": vulnerabilities,
        }
    )

    if command.strip() and not command.strip().lower() == "history":
        server.command_history.append(command.strip())

    # Add artificial latency
    if config["honeypot"].getboolean("latency_enable", False):
        min_latency = config["honeypot"].getint("latency_min_ms", 20) / 1000
        max_latency = config["honeypot"].getint("latency_max_ms", 250) / 1000
        await asyncio.sleep(min_latency + (max_latency - min_latency) * time.time() % 1)

    # Handle manual commands first
    manual_response = handle_manual_commands(command, process, server)
    if manual_response:
        response_content = manual_response
    else:
        response_content = await _get_llm_response(
            command, attack_analysis, process, server, llm_config, interactive
        )

    # Handle special commands
    if command.strip() in ["help", "--help", "-h"]:
        response_content = get_help_text()
    elif command.startswith("echo ") and ">" in command:
        handle_file_creation(command, server)

    if response_content != "XXX-END-OF-SESSION-XXX":
        # Record response in session transcript
        if server.session_recording and server.session_transcript is not None:
            server.session_transcript.append(
                {
                    "timestamp": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                    "type": "output",
                    "content": response_content,
                    "interactive": interactive,
                }
            )

        if response_content and response_content.strip():
            process.stdout.write(f"{response_content}\n")
        process.stdout.write(get_prompt(server))
        logger.info(
            "LLM response",
            extra={
                "details": b64encode(response_content.encode("utf-8")).decode("utf-8"),
                "interactive": interactive,
            },
        )

    return response_content


def handle_manual_commands(
    command: str,
    process: asyncssh.SSHServerProcess,
    server: Optional["MySSHServer"] = None,
) -> Optional[str]:
    """Handle only basic Unix commands that don't require file/folder arguments"""
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return ""

    cmd = cmd_parts[0].lower()
    username = process.get_extra_info("username") or "guest"

    # Handle exit commands immediately - these should always work
    if cmd in ["exit", "logout", "quit"]:
        return "XXX-END-OF-SESSION-XXX"

    # Handle cd command manually for directory tracking
    elif cmd == "cd":
        if server:
            return server._handle_cd_command(command)
        return ""

    # Handle clear command immediately - should always work
    elif cmd == "clear":
        return "\033[2J\033[H"

    # Let LLM handle download commands dynamically
    elif cmd in ["wget", "curl"] and server and server.file_handler:
        # Still track the download for session data
        try:
            download_info = server.file_handler.handle_download(command)
            server.session_data["files_downloaded"].append(download_info)
        except Exception:
            pass
        # Let LLM provide the response
        return None

    elif cmd == "pwd":
        current_path = server.current_directory if server else f"/home/{username}"
        return current_path

    elif cmd == "whoami":
        return username

    elif cmd == "date":
        return datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")

    elif cmd == "history":
        if server and hasattr(server, "command_history"):
            history_output = ""
            for i, hist_cmd in enumerate(server.command_history, 1):
                history_output += f"{i:5d}  {hist_cmd}\n"
            return history_output.rstrip()
        else:
            return "bash: history: command not found"

    # Pass everything else to LLM (ls, cat, find, etc.)
    return None


def clean_ansi_sequences(text: str) -> str:
    """Clean malformed ANSI escape sequences from text"""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = re.sub(r"\s*\[\d*;?\d*m\s*", "", text)
    text = re.sub(r"\s*\[\d+m\s*", "", text)
    text = re.sub(r"\b\d+\s+", "\n", text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\n\s+", "\n", text)
    return text.strip()


# Removed file caching and tab completion functions - LLM handles everything


def get_prompt(server: Optional["MySSHServer"]) -> str:
    """Generate dynamic prompt based on current directory"""
    if server and hasattr(server, "current_directory"):
        username = getattr(server, "username", "guest")
        path = server.current_directory
        if path == f"/home/{username}":
            return f"{username}@corp-srv-01:~$ "
        elif path.startswith(f"/home/{username}/"):
            short_path = path.replace(f"/home/{username}/", "")
            # amazonq-ignore-next-line
            return f"{username}@corp-srv-01:~/{short_path}$ "
        else:
            return f"{username}@corp-srv-01:{path}$ "
    username = getattr(server, "username", "guest") if server else "guest"
    return f"{username}@corp-srv-01:~$ "


def get_help_text() -> str:
    """Return help text for common commands"""
    return """Available commands:
  ls, dir          - List directory contents
  cd <dir>         - Change directory
  pwd              - Print working directory
  cat <file>       - Display file contents
  ps               - Show running processes
  top              - Display system processes
  whoami           - Show current user
  id               - Show user and group IDs
  uname -a         - Show system information
  netstat -an      - Show network connections
  ifconfig         - Show network interfaces
  history          - Show command history
  clear            - Clear screen
  exit, logout     - End session
  help             - Show this help
"""


def handle_file_creation(command: str, server: MySSHServer):
    """Handle file creation commands"""
    try:
        # Extract filename and content from echo command
        match = re.match(r'echo\s+["\']?(.+?)["\']?\s*>\s*(.+)', command)
        if match:
            content, filename = match.groups()

            # Create file in session directory if available
            if hasattr(server, "session_dir") and server.session_dir:
                file_path = server.session_dir / "created_files" / filename.strip()
                file_path.parent.mkdir(parents=True, exist_ok=True)

                with open(file_path, "w") as f:
                    f.write(content.strip())

                # Log file creation
                creation_info = {
                    "timestamp": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                    "filename": filename.strip(),
                    "content": content.strip(),
                    "file_path": str(file_path),
                    "command": command,
                }

                server.session_data["files_uploaded"].append(creation_info)

                if server.forensic_logger:
                    server.forensic_logger.log_event("file_created", creation_info)
                    server.forensic_logger.add_evidence(
                        "created_file", str(file_path), f"File created via: {command}"
                    )

    except Exception as e:
        logger.error(f"Error handling file creation: {e}")


async def start_server() -> None:
    server_instance = MySSHServer()

    port = config["ssh"].getint("port", 8022)
    llm_provider = config["llm"].get("llm_provider", "openai")
    model_name = config["llm"].get("model_name", "gpt-4o-mini")

    print(f"\n✅ SSH Honeypot Starting...")
    print(f"📡 Port: {port}")
    print(f"🤖 LLM Provider: {llm_provider}")
    print(f"📊 Model: {model_name}")
    print(f"🔍 Sensor: {sensor_name}")
    print(f"📁 Log File: {config['honeypot'].get('log_file', 'ssh_log.log')}")
    print(f"⚠️  Press Ctrl+C to stop\n")

    async def process_factory(process: asyncssh.SSHServerProcess) -> None:
        await handle_client(process, server_instance)

    await asyncssh.listen(
        port=port,
        reuse_address=True,
        server_factory=lambda: server_instance,
        server_host_keys=config["ssh"].get("host_priv_key", "ssh_host_key"),
        process_factory=process_factory,
        server_version=config["ssh"].get(
            "server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
        ),
        keepalive_interval=30,
        keepalive_count_max=10,
        login_timeout=3600,
    )

    print(f"✅ SSH honeypot listening on 127.0.0.1:{port}")
    print("📡 Ready for connections...")


class ContextFilter(logging.Filter):
    """
    This filter is used to add the current asyncio task name to the log record,
    so you can group events in the same session together.
    """

    def filter(self, record):
        try:
            # Safely get task name if we're in an async context
            task_name = getattr(asyncio.current_task(), "get_name", lambda: "-")()
        except RuntimeError:
            # Fallback if we're not in an async context
            task_name = thread_local.__dict__.get("session_id", "-")

        # Add connection details from thread local storage
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

    # Get temperature parameter from config, default to 0.2 if not specified
    temperature = config["llm"].getfloat("temperature", 0.2)

    # Base model kwargs
    base_kwargs = {"temperature": temperature}

    # Provider-specific kwargs
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
        # amazonq-ignore-next-line
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
    parser = argparse.ArgumentParser(description="Start the SSH honeypot server.")
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
        "-P", "--port", type=int, help="The port the SSH honeypot will listen on"
    )
    parser.add_argument(
        "-k", "--host-priv-key", type=str, help="The host key to use for the SSH server"
    )
    parser.add_argument(
        "-v",
        "--server-version-string",
        type=str,
        help="The server version string to send to clients",
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
        # User explicitly set a config file; error if it doesn't exist.
        if not os.path.exists(args.config):
            print(
                f"Error: The specified config file '{args.config}' does not exist.",
                file=sys.stderr,
            )
            sys.exit(1)
        config.read(args.config)
    else:
        default_config = "config.ini"
        if os.path.exists(default_config):
            config.read(default_config)
        else:
            # Use defaults when no config file found.
            default_log_file = str(
                Path(__file__).parent.parent.parent / "logs" / "ssh_log.log"
            )
            config["honeypot"] = {
                "log_file": default_log_file,
                "sensor_name": socket.gethostname(),
            }
            config["ssh"] = {
                "port": "8022",
                "host_priv_key": "ssh_host_key",
                "server_version_string": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
            }
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
    if args.port:
        config["ssh"]["port"] = str(args.port)
    if args.host_priv_key:
        config["ssh"]["host_priv_key"] = args.host_priv_key
    if args.server_version_string:
        config["ssh"]["server_version_string"] = args.server_version_string
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
        config["honeypot"].get("log_file", "ssh_log.log")
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
        RunnablePassthrough.assign(messages=itemgetter("messages") | llm_trimmer)
        | llm_prompt
        | llm
    )

    with_message_history = RunnableWithMessageHistory(
        llm_chain, llm_get_session_history, input_messages_key="messages"
    )
    # Thread-local storage for connection details
    thread_local = threading.local()

    # Kick off the server!
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
        loop.run_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n🛑 SSH honeypot stopped by user")
        logger.info("SSH honeypot stopped by user")
    finally:
        try:
            loop.close()
        except Exception:
            pass

except KeyboardInterrupt:
    print("\n🛑 SSH honeypot stopped by user")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
