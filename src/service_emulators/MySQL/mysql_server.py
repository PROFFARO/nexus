#!/usr/bin/env python3

import argparse
import asyncio
import datetime
import hashlib
import importlib
import json
import logging
import os
import re
import socket
import struct
import threading
import time
import traceback
import uuid
from base64 import b64decode, b64encode
from configparser import ConfigParser
from operator import itemgetter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Module-level logger (safe to call before main)
logger = logging.getLogger(__name__)

# Import new MySQL components
try:
    from mysql_database import MySQLDatabaseSystem
    from mysql_command_executor import MySQLCommandExecutor
    from mysql_llm_guard import MySQLLLMGuard
    MYSQL_COMPONENTS_AVAILABLE = True
except ImportError:
    MYSQL_COMPONENTS_AVAILABLE = False
    logger.warning("MySQL components not available, using legacy mode")

# Thread-local used by ContextFilter
thread_local = threading.local()

# Global configuration variable
config = None

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

# --------------------------
# Dynamic import of mysql_mimic (avoid static Pylance errors)
# --------------------------
mysql_mimic = None
utils = None
MysqlServer = None
Session = None
ResultColumn = None
infer_type = None
ResultSet = None
ConnectionClosed = Exception
Connection = None
Variables = None
AllowedResult = None
MysqlError = Exception
IdentityProvider = None
User = None
AuthState = None
Success = None
NativePasswordAuthPlugin = None


# Provide minimal fallback stubs so the file loads without mysql_mimic
class _FallbackIdentityProvider:
    def get_plugins(self):
        return []

    def get_default_plugin(self):
        return None


class _FallbackUser:
    def __init__(self, name: str, auth_plugin: Optional[str] = None):
        self.name = name
        self.auth_plugin = auth_plugin


class _FallbackAuthState:
    pass


class _FallbackSuccess:
    def __init__(self, username: str):
        self.username = username


class _FallbackNativePasswordAuthPlugin:
    async def auth(self, auth_info=None):
        yield _FallbackSuccess("unknown")


# Try to import mysql_mimic dynamically
try:
    mysql_mimic = importlib.import_module("mysql_mimic")
    utils = importlib.import_module("mysql_mimic.utils")
    server_mod = importlib.import_module("mysql_mimic.server")
    auth_mod = importlib.import_module("mysql_mimic.auth")
    connection_mod = importlib.import_module("mysql_mimic.connection")
    results_mod = importlib.import_module("mysql_mimic.results")
    stream_mod = importlib.import_module("mysql_mimic.stream")
    variables_mod = importlib.import_module("mysql_mimic.variables")
    session_mod = importlib.import_module("mysql_mimic.session")
    errors_mod = importlib.import_module("mysql_mimic.errors")

    MysqlServer = getattr(server_mod, "MysqlServer", None)
    # Some modules export Session/ResultColumn at different locations
    Session = getattr(mysql_mimic, "Session", getattr(session_mod, "Session", None))
    ResultColumn = getattr(
        results_mod, "ResultColumn", getattr(mysql_mimic, "ResultColumn", None)
    )
    infer_type = getattr(results_mod, "infer_type", None)
    ResultSet = getattr(
        results_mod, "ResultSet", getattr(mysql_mimic, "ResultSet", None)
    )
    ConnectionClosed = getattr(stream_mod, "ConnectionClosed", ConnectionClosed)
    Connection = getattr(connection_mod, "Connection", None)
    Variables = getattr(variables_mod, "Variables", None)
    AllowedResult = getattr(session_mod, "AllowedResult", None)
    MysqlError = getattr(errors_mod, "MysqlError", Exception)

    IdentityProvider = getattr(auth_mod, "IdentityProvider", None)
    User = getattr(auth_mod, "User", None)
    AuthState = getattr(auth_mod, "AuthState", None)
    Success = getattr(auth_mod, "Success", None)
    NativePasswordAuthPlugin = getattr(auth_mod, "NativePasswordAuthPlugin", None)

except Exception:
    # Keep fallback stubs
    if IdentityProvider is None:
        IdentityProvider = _FallbackIdentityProvider
    if User is None:
        User = _FallbackUser
    if AuthState is None:
        AuthState = _FallbackAuthState
    if Success is None:
        Success = _FallbackSuccess
    if NativePasswordAuthPlugin is None:
        NativePasswordAuthPlugin = _FallbackNativePasswordAuthPlugin

# --------------------------
# Langchain imports (keep as before; if missing they will raise at runtime)
# --------------------------
from langchain_openai import AzureChatOpenAI, ChatOpenAI

try:
    from langchain_aws import ChatBedrock, ChatBedrockConverse
except ImportError:
    ChatBedrock = ChatBedrockConverse = None

from langchain_google_genai import ChatGoogleGenerativeAI

try:
    from langchain_ollama import ChatOllama
except ImportError:
    ChatOllama = None

from langchain_core.chat_history import (
    BaseChatMessageHistory,
    InMemoryChatMessageHistory,
)
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_core.runnables.history import RunnableWithMessageHistory

# Additional Logging Imports
import logging.handlers
import json

class MySQLJSONFormatter(logging.Formatter):
    """JSON Formatter for structured logging"""
    def __init__(self, sensor_name):
        super().__init__()
        self.sensor_name = sensor_name

    def format(self, record):
        log_entry = {
            "timestamp": datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(),
            "sensor": self.sensor_name,
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "line": record.lineno
        }
        
        # Merge extra fields if present (passed via extra={'structured_data': ...})
        if hasattr(record, "structured_data") and isinstance(record.structured_data, dict):
            log_entry.update(record.structured_data)
        
        # Include session_id if available on record (from ContextFilter)
        if hasattr(record, "session_id"):
            log_entry["session_id"] = record.session_id
            
        return json.dumps(log_entry)

class ContextFilter(logging.Filter):
    """Filter to add context info to logs"""
    def filter(self, record):
        if hasattr(thread_local, "session_id"):
            record.session_id = thread_local.session_id
        return True

# Load environment variables
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    logger.debug("python-dotenv not installed; skipping loading .env")

# Import ML components
# ML components already imported above


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
            # Fallback to basic patterns
            return {
                "sql_injection": {
                    "patterns": [
                        r"union.*select",
                        r"or.*1=1",
                        r"drop.*table",
                        r"insert.*into",
                    ],
                    "severity": "critical",
                },
                "privilege_escalation": {
                    "patterns": [r"grant.*all", r"create.*user", r"alter.*user"],
                    "severity": "high",
                },
                "data_exfiltration": {
                    "patterns": [
                        r"select.*from.*information_schema",
                        r"show.*tables",
                        r"describe.*",
                    ],
                    "severity": "medium",
                },
                "reconnaissance": {
                    "patterns": [r"show.*databases", r"show.*users", r"version\(\)"],
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

    def analyze_query(
        self, query: str, username: str = "", database: str = ""
    ) -> Dict[str, Any]:
        """Analyze MySQL query for attack patterns with ML integration"""
        analysis = {
            "query": query,
            "username": username,
            "database": database,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attack_types": [],
            "severity": "low",
            "indicators": [],
            "vulnerabilities": [],
            "pattern_matches": [],
        }

        # Check attack patterns from JSON
        for attack_type, attack_data in self.attack_patterns.items():
            patterns = attack_data.get("patterns", [])
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
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
                if re.search(pattern, query, re.IGNORECASE):
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

        analysis["severity"] = max_severity

        # Calculate threat score
        threat_score = self._calculate_threat_score(analysis)
        analysis["threat_score"] = threat_score

        # Add ML-based analysis if available
        if self.ml_detector:
            try:
                # Prepare comprehensive ML data
                ml_data = {
                    "query": query,
                    "username": username,
                    "database": database,
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
                    f"MySQL ML Analysis: Score={ml_score:.3f}, Risk={risk_info['risk_level']}, "
                    f"Vectors={len(attack_vectors)}, Labels={ml_results.get('ml_labels', [])}"
                )

            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                # Add ML error information to analysis
                analysis["ml_error"] = str(e)
                analysis["ml_anomaly_score"] = 0.0
                analysis["ml_labels"] = ["ml_error"]
                analysis["attack_vectors"] = []

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


# --------------------------
# Utility: patch mysql_mimic callback to avoid noisy logs when protocol errors happen
# --------------------------
def patch_client_connected_cb_to_avoid_log_errors():
    """Patch mysql_mimic to handle connection errors gracefully"""
    if mysql_mimic is None:
        return

    # Only patch if server exists
    server_mod = getattr(mysql_mimic, "server", None)
    if server_mod is None:
        return

    orig_cb = getattr(server_mod.MysqlServer, "_client_connected_cb", None)
    if orig_cb is None:
        return

    async def safe_cb(self, reader, writer):
        try:
            await orig_cb(self, reader, writer)
        except (ConnectionClosed, ConnectionResetError, BrokenPipeError):
            # Normal disconnection, don't log as error
            pass
        except MysqlError as e:
            logger.debug(f"MySQL protocol error: {e}")
        except Exception as e:
            logger.debug(f"Client connection error: {e}")

    server_mod.MysqlServer._client_connected_cb = safe_cb


# --------------------------
# Authentication plugin and provider
# --------------------------
# Create base class dynamically to avoid Pylance errors
# Create base class dynamically to avoid Pylance errors
if NativePasswordAuthPlugin is None:
    NativePasswordAuthPlugin = _FallbackNativePasswordAuthPlugin


class PasswordVerifyAuthPlugin(NativePasswordAuthPlugin):
    """
    Correct plugin for mysql-mimic >= 1.1
    """

    def __init__(self, accounts: Dict[str, str]):
        super().__init__()
        self.accounts = accounts
        self._nonce = None

    # local XOR function (pxor replacement)
    def _pxor(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    async def auth(self, auth_info=None):
        # STEP 1: server sends nonce on first call
        if auth_info is None:
            self._nonce = utils.nonce(20)
            auth_info = yield self._nonce + b"\x00"

        username = auth_info.username  # correct API

        # STEP 2: unknown user
        if username not in self.accounts:
            yield MysqlError(
                code=1045,
                message=f"Access denied for user '{username}' (unknown user)",
            )
            return

        stored_pw = self.accounts[username]

        # STEP 3: wildcard → accept any password
        if stored_pw == "*":
            yield Success(username)
            return

        client_resp = auth_info.data  # correct API

        if not client_resp:
            yield MysqlError(
                code=1045,
                message=f"Access denied for user '{username}' (empty password)",
            )
            return

        import hashlib

        # MySQL native double SHA1 hashing
        stage1 = hashlib.sha1(stored_pw.encode()).digest()
        stage2 = hashlib.sha1(stage1).digest()

        # match = SHA1(nonce + stage2) XOR stage1
        expected = self._pxor(
            client_resp,
            hashlib.sha1(self._nonce + stage2).digest(),
        )

        if expected == stage1:
            yield Success(username)
            return

        # wrong password
        yield MysqlError(
            code=1045,
            message=f"Access denied for user '{username}' (incorrect password)",
        )
        return


class ConfigBasedIdentityProvider(IdentityProvider):
    def __init__(self, accounts: Dict[str, str]):
        self.accounts = accounts
        self.plugin = PasswordVerifyAuthPlugin(accounts)

    def get_plugins(self):
        return [self.plugin]

    def get_default_plugin(self):
        return self.plugin

    async def get_user(self, username: str) -> Optional[User]:
        if username not in self.accounts:
            return None

        return User(
            name=username,
            auth_plugin="mysql_native_password",
        )


# --------------------------
# Analysis / logging classes (unchanged behavior)
# --------------------------
class MySQLAttackAnalyzer:
    """AI-based MySQL attack analyzer with integrated JSON patterns and ML detection"""

    def __init__(self):
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_signatures = self._load_vulnerability_signatures()

        # Initialize ML detector if available
        self.ml_detector = None
        if ML_AVAILABLE:
            try:
                ml_config = MLConfig("mysql")
                if ml_config.is_enabled():
                    self.ml_detector = MLDetector("mysql", ml_config)
                    logging.info("ML detector initialized for MySQL service")
            except Exception as e:
                logging.warning(f"Failed to initialize ML detector: {e}")
                self.ml_detector = None

    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load MySQL-specific attack patterns"""
        try:
            patterns_file = Path(__file__).parent / "attack_patterns.json"
            with open(patterns_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load attack patterns: {e}")
            return {
                "sql_injection": {
                    "patterns": [
                        r"'.*or.*1\s*=\s*1",
                        r"union.*select.*from",
                        r"';.*drop",
                        r"';.*delete",
                    ],
                    "severity": "critical",
                },
                "reconnaissance": {
                    "patterns": [r"show.*databases.*where", r"show.*tables.*like.*%"],
                    "severity": "medium",
                },
            }

    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load MySQL vulnerability signatures"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load vulnerability signatures: {e}")
            return {}

    def analyze_query(
        self, query: str, username: str = "", database: str = ""
    ) -> Dict[str, Any]:
        """Analyze MySQL query for attack patterns with ML integration"""
        analysis = {
            "query": query,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attack_types": [],
            "severity": "low",
            "indicators": [],
            "vulnerabilities": [],
            "pattern_matches": [],
        }

        # Check if attack pattern recognition is enabled
        if config and not config["ai_features"].getboolean(
            "attack_pattern_recognition", True
        ):
            return analysis

        # Check attack patterns
        for attack_type, attack_data in self.attack_patterns.items():
            patterns = attack_data.get("patterns", [])
            for pattern in patterns:
                try:
                    if re.search(pattern, query, re.IGNORECASE):
                        analysis["attack_types"].append(attack_type)
                        analysis["indicators"].extend(attack_data.get("indicators", []))
                        analysis["pattern_matches"].append(
                            {
                                "type": attack_type,
                                "pattern": pattern,
                                "severity": attack_data.get("severity", "medium"),
                            }
                        )
                except re.error as e:
                    logger.warning(
                        f"Invalid regex pattern '{pattern}' in attack type '{attack_type}': {e}"
                    )
                    continue

        # Check vulnerability signatures
        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                try:
                    if re.search(pattern, query, re.IGNORECASE):
                        analysis["vulnerabilities"].append(
                            {
                                "vulnerability_id": vuln_id,
                                "vuln_name": vuln_data.get("name", vuln_id),
                                "severity": vuln_data.get("severity", "medium"),
                                "cvss_score": vuln_data.get("cvss_score", 0.0),
                                "pattern_matched": pattern,
                            }
                        )
                except re.error as e:
                    logging.warning(
                        f"Invalid regex pattern '{pattern}' in vulnerability '{vuln_id}': {e}"
                    )
                    continue

        # Determine overall severity
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = "low"

        for match in analysis["pattern_matches"]:
            if (
                severity_scores.get(match["severity"], 1)
                > severity_scores[max_severity]
            ):
                max_severity = match["severity"]

        for vuln in analysis["vulnerabilities"]:
            if severity_scores.get(vuln["severity"], 1) > severity_scores[max_severity]:
                max_severity = vuln["severity"]

        # Apply sensitivity level adjustment - dynamically loaded from config
        if config:
            sensitivity = (
                config["attack_detection"].get("sensitivity_level", "medium").lower()
            )
            if sensitivity == "critical":
                # Treat all detections as high severity
                if max_severity in ["low", "medium"]:
                    max_severity = "high"
            elif sensitivity == "high" and max_severity == "low":
                max_severity = "medium"
            elif sensitivity == "low" and max_severity == "medium":
                max_severity = "low"

        analysis["severity"] = max_severity

        # Calculate threat score if enabled - uses config alert_threshold
        if config and config["attack_detection"].getboolean("threat_scoring", True):
            threat_score = self._calculate_threat_score(analysis)
            analysis["threat_score"] = threat_score

            # Check alert threshold - dynamically loaded from config
            alert_threshold = config["attack_detection"].getint("alert_threshold", 70)
            analysis["alert_triggered"] = threat_score >= alert_threshold
            
            # Log the dynamic threshold being used
            logging.debug(
                f"Threat scoring: score={threat_score}, threshold={alert_threshold}, triggered={analysis['alert_triggered']}"
            )

        # Add ML-based analysis if available and enabled - uses config ml.enabled
        if self.ml_detector and config and config["ml"].getboolean("enabled", True) if "ml" in config else False:
            try:
                # Prepare comprehensive ML data
                ml_data = {
                    "query": query,
                    "username": username,
                    "database": database,
                    "timestamp": analysis["timestamp"],
                    "attack_types": analysis["attack_types"],
                    "severity": analysis["severity"],
                    "indicators": analysis["indicators"],
                    "vulnerabilities": analysis["vulnerabilities"],
                    "pattern_matches": analysis["pattern_matches"],
                    "session_data": {
                        "query_count": 1,
                        "failed_queries": 0,
                        "bytes_transferred": len(query),
                    },
                }

                # Get ML scoring results
                ml_results = self.ml_detector.score(ml_data)

                # Integrate ML results into analysis
                analysis["ml_anomaly_score"] = ml_results.get("ml_anomaly_score", 0.0)
                analysis["ml_labels"] = ml_results.get("ml_labels", [])
                analysis["ml_cluster"] = ml_results.get("ml_cluster", -1)
                analysis["ml_reason"] = ml_results.get("ml_reason", "No ML analysis")
                analysis["ml_confidence"] = ml_results.get("ml_confidence", 0.0)
                analysis["ml_inference_time_ms"] = ml_results.get(
                    "ml_inference_time_ms", 0
                )

                # Log ML analysis results with dynamic config parameters
                logging.info(
                    "MySQL ML analysis completed",
                    extra={
                        "ml_anomaly_score": analysis["ml_anomaly_score"],
                        "ml_labels": analysis["ml_labels"],
                        "ml_reason": analysis["ml_reason"],
                        "ml_inference_time_ms": analysis["ml_inference_time_ms"],
                        "ml_enabled": config["ml"].getboolean("enabled", True),
                        "anomaly_threshold": config["ml"].getfloat("anomaly_threshold", 0.95),
                        "query": query[:50] + "..." if len(query) > 50 else query,
                        "username": username,
                        "database": database,
                    },
                )

                # Enhance severity based on ML anomaly score using dynamic threshold
                ml_threshold = config["ml"].getfloat("anomaly_threshold", 0.95) if "ml" in config else 0.95
                if ml_results.get("ml_anomaly_score", 0) > ml_threshold:
                    if analysis["severity"] in ["low", "medium"]:
                        analysis["severity"] = "high"
                        analysis["attack_types"].append("ml_anomaly")

            except Exception as e:
                logging.error(f"ML analysis failed: {e}")
                ml_fallback = config["ml"].getboolean("fallback_on_error", True) if "ml" in config else True
                if not ml_fallback:
                    raise
                logging.info("ML error fallback enabled, continuing with rule-based analysis")

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

        return min(score, 100)  # Cap at 100


class MySQLVulnerabilityLogger:
    """Log MySQL vulnerability exploitation attempts"""

    def __init__(self):
        self.vulnerability_signatures = self._load_vulnerability_signatures()

    def _load_vulnerability_signatures(self) -> Dict[str, Any]:
        """Load vulnerability signatures"""
        try:
            vuln_file = Path(__file__).parent / "vulnerability_signatures.json"
            with open(vuln_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load vulnerability signatures: {e}")
            return {
                "MYSQL_INJECTION": {
                    "patterns": [r"'.*or.*1\s*=\s*1", r"union.*select.*from"],
                    "severity": "critical",
                },
                "MYSQL_ENUMERATION": {
                    "patterns": [
                        r"information_schema\.(tables|columns)",
                        r"show.*databases.*where",
                    ],
                    "severity": "medium",
                },
            }

    def analyze_for_vulnerabilities(self, query: str) -> List[Dict[str, Any]]:
        """Analyze query for vulnerability exploitation"""
        vulnerabilities = []

        # Check if vulnerability detection is enabled
        if not config["ai_features"].getboolean("vulnerability_detection", True):
            return vulnerabilities

        for vuln_id, vuln_data in self.vulnerability_signatures.items():
            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                try:
                    if re.search(pattern, query, re.IGNORECASE):
                        vulnerabilities.append(
                            {
                                "vulnerability_id": vuln_id,
                                "vuln_name": vuln_data.get("name", vuln_id),
                                "description": vuln_data.get("description", ""),
                                "pattern_matched": pattern,
                                "input": query,
                                "timestamp": datetime.datetime.now(
                                    datetime.timezone.utc
                                ).isoformat(),
                                "severity": vuln_data.get("severity", "medium"),
                                "cvss_score": vuln_data.get("cvss_score", 0.0),
                                "indicators": vuln_data.get("indicators", []),
                            }
                        )
                except re.error as e:
                    logger.warning(
                        f"Invalid regex pattern '{pattern}' in vulnerability '{vuln_id}': {e}"
                    )
                    continue

        return vulnerabilities


class MySQLForensicLogger:
    """Generate forensic chain of custody for MySQL attacks"""

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

        # Validate and sanitize file path to prevent path traversal
        safe_path = Path(file_path).resolve()
        try:
            safe_path.relative_to(Path.cwd())
        except ValueError:
            logger.warning(
                f"Rejected evidence file outside working directory: {file_path}"
            )
            return

        if os.path.exists(safe_path):
            with open(safe_path, "rb") as f:
                content = f.read()

            evidence = {
                "evidence_id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": evidence_type,
                "file_path": str(safe_path),
                "file_size": len(content),
                "description": description,
            }

            # Add file hash analysis if enabled
            if config["forensics"].getboolean("query_hash_analysis", True):
                evidence["file_hash"] = hashlib.sha256(content).hexdigest()
                evidence["md5_hash"] = hashlib.md5(content).hexdigest()

            self.chain_data["evidence"].append(evidence)
            self._save_chain()

    def _save_chain(self):
        """Save forensic chain to file"""
        with open(self.chain_file, "w", encoding="utf-8") as f:
            json.dump(self.chain_data, f, indent=2, ensure_ascii=False)


class MySQLJSONFormatter(logging.Formatter):
    """JSON formatter for MySQL honeypot logs"""

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
            "sensor_protocol": "mysql",
        }

        # Include additional fields, excluding problematic ones
        excluded_fields = {
            "args",
            "msg",
            "name",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "taskName",
        }
        for key, value in record.__dict__.items():
            if key not in log_record and key not in excluded_fields:
                log_record[key] = value

        return json.dumps(log_record)


# --------------------------
# MySQL session implementation using mysql_mimic.Session as base (or fallback)
# --------------------------
# If mysql_mimic.Session is not available, provide a small local fallback base class
if Session is None:

    class _FallbackSession:
        def __init__(self, variables=None):
            self.variables = variables

        async def init(self, connection):
            return None

        async def handle_query(self, sql: str, attrs: Dict[str, str]):
            return None

    Session = _FallbackSession

# Minimal ResultColumn / ResultSet fallback
if ResultColumn is None:

    class _ResultColumn:
        def __init__(self, name: str, type: Any = 253):
            self.name = name
            self.type = type  # Use MySQL type integer (253 = MYSQL_TYPE_VAR_STRING)

    ResultColumn = _ResultColumn

if ResultSet is None:

    class _ResultSet:
        def __init__(self, rows=None, columns=None):
            self.rows = rows or []
            self.columns = columns or []

    ResultSet = _ResultSet

# Minimal infer_type fallback
if infer_type is None:

    def _infer_type(value: Any) -> int:
        # MySQL column type constants
        if isinstance(value, int):
            return 3  # MYSQL_TYPE_LONG
        if isinstance(value, float):
            return 5  # MYSQL_TYPE_DOUBLE
        return 253  # MYSQL_TYPE_VAR_STRING

    infer_type = _infer_type


class MySQLHoneypotSession(Session):
    """Enhanced MySQL session with AI and attack analysis"""

    def __init__(self, config: ConfigParser, variables=None):
        super().__init__(variables)
        self.config = config
        self.attack_analyzer = MySQLAttackAnalyzer()
        self.vuln_logger = MySQLVulnerabilityLogger()
        # Get default database from config for initial session context
        default_db = config["mysql"].get("default_database", "nexus_gamedev")
        
        # Initialize new MySQL components for command handling
        if MYSQL_COMPONENTS_AVAILABLE:
            self.db_system = MySQLDatabaseSystem()
            self.db_system.use_database(default_db)  # Set default database
            self.llm_guard = MySQLLLMGuard(self.config)
            self.command_executor = MySQLCommandExecutor(self.db_system, self.llm_guard, self.config)
            logger.info("MySQL components initialized successfully")
        else:
            self.db_system = None
            self.llm_guard = None
            self.command_executor = None
            
        self.session_data = {
            "session_id": str(uuid.uuid4()),
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "end_time": None,
            "database": default_db,  # Initialize with default database from config
            "created_databases": [],  # Track databases created in this session
            "queries": [],
            "attack_analysis": [],
            "vulnerabilities": [],
            "authenticated": False,
            "username": None,
            "client_info": {"ip": "unknown", "port": "unknown"},
            "session_stats": {
                "total_queries": 0,
                "attack_queries": 0,
            },
        }
        self.forensic_logger = None

    def _extract_server_connection_info(self, connection) -> tuple[bool, str, str]:
        """Extract connection info from server's captured data"""
        if not (hasattr(self, "_server") and hasattr(self._server, "connection_info")):
            return False, "unknown", "unknown"

        for transport_id, conn_info in self._server.connection_info.items():
            if self._transport_matches(connection, transport_id):
                logger.debug(
                    f"Using server captured connection info: {conn_info['client_ip']}:{conn_info['client_port']}"
                )
                return True, conn_info["client_ip"], conn_info["client_port"]

        return False, "unknown", "unknown"

    def _transport_matches(self, connection, transport_id: int) -> bool:
        """Check if connection matches transport ID"""
        transport_checks = [
            lambda: hasattr(connection, "_reader")
            and hasattr(connection._reader, "_transport")
            and id(connection._reader._transport) == transport_id,
            lambda: hasattr(connection, "transport")
            and id(connection.transport) == transport_id,
            lambda: hasattr(connection, "_transport")
            and id(connection._transport) == transport_id,
            lambda: hasattr(connection, "writer")
            and hasattr(connection.writer, "transport")
            and id(connection.writer.transport) == transport_id,
        ]

        return any(check() for check in transport_checks)

    def _extract_direct_connection_info(self, connection) -> tuple[bool, str, str]:
        """Extract connection info directly from transport"""
        transport = self._get_transport(connection)
        if not transport or not hasattr(transport, "get_extra_info"):
            return False, "unknown", "unknown"

        peername = transport.get_extra_info("peername")
        if peername:
            logger.debug(
                f"Direct extraction connection info: {peername[0]}:{peername[1]}"
            )
            return True, peername[0], peername[1]

        return False, "unknown", "unknown"

    def _get_transport(self, connection):
        """Get transport object from connection"""
        transport_getters = [
            lambda: getattr(connection._reader, "_transport", None)
            if hasattr(connection, "_reader")
            else None,
            lambda: getattr(connection, "transport", None),
            lambda: getattr(connection, "_transport", None),
            lambda: getattr(connection.writer, "transport", None)
            if hasattr(connection, "writer")
            else None,
        ]

        for getter in transport_getters:
            try:
                transport = getter()
                if transport:
                    return transport
            except AttributeError:
                continue
        return None

    def _extract_username(self, connection) -> str:
        """Extract username from connection"""
        try:
            session = getattr(connection, "session", None)
            if session:
                username = getattr(session, "username", None)
                return username or "unknown"
        except Exception:
            pass
        return "unknown"

    async def init(self, connection) -> None:
        """Initialize session with connection info"""
        try:
            # Try multiple methods to extract connection info
            connection_found, client_ip, client_port = (
                self._extract_server_connection_info(connection)
            )

            if not connection_found:
                connection_found, client_ip, client_port = (
                    self._extract_direct_connection_info(connection)
                )

            if not connection_found:
                client_ip, client_port = "127.0.0.1", "0"
                logger.debug("Using localhost fallback for connection info")

            self.session_data["client_info"]["ip"] = client_ip
            self.session_data["client_info"]["port"] = client_port
            self.session_data["username"] = self._extract_username(connection)

        except Exception as e:
            logger.debug(f"Failed to extract connection info: {e}")
            self.session_data["client_info"]["ip"] = "127.0.0.1"
            self.session_data["client_info"]["port"] = "0"
            self.session_data["username"] = "unknown"

        self.session_data["authenticated"] = True

        try:
            self._connection = connection
        except Exception:
            self._connection = None
            
        # Check rate limiting
        if self.config["security"].getboolean("rate_limiting", True):
             client_ip = self.session_data["client_info"]["ip"]
             max_conn = int(self.config["security"].get("max_connections_per_ip", 10))
             # In a real implementation we would track active connections here
             # For now we just log the check
             logger.debug(f"Checking rate limit for {client_ip} (limit: {max_conn})")
        
        # Reinitialize MySQL components with authenticated username for per-user persistence
        username = self.session_data.get("username", "anonymous")
        default_db = self.config["mysql"].get("default_database", "nexus_gamedev")
        
        if MYSQL_COMPONENTS_AVAILABLE:
            # Get sessions directory from config
            try:
                sessions_dir = Path(self.config["honeypot"].get("sessions_dir", "sessions"))
            except (KeyError, TypeError):
                sessions_dir = Path("sessions")
            db_states_dir = sessions_dir / "database_states"
            
            # Reinitialize with username for per-user persistence
            try:
                self.db_system = MySQLDatabaseSystem(username=username, sessions_dir=str(db_states_dir))
                self.db_system.use_database(default_db)
                self.llm_guard = MySQLLLMGuard(self.config)
                self.command_executor = MySQLCommandExecutor(self.db_system, self.llm_guard, self.config)
                logger.info(f"MySQL components reinitialized for user {username}")
            except Exception as e:
                logger.error(f"Failed to reinitialize MySQL components: {e}")
                # Keep using the existing components from __init__

        # Setup forensic logging if enabled
        if self.config["forensics"].getboolean("chain_of_custody", True):
            sessions_dir = Path(self.config["honeypot"].get("sessions_dir", "sessions"))
            session_dir = sessions_dir / self.session_data["session_id"]
            session_dir.mkdir(parents=True, exist_ok=True)
            self.forensic_logger = MySQLForensicLogger(str(session_dir))
        else:
            self.forensic_logger = None

        # Log connection
        connection_info = {
            "username": self.session_data["username"],
            "session_id": self.session_data["session_id"],
            "client_ip": self.session_data["client_info"]["ip"],
            "client_port": self.session_data["client_info"]["port"],
        }

        logger.info("MySQL session authenticated", extra=connection_info)
        if self.forensic_logger and hasattr(self.forensic_logger, "log_event"):
            self.forensic_logger.log_event("authentication_success", connection_info)

        return await super().init(connection)

    async def close_session(self):
        """Handle session termination and generate summary"""
        self.session_data["end_time"] = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        self.session_data["duration"] = self._calculate_session_duration()

        # Save comprehensive session data files like other services
        if self.forensic_logger:
            session_dir = self.forensic_logger.session_dir

            # Save session_summary.json (main session data)
            session_file = session_dir / "session_summary.json"
            with open(session_file, "w", encoding="utf-8") as f:
                json.dump(
                    self.session_data, f, indent=2, default=str, ensure_ascii=False
                )

            # Save session_data.json (detailed session data for reports)
            session_data_file = session_dir / "session_data.json"
            with open(session_data_file, "w", encoding="utf-8") as f:
                json.dump(
                    self.session_data, f, indent=2, default=str, ensure_ascii=False
                )

            # Save query_log.json (detailed query information)
            query_log_file = None
            if self.session_data.get("queries"):
                query_log_file = session_dir / "query_log.json"
                with open(query_log_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "session_id": self.session_data["session_id"],
                            "queries": self.session_data["queries"],
                            "total_queries": len(self.session_data["queries"]),
                            "attack_queries": len(
                                [
                                    q
                                    for q in self.session_data["queries"]
                                    if q.get("attack_analysis", {}).get("attack_types")
                                ]
                            ),
                            "start_time": self.session_data["start_time"],
                            "end_time": self.session_data["end_time"],
                        },
                        f,
                        indent=2,
                        default=str,
                        ensure_ascii=False,
                    )

            # Save attack_analysis.json (security analysis)
            attack_file = None
            if self.session_data.get("attack_analysis") or self.session_data.get(
                "vulnerabilities"
            ):
                attack_file = session_dir / "attack_analysis.json"
                with open(attack_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "session_id": self.session_data["session_id"],
                            "attack_analysis": self.session_data["attack_analysis"],
                            "vulnerabilities": self.session_data["vulnerabilities"],
                            "total_attacks": len(self.session_data["attack_analysis"]),
                            "total_vulnerabilities": len(
                                self.session_data["vulnerabilities"]
                            ),
                            "severity_summary": self._get_severity_summary(),
                            "attack_timeline": self._generate_attack_timeline(),
                        },
                        f,
                        indent=2,
                        default=str,
                        ensure_ascii=False,
                    )

            # Add session files as evidence
            if config["forensics"].getboolean("chain_of_custody", True):
                self.forensic_logger.add_evidence(
                    "session_summary",
                    str(session_file),
                    "Complete MySQL session activity summary",
                )
                self.forensic_logger.add_evidence(
                    "session_data",
                    str(session_data_file),
                    "Detailed MySQL session data for analysis",
                )
                if query_log_file is not None:
                    self.forensic_logger.add_evidence(
                        "query_log",
                        str(query_log_file),
                        "Complete MySQL query execution log",
                    )
                if attack_file is not None:
                    self.forensic_logger.add_evidence(
                        "attack_analysis",
                        str(attack_file),
                        "MySQL attack and vulnerability analysis",
                    )

        # Log session summary
        logger.info(
            "MySQL session terminated",
            extra={
                "session_id": self.session_data["session_id"],
                "username": self.session_data["username"],
                "duration": self.session_data["duration"],
                "total_queries": self.session_data["session_stats"]["total_queries"],
                "attack_queries": self.session_data["session_stats"]["attack_queries"],
                "created_databases": len(self.session_data["created_databases"]),
                "vulnerabilities_found": len(self.session_data["vulnerabilities"]),
            },
        )

        # Generate AI session summary if enabled
        if config["ai_features"].getboolean("ai_attack_summaries", True):
            try:
                await self.generate_session_summary(self.session_data)
                logger.info(
                    f"AI session summary generated for session {self.session_data['session_id']}"
                )
            except Exception as e:
                logger.error(f"Failed to generate AI session summary: {e}")
                # Generate basic summary as fallback
                self._generate_basic_summary()
        else:
            # Generate basic summary even if AI is disabled
            self._generate_basic_summary()
            logger.info(
                f"Basic session summary generated for session {self.session_data['session_id']}"
            )

    def _calculate_session_duration(self) -> str:
        """Calculate session duration in human readable format"""
        try:
            start = datetime.datetime.fromisoformat(
                self.session_data["start_time"].replace("Z", "+00:00")
            )
            end = datetime.datetime.fromisoformat(
                self.session_data["end_time"].replace("Z", "+00:00")
            )
            duration = end - start
            return str(duration)
        except Exception:
            return "unknown"

    def _get_severity_summary(self) -> Dict[str, int]:
        """Get summary of attack severities"""
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for analysis in self.session_data.get("attack_analysis", []):
            severity = analysis.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1

        for vuln in self.session_data.get("vulnerabilities", []):
            severity = vuln.get("severity", "medium")
            if severity in severity_counts:
                severity_counts[severity] += 1

        return severity_counts

    def _generate_attack_timeline(self) -> List[Dict[str, Any]]:
        """Generate chronological attack timeline"""
        timeline = []

        # Add queries with attack analysis
        for query_info in self.session_data.get("queries", []):
            if query_info.get("attack_analysis", {}).get("attack_types"):
                timeline.append(
                    {
                        "timestamp": query_info["timestamp"],
                        "type": "attack_detected",
                        "query": query_info["query"],
                        "attack_types": query_info["attack_analysis"]["attack_types"],
                        "severity": query_info["attack_analysis"]["severity"],
                        "threat_score": query_info["attack_analysis"].get(
                            "threat_score", 0
                        ),
                    }
                )

        # Add vulnerability exploits
        for vuln in self.session_data.get("vulnerabilities", []):
            timeline.append(
                {
                    "timestamp": vuln["timestamp"],
                    "type": "vulnerability_exploit",
                    "vulnerability_id": vuln["vulnerability_id"],
                    "vuln_name": vuln["vuln_name"],
                    "severity": vuln["severity"],
                    "cvss_score": vuln.get("cvss_score", 0.0),
                }
            )

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        return timeline

    def _classify_query(self, query: str) -> str:
        """Classify MySQL query type for logging"""
        query_lower = query.lower().strip()

        if query_lower.startswith("select"):
            return "SELECT"
        elif query_lower.startswith("insert"):
            return "INSERT"
        elif query_lower.startswith("update"):
            return "UPDATE"
        elif query_lower.startswith("delete"):
            return "DELETE"
        elif query_lower.startswith("create"):
            if "database" in query_lower:
                return "CREATE_DATABASE"
            elif "table" in query_lower:
                return "CREATE_TABLE"
            else:
                return "CREATE"
        elif query_lower.startswith("drop"):
            if "database" in query_lower:
                return "DROP_DATABASE"
            elif "table" in query_lower:
                return "DROP_TABLE"
            else:
                return "DROP"
        elif query_lower.startswith("alter"):
            return "ALTER"
        elif query_lower.startswith("show"):
            if "databases" in query_lower:
                return "SHOW_DATABASES"
            elif "tables" in query_lower:
                return "SHOW_TABLES"
            elif "columns" in query_lower or "fields" in query_lower:
                return "SHOW_COLUMNS"
            elif "status" in query_lower:
                return "SHOW_STATUS"
            elif "variables" in query_lower:
                return "SHOW_VARIABLES"
            else:
                return "SHOW"
        elif query_lower.startswith("describe") or query_lower.startswith("desc"):
            return "DESCRIBE"
        elif query_lower.startswith("use"):
            return "USE"
        elif query_lower.startswith("set"):
            return "SET"
        elif query_lower.startswith("grant"):
            return "GRANT"
        elif query_lower.startswith("revoke"):
            return "REVOKE"
        elif query_lower.startswith("flush"):
            return "FLUSH"
        elif query_lower.startswith("explain"):
            return "EXPLAIN"
        else:
            return "OTHER"

    def _handle_termination_query(self, query: str) -> Optional[Any]:
        """Handle session termination queries"""
        if query.lower() in ["quit", "exit", r"\q"]:
            self.session_data["end_time"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            self.session_data["duration"] = self._calculate_session_duration()

            logger.info(
                "MySQL session terminating",
                extra={
                    "session_id": self.session_data["session_id"],
                    "command": query,
                    "username": self.session_data.get("username"),
                    "total_queries": self.session_data["session_stats"][
                        "total_queries"
                    ],
                },
            )

            return ResultSet(rows=[], columns=[])
        return None

    def _handle_use_database(self, query: str) -> Optional[Any]:
        """Handle USE database commands - update session context AND db_system"""
        if query.lower().startswith("use "):
            try:
                # Extract database name (handle quotes if present)
                parts = query.split(maxsplit=1)
                if len(parts) > 1:
                    db_name = parts[1].strip().strip(";'\"`")
                    
                    # Update BOTH session_data AND db_system
                    old_db = self.session_data.get("database")
                    self.session_data["database"] = db_name
                    
                    # Critical: Also update db_system so SHOW TABLES works correctly
                    if self.db_system:
                        if self.db_system.use_database(db_name):
                            logger.info(f"[USE_DATABASE] Switched: {old_db} -> {db_name} (db_system synced)")
                        else:
                            logger.warning(f"[USE_DATABASE] Database '{db_name}' not found in db_system, available: {self.db_system.list_databases()}")
                    else:
                        logger.info(f"[USE_DATABASE] Switched: {old_db} -> {db_name} (session only)")
                    
                    # Successful USE returns no rows
                    return ResultSet(rows=[], columns=[])
            except Exception as e:
                logger.error(f"Error handling USE command: {e}")
        return None

    def _log_query_info(self, query: str) -> Dict[str, Any]:
        """Log query information and return query info dict"""
        query_info = {
            "query": query,
            "query_type": self._classify_query(query),
            "query_length": len(query),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "username": self.session_data.get("username"),
            "session_id": self.session_data.get("session_id"),
        }

        logger.info("MySQL query received", extra=query_info)
        if self.forensic_logger and hasattr(self.forensic_logger, "log_event"):
            self.forensic_logger.log_event("query_executed", query_info)

        return query_info

    def _analyze_and_log_threats(
        self, query: str
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Analyze query for threats and log findings"""
        # Get session context for ML analysis
        username = self.session_data.get("username", "unknown")

        # Perform comprehensive analysis with ML integration
        attack_analysis = self.attack_analyzer.analyze_query(query, username, "")
        vulnerabilities = self.vuln_logger.analyze_for_vulnerabilities(query)

        # Log ML analysis results if available
        if attack_analysis.get("ml_anomaly_score") is not None:
            logger.info(
                "MySQL ML analysis completed",
                extra={
                    "ml_anomaly_score": attack_analysis.get("ml_anomaly_score", 0.0),
                    "ml_labels": attack_analysis.get("ml_labels", []),
                    "ml_reason": attack_analysis.get("ml_reason", "No reason"),
                    "ml_inference_time_ms": attack_analysis.get(
                        "ml_inference_time_ms", 0
                    ),
                    "query": query[:50] + "..." if len(query) > 50 else query,
                    "session_id": self.session_data["session_id"],
                },
            )

        # attack_logging config check
        should_log_attacks = self.config["honeypot"].getboolean("attack_logging", True)

        if attack_analysis.get("attack_types") and should_log_attacks:
            logger.warning(
                "MySQL attack pattern detected",
                extra={
                    "attack_types": attack_analysis["attack_types"],
                    "severity": attack_analysis["severity"],
                    "query": query,
                    "threat_score": attack_analysis.get("threat_score", 0),
                    "session_id": self.session_data["session_id"],
                },
            )

            if self.forensic_logger:
                self.forensic_logger.log_event("attack_detected", attack_analysis)

        for vuln in vulnerabilities:
            if should_log_attacks:
                logger.critical(
                    "MySQL vulnerability exploitation attempt",
                    extra={
                        "vulnerability_id": vuln["vulnerability_id"],
                        "vuln_name": vuln["vuln_name"],
                        "description": vuln["description"],
                        "pattern_matched": vuln["pattern_matched"],
                        "input": vuln["input"],
                        "severity": vuln["severity"],
                        "cvss_score": vuln["cvss_score"],
                        "indicators": vuln["indicators"],
                        "session_id": self.session_data["session_id"],
                    },
                )

                if self.forensic_logger:
                    self.forensic_logger.log_event("vulnerability_exploit", vuln)

        return attack_analysis, vulnerabilities

    def _update_session_data(
        self,
        query_info: Dict[str, Any],
        attack_analysis: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
    ):
        """Update session data with query and threat information"""
        query_info["attack_analysis"] = attack_analysis
        query_info["vulnerabilities"] = vulnerabilities

        if config["forensics"].getboolean("query_logging", True):
            self.session_data["queries"].append(query_info)

        if attack_analysis.get("attack_types"):
            self.session_data["attack_analysis"].append(attack_analysis)

        if vulnerabilities:
            self.session_data["vulnerabilities"].extend(vulnerabilities)

        self.session_data["session_stats"]["total_queries"] += 1
        if attack_analysis.get("attack_types"):
            self.session_data["session_stats"]["attack_queries"] += 1

    async def _process_llm_query(self, query: str) -> Any:
        """Process query through LLM and return result"""
        start_time = time.time()
        try:
            llm_response = await self._get_llm_response(query)
            result = self._parse_llm_response(llm_response, query)

            result_info = {
                "query": query,
                "query_type": self._classify_query(query),
                "rows_returned": len(result.rows) if hasattr(result, "rows") else 0,
                "columns_returned": len(result.columns)
                if hasattr(result, "columns")
                else 0,
                "execution_time": time.time() - start_time,
                "session_id": self.session_data.get("session_id"),
            }
            logger.info("MySQL query completed", extra=result_info)

            return result
        except Exception as e:
            logger.error(
                f"LLM query processing failed: {e}",
                extra={
                    "query": query,
                    "query_type": self._classify_query(query),
                    "session_id": self.session_data.get("session_id"),
                    "error_type": type(e).__name__,
                },
            )

            if ResultColumn is not None:
                return ResultSet(
                    rows=[(f"ERROR 1105 (HY000): {str(e)}",)],
                    columns=[ResultColumn(name="Error", type=253)],
                )
            else:
                return ResultSet(
                    rows=[(f"ERROR 1105 (HY000): {str(e)}",)],
                    columns=[_ResultColumn(name="Error", type=253)],
                )

    async def handle_query(self, sql: str, attrs: Dict[str, str]) -> Any:  # type: ignore
        """Handle MySQL query with logging wrapper"""
        start_time = time.time()
        
        # Prepare context data
        username = self.session_data.get("username", "unknown")
        client_ip = self.session_data.get("client_info", {}).get("ip", "unknown")
        session_id = self.session_data.get("session_id", "unknown")
        
        # Log Request Structurally
        request_data = {
            "event": "query_request",
            "query": sql,
            "client_ip": client_ip,
            "username": username,
            "session_id": session_id,
        }
        logger.info("Incoming MySQL Query", extra={"structured_data": request_data})
        
        status = "success"
        result_summary = "unknown"
        response_content = None  # Store actual response data
        error_details = None
        query_result = None  # Store result for finally block
        
        try:
            query_result = await self._handle_query_logic(sql, attrs)
            
            # Analyze result for logging summary and extract response content
            if query_result is None:
                 result_summary = "None"
                 response_content = None
            elif hasattr(query_result, "rows"):
                result_summary = f"{len(query_result.rows)} rows"
                # Extract actual row data for logging (limit to prevent huge logs)
                try:
                    rows_data = []
                    for row in query_result.rows[:50]:  # Limit to first 50 rows
                        if hasattr(row, '__iter__') and not isinstance(row, (str, bytes)):
                            rows_data.append([str(cell) for cell in row])
                        else:
                            rows_data.append([str(row)])
                    response_content = rows_data
                except Exception:
                    response_content = f"[{len(query_result.rows)} rows - extraction failed]"
            elif isinstance(query_result, list):
                 result_summary = f"{len(query_result)} items"
                 response_content = query_result[:50] if len(query_result) > 50 else query_result
            elif hasattr(query_result, "message"): 
                 result_summary = query_result.message
                 response_content = query_result.message
            else:
                 result_summary = str(type(query_result).__name__)
                 response_content = str(query_result)[:500]  # Truncate long responses
                 
            return query_result
            
        except Exception as e:
            status = "error"
            error_details = str(e)
            result_summary = f"Exception: {type(e).__name__}"
            response_content = f"ERROR: {str(e)}"
            raise e 
            
        finally:
            duration_ms = (time.time() - start_time) * 1000
            
            response_data = {
                "event": "query_response",
                "query": sql, 
                "status": status,
                "duration_ms": round(duration_ms, 2),
                "summary": result_summary,
                "session_id": session_id
            }
            
            # Add actual response content if available
            if response_content is not None:
                response_data["response"] = response_content
                
            if error_details:
                response_data["error"] = error_details
                
            logger.info("MySQL Query Processed", extra={"structured_data": response_data})

    async def _handle_query_logic(self, sql: str, attrs: Dict[str, str]) -> Any:  # type: ignore
        """Core logic for handling MySQL query"""
        try:
            # Pass original query to executor for proper validation
            # The executor will validate semicolons before stripping them
            query = sql.strip()
            username = self.session_data.get("username", "unknown")
            
            # CRITICAL: Sync mysql_mimic's self.database to db_system
            # mysql_mimic handles USE commands internally and updates self.database
            # BEFORE queries reach handle_query. We must sync this to db_system.
            mimic_db = getattr(self, 'database', None)  # mysql_mimic's database attribute
            if mimic_db and self.db_system:
                if self.db_system.current_database != mimic_db:
                    old_db = self.db_system.current_database
                    if self.db_system.use_database(mimic_db):
                        logger.info(f"[DB_SYNC] Synced db_system from mysql_mimic: {old_db} -> {mimic_db}")
                        self.session_data["database"] = mimic_db
                    else:
                        logger.warning(f"[DB_SYNC] Failed to sync database '{mimic_db}', not in db_system")
            
            # DEBUG: Log current state before processing - use db_system for accuracy
            db_system_db = self.db_system.current_database if self.db_system else None
            logger.info(f"[QUERY_DEBUG] handle_query called: query='{query}', current_db={db_system_db}")

            # Use new command executor if available
            if self.command_executor is not None:
                try:
                    # Execute through command executor (handles validation, injection, routing)
                    result, routing, error_info = self.command_executor.execute(
                        query,
                        username=username,
                        client_ip=self.session_data.get("client_info", {}).get("ip", "unknown")
                    )
                    
                    logger.info(f"[QUERY_DEBUG] Command executor result: routing={routing}, has_result={result is not None}, type={type(result).__name__}")
                    
                    # Handle error responses (injection, gibberish, syntax errors)
                    if routing == "error" and error_info:
                        logger.warning(f"Query rejected: {error_info.get('message', 'Unknown error')}")
                        return self._format_error_response(error_info)
                    
                    # Handle local execution results
                    if routing == "local" and result is not None:
                        # Check for special result types
                        if isinstance(result, dict):
                            if "error" in result:
                                error_data = result["error"]
                                if isinstance(error_data, dict):
                                    return self._format_error_response(error_data)
                                else:
                                    return self._format_error_response({"message": str(error_data)})
                            elif "success" in result:
                                # Successful command like USE, CREATE, etc.
                                if result.get("message") == "Database changed":
                                    # Sync database change with session data
                                    old_db = self.session_data.get("database")
                                    new_db = self.db_system.current_database
                                    self.session_data["database"] = new_db
                                    logger.info(f"[USE_SYNC] Database synced: {old_db} -> {new_db}")
                                return ResultSet(rows=[], columns=[])
                            elif "exit" in result:
                                # Exit command
                                try:
                                    await self.close_session()
                                except Exception as e:
                                    logger.debug(f"Error during session close: {e}")
                                return ResultSet(rows=[], columns=[])
                        
                        # Format list results (SHOW, DESCRIBE, etc.)
                        if isinstance(result, list):
                            return self._format_local_result(result, query)
                        
                        # Return as-is if already formatted
                        return result
                    
                    # Route to LLM if needed
                    if routing == "llm":
                        # Log query information
                        query_info = self._log_query_info(query)
                        
                        # Analyze for threats
                        attack_analysis, vulnerabilities = self._analyze_and_log_threats(query)
                        
                        # Update session data
                        self._update_session_data(query_info, attack_analysis, vulnerabilities)
                        
                        # Enhance context for LLM
                        if self.db_system and self.llm_guard:
                            current_db = self.db_system.get_current_database()
                            table_names = current_db.list_tables() if current_db else []
                            # Store enhanced context for LLM
                            self._llm_context = self.llm_guard.enhance_llm_context(
                                query, 
                                self.db_system.current_database,
                                table_names,
                                username
                            )
                        
                        # Process query through LLM
                        return await self._process_llm_query(query)
                        
                except Exception as e:
                    logger.error(f"Command executor error: {e}", exc_info=True)
                    # Fall through to legacy handling
            
            # Fallback to legacy handling if components not available or failed
            # Syntax check
            if self._is_syntax_error(query):
                return self._generate_syntax_error(query)

            # Check for session termination queries
            termination_result = self._handle_termination_query(query)
            if termination_result is not None:
                try:
                    await self.close_session()
                except Exception as e:
                    logger.debug(f"Error during session close: {e}")
                return termination_result

            # Handle USE database commands
            use_result = self._handle_use_database(query)
            if use_result is not None:
                logger.info(f"[QUERY_DEBUG] USE command result: db_set_to={self.session_data.get('database')}, result={use_result}")
                return use_result

            # Log query information
            query_info = self._log_query_info(query)

            # Analyze for threats
            attack_analysis, vulnerabilities = self._analyze_and_log_threats(query)

            # Update session data
            self._update_session_data(query_info, attack_analysis, vulnerabilities)

            # Process query through LLM
            return await self._process_llm_query(query)
            
        except Exception as e:
            logger.error(f"Critical error in handle_query: {e}", exc_info=True)
            # Return a safe error response instead of crashing
            if ResultColumn is not None:
                return ResultSet(
                    rows=[(f"ERROR 1105 (HY000): Internal error - {str(e)}",)],
                    columns=[ResultColumn(name="Error", type=253)]
                )
            else:
                return ResultSet(
                    rows=[(f"ERROR 1105 (HY000): Internal error - {str(e)}",)],
                    columns=[_ResultColumn(name="Error", type=253)]
                )
    
    def _format_error_response(self, error_info: Dict[str, Any]) -> Any:
        """Format error info into MySQL error response"""
        code = error_info.get("code", error_info.get("error_code", 1064))
        state = error_info.get("state", error_info.get("sql_state", "42000"))
        message = error_info.get("message", "Unknown error")
        
        error_text = f"ERROR {code} ({state}): {message}"
        
        if ResultColumn is not None:
            return ResultSet(
                rows=[(error_text,)],
                columns=[ResultColumn(name="Error", type=253)]
            )
        else:
            return ResultSet(
                rows=[(error_text,)],
                columns=[_ResultColumn(name="Error", type=253)]
            )
    
    def _format_local_result(self, result: List[Dict[str, Any]], query: str) -> Any:
        """Format local execution result into MySQL ResultSet"""
        if not result:
            return ResultSet(rows=[], columns=[])
        
        # Get column names from first row
        if isinstance(result[0], dict):
            columns = list(result[0].keys())
        else:
            columns = ["Result"]
        
        # Build rows
        rows = []
        for row in result:
            if isinstance(row, dict):
                row_values = tuple(row.get(col, None) for col in columns)
            else:
                row_values = (row,)
            rows.append(row_values)
        
        # Create column definitions
        if ResultColumn is not None:
            col_defs = [ResultColumn(name=col, type=253) for col in columns]
        else:
            col_defs = [_ResultColumn(name=col, type=253) for col in columns]
        
        return ResultSet(rows=rows, columns=col_defs)

    def _handle_session_variable(self, query: str, raw_sql: str) -> Optional[Any]:  # type: ignore
        """Handle session variable queries"""
        try:
            cmd, _, rest = query.partition(" ")
            if cmd.lower() == "set" and rest.startswith("@"):
                var, val = map(str.strip, rest.split("=", 1))
                val = {"null": None, "true": True, "false": False}.get(val.lower(), val)
                if isinstance(val, str):
                    try:
                        val = json.loads(val)
                    except Exception:
                        val = val.strip("'\"")
                self.session_data["vars"][var.lstrip("@")] = val
                return [], []
            if cmd.lower() == "select" and rest.startswith("@"):
                name = rest.strip().lstrip("@")
                val = self.session_data.get("vars", {}).get(name)
                return [
                    (
                        (
                            None
                            if val is None
                            else (
                                json.dumps(val)
                                if isinstance(val, (dict, list))
                                else val
                            )
                        ),
                    )
                ], [f"@{name}"]
        except Exception:
            logger.warning(f"Malformed session variable query: {raw_sql}")
            raise Exception("Malformed session variable query")
        return None

    async def _get_llm_response(self, query: str) -> str:
        """Get LLM response for MySQL query - with all dynamic config parameters"""
        session_id = self.session_data["session_id"]

        # Create LLM session if not exists
        if session_id not in llm_sessions:
            llm_sessions[session_id] = InMemoryChatMessageHistory()

        config_dict = {"configurable": {"session_id": session_id}}
        username = self.session_data.get("username", "unknown")

        # Build context if context_awareness is enabled (from config)
        context_info = ""
        if self.config["llm"].getboolean("context_awareness", True):
            current_db = self.session_data.get("database", None)
            if current_db:
                context_info = f"\nContext: User={username}, Session={session_id[:8]}, Current Database={current_db} (SELECTED - use this for SHOW TABLES and table queries)"
            else:
                context_info = f"\nContext: User={username}, Session={session_id[:8]}, Current Database=NONE (no database selected)"

        # Add threat adaptation context if enabled (from config)
        threat_context = ""
        if self.config["llm"].getboolean("threat_adaptation", True):
            if self.session_data.get("attack_analysis"):
                latest_attack = self.session_data["attack_analysis"][-1] if self.session_data["attack_analysis"] else None
                if latest_attack:
                    threat_level = latest_attack.get("severity", "low")
                    threat_context = f"\nThreat Level: {threat_level}"

        # Get system prompt from prompt.txt or config
        system_prompt = ""
        try:
            prompt_path = Path(__file__).parent / "prompt.txt"
            if prompt_path.exists():
                with open(prompt_path, "r", encoding="utf-8") as f:
                    system_prompt = f.read().strip()
                logger.info("Loaded system prompt from prompt.txt")
        except Exception as e:
            logger.warning(f"Failed to load prompt.txt: {e}")

        if not system_prompt:
            system_prompt = self.config["llm"].get(
                "system_prompt",
                "You are a MySQL 8.0.32 database server. Respond ONLY with valid JSON arrays."
            )

        # Build the prompt with all dynamic config parameters
        # Use triple braces to escape JSON in f-string
        prompt = f"""{system_prompt}

User Query: {query}{context_info}{threat_context}

Respond ONLY with valid JSON array format. No text, markdown, or explanations."""

        try:
            # Log the configuration being used
            logger.debug(
                "LLM request config",
                extra={
                    "provider": self.config["llm"].get("llm_provider", "ollama"),
                    "model": self.config["llm"].get("model_name", "llama3.2"),
                    "temperature": self.config["llm"].getfloat("temperature", 0.2),
                    "context_awareness": self.config["llm"].getboolean("context_awareness", True),
                    "threat_adaptation": self.config["llm"].getboolean("threat_adaptation", True),
                    "creativity_level": self.config["llm"].getfloat("creativity_level", 0.4),
                },
            )

            template_vars = {
                "messages": [HumanMessage(content=prompt)],
            }
            response = await with_message_history.ainvoke(template_vars, config=config_dict)
            raw = getattr(response, "content", response)
            if not isinstance(raw, str):
                try:
                    raw = raw.decode("utf-8", errors="replace")
                except Exception:
                    raw = str(raw)
            
            logger.info(
                "LLM response",
                extra={
                    "structured_data": {
                        "event": "llm_interaction",
                        "query": query,
                        "response": raw,
                        "session_id": session_id,
                        "model": self.config["llm"].get("model_name", "llama3.2"),
                        "creativity": self.config["llm"].getfloat("creativity_level", 0.4),
                    }
                },
            )
            return raw
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            # ML fallback behavior from config
            if "ml" in self.config and self.config["ml"].getboolean("fallback_on_error", True):
                logger.info("Using fallback response due to ML error")
            return json.dumps([])


    def _parse_llm_response(self, llm_response: str, query: str) -> Any:  # type: ignore
        """Parse LLM response into MySQL result set with proper formatting"""
        query_lower = query.lower().strip()

        # Handle syntax errors first
        if self._is_syntax_error(query):
            return self._generate_syntax_error(query)

        try:
            # Clean and extract JSON more aggressively
            raw = llm_response.strip()

            # Remove markdown blocks
            raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
            raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)

            # Remove any text before the first [ and after the last ]
            start_idx = raw.find("[")
            end_idx = raw.rfind("]")

            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                raw = raw[start_idx : end_idx + 1]

            # Clean up common issues
            raw = re.sub(r"\n\s*Note:.*$", "", raw, flags=re.DOTALL)
            raw = re.sub(r"\n\s*This.*$", "", raw, flags=re.DOTALL)
            raw = raw.strip()

            # Try to parse JSON
            try:
                parsed = json.loads(raw)
            except Exception:
                return ResultSet(
                    rows=[],
                    columns=[ResultColumn(name="Error", type="text")],
                )

            # Handle specific MySQL commands with proper formatting
            return self._format_mysql_response(parsed, query_lower)

        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode error: {e}, response: {llm_response[:200]}")
            return self._fallback_parse(llm_response, query_lower)
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._generate_mysql_error(1105, f"Internal server error: {str(e)}")

    def _is_syntax_error(self, query: str) -> bool:
        """Check if query has syntax errors"""
        query = query.strip().rstrip(";")

        # Common syntax error patterns
        syntax_errors = [
            r"^\s*$",  # Empty query
            r"^\s*;\s*$",  # Only semicolon
            r"\bSELECT\s+FROM\b",  # SELECT without columns
            r"\bINSERT\s+INTO\s+\w+\s*$",  # INSERT without VALUES
            r"\bUPDATE\s+\w+\s*$",  # UPDATE without SET
            r"\bDELETE\s+\w+\s*$",  # DELETE without FROM
            r"\bCREATE\s+TABLE\s+\w+\s*$",  # CREATE TABLE without columns
        ]

        for pattern in syntax_errors:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        return False

    def _generate_syntax_error(self, query: str) -> Any:  # type: ignore
        """Generate MySQL syntax error"""
        error_msg = f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{query[:50]}' at line 1"
        return self._generate_mysql_error(1064, error_msg)

    def _generate_mysql_error(self, error_code: int, error_msg: str) -> Any:  # type: ignore
        """Generate MySQL error response"""
        logger.warning(f"MySQL error {error_code}: {error_msg}")
        if ResultColumn is not None:
            return ResultSet(
                rows=[(f"ERROR {error_code} (42000): {error_msg}",)],
                columns=[ResultColumn(name="Error", type=253)],
            )
        else:
            return ResultSet(
                rows=[(f"ERROR {error_code} (42000): {error_msg}",)],
                columns=[_ResultColumn(name="Error", type=253)],
            )

    def _format_empty_result(self, parsed: Any, query_lower: str) -> Optional[Any]:
        """Handle empty array results (DDL operations)"""
        if isinstance(parsed, list) and len(parsed) == 0:
            # Only return empty result for valid DDL/DML commands
            # This prevents invalid commands (e.g. 'show tals') from returning "Query OK"
            valid_verbs = ["create", "insert", "update", "delete", "drop", "alter", "use", "set", "grant", "revoke", "truncate", "start", "begin", "commit", "rollback"]
            
            # Check if query starts with any valid verb
            if any(query_lower.startswith(verb) for verb in valid_verbs):
                logger.info(f"DDL/DML operation completed: {query_lower[:50]}")
                return ResultSet(rows=[], columns=[])
            
            # If it's not a valid DDL/DML verb, return None to trigger error generation
            return None
        return None

    def _format_show_databases(self, parsed: Any) -> Any:
        """Format SHOW DATABASES response - LLM generates everything"""
        if isinstance(parsed, list) and parsed:
            if isinstance(parsed[0], str):
                rows = [(db,) for db in parsed]
            elif isinstance(parsed[0], dict) and "Database" in parsed[0]:
                rows = [(row["Database"],) for row in parsed]
            else:
                rows = []

            logger.info(f"SHOW DATABASES returned {len(rows)} databases (from LLM)")
            return ResultSet(
                rows=rows, columns=[ResultColumn(name="Database", type=253)]
            )
        return ResultSet(rows=[], columns=[])

    def _format_show_tables(self, parsed: Any) -> Any:
        """Format SHOW TABLES response - LLM generates everything"""
        if isinstance(parsed, list) and parsed:
            # If parsed is an error object from LLM, return it as-is
            if len(parsed) > 0 and isinstance(parsed[0], dict) and "Error" in parsed[0]:
                return ResultSet(
                    rows=[(parsed[0]["Error"],)],
                    columns=[ResultColumn(name="Error", type=253)],
                )

            # Process LLM response for SHOW TABLES
            # Process LLM response for SHOW TABLES
            # Flatten nested lists if present (e.g. [['table1']])
            if isinstance(parsed[0], list):
                parsed = [item for sublist in parsed for item in sublist]
            
            # Filter out empty strings or non-string items
            parsed = [p for p in parsed if isinstance(p, str) and p.strip()]

            if not parsed:
                return ResultSet(rows=[], columns=[])

            if isinstance(parsed[0], str):
                # Fix: Handle comma-separated string or stringified list from LLM
                table_names = []
                first_item = parsed[0].strip()
                
                if first_item.startswith("[") and first_item.endswith("]"):
                    # Handle stringified list: "['table1', 'table2']"
                    try:
                        # Use ast.literal_eval for safe parsing, or simple json/regex
                        import ast
                        evaluated = ast.literal_eval(first_item)
                        if isinstance(evaluated, list):
                            table_names = [str(t) for t in evaluated]
                    except Exception:
                        # Fallback to simple strip/split if eval fails
                        content = first_item[1:-1]
                        table_names = [t.strip().strip("'\"") for t in content.split(",")]
                elif "," in first_item:
                    # Handle comma-separated string: "table1, table2"
                    table_names = [t.strip() for t in first_item.split(",")]
                else:
                    # Simple list of table names (already parsed as list of strings)
                    table_names = parsed

                rows = [(table,) for table in table_names]
                col_name = f"Tables_in_{self.session_data.get('database', 'database')}"
            elif isinstance(parsed[0], dict):
                # Look for Tables_in_ key (LLM provides proper column name with database)
                key = None
                col_name = "Tables_in_database"
                
                for k in parsed[0].keys():
                    if k.startswith("Tables_in_"):
                        key = k
                        col_name = k
                        break
                
                if not key:
                    # Fallback: use first available key or default
                    if parsed[0]:
                        key = next(iter(parsed[0].keys()))
                    else:
                        key = "table"
                
                rows = [(row.get(key, "") if isinstance(row, dict) else str(row),) for row in parsed]
            else:
                rows = []

            logger.info(f"SHOW TABLES returned {len(rows)} tables (from LLM)")
            return ResultSet(
                rows=rows, columns=[ResultColumn(name=col_name, type=253)]
            )
        return ResultSet(rows=[], columns=[])

    def _format_describe(self, parsed: Any) -> Any:
        """Format DESCRIBE/DESC response"""
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            columns = [
                ResultColumn(name="Field", type=253),
                ResultColumn(name="Type", type=253),
                ResultColumn(name="Null", type=253),
                ResultColumn(name="Key", type=253),
                ResultColumn(name="Default", type=253),
                ResultColumn(name="Extra", type=253),
            ]

            rows = [
                (
                    row.get("Field", "unknown"),
                    row.get("Type", "varchar(255)"),
                    row.get("Null", "YES"),
                    row.get("Key", ""),
                    row.get("Default", None),
                    row.get("Extra", ""),
                )
                for row in parsed
            ]

            logger.info(f"DESCRIBE returned {len(rows)} columns")
            return ResultSet(rows=rows, columns=columns)
        return ResultSet(rows=[], columns=[])

    def _format_select(self, parsed: Any, query_lower: str) -> Any:
        """Format SELECT query response"""
        if isinstance(parsed, list) and parsed:
            if isinstance(parsed[0], dict):
                columns = list(parsed[0].keys())
                # Safely extract values from each row, handling non-dict items
                rows = []
                for row in parsed:
                    if isinstance(row, dict):
                        rows.append(tuple(row.get(col) for col in columns))
                    else:
                        # If row is not a dict, return empty values
                        rows.append(tuple([None] * len(columns)))

                result_columns = [
                    ResultColumn(name=col, type=infer_type(parsed[0].get(col) if isinstance(parsed[0], dict) else None))
                    for col in columns
                ]

                logger.info(
                    f"SELECT returned {len(rows)} rows with {len(columns)} columns"
                )
                return ResultSet(rows=rows, columns=result_columns)
            else:
                col_name = "Value"
                if "@@version" in query_lower:
                    col_name = "@@version_comment"
                elif "@@" in query_lower:
                    var_match = re.search(r"@@(\w+)", query_lower)
                    if var_match:
                        col_name = f"@@{var_match.group(1)}"

                rows = [(value,) for value in parsed]
                logger.info(f"SELECT returned {len(rows)} rows")
                return ResultSet(
                    rows=rows, columns=[ResultColumn(name=col_name, type=253)]
                )
        return ResultSet(rows=[], columns=[])

    def _format_show_variables(self, parsed: Any) -> Any:
        """Format SHOW STATUS/VARIABLES response"""
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            columns = [
                ResultColumn(name="Variable_name", type=253),
                ResultColumn(name="Value", type=253),
            ]

            rows = []
            for row in parsed:
                if "Variable_name" in row and "Value" in row:
                    rows.append((row["Variable_name"], row["Value"]))
                else:
                    for key, value in row.items():
                        rows.append((key, str(value)))

            logger.info(f"SHOW STATUS/VARIABLES returned {len(rows)} variables")
            return ResultSet(rows=rows, columns=columns)
        return ResultSet(rows=[], columns=[])

    def _format_mysql_response(self, parsed: Any, query_lower: str) -> Any:  # type: ignore
        """Format response according to MySQL CLI standards"""
        # Handle empty results
        empty_result = self._format_empty_result(parsed, query_lower)
        if empty_result is not None:
            return empty_result

        # Handle specific command types
        if "show databases" in query_lower:
            return self._format_show_databases(parsed)
        elif "show tables" in query_lower:
            return self._format_show_tables(parsed)
        elif any(cmd in query_lower for cmd in ["describe", "desc"]):
            return self._format_describe(parsed)
        elif "select" in query_lower:
            return self._format_select(parsed, query_lower)
        elif any(
            cmd in query_lower
            for cmd in ["show status", "show variables", "show global"]
        ):
            return self._format_show_variables(parsed)

        # Default handling for other queries
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            columns = list(parsed[0].keys())
            # Fix: Handle non-dict rows safely
            rows = []
            for row in parsed:
                if isinstance(row, dict):
                    rows.append(tuple(row.get(col) for col in columns))
                else:
                    # Fallback for non-dict rows (e.g. if LLM returns mixed types)
                    rows.append(tuple([None] * len(columns)))
            
            result_columns = [
                ResultColumn(name=col, type=infer_type(parsed[0].get(col)))
                for col in columns
            ]
            return ResultSet(rows=rows, columns=result_columns)

        return ResultSet(rows=[], columns=[])

    def _fallback_parse(self, llm_response: str, query_lower: str) -> Any:  # type: ignore
        """Enhanced fallback parsing with better MySQL CLI formatting"""
        try:
            # For SHOW DATABASES
            if "show databases" in query_lower:
                db_names = re.findall(
                    r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', llm_response
                )
                # No hardcoded fallback - let LLM handle it or return empty
                rows = [(name,) for name in db_names]
                logger.info(f"Fallback SHOW DATABASES returned {len(rows)} databases")
                return ResultSet(
                    rows=rows, columns=[ResultColumn(name="Database", type=253)]
                )

            # For SHOW TABLES
            elif "show tables" in query_lower:
                table_names = re.findall(
                    r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', llm_response
                )
                # No hardcoded fallback
                
                db_name = self.session_data.get("database", "database")
                col_name = f"Tables_in_{db_name}"
                rows = [(name,) for name in table_names]
                logger.info(f"Fallback SHOW TABLES returned {len(rows)} tables")
                return ResultSet(
                    rows=rows, columns=[ResultColumn(name=col_name, type=253)]
                )

            # For version queries
            elif "@@version" in query_lower:
                version = "8.0.32"
                if "comment" in query_lower:
                    version = "(Ubuntu)"

                col_name = (
                    "@@version_comment" if "comment" in query_lower else "@@version"
                )
                logger.info(f"Version query returned: {version}")
                return ResultSet(
                    rows=[(version,)], columns=[ResultColumn(name=col_name, type=253)]
                )

            # Default empty result
            return ResultSet(rows=[], columns=[])

        except Exception as e:
            logger.error(f"Fallback parsing failed: {e}")
            return self._generate_mysql_error(1105, "Unable to parse server response")

    async def generate_session_summary(self, session_data: Dict[str, Any]):
        """Generate AI-powered session summary"""
        queries = [q["query"] for q in session_data.get("queries", [])]
        attack_types = [
            a
            for analysis in session_data.get("attack_analysis", [])
            for a in analysis.get("attack_types", [])
        ]
        vulnerabilities = [
            v["vulnerability_id"] for v in session_data.get("vulnerabilities", [])
        ]

        # Skip summary if no activity
        if not queries and not session_data.get("authenticated"):
            logger.info(
                "MySQL session summary",
                extra={
                    "session_id": session_data["session_id"],
                    "details": "Empty session - no queries executed, no authentication attempted",
                    "judgement": "BENIGN",
                },
            )
            return

        try:
            prompt = f"""
Analyze this MySQL honeypot session for malicious activity. You have access to:
- Complete query history: {queries}
- Attack patterns detected: {attack_types}
- Vulnerabilities exploited: {vulnerabilities}
- Session duration: {session_data.get("duration", "unknown")}
- Username used: {session_data.get("username", "unknown")}
- Database accessed: {session_data.get("database", "none")}
- Total queries: {len(queries)}
- Attack queries: {session_data.get("session_stats", {}).get("attack_queries", 0)}

Provide a concise analysis covering:
1. Attack stage identification (reconnaissance, initial access, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration, impact)
2. Primary attacker objectives based on query patterns
3. Threat level assessment

Key indicators to analyze:
- Database enumeration (SHOW DATABASES, SHOW TABLES, DESCRIBE)
- Information gathering (SELECT @@version, SELECT USER(), SELECT DATABASE())
- SQL injection attempts (UNION SELECT, OR 1=1, etc.)
- Privilege escalation (GRANT, REVOKE, CREATE USER)
- Data extraction (SELECT * FROM sensitive_tables)
- Database manipulation (DROP, DELETE, UPDATE)
- Persistence attempts (CREATE USER, GRANT ALL)

Classification criteria:
- BENIGN: Basic database operations, normal queries, connection testing
- SUSPICIOUS: Database enumeration, information gathering, reconnaissance
- MALICIOUS: SQL injection, privilege escalation, data theft, database manipulation

End with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]" and specify the primary attack goal.
"""

            session_id = session_data["session_id"]
            if session_id not in llm_sessions:
                llm_sessions[session_id] = InMemoryChatMessageHistory()

            config_dict = {"configurable": {"session_id": session_id}}

            # Prepare template variables for the session summary prompt
            template_vars = {
                "messages": [HumanMessage(content=prompt)],
                "username": session_data.get("username", "unknown"),
                "host": session_data.get("client_info", {}).get("ip", "localhost"),
                "database": session_data.get("database", None),
                "available_databases": None,
                "tables_in_database": None,
                "schema_definitions": None,
                "max_rows": 10,
            }

            llm_response = await with_message_history.ainvoke(
                template_vars, config=config_dict
            )

            # Extract judgement
            judgement = "UNKNOWN"
            response_content = getattr(
                llm_response, "content", str(llm_response)
            ).upper()

            if "JUDGEMENT: BENIGN" in response_content:
                judgement = "BENIGN"
            elif "JUDGEMENT: SUSPICIOUS" in response_content:
                judgement = "SUSPICIOUS"
            elif "JUDGEMENT: MALICIOUS" in response_content:
                judgement = "MALICIOUS"
            elif "BENIGN" in response_content:
                judgement = "BENIGN"
            elif "SUSPICIOUS" in response_content:
                judgement = "SUSPICIOUS"
            elif "MALICIOUS" in response_content:
                judgement = "MALICIOUS"

            logger.info(
                "MySQL session summary",
                extra={
                    "session_id": session_data["session_id"],
                    "details": getattr(llm_response, "content", str(llm_response)),
                    "judgement": judgement,
                },
            )

            # Save session summary to file
            if self.forensic_logger:
                summary_file = (
                    self.forensic_logger.session_dir / "session_ai_summary.json"
                )
                with open(summary_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "session_id": session_data["session_id"],
                            "ai_analysis": getattr(
                                llm_response, "content", str(llm_response)
                            ),
                            "judgement": judgement,
                            "generated_at": datetime.datetime.now(
                                datetime.timezone.utc
                            ).isoformat(),
                            "query_count": len(queries),
                            "attack_count": len([a for a in attack_types if a]),
                            "vulnerability_count": len(vulnerabilities),
                            "method": "ai_summary",
                        },
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )

                # Add as evidence
                if config["forensics"].getboolean("chain_of_custody", True):
                    self.forensic_logger.add_evidence(
                        "ai_summary",
                        str(summary_file),
                        "AI-generated session analysis and threat assessment",
                    )

        except Exception as e:
            logger.error(f"Session summary generation failed: {e}")
            # Generate fallback summary
            fallback_judgement = (
                "SUSPICIOUS" if (attack_types or vulnerabilities) else "BENIGN"
            )
            fallback_summary = f"MySQL session with {len(queries)} queries, {len(attack_types)} attacks detected, {len(vulnerabilities)} vulnerabilities found"

            logger.info(
                "MySQL session summary (fallback)",
                extra={
                    "session_id": session_data["session_id"],
                    "details": fallback_summary,
                    "judgement": fallback_judgement,
                    "query_count": len(queries),
                    "attack_count": len(attack_types),
                    "vulnerability_count": len(vulnerabilities),
                    "username": session_data.get("username", "unknown"),
                    "duration": session_data.get("duration", "unknown"),
                },
            )

    def _generate_basic_summary(self):
        """Generate basic session summary when AI is disabled"""
        try:
            queries = self.session_data.get("queries", [])
            attack_types = [
                a
                for analysis in self.session_data.get("attack_analysis", [])
                for a in analysis.get("attack_types", [])
            ]
            vulnerabilities = self.session_data.get("vulnerabilities", [])

            # Determine basic judgement
            if len(vulnerabilities) > 0 or len([a for a in attack_types if a]) > 2:
                judgement = "MALICIOUS"
            elif len(attack_types) > 0:
                judgement = "SUSPICIOUS"
            else:
                judgement = "BENIGN"

            summary = f"MySQL session with {len(queries)} queries, {len(attack_types)} attacks detected, {len(vulnerabilities)} vulnerabilities found"

            logger.info(
                "MySQL session summary (basic)",
                extra={
                    "session_id": self.session_data["session_id"],
                    "details": summary,
                    "judgement": judgement,
                    "query_count": len(queries),
                    "attack_count": len(attack_types),
                    "vulnerability_count": len(vulnerabilities),
                    "username": self.session_data.get("username", "unknown"),
                    "duration": self.session_data.get("duration", "unknown"),
                },
            )

            # Save basic summary to file
            if self.forensic_logger:
                summary_file = (
                    self.forensic_logger.session_dir / "session_basic_summary.json"
                )
                with open(summary_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "session_id": self.session_data["session_id"],
                            "basic_analysis": summary,
                            "judgement": judgement,
                            "generated_at": datetime.datetime.now(
                                datetime.timezone.utc
                            ).isoformat(),
                            "query_count": len(queries),
                            "attack_count": len(attack_types),
                            "vulnerability_count": len(vulnerabilities),
                            "method": "basic_summary",
                        },
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )
        except Exception as e:
            logger.debug(f"Failed to generate basic summary: {e}")


# --------------------------
# Server wrapper
# --------------------------
class MySQLHoneypotServer:
    """MySQL honeypot server implementation using mysql_mimic"""

    def __init__(self, config: ConfigParser):
        self.config = config
        self.host = config["mysql"].get("host", "0.0.0.0")
        self.port = config["mysql"].getint("port", 3326)
        self.accounts = self._load_accounts()
        self.server_version = config["mysql"].get(
            "server_version", "8.0.32-0ubuntu0.20.04.2"
        )

        # MySQL server configuration
        self.default_database = config["mysql"].get("default_database", "nexus_gamedev")
        self.charset = config["mysql"].get("charset", "utf8mb4")
        self.collation = config["mysql"].get("collation", "utf8mb4_unicode_ci")
        self.max_connections = config["mysql"].getint("max_connections", 100)
        self.connect_timeout = config["mysql"].getint("connect_timeout", 10)
        self.query_timeout = config["mysql"].getint("query_timeout", 30)

        # Connection tracking for max_connections limit
        self.connection_count = 0

        # Behavioral analysis and adaptive responses
        self.behavioral_analysis = config["honeypot"].getboolean(
            "behavioral_analysis", True
        )
        self.adaptive_responses = config["honeypot"].getboolean(
            "adaptive_responses", True
        )
        self.attack_logging = config["honeypot"].getboolean("attack_logging", True)
        self.forensic_chain = config["honeypot"].getboolean("forensic_chain", True)

        # AI features configuration
        self.dynamic_responses = config["ai_features"].getboolean(
            "dynamic_responses", True
        )
        self.real_time_analysis = config["ai_features"].getboolean(
            "real_time_analysis", True
        )
        self.ai_attack_summaries = config["ai_features"].getboolean(
            "ai_attack_summaries", True
        )
        self.deception_techniques = config["ai_features"].getboolean(
            "deception_techniques", True
        )
        self.query_result_manipulation = config["ai_features"].getboolean(
            "query_result_manipulation", True
        )

        # Security configuration
        self.rate_limiting = config["security"].getboolean("rate_limiting", True)
        self.max_connections_per_ip = config["security"].getint(
            "max_connections_per_ip", 10
        )
        self.connection_timeout = config["security"].getint("connection_timeout", 300)
        self.intrusion_detection = config["security"].getboolean(
            "intrusion_detection", True
        )
        self.automated_blocking = config["security"].getboolean(
            "automated_blocking", False
        )
        self.ssl_simulation = config["security"].getboolean("ssl_simulation", True)

        # Connection tracking per IP for rate limiting
        self.ip_connections = {}

        # Attack detection configuration
        self.sql_injection_detection = config["attack_detection"].getboolean(
            "sql_injection_detection", True
        )
        self.privilege_escalation_detection = config["attack_detection"].getboolean(
            "privilege_escalation_detection", True
        )
        self.data_exfiltration_detection = config["attack_detection"].getboolean(
            "data_exfiltration_detection", True
        )
        self.sensitivity_level = config["attack_detection"].get(
            "sensitivity_level", "medium"
        )
        self.threat_scoring = config["attack_detection"].getboolean(
            "threat_scoring", True
        )
        self.alert_threshold = config["attack_detection"].getint("alert_threshold", 70)

        # Forensics configuration
        self.query_logging = config["forensics"].getboolean("query_logging", True)
        self.save_queries = config["forensics"].getboolean("save_queries", True)
        self.query_hash_analysis = config["forensics"].getboolean(
            "query_hash_analysis", True
        )
        self.attack_correlation = config["forensics"].getboolean(
            "attack_correlation", True
        )
        self.forensic_reports = config["forensics"].getboolean("forensic_reports", True)

        # Database simulation configuration
        self.realistic_data_generation = config["database_simulation"].getboolean(
            "realistic_data_generation", True
        )
        self.schema_evolution = config["database_simulation"].getboolean(
            "schema_evolution", True
        )

        # LLM configuration - all dynamically loaded
        self.llm_provider = config["llm"].get("llm_provider", "ollama")
        self.model_name = config["llm"].get("model_name", "llama3.2")
        self.temperature = config["llm"].getfloat("temperature", 0.2)
        self.max_response_tokens = config["llm"].getint("max_response_tokens", 2048)
        self.context_awareness = config["llm"].getboolean("context_awareness", True)
        self.threat_adaptation = config["llm"].getboolean("threat_adaptation", True)
        self.creativity_level = config["llm"].getfloat("creativity_level", 0.4)
        self.system_prompt = config["llm"].get("system_prompt", "You are a MySQL 8.0.32 database server.")

        # ML configuration - all dynamically loaded
        self.ml_enabled = config["ml"].getboolean("enabled", True) if "ml" in config else False
        self.anomaly_threshold = config["ml"].getfloat("anomaly_threshold", 0.95) if "ml" in config else 0.95
        self.max_inference_ms = config["ml"].getint("max_inference_ms", 15) if "ml" in config else 15
        self.ml_fallback_on_error = config["ml"].getboolean("fallback_on_error", True) if "ml" in config else True
        self.embedding_model = config["ml"].get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2") if "ml" in config else "sentence-transformers/all-MiniLM-L6-v2"
        self.batch_size = config["ml"].getint("batch_size", 32) if "ml" in config else 32
        self.cache_embeddings = config["ml"].getboolean("cache_embeddings", True) if "ml" in config else True
        self.use_gpu = config["ml"].getboolean("use_gpu", False) if "ml" in config else False
        self.model_update_interval = config["ml"].getint("model_update_interval", 3600) if "ml" in config else 3600
        self.min_training_samples = config["ml"].getint("min_training_samples", 100) if "ml" in config else 100

        # Initialize components
        self.attack_analyzer = MySQLAttackAnalyzer()
        self.vuln_logger = MySQLVulnerabilityLogger()

        # Session tracking
        self.sessions = {}
        self.active_sessions = {}  # Track active sessions for cleanup

        # Patch mysql_mimic for better error handling
        try:
            patch_client_connected_cb_to_avoid_log_errors()
        except Exception as e:
            logger.debug(f"Could not patch mysql_mimic: {e}")

    def _load_accounts(self) -> Dict[str, str]:
        """Load user accounts from config"""
        accounts = {}
        if "user_accounts" in self.config:
            for username, password in self.config.items("user_accounts"):
                accounts[username] = password
        return accounts

    def create_session_factory(self):
        """Create session factory for mysql_mimic"""
        server_instance = self

        def session_factory(variables=None):
            try:
                session = MySQLHoneypotSession(self.config, variables)
                # Store reference to server for connection info extraction
                session._server = server_instance
                # Track active sessions for cleanup
                session_id = session.session_data["session_id"]
                self.active_sessions[session_id] = session
                logger.debug(f"Created new session: {session_id}")
                return session
            except Exception as e:
                logger.error(f"Error creating session: {e}")
                # Return a minimal fallback session
                return MySQLHoneypotSession(self.config, variables)

        return session_factory

    async def _periodic_session_cleanup(self):
        """Periodically clean up stale sessions"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute for better responsiveness
                current_time = datetime.datetime.now(datetime.timezone.utc)
                stale_sessions = []

                # Create a copy of the items to avoid modification during iteration
                for session_id, session in list(self.active_sessions.items()):
                    try:
                        start_time_str = session.session_data.get("start_time", "")
                        if start_time_str:
                            start_time = datetime.datetime.fromisoformat(
                                start_time_str.replace("Z", "+00:00")
                            )
                            # Clean up sessions older than 10 minutes (more aggressive cleanup)
                            if (current_time - start_time).total_seconds() > 600:
                                stale_sessions.append(session_id)
                    except Exception:
                        # If we can't parse time, consider it stale
                        stale_sessions.append(session_id)

                for session_id in stale_sessions:
                    logger.debug(f"Cleaning up stale session: {session_id}")
                    await self.cleanup_session(session_id)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Error in periodic session cleanup: {e}")

    async def cleanup_session(self, session_id: str):
        """Clean up session when connection closes"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            try:
                # Ensure session has end time
                if not session.session_data.get("end_time"):
                    session.session_data["end_time"] = datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat()
                    session.session_data["duration"] = (
                        session._calculate_session_duration()
                    )

                # Force session close to generate summaries
                await session.close_session()
                logger.info(
                    f"MySQL session {session_id} cleaned up and summary generated"
                )
            except Exception as e:
                logger.debug(f"Error during session cleanup: {e}")
                # Force basic summary on cleanup error
                try:
                    if hasattr(session, "_generate_basic_summary"):
                        session._generate_basic_summary()
                        logger.info(
                            f"Generated basic summary for session {session_id} after cleanup error"
                        )
                except Exception as summary_error:
                    logger.debug(f"Failed to generate basic summary: {summary_error}")
            finally:
                # Always remove from active sessions
                try:
                    del self.active_sessions[session_id]
                except KeyError:
                    pass

    async def start_server(self):
        """Start the MySQL honeypot server using mysql_mimic"""
        # If mysql_mimic is not installed, provide clear error
        if mysql_mimic is None or MysqlServer is None:
            raise RuntimeError(
                "mysql-mimic is not installed or could not be imported. Install it with: pip install mysql-mimic"
            )

        def load_user_accounts(config):
            accounts = {}
            if "user_accounts" in config:
                for user, pwd in config["user_accounts"].items():
                    accounts[user] = pwd.strip()
            else:
                logger.error("user_accounts section missing in config.ini")
            return accounts

        # Load config.ini (if not already loaded)
        global config
        if config is None:
            config = ConfigParser()
            config.read(Path(__file__).parent / "config.ini")

        # Load all MySQL username/password pairs
        accounts = load_user_accounts(config)
        identity_provider = ConfigBasedIdentityProvider(accounts)

        # Create server instance using mysql_mimic with correct auth provider
        server = MysqlServer(
            session_factory=self.create_session_factory(),
            identity_provider=identity_provider,
            host=config["mysql"]["host"],
            port=config["mysql"].getint("port"),
        )

        # Store connection info for sessions
        self.connection_info = {}

        llm_provider = self.config["llm"].get("llm_provider", "openai")
        model_name = self.config["llm"].get("model_name", "gpt-4o-mini")
        sensor_name = self.config["honeypot"].get("sensor_name", "nexus-mysql-honeypot")

        print(f"\n[INFO] MySQL Honeypot Starting...")
        print(f"[INFO] Host: {self.host}:{self.port}")
        print(f"[INFO] Server Version: {self.server_version}")
        print(f"[INFO] Default Database: {self.default_database}")
        print(f"[INFO] Charset: {self.charset} ({self.collation})")
        print(f"[INFO] LLM Provider: {llm_provider}")
        print(f"[INFO] Model: {model_name}")
        print(f"[INFO] Sensor: {sensor_name}")
        print(
            f"[INFO] Log File: {self.config['honeypot'].get('log_file', 'mysql_log.log')}"
        )
        print(f"[INFO] Max Connections: {self.max_connections}")
        print(
            f"[INFO] Connection Timeout: {self.connect_timeout}s / Query Timeout: {self.query_timeout}s"
        )
        print(f"[INFO] Rate Limiting: {'Enabled' if self.rate_limiting else 'Disabled'}")
        print(
            f"[INFO] SQL Injection Detection: {'Enabled' if self.sql_injection_detection else 'Disabled'}"
        )
        print(
            f"[INFO] Behavioral Analysis: {'Enabled' if self.behavioral_analysis else 'Disabled'}"
        )
        print(
            f"[INFO] Adaptive Responses: {'Enabled' if self.adaptive_responses else 'Disabled'}"
        )
        print(f"[INFO] SSL Simulation: {'Enabled' if self.ssl_simulation else 'Disabled'}")
        print(f"[INFO] Press Ctrl+C to stop\n")

        logger.info(f"MySQL honeypot server started on {self.host}:{self.port}")
        print(f"[SUCCESS] MySQL honeypot listening on {self.host}:{self.port}")
        print("[INFO] Ready for connections...")
        print(
            f"Test connection: mysql -h localhost -P {self.port} -u <username> -p<password>\n"
        )

        # Patch server to capture connection info
        original_client_connected = server._client_connected_cb
        server_instance = self

        async def enhanced_client_connected(reader, writer):
            transport_id = None
            session_id = None
            client_ip = "unknown"
            client_port = "unknown"

            # Extract connection info before processing
            try:
                if hasattr(writer, "transport") and hasattr(
                    writer.transport, "get_extra_info"
                ):
                    peername = writer.transport.get_extra_info("peername")
                    if peername:
                        client_ip, client_port = peername[0], peername[1]

                        # Check connection limit
                        if (
                            server_instance.connection_count
                            >= server_instance.max_connections
                        ):
                            logger.warning(
                                f"Connection limit reached ({server_instance.max_connections}), rejecting connection from {client_ip}"
                            )
                            writer.close()
                            await writer.wait_closed()
                            return

                        # Rate limiting check
                        if server_instance.rate_limiting:
                            if client_ip not in server_instance.ip_connections:
                                server_instance.ip_connections[client_ip] = 0

                            if (
                                server_instance.ip_connections[client_ip]
                                >= server_instance.max_connections_per_ip
                            ):
                                logger.warning(
                                    f"Rate limit exceeded for IP {client_ip} ({server_instance.ip_connections[client_ip]} connections)"
                                )
                                writer.close()
                                await writer.wait_closed()
                                return

                            server_instance.ip_connections[client_ip] += 1

                        server_instance.connection_count += 1

                        # Store connection info by transport object for later retrieval
                        transport_id = id(writer.transport)
                        server_instance.connection_info[transport_id] = {
                            "client_ip": client_ip,
                            "client_port": client_port,
                        }
                        logger.debug(
                            f"Captured connection info: {client_ip}:{client_port}"
                        )
            except Exception as e:
                logger.debug(f"Failed to capture connection info: {e}")

            try:
                await original_client_connected(reader, writer)
            except (ConnectionClosed, ConnectionResetError, BrokenPipeError):
                # Normal disconnection, don't log as error
                logger.debug("MySQL client disconnected cleanly")
            except Exception as e:
                logger.debug(f"MySQL client connection error: {e}")
            finally:
                # Decrement connection counts
                try:
                    server_instance.connection_count -= 1

                    # Decrement IP connection count for rate limiting
                    if (
                        server_instance.rate_limiting
                        and client_ip != "unknown"
                        and client_ip in server_instance.ip_connections
                    ):
                        server_instance.ip_connections[client_ip] -= 1
                        if server_instance.ip_connections[client_ip] <= 0:
                            del server_instance.ip_connections[client_ip]

                    # Clean up connection info
                    if transport_id and transport_id in server_instance.connection_info:
                        del server_instance.connection_info[transport_id]

                    # Force cleanup of any sessions that might be orphaned
                    current_time = datetime.datetime.now(datetime.timezone.utc)
                    orphaned_sessions = []

                    for sid, session in list(server_instance.active_sessions.items()):
                        try:
                            start_time_str = session.session_data.get("start_time", "")
                            if start_time_str:
                                start_time = datetime.datetime.fromisoformat(
                                    start_time_str.replace("Z", "+00:00")
                                )
                                # Clean up sessions older than 5 minutes (connection likely closed)
                                if (current_time - start_time).total_seconds() > 300:
                                    orphaned_sessions.append(sid)
                        except Exception:
                            orphaned_sessions.append(sid)

                    for sid in orphaned_sessions:
                        try:
                            await server_instance.cleanup_session(sid)
                        # amazonq-ignore-next-line
                        # amazonq-ignore-next-line
                        except Exception:
                            pass
                except Exception:
                    pass

        server._client_connected_cb = enhanced_client_connected

        # Start periodic session cleanup task
        cleanup_task = asyncio.create_task(self._periodic_session_cleanup())

        try:
            await server.serve_forever()
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n🛑 MySQL honeypot stopped by user")
            logger.info("MySQL honeypot stopped by user")
        finally:
            # Clean up all active sessions before shutdown
            if self.active_sessions:
                session_count = len(self.active_sessions)
                logger.info(
                    f"Cleaning up {session_count} active sessions before shutdown..."
                )
                for session_id in list(self.active_sessions.keys()):
                    try:
                        await self.cleanup_session(session_id)
                    except Exception as e:
                        logger.debug(f"Error cleaning up session {session_id}: {e}")
                logger.info("All active sessions cleaned up")

            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass


# --------------------------
# Logging context filter
# --------------------------
class ContextFilter(logging.Filter):
    """Add context information to log records"""

    def filter(self, record):
        try:
            task = asyncio.current_task()
            task_name = (
                task.get_name()
                if task is not None and hasattr(task, "get_name")
                else "-"
            )
        except RuntimeError:
            task_name = "-"

        record.task_name = task_name
        record.src_ip = getattr(thread_local, "src_ip", "-")
        record.src_port = getattr(thread_local, "src_port", "-")
        record.dst_ip = getattr(thread_local, "dst_ip", "-")
        record.dst_port = getattr(thread_local, "dst_port", "-")

        return True


# --------------------------
# LLM session history helper
# --------------------------
def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    """Get LLM session history"""
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]


def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    """Choose and configure LLM"""
    llm_provider_name = llm_provider or config["llm"].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = model_name or config["llm"].get("model_name", "gpt-4o-mini")

    temperature = config["llm"].getfloat("temperature", 0.2)

    if llm_provider_name == "openai":
        return ChatOpenAI(
            model=model_name, temperature=temperature, timeout=30, max_retries=2
        )
    elif llm_provider_name == "azure":
        return AzureChatOpenAI(
            azure_deployment=config["llm"].get("azure_deployment"),
            azure_endpoint=config["llm"].get("azure_endpoint"),
            api_version=config["llm"].get("azure_api_version"),
            model=model_name,
            temperature=temperature,
            timeout=30,
            max_retries=2,
        )
    elif llm_provider_name == "ollama":
        if ChatOllama is None:
            raise ValueError(
                "langchain_ollama not installed. Install with: pip install langchain-ollama"
            )
        base_url = config["llm"].get("base_url", "http://localhost:11434")
        return ChatOllama(model=model_name, base_url=base_url, temperature=temperature)
    elif llm_provider_name == "aws":
        if ChatBedrockConverse is None:
            raise ValueError(
                "langchain_aws not installed. Install with: pip install langchain-aws"
            )
        return ChatBedrockConverse(
            model=model_name,
            region_name=config["llm"].get("aws_region", "us-east-1"),
            credentials_profile_name=config["llm"].get(
                "aws_credentials_profile", "default"
            ),
            temperature=temperature,
        )
    elif llm_provider_name == "gemini":
        return ChatGoogleGenerativeAI(
            model=model_name, temperature=temperature, timeout=30
        )
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}")


def get_prompts(prompt: Optional[str], prompt_file: Optional[str]) -> dict:
    """Get system and user prompts"""
    system_prompt = config["llm"]["system_prompt"]

    if prompt is not None:
        if not prompt.strip():
            raise ValueError("The prompt text cannot be empty")
        user_prompt = prompt
    elif prompt_file and os.path.exists(prompt_file):
        with open(prompt_file, "r") as f:
            user_prompt = f.read()
    elif os.path.exists("prompt.txt"):
        with open("prompt.txt", "r") as f:
            user_prompt = f.read()
    else:
        raise ValueError("Either prompt or prompt_file must be provided")

    return {"system_prompt": system_prompt, "user_prompt": user_prompt}


# --------------------------
# Main entrypoint
# --------------------------
def _create_default_config() -> ConfigParser:
    """Create default configuration"""
    config = ConfigParser()
    config["honeypot"] = {
        "log_file": "../../logs/mysql_log.log",
        "sensor_name": "nexus-mysql-honeypot",
        "sessions_dir": "sessions",
        "attack_logging": "true",
        "behavioral_analysis": "true",
        "forensic_chain": "true",
        "adaptive_responses": "true",
    }
    config["mysql"] = {
        "host": "0.0.0.0",
        "port": "3306",
        "server_version": "8.0.32-0ubuntu0.20.04.2",
        "default_database": "nexus_gamedev",
        "charset": "utf8mb4",
        "collation": "utf8mb4_unicode_ci",
        "max_connections": "100",
        "connect_timeout": "10",
        "query_timeout": "30",
    }
    config["llm"] = {
        "llm_provider": "openai",
        "model_name": "gpt-4o-mini",
        "temperature": "0.2",
        "trimmer_max_tokens": "64000",
        "context_awareness": "true",
        "threat_adaptation": "true",
        "system_prompt": 'You are a MySQL 8.0.32 server at NexusGames Studio game company. Return ONLY valid JSON arrays. No explanations, notes, or extra text ever. Examples: SHOW DATABASES -> [{"Database":"player_data"},{"Database":"game_analytics"}]. SHOW TABLES -> [{"Tables_in_dbname":"players"},{"Tables_in_dbname":"scores"}]. DESCRIBE table -> [{"Field":"id","Type":"int(11)","Null":"NO","Key":"PRI","Default":null,"Extra":"auto_increment"}]. SELECT -> realistic game data rows. CREATE/INSERT/UPDATE/DELETE -> []. Always valid JSON only.',
    }
    config["user_accounts"] = {
        "root": "*",
        "admin": "admin",
        "mysql": "mysql",
        "user": "password",
        "developer": "dev123",
        "gamedev": "nexus2024",
    }
    config["ai_features"] = {
        "dynamic_responses": "true",
        "attack_pattern_recognition": "true",
        "vulnerability_detection": "true",
        "real_time_analysis": "true",
        "ai_attack_summaries": "true",
        "deception_techniques": "true",
        "query_result_manipulation": "true",
    }
    config["attack_detection"] = {
        "sensitivity_level": "medium",
        "threat_scoring": "true",
        "alert_threshold": "70",
        "sql_injection_detection": "true",
        "privilege_escalation_detection": "true",
        "data_exfiltration_detection": "true",
    }
    config["forensics"] = {
        "query_logging": "true",
        "save_queries": "true",
        "query_hash_analysis": "true",
        "attack_correlation": "true",
        "forensic_reports": "true",
        "chain_of_custody": "true",
    }
    config["database_simulation"] = {
        "realistic_data_generation": "true",
        "schema_evolution": "true",
    }
    config["logging"] = {
        "log_level": "INFO",
        "structured_logging": "true",
        "real_time_streaming": "true",
    }
    config["security"] = {
        "rate_limiting": "true",
        "max_connections_per_ip": "10",
        "connection_timeout": "300",
        "intrusion_detection": "true",
        "automated_blocking": "false",
        "ssl_simulation": "true",
    }
    return config


def _load_config(args) -> ConfigParser:
    """Load configuration from file or create default"""
    config = ConfigParser()
    if os.path.exists(args.config):
        config.read(args.config)
    else:
        config = _create_default_config()

    # Override with command line arguments
    if args.host:
        config["mysql"]["host"] = args.host
    if args.port:
        config["mysql"]["port"] = str(args.port)
    if args.log_file:
        config["honeypot"]["log_file"] = args.log_file
    if args.sensor_name:
        config["honeypot"]["sensor_name"] = args.sensor_name
    if args.llm_provider:
        config["llm"]["llm_provider"] = args.llm_provider
    if args.model_name:
        config["llm"]["model_name"] = args.model_name
    if args.temperature is not None:
        config["llm"]["temperature"] = str(args.temperature)
    if args.max_tokens:
        config["llm"]["trimmer_max_tokens"] = str(args.max_tokens)

    # Merge command-line user accounts
    if args.user_account:
        if "user_accounts" not in config:
            config["user_accounts"] = {}
        for account in args.user_account:
            if "=" in account:
                key, value = account.split("=", 1)
                config["user_accounts"][key.strip()] = value.strip()
            else:
                config["user_accounts"][account.strip()] = ""

    return config


def _setup_logging(config: ConfigParser):
    """Setup logging configuration with rotation and structured format"""
    global logger

    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
            record.created, datetime.timezone.utc
        ).isoformat(sep="T", timespec="milliseconds")
    )

    sensor_name = config["honeypot"].get("sensor_name", socket.gethostname())

    logger = logging.getLogger(__name__)
    log_level = config["logging"].get("log_level", "INFO").upper()
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Determine log file path
    log_file_path = Path(config["honeypot"].get("log_file", "mysql_log.log"))
    
    # Ensure log directory exists
    try:
        if not log_file_path.is_absolute():
            # If relative, it's relative to CWD (usually src/service_emulators/MySQL)
            # The config says ../../logs/mysql_log.log
            # We should try to respect that.
            pass
        
        log_dir = log_file_path.parent
        if str(log_dir) != ".":
             log_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not create log directory {log_dir}: {e}")

    # Log Rotation Settings
    try:
        max_bytes = config["logging"].getint("log_rotation_size", 100) * 1024 * 1024
        backup_count = config["logging"].getint("log_backup_count", 10)
    except (ValueError, KeyError):
        max_bytes = 100 * 1024 * 1024
        backup_count = 10

    try:
        # Use RotatingFileHandler
        log_file_handler = logging.handlers.RotatingFileHandler(
            str(log_file_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
    except Exception as e:
        print(f"Error creating log handler for {log_file_path}: {e}")
        # Fallback to local file
        log_file_handler = logging.FileHandler("mysql_server_fallback.log")

    logger.addHandler(log_file_handler)

    # Configure structured logging
    if config["logging"].getboolean("structured_logging", True):
        log_file_handler.setFormatter(MySQLJSONFormatter(sensor_name))
    else:
        log_file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )

    # Add console handler for real-time streaming if enabled
    if config["logging"].getboolean("real_time_streaming", True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        if config["logging"].getboolean("structured_logging", True):
            console_handler.setFormatter(MySQLJSONFormatter(sensor_name))
        else:
            console_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
        logger.addHandler(console_handler)

    context_filter = ContextFilter()
    logger.addFilter(context_filter)


def _setup_llm(config: ConfigParser, args):
    """Setup LLM configuration - uses prompt.txt as static guidance, not as template"""
    global llm_sessions, with_message_history

    # Use system prompt from config - this is safe as it's a simple string
    llm_system_prompt = config["llm"]["system_prompt"]

    # Load the detailed prompt from prompt.txt if available, but treat it as static text
    # We'll use it as additional system context, not as a template with variables
    llm_detailed_prompt = ""
    if args.prompt:
        llm_detailed_prompt = args.prompt
    elif args.prompt_file and os.path.exists(args.prompt_file):
        with open(args.prompt_file, "r") as f:
            llm_detailed_prompt = f.read()
    elif os.path.exists("prompt.txt"):
        with open("prompt.txt", "r") as f:
            llm_detailed_prompt = f.read()

    # If we have a detailed prompt, use it as additional system context
    # But we'll inject the actual runtime variables via the messages, not template substitution
    if llm_detailed_prompt:
        # Combine both prompts as system messages
        combined_system_prompt = f"{llm_system_prompt}\n\n{llm_detailed_prompt}"
    else:
        combined_system_prompt = llm_system_prompt

    llm = choose_llm(config["llm"].get("llm_provider"), config["llm"].get("model_name"))

    llm_sessions = {}

    llm_trimmer = trim_messages(
        max_tokens=config["llm"].getint("trimmer_max_tokens", 64000),
        strategy="last",
        token_counter=len,
        include_system=True,
        allow_partial=False,
        start_on="human",
    )

    # Create prompt template with NO variables in the system prompt
    # All runtime data goes through the messages placeholder
    llm_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", combined_system_prompt),
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


async def main():
    """Main entry point"""
    global config, logger, llm_sessions, with_message_history, thread_local

    server = None

    # Parse arguments
    parser = argparse.ArgumentParser(description="Start the MySQL honeypot server")
    parser.add_argument(
        "-c", "--config", type=str, default="config.ini", help="Configuration file path"
    )
    parser.add_argument("--host", type=str, help="Host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)")
    parser.add_argument("--port", type=int, help="Port to listen on")
    parser.add_argument("--log-file", type=str, help="Log file path")
    parser.add_argument("--sensor-name", type=str, help="Sensor name for logging")
    parser.add_argument("--llm-provider", type=str, help="LLM provider to use")
    parser.add_argument("--model-name", type=str, help="Model name to use")
    parser.add_argument("--temperature", type=float, help="LLM temperature")
    parser.add_argument("--max-tokens", type=int, help="Maximum tokens for LLM")
    parser.add_argument("--prompt", type=str, help="Custom prompt text")
    parser.add_argument("--prompt-file", type=str, help="Custom prompt file")
    parser.add_argument(
        "--user-account", action="append", help="User account (username=password)"
    )
    args = parser.parse_args()

    # Load configuration
    config = _load_config(args)

    # Setup logging
    _setup_logging(config)

    # Setup LLM
    try:
        _setup_llm(config, args)
    except Exception as e:
        logger.warning(f"LLM setup failed: {e}. Server will continue with basic responses.")
        print(f"[WARNING] LLM setup failed: {e}. Server will continue with basic responses.")

    # Thread-local storage
    thread_local = threading.local()

    # Start server
    try:
        server = MySQLHoneypotServer(config)
        await server.start_server()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n🛑 MySQL honeypot stopped by user")
        logger.info("MySQL honeypot stopped by user")
    except Exception as e:
        logger.error(f"MySQL honeypot error: {e}")
        traceback.print_exc()
    finally:
        # Clean up active sessions on shutdown
        if server and hasattr(server, "active_sessions") and server.active_sessions:
            session_count = len(server.active_sessions)
            logger.info(f"Emergency cleanup of {session_count} sessions...")
            for session_id in list(server.active_sessions.keys()):
                try:
                    await server.cleanup_session(session_id)
                # amazonq-ignore-next-line
                except Exception:
                    pass


if __name__ == "__main__":
    asyncio.run(main())
