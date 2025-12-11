"""
ML Analysis Routes for NEXUS Honeypot API
Provides endpoints for real-time ML analysis data from all service sessions
"""

import asyncio
import configparser
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ml", tags=["ML Analysis"])

# Base paths
BASE_DIR = Path(__file__).parent.parent
SERVICE_EMULATORS_DIR = BASE_DIR / "service_emulators"

# Session directories for each service
SESSION_DIRS = {
    "ssh": SERVICE_EMULATORS_DIR / "SSH" / "sessions",
    "ftp": SERVICE_EMULATORS_DIR / "FTP" / "sessions",
    "mysql": SERVICE_EMULATORS_DIR / "MySQL" / "sessions",
}

# Config files for LLM settings
CONFIG_FILES = {
    "ssh": SERVICE_EMULATORS_DIR / "SSH" / "config.ini",
    "ftp": SERVICE_EMULATORS_DIR / "FTP" / "config.ini",
    "mysql": SERVICE_EMULATORS_DIR / "MySQL" / "config.ini",
}


# ============== Pydantic Models ==============

class MLMetrics(BaseModel):
    ml_anomaly_score: float = 0.0
    ml_labels: List[str] = []
    ml_cluster: int = -1
    ml_reason: str = ""
    ml_confidence: float = 0.0
    ml_risk_score: float = 0.0
    ml_inference_time_ms: float = 0.0
    ml_risk_level: str = "low"
    ml_threat_score: int = 0
    ml_risk_color: str = "#28a745"


class AttackAnalysis(BaseModel):
    command: str = ""
    timestamp: str = ""
    attack_types: List[str] = []
    severity: str = "low"
    indicators: List[str] = []
    vulnerabilities: List[Dict[str, Any]] = []
    pattern_matches: List[Dict[str, Any]] = []
    threat_score: int = 0
    alert_triggered: bool = False
    ml_metrics: Optional[MLMetrics] = None
    attack_vectors: List[Dict[str, Any]] = []


class SessionSummary(BaseModel):
    session_id: str
    service: str
    start_time: str = ""
    end_time: str = ""
    duration: str = ""
    total_commands: int = 0
    attack_count: int = 0
    avg_ml_score: float = 0.0
    max_ml_score: float = 0.0
    risk_level: str = "low"
    attacks: List[AttackAnalysis] = []
    client_ip: str = ""
    username: str = ""


class MLStats(BaseModel):
    total_sessions: int = 0
    total_commands: int = 0
    total_attacks: int = 0
    avg_anomaly_score: float = 0.0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    avg_inference_time_ms: float = 0.0
    services_active: List[str] = []
    risk_distribution: Dict[str, int] = {}
    attack_type_distribution: Dict[str, int] = {}
    severity_distribution: Dict[str, int] = {}


class AttackUpdateRequest(BaseModel):
    severity: Optional[str] = None
    notes: Optional[str] = None
    false_positive: Optional[bool] = None


class LLMSummaryRequest(BaseModel):
    session_id: str
    service: str


# ============== Helper Functions ==============

def get_llm_config(service: str) -> Dict[str, str]:
    """Read LLM configuration from service-specific config.ini"""
    config_path = CONFIG_FILES.get(service)
    if not config_path or not config_path.exists():
        return {"llm_provider": "gemini", "model_name": "gemini-2.5-flash"}
    
    config = configparser.ConfigParser()
    config.read(config_path)
    
    return {
        "llm_provider": config.get("llm", "llm_provider", fallback="gemini"),
        "model_name": config.get("llm", "model_name", fallback="gemini-2.5-flash"),
        "temperature": config.get("llm", "temperature", fallback="0.2"),
    }


def parse_session_file(session_dir: Path, service: str) -> Optional[SessionSummary]:
    """Parse session data from a session directory"""
    try:
        session_id = session_dir.name
        
        # Try different file patterns based on service
        data = None
        meta_data = None  # Additional metadata (for FTP)
        
        if service == "mysql":
            # MySQL uses session_data.json or session_summary.json
            for filename in ["session_data.json", "session_summary.json"]:
                filepath = session_dir / filename
                if filepath.exists():
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    break
        elif service == "ftp":
            # FTP: read meta.json for client info, then session files
            meta_path = session_dir / "meta.json"
            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta_data = json.load(f)
            
            for filename in ["session_summary.json", "session_replay.json", "forensic_chain.json"]:
                filepath = session_dir / filename
                if filepath.exists():
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    break
        else:
            # SSH uses forensic_chain.json primarily
            for filename in ["forensic_chain.json", "session_summary.json"]:
                filepath = session_dir / filename
                if filepath.exists():
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    break
        
        if not data:
            return None
        
        # Extract attacks and ML metrics
        attacks = []
        total_ml_score = 0.0
        max_ml_score = 0.0
        attack_count = 0
        
        # Handle different data structures
        if service == "mysql":
            commands = data.get("queries", [])
            attack_analyses = data.get("attack_analysis", [])
        else:
            commands = data.get("commands", [])
            attack_analyses = data.get("attack_analysis", [])
            
            # For forensic_chain.json, extract from events
            if "events" in data:
                for event in data.get("events", []):
                    if event.get("event_type") == "attack_detected":
                        event_data = event.get("data", {})
                        attack_analyses.append(event_data)
        
        # Process attack analyses
        for analysis in attack_analyses:
            ml_score = analysis.get("ml_anomaly_score", 0.0)
            total_ml_score += ml_score
            max_ml_score = max(max_ml_score, ml_score)
            
            if analysis.get("attack_types") or ml_score > 0.5:
                attack_count += 1
            
            ml_metrics = MLMetrics(
                ml_anomaly_score=ml_score,
                ml_labels=analysis.get("ml_labels", []),
                ml_cluster=analysis.get("ml_cluster", -1),
                ml_reason=analysis.get("ml_reason", ""),
                ml_confidence=analysis.get("ml_confidence", 0.0),
                ml_risk_score=analysis.get("ml_risk_score", 0.0),
                ml_inference_time_ms=analysis.get("ml_inference_time_ms", 0.0),
                ml_risk_level=analysis.get("ml_risk_level", "low"),
                ml_threat_score=analysis.get("ml_threat_score", 0),
                ml_risk_color=analysis.get("ml_risk_color", "#28a745"),
            )
            
            attack = AttackAnalysis(
                command=analysis.get("command", analysis.get("query", "")),
                timestamp=analysis.get("timestamp", ""),
                attack_types=analysis.get("attack_types", []),
                severity=analysis.get("severity", "low"),
                indicators=analysis.get("indicators", []),
                vulnerabilities=analysis.get("vulnerabilities", []),
                pattern_matches=analysis.get("pattern_matches", []),
                threat_score=analysis.get("threat_score", 0),
                alert_triggered=analysis.get("alert_triggered", False),
                ml_metrics=ml_metrics,
                attack_vectors=analysis.get("attack_vectors", []),
            )
            attacks.append(attack)
        
        # Calculate averages
        total_commands = len(commands) if commands else len(attack_analyses)
        avg_ml_score = total_ml_score / len(attack_analyses) if attack_analyses else 0.0
        
        # Determine risk level
        if max_ml_score > 0.7:
            risk_level = "high"
        elif max_ml_score > 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Extract client info - try multiple sources
        client_info = data.get("client_info", {})
        client_ip = client_info.get("ip", "")
        
        # For FTP, get from meta.json first
        if not client_ip and meta_data:
            client_ip = meta_data.get("client_ip", "") or meta_data.get("src_ip", "")
        
        # Try to get from root level
        if not client_ip:
            client_ip = data.get("src_ip", "") or data.get("client_ip", "")
        
        # For forensic_chain.json (SSH/FTP), extract from connection_established event
        if not client_ip and "events" in data:
            for event in data.get("events", []):
                if event.get("event_type") == "connection_established":
                    event_data = event.get("data", {})
                    client_ip = event_data.get("src_ip", "")
                    break
        
        # Try to extract IP from session directory name (e.g., session_20251211_001731_127.0.0.1)
        if not client_ip:
            parts = session_id.split("_")
            if len(parts) >= 4:
                # Last part might be IP address
                potential_ip = parts[-1]
                if potential_ip.count(".") == 3:  # Simple IP check
                    client_ip = potential_ip
        
        # Extract username - try multiple sources
        username = data.get("username", "")
        
        # For FTP, get from meta.json
        if not username and meta_data:
            username = meta_data.get("username", "") or ""
        
        # For SSH/FTP with forensic_chain, check various event types
        if not username and "events" in data:
            for event in data.get("events", []):
                event_type = event.get("event_type", "")
                event_data = event.get("data", {})
                
                # Check authentication events
                if event_type in ["authentication", "authentication_success", "login", "session_start"]:
                    username = event_data.get("username", "")
                    if username:
                        break
                
                # Check if username is in connection event
                if event_type == "connection_established" and not username:
                    username = event_data.get("username", "")
        
        # For SSH, if still no username and there are attack events (user was active), default to 'guest'
        if not username and service == "ssh" and (attack_count > 0 or total_commands > 0):
            username = "guest"
        
        return SessionSummary(
            session_id=session_id,
            service=service,
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            duration=data.get("duration", ""),
            total_commands=total_commands,
            attack_count=attack_count,
            avg_ml_score=round(avg_ml_score, 4),
            max_ml_score=round(max_ml_score, 4),
            risk_level=risk_level,
            attacks=attacks,
            client_ip=client_ip,
            username=username,
        )
        
    except Exception as e:
        logger.error(f"Error parsing session {session_dir}: {e}")
        return None


def get_all_sessions(service_filter: Optional[str] = None) -> List[SessionSummary]:
    """Get all sessions from all services or a specific service"""
    sessions = []
    
    services = [service_filter] if service_filter else list(SESSION_DIRS.keys())
    
    for service in services:
        session_dir = SESSION_DIRS.get(service)
        if not session_dir or not session_dir.exists():
            continue
        
        # Iterate through session directories
        for item in session_dir.iterdir():
            if item.is_dir() and not item.name.startswith("_") and not item.name.endswith("_states"):
                session = parse_session_file(item, service)
                if session:
                    sessions.append(session)
    
    # Sort by start_time descending
    sessions.sort(key=lambda x: x.start_time, reverse=True)
    
    return sessions


# ============== API Endpoints ==============

@router.get("/stats", response_model=MLStats)
async def get_ml_stats(service: Optional[str] = Query(None, description="Filter by service (ssh/ftp/mysql)")):
    """Get aggregated ML statistics across all sessions"""
    sessions = get_all_sessions(service)
    
    if not sessions:
        return MLStats()
    
    # Aggregate statistics
    total_commands = 0
    total_attacks = 0
    total_ml_score = 0.0
    total_inference_time = 0.0
    inference_count = 0
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    attack_types: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    services_seen = set()
    
    for session in sessions:
        services_seen.add(session.service)
        total_commands += session.total_commands
        total_attacks += session.attack_count
        
        if session.risk_level == "high":
            high_risk += 1
        elif session.risk_level == "medium":
            medium_risk += 1
        else:
            low_risk += 1
        
        for attack in session.attacks:
            total_ml_score += attack.ml_metrics.ml_anomaly_score if attack.ml_metrics else 0
            if attack.ml_metrics and attack.ml_metrics.ml_inference_time_ms > 0:
                total_inference_time += attack.ml_metrics.ml_inference_time_ms
                inference_count += 1
            
            for atype in attack.attack_types:
                attack_types[atype] = attack_types.get(atype, 0) + 1
            
            severity_counts[attack.severity] = severity_counts.get(attack.severity, 0) + 1
    
    attack_count = sum(len(s.attacks) for s in sessions)
    
    return MLStats(
        total_sessions=len(sessions),
        total_commands=total_commands,
        total_attacks=total_attacks,
        avg_anomaly_score=round(total_ml_score / attack_count, 4) if attack_count > 0 else 0.0,
        high_risk_count=high_risk,
        medium_risk_count=medium_risk,
        low_risk_count=low_risk,
        avg_inference_time_ms=round(total_inference_time / inference_count, 2) if inference_count > 0 else 0.0,
        services_active=list(services_seen),
        risk_distribution={"high": high_risk, "medium": medium_risk, "low": low_risk},
        attack_type_distribution=attack_types,
        severity_distribution=severity_counts,
    )


@router.get("/sessions", response_model=List[SessionSummary])
async def get_sessions(
    service: Optional[str] = Query(None, description="Filter by service (ssh/ftp/mysql)"),
    limit: int = Query(50, ge=1, le=500),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (low/medium/high)")
):
    """Get all ML analysis sessions with optional filters"""
    sessions = get_all_sessions(service)
    
    if risk_level:
        sessions = [s for s in sessions if s.risk_level == risk_level]
    
    return sessions[:limit]


@router.get("/sessions/{session_id}", response_model=SessionSummary)
async def get_session(session_id: str):
    """Get detailed ML analysis for a specific session"""
    sessions = get_all_sessions()
    
    for session in sessions:
        if session.session_id == session_id:
            return session
    
    raise HTTPException(status_code=404, detail=f"Session {session_id} not found")


@router.get("/attacks", response_model=List[AttackAnalysis])
async def get_attacks(
    service: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get all attacks across all sessions with ML analysis"""
    sessions = get_all_sessions(service)
    
    attacks = []
    for session in sessions:
        for attack in session.attacks:
            # Apply filters
            if severity and attack.severity != severity:
                continue
            if attack.ml_metrics and attack.ml_metrics.ml_anomaly_score < min_score:
                continue
            attacks.append(attack)
    
    # Sort by ML score descending
    attacks.sort(
        key=lambda x: x.ml_metrics.ml_anomaly_score if x.ml_metrics else 0,
        reverse=True
    )
    
    return attacks[:limit]


@router.get("/config/{service}")
async def get_service_config(service: str):
    """Get LLM configuration for a specific service"""
    if service not in CONFIG_FILES:
        raise HTTPException(status_code=404, detail=f"Unknown service: {service}")
    
    return get_llm_config(service)


@router.get("/active-services")
async def get_active_services():
    """Check which services have session data"""
    active = []
    for service, session_dir in SESSION_DIRS.items():
        if session_dir.exists():
            session_count = sum(1 for item in session_dir.iterdir() 
                              if item.is_dir() and not item.name.endswith("_states"))
            if session_count > 0:
                active.append({
                    "service": service,
                    "session_count": session_count,
                    "config": get_llm_config(service)
                })
    return active


@router.post("/summary")
async def generate_summary(request: LLMSummaryRequest):
    """Generate LLM-powered summary for a session (placeholder - requires LLM integration)"""
    sessions = get_all_sessions(request.service)
    
    session = next((s for s in sessions if s.session_id == request.session_id), None)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get LLM config for the service
    llm_config = get_llm_config(request.service)
    
    # For now, return a structured summary based on session data
    # Full LLM integration would call the appropriate provider here
    attack_summary = []
    for attack in session.attacks:
        if attack.attack_types:
            attack_summary.append({
                "command": attack.command[:100],
                "types": attack.attack_types,
                "severity": attack.severity,
                "ml_score": attack.ml_metrics.ml_anomaly_score if attack.ml_metrics else 0
            })
    
    return {
        "session_id": session.session_id,
        "service": session.service,
        "llm_provider": llm_config["llm_provider"],
        "model": llm_config["model_name"],
        "summary": {
            "overview": f"Session from {session.client_ip or 'unknown'} with {session.total_commands} commands and {session.attack_count} detected attacks.",
            "risk_assessment": f"Overall risk level: {session.risk_level.upper()} (max ML score: {session.max_ml_score:.2f})",
            "attack_highlights": attack_summary[:5],
            "duration": session.duration,
            "recommendation": "Review high-severity attacks and update threat intelligence." if session.risk_level == "high" else "Continue monitoring."
        }
    }


@router.get("/cve/{cve_id}")
async def lookup_cve(cve_id: str):
    """Lookup CVE information (using cve.circl.lu API)"""
    import aiohttp
    
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(
                f"https://cve.circl.lu/api/cve/{cve_id}",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "cve_id": cve_id,
                        "found": True,
                        "data": data
                    }
                else:
                    return {
                        "cve_id": cve_id,
                        "found": False,
                        "error": f"CVE not found (status: {response.status})"
                    }
    except Exception as e:
        return {
            "cve_id": cve_id,
            "found": False,
            "error": str(e)
        }
