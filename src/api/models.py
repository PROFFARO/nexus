from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class LogEntry(BaseModel):
    timestamp: str
    level: str
    message: str
    sensor_name: Optional[str] = None
    sensor_protocol: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[Any] = None # Can be int or "-"
    dst_ip: Optional[str] = None
    dst_port: Optional[Any] = None # Can be int or "-"
    session_id: Optional[str] = None
    
    # Attack specific fields
    attack_types: Optional[List[str]] = None
    severity: Optional[str] = None
    threat_score: Optional[float] = None
    indicators: Optional[List[str]] = None
    
    # Catch-all for other fields
    extra: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"

class AttackEvent(BaseModel):
    id: str
    timestamp: str
    protocol: str
    attacker_ip: str
    attack_type: str
    severity: str
    description: str
    raw_log: Dict[str, Any]
