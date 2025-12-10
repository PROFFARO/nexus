export interface LogEntry {
    timestamp: string;
    level: string;
    message: string;
    sensor_name?: string;
    sensor_protocol?: string;
    src_ip?: string;
    src_port?: string | number;
    dst_ip?: string;
    dst_port?: string | number;
    session_id?: string;
    task_name?: string;
    username?: string;
    command?: string;
    details?: string;
    attack_types?: string[];
    severity?: 'low' | 'medium' | 'high' | 'critical';
    threat_score?: number;
    indicators?: string[];
    [key: string]: any;
}

export interface WebSocketMessage {
    type: string;
    data: any;
}
