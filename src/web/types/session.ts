import { LogEntry } from './api';

// Session protocol types - SSH, FTP, MySQL only
export type SessionProtocol = 'ssh' | 'ftp' | 'mysql' | 'unknown';
export type RiskLevel = 'high' | 'medium' | 'low';

// ML Metrics from API
export interface MLMetrics {
    ml_anomaly_score: number;
    ml_labels: string[];
    ml_cluster: number;
    ml_reason: string;
    ml_confidence: number;
    ml_risk_score: number;
    ml_inference_time_ms: number;
    ml_risk_level: string;
    ml_threat_score: number;
    ml_risk_color: string;
}

// Attack Analysis from API
export interface AttackAnalysis {
    command: string;
    timestamp: string;
    attack_types: string[];
    severity: string;
    indicators: string[];
    vulnerabilities: any[];
    pattern_matches: any[];
    threat_score: number;
    alert_triggered: boolean;
    ml_metrics: MLMetrics | null;
    attack_vectors: any[];
}

// Session Summary from API - matches ml_routes.py SessionSummary
export interface SessionSummary {
    session_id: string;
    service: string;
    start_time: string;
    end_time: string;
    duration: string;
    total_commands: number;
    attack_count: number;
    avg_ml_score: number;
    max_ml_score: number;
    risk_level: RiskLevel;
    attacks: AttackAnalysis[];
    client_ip: string;
    username: string;
}

// ML Stats from API
export interface MLStats {
    total_sessions: number;
    total_commands: number;
    total_attacks: number;
    avg_anomaly_score: number;
    high_risk_count: number;
    medium_risk_count: number;
    low_risk_count: number;
    avg_inference_time_ms: number;
    services_active: string[];
    risk_distribution: Record<string, number>;
    attack_type_distribution: Record<string, number>;
    severity_distribution: Record<string, number>;
}

// Session filter options
export interface SessionFilters {
    service: 'all' | SessionProtocol;
    riskLevel: 'all' | RiskLevel;
    searchQuery: string;
}

// Default filter values
export const defaultSessionFilters: SessionFilters = {
    service: 'all',
    riskLevel: 'all',
    searchQuery: ''
};

// Computed session stats for UI
export interface ComputedSessionStats {
    totalSessions: number;
    activeSessions: number;
    totalCommands: number;
    totalAttacks: number;
    uniqueAttackers: number;
    byService: {
        ssh: number;
        ftp: number;
        mysql: number;
    };
    byRiskLevel: {
        high: number;
        medium: number;
        low: number;
    };
}

// Utility: Format duration for display
export function formatDuration(durationStr: string): string {
    if (!durationStr) return 'N/A';
    // Duration comes as "H:MM:SS.microseconds" or "0:10:29.099363"
    const parts = durationStr.split(':');
    if (parts.length === 3) {
        const hours = parseInt(parts[0], 10);
        const mins = parseInt(parts[1], 10);
        const secs = parseFloat(parts[2]);

        if (hours > 0) return `${hours}h ${mins}m`;
        if (mins > 0) return `${mins}m ${Math.floor(secs)}s`;
        return `${Math.floor(secs)}s`;
    }
    return durationStr;
}

// Protocol colors
export const PROTOCOL_COLORS: Record<string, string> = {
    ssh: '#06b6d4',     // cyan
    ftp: '#22c55e',     // green
    mysql: '#a855f7',   // purple
    unknown: '#6b7280'  // gray
};

// Risk level colors
export const RISK_COLORS: Record<RiskLevel, string> = {
    high: '#ef4444',    // red
    medium: '#f59e0b',  // amber
    low: '#22c55e',     // green
};
