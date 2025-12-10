'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

/**
 * ML Analysis entry derived from real-time log data
 */
export interface MLAnalysisEntry {
    id: string;
    timestamp: string;
    service: string;
    command: string;
    session_id?: string;
    src_ip?: string;
    username?: string;

    // ML metrics
    ml_anomaly_score: number;
    ml_risk_level: string;
    ml_confidence: number;
    ml_inference_time_ms: number;
    ml_risk_color: string;
    ml_labels: string[];
    ml_reason: string;

    // Attack info
    attack_types: string[];
    severity: string;
    threat_score: number;
    indicators: string[];
    pattern_matches: string[];
    vulnerabilities: string[];
}

/**
 * Hook for real-time ML analysis data using WebSocket
 * Uses the same WebSocket as Live Attacks but transforms data for ML analysis
 */
export function useRealtimeMLAnalysis() {
    const [entries, setEntries] = useState<MLAnalysisEntry[]>([]);
    const [isConnected, setIsConnected] = useState(false);
    const [stats, setStats] = useState({
        totalCommands: 0,
        totalAttacks: 0,
        highRisk: 0,
        mediumRisk: 0,
        lowRisk: 0,
        avgAnomalyScore: 0,
    });
    const wsRef = useRef<WebSocket | null>(null);

    // Transform log entry to ML analysis entry
    const transformLogEntry = useCallback((log: any): MLAnalysisEntry | null => {
        // Extract service from sensor_protocol or sensor_name
        const service = (log.sensor_protocol || log.sensor_name || 'unknown').toLowerCase();

        // Skip entries without useful command data
        const command = log.command || log.query || log.message || '';
        if (!command || command.length < 2) return null;

        // Extract ML metrics from the log entry
        const mlAnomalyScore = log.ml_anomaly_score ?? log.anomaly_score ?? log.threat_score ?? 0;
        const mlRiskLevel = log.ml_risk_level || log.risk_level || (mlAnomalyScore > 0.7 ? 'high' : mlAnomalyScore > 0.4 ? 'medium' : 'low');
        const mlRiskColor = log.ml_risk_color || (mlRiskLevel === 'high' || mlRiskLevel === 'critical' ? '#ef4444' : mlRiskLevel === 'medium' ? '#f59e0b' : '#22c55e');

        // Compute confidence - use log value, or derive from anomaly score (higher anomaly = higher confidence in detection)
        const rawConfidence = log.ml_confidence ?? log.confidence ?? log.ml_prediction_confidence;
        const mlConfidence = rawConfidence !== undefined && rawConfidence !== null
            ? rawConfidence
            : (mlAnomalyScore > 0 ? Math.min(0.95, 0.5 + mlAnomalyScore * 0.5) : 0);

        // Compute threat score - use log value, or derive from anomaly score (scale to percentage)
        const rawThreatScore = log.threat_score ?? log.ml_threat_score ?? log.risk_score;
        const threatScore = rawThreatScore !== undefined && rawThreatScore !== null
            ? (rawThreatScore > 1 ? rawThreatScore : rawThreatScore * 100)  // Normalize to 0-100
            : mlAnomalyScore * 100;  // Fallback: use anomaly score as percentage

        return {
            id: `${log.timestamp}-${log.session_id || Math.random().toString(36).substring(7)}`,
            timestamp: log.timestamp,
            service,
            command,
            session_id: log.session_id,
            // Extract src_ip from various possible field names (different protocols use different names)
            src_ip: log.src_ip || log.source_ip || log.client_ip || log.ip || log.remote_ip || log.peer_ip || log.attacker_ip,
            // Extract username from various possible field names
            username: log.username || log.user || log.login || log.client_user || log.auth_user || log.ftp_user || log.ssh_user,

            // ML metrics - with computed fallbacks
            ml_anomaly_score: mlAnomalyScore,
            ml_risk_level: mlRiskLevel,
            ml_confidence: mlConfidence,
            ml_inference_time_ms: log.ml_inference_time_ms ?? log.inference_time_ms ?? 0,
            ml_risk_color: mlRiskColor,
            ml_labels: log.ml_labels || log.labels || [],
            ml_reason: log.ml_reason || log.reason || log.classification_reason || '',

            // Attack info
            attack_types: log.attack_types || [],
            severity: log.severity || mlRiskLevel || 'low',
            threat_score: threatScore,
            indicators: log.indicators || [],
            pattern_matches: log.pattern_matches || [],
            vulnerabilities: log.vulnerabilities || [],
        };
    }, []);

    // Update stats based on entries
    const updateStats = useCallback((entries: MLAnalysisEntry[]) => {
        const totalCommands = entries.length;
        const attacks = entries.filter(e => e.attack_types.length > 0 || e.ml_anomaly_score > 0.3);
        const totalAttacks = attacks.length;

        const highRisk = entries.filter(e => e.ml_risk_level === 'high' || e.ml_risk_level === 'critical').length;
        const mediumRisk = entries.filter(e => e.ml_risk_level === 'medium').length;
        const lowRisk = entries.filter(e => e.ml_risk_level === 'low').length;

        const avgAnomalyScore = totalCommands > 0
            ? entries.reduce((sum, e) => sum + e.ml_anomaly_score, 0) / totalCommands
            : 0;

        setStats({
            totalCommands,
            totalAttacks,
            highRisk,
            mediumRisk,
            lowRisk,
            avgAnomalyScore,
        });
    }, []);

    useEffect(() => {
        const connect = () => {
            const ws = new WebSocket('ws://localhost:8000/ws/attacks');

            ws.onopen = () => {
                console.log('Connected to Nexus ML Analysis Stream');
                setIsConnected(true);
            };

            ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    if (message.type === 'log_entry') {
                        const mlEntry = transformLogEntry(message.data);
                        if (mlEntry) {
                            setEntries(prev => {
                                const newEntries = [mlEntry, ...prev].slice(0, 500);
                                updateStats(newEntries);
                                return newEntries;
                            });
                        }
                    }
                } catch (e) {
                    console.error('Error parsing WebSocket message', e);
                }
            };

            ws.onclose = () => {
                setIsConnected(false);
                // Reconnect after 3 seconds
                setTimeout(connect, 3000);
            };

            ws.onerror = (error) => {
                console.error('WebSocket error', error);
                ws.close();
            };

            wsRef.current = ws;
        };

        connect();

        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, [transformLogEntry, updateStats]);

    // Filter entries by service
    const getEntriesByService = useCallback((service?: string) => {
        if (!service) return entries;
        return entries.filter(e => e.service === service);
    }, [entries]);

    return {
        entries,
        isConnected,
        stats,
        getEntriesByService,
    };
}
