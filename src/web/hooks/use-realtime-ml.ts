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
    response?: string;
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

    // Fallback: Detect attack patterns from command/query content
    const detectAttackPatterns = useCallback((input: string): { types: string[]; severity: string; score: number } => {
        const result = { types: [] as string[], severity: 'low', score: 0 };
        if (!input) return result;

        const patterns: { [key: string]: { regex: RegExp[]; severity: string; score: number } } = {
            'sql_injection': {
                regex: [
                    /'\s*(or|and)\s*['"]?\d+['"]?\s*=\s*['"]?\d+/i,           // '1'='1' style
                    /'\s*(or|and)\s*['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+['"]?/i, // 'a'='a' style
                    /union\s+(all\s+)?select/i,                                // UNION SELECT
                    /;\s*(drop|delete|truncate|update|insert)\s+/i,            // destructive queries
                    /--\s*$/,                                                  // SQL comment at end
                    /';\s*--/,                                                 // '; -- injection
                    /sleep\s*\(\s*\d+\s*\)/i,                                  // time-based blind
                    /benchmark\s*\(/i,                                         // MySQL benchmark
                    /load_file\s*\(/i,                                         // file read
                    /into\s+(out|dump)file/i,                                  // file write
                ],
                severity: 'critical',
                score: 90
            },
            'command_injection': {
                regex: [
                    /[;&|`$]\s*(cat|wget|curl|nc|bash|sh|python|perl|ruby|php)/i,
                    /\|\s*(cat|grep|awk|sed|head|tail|less|more)/i,
                    /`[^`]+`/,                                                 // backtick execution
                    /\$\([^)]+\)/,                                             // $(command)
                ],
                severity: 'critical',
                score: 85
            },
            'path_traversal': {
                regex: [
                    /\.\.[\/\\]/,                                               // ../
                    /etc\/passwd/i,
                    /etc\/shadow/i,
                ],
                severity: 'high',
                score: 75
            },
            'reconnaissance': {
                regex: [
                    /information_schema\./i,
                    /mysql\.user/i,
                ],
                severity: 'medium',
                score: 50
            }
        };

        for (const [attackType, config] of Object.entries(patterns)) {
            for (const regex of config.regex) {
                if (regex.test(input)) {
                    if (!result.types.includes(attackType)) {
                        result.types.push(attackType);
                    }
                    if (config.score > result.score) {
                        result.score = config.score;
                        result.severity = config.severity;
                    }
                    break;
                }
            }
        }

        return result;
    }, []);

    // Transform log entry to ML analysis entry
    const transformLogEntry = useCallback((log: any): MLAnalysisEntry | null => {
        // Flatten structured_data if present (MySQL logs)
        let flatLog = log;
        if (log.structured_data && typeof log.structured_data === 'object') {
            flatLog = { ...log, ...log.structured_data };
        }

        // Extract service from sensor_protocol or sensor_name
        const service = (flatLog.sensor_protocol || flatLog.sensor_name || 'unknown').toLowerCase();

        // Skip entries without useful command data
        const command = flatLog.command || flatLog.query || flatLog.message || '';
        if (!command || command.length < 2) return null;

        // Extract ML metrics from the log entry
        const mlAnomalyScore = flatLog.ml_anomaly_score ?? flatLog.anomaly_score ?? flatLog.threat_score ?? 0;
        const mlRiskLevel = flatLog.ml_risk_level || flatLog.risk_level || (mlAnomalyScore > 0.7 ? 'high' : mlAnomalyScore > 0.4 ? 'medium' : 'low');
        const mlRiskColor = flatLog.ml_risk_color || (mlRiskLevel === 'high' || mlRiskLevel === 'critical' ? '#ef4444' : mlRiskLevel === 'medium' ? '#f59e0b' : '#22c55e');

        // Compute confidence - use log value, or derive from anomaly score (higher anomaly = higher confidence in detection)
        const rawConfidence = flatLog.ml_confidence ?? flatLog.confidence ?? flatLog.ml_prediction_confidence;
        const mlConfidence = rawConfidence !== undefined && rawConfidence !== null
            ? rawConfidence
            : (mlAnomalyScore > 0 ? Math.min(0.95, 0.5 + mlAnomalyScore * 0.5) : 0);

        // Compute threat score - use log value, or derive from anomaly score (scale to percentage)
        const rawThreatScore = flatLog.threat_score ?? flatLog.ml_threat_score ?? flatLog.risk_score;
        const threatScore = rawThreatScore !== undefined && rawThreatScore !== null
            ? (rawThreatScore > 1 ? rawThreatScore : rawThreatScore * 100)  // Normalize to 0-100
            : mlAnomalyScore * 100;  // Fallback: use anomaly score as percentage

        // Extract response info - handle array format from MySQL
        let response = flatLog.response || flatLog.summary;
        if (Array.isArray(response)) {
            try {
                response = response.map((row: any[]) => Array.isArray(row) ? row.join(', ') : String(row)).join('\n');
            } catch {
                response = JSON.stringify(response);
            }
        }
        if (!response && flatLog.details) {
            try {
                response = atob(flatLog.details);
            } catch {
                response = flatLog.details;
            }
        }

        // FALLBACK: Detect attack patterns from command when backend doesn't provide them
        let finalAttackTypes = flatLog.attack_types || [];
        let finalSeverity = flatLog.severity || mlRiskLevel || 'low';
        let finalAnomalyScore = mlAnomalyScore;
        let finalThreatScore = threatScore;

        if ((!finalAttackTypes || finalAttackTypes.length === 0) && command) {
            const detected = detectAttackPatterns(command);
            if (detected.types.length > 0) {
                finalAttackTypes = detected.types;
                finalSeverity = detected.severity;
                finalAnomalyScore = detected.score / 100;  // Convert to 0-1 scale
                finalThreatScore = detected.score;
            }
        }

        return {
            id: `${flatLog.timestamp}-${flatLog.session_id || Math.random().toString(36).substring(7)}`,
            timestamp: flatLog.timestamp,
            service,
            command,
            session_id: flatLog.session_id,
            // Extract src_ip from various possible field names (different protocols use different names)
            src_ip: flatLog.src_ip || flatLog.source_ip || flatLog.client_ip || flatLog.ip || flatLog.remote_ip || flatLog.peer_ip || flatLog.attacker_ip,
            // Extract username from various possible field names
            username: flatLog.username || flatLog.user || flatLog.login || flatLog.client_user || flatLog.auth_user || flatLog.ftp_user || flatLog.ssh_user,

            // ML metrics - with computed fallbacks and pattern detection
            ml_anomaly_score: finalAnomalyScore,
            ml_risk_level: finalSeverity,
            ml_confidence: mlConfidence || (finalAnomalyScore > 0 ? 0.85 : 0),
            ml_inference_time_ms: flatLog.ml_inference_time_ms ?? flatLog.inference_time_ms ?? 0,
            ml_risk_color: finalSeverity === 'critical' || finalSeverity === 'high' ? '#ef4444' : finalSeverity === 'medium' ? '#f59e0b' : '#22c55e',
            ml_labels: flatLog.ml_labels || flatLog.labels || [],
            ml_reason: flatLog.ml_reason || flatLog.reason || flatLog.classification_reason || (finalAttackTypes.length > 0 ? `Detected: ${finalAttackTypes.join(', ')}` : ''),

            // Attack info - with pattern detection fallback
            attack_types: finalAttackTypes,
            severity: finalSeverity,
            threat_score: finalThreatScore,
            indicators: flatLog.indicators || [],
            pattern_matches: flatLog.pattern_matches || [],
            vulnerabilities: flatLog.vulnerabilities || [],
            response,
        };
    }, [detectAttackPatterns]);

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
