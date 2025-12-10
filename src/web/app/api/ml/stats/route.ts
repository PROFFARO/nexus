/**
 * Next.js API Route for ML Analysis Stats
 * Reads session data directly from filesystem - no external API needed
 */

import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs/promises';
import path from 'path';

const SERVICE_EMULATORS_DIR = path.resolve(process.cwd(), '../service_emulators');

const SESSION_DIRS: Record<string, string> = {
    ssh: path.join(SERVICE_EMULATORS_DIR, 'SSH', 'sessions'),
    ftp: path.join(SERVICE_EMULATORS_DIR, 'FTP', 'sessions'),
    mysql: path.join(SERVICE_EMULATORS_DIR, 'MySQL', 'sessions'),
};

interface MLStats {
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

async function parseSessionFile(sessionDir: string, service: string) {
    try {
        const files = await fs.readdir(sessionDir);

        // Try different file patterns
        const dataFiles = ['session_summary.json', 'session_data.json', 'forensic_chain.json'];

        for (const filename of dataFiles) {
            if (files.includes(filename)) {
                const filePath = path.join(sessionDir, filename);
                const content = await fs.readFile(filePath, 'utf-8');
                const data = JSON.parse(content);
                return { data, service, sessionDir };
            }
        }
    } catch (err) {
        // Session dir might not have valid data
    }
    return null;
}

async function getAllSessionData(serviceFilter?: string) {
    const sessions: any[] = [];
    const services = serviceFilter ? [serviceFilter] : Object.keys(SESSION_DIRS);

    for (const service of services) {
        const sessionDir = SESSION_DIRS[service];

        try {
            const items = await fs.readdir(sessionDir);

            for (const item of items) {
                if (item.startsWith('_') || item.endsWith('_states')) continue;

                const itemPath = path.join(sessionDir, item);
                const stat = await fs.stat(itemPath);

                if (stat.isDirectory()) {
                    const sessionData = await parseSessionFile(itemPath, service);
                    if (sessionData) {
                        sessions.push(sessionData);
                    }
                }
            }
        } catch (err) {
            // Directory doesn't exist or can't be read
        }
    }

    return sessions;
}

export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);
        const service = searchParams.get('service') || undefined;

        const sessions = await getAllSessionData(service);

        const stats: MLStats = {
            total_sessions: 0,
            total_commands: 0,
            total_attacks: 0,
            avg_anomaly_score: 0,
            high_risk_count: 0,
            medium_risk_count: 0,
            low_risk_count: 0,
            avg_inference_time_ms: 0,
            services_active: [],
            risk_distribution: { high: 0, medium: 0, low: 0 },
            attack_type_distribution: {},
            severity_distribution: {},
        };

        const servicesSet = new Set<string>();
        let totalMLScore = 0;
        let totalInferenceTime = 0;
        let inferenceCount = 0;
        let attackCount = 0;

        for (const session of sessions) {
            stats.total_sessions++;
            servicesSet.add(session.service);

            const { data } = session;

            // Get attacks from various data structures
            let attacks: any[] = [];

            if (data.attack_analysis) {
                attacks = data.attack_analysis;
            } else if (data.events) {
                attacks = data.events
                    .filter((e: any) => e.event_type === 'attack_detected')
                    .map((e: any) => e.data);
            } else if (data.commands) {
                attacks = data.commands
                    .filter((c: any) => c.attack_analysis)
                    .map((c: any) => c.attack_analysis);
            } else if (data.queries) {
                attacks = data.queries
                    .filter((q: any) => q.attack_analysis)
                    .map((q: any) => q.attack_analysis);
            }

            stats.total_commands += data.commands?.length || data.queries?.length || attacks.length;

            for (const attack of attacks) {
                attackCount++;

                // Get ML score from multiple possible fields
                const mlScore = attack.ml_anomaly_score || attack.anomaly_score || attack.threat_score || 0;
                totalMLScore += mlScore;

                if (attack.ml_inference_time_ms || attack.inference_time_ms) {
                    totalInferenceTime += attack.ml_inference_time_ms || attack.inference_time_ms || 0;
                    inferenceCount++;
                }

                // Determine risk level from multiple sources with fallback calculation
                let riskLevel = attack.ml_risk_level || attack.risk_level || attack.severity;

                // If no explicit risk level, calculate from anomaly score
                if (!riskLevel || riskLevel === 'unknown') {
                    if (mlScore > 0.7) riskLevel = 'high';
                    else if (mlScore > 0.4) riskLevel = 'medium';
                    else riskLevel = 'low';
                }

                // Normalize risk level naming
                riskLevel = riskLevel.toLowerCase();
                if (riskLevel === 'critical') riskLevel = 'high';

                // Update risk distribution
                stats.risk_distribution[riskLevel] = (stats.risk_distribution[riskLevel] || 0) + 1;

                if (riskLevel === 'high') {
                    stats.high_risk_count++;
                } else if (riskLevel === 'medium') {
                    stats.medium_risk_count++;
                } else {
                    stats.low_risk_count++;
                }

                // Count attacks with attack_types
                if (attack.attack_types && attack.attack_types.length > 0) {
                    stats.total_attacks++;
                    for (const type of attack.attack_types) {
                        stats.attack_type_distribution[type] = (stats.attack_type_distribution[type] || 0) + 1;
                    }
                } else {
                    // Still count as an attack if it has non-zero ML score
                    if (mlScore > 0) {
                        stats.total_attacks++;
                    }
                }

                const severity = attack.severity || riskLevel || 'low';
                stats.severity_distribution[severity] = (stats.severity_distribution[severity] || 0) + 1;
            }
        }

        stats.services_active = Array.from(servicesSet);
        stats.avg_anomaly_score = attackCount > 0 ? totalMLScore / attackCount : 0;
        stats.avg_inference_time_ms = inferenceCount > 0 ? totalInferenceTime / inferenceCount : 0;

        return NextResponse.json(stats, {
            headers: {
                'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
            },
        });
    } catch (error) {
        console.error('ML stats error:', error);
        return NextResponse.json(
            { error: 'Failed to fetch ML stats' },
            { status: 500 }
        );
    }
}
