'use client';

import { useEffect, useState } from 'react';
import {
    IconBrain,
    IconAlertTriangle,
    IconShieldCheck,
    IconClock,
    IconServer,
    IconChartBar,
} from '@tabler/icons-react';
import { MLStats, getMLStats } from '@/lib/ml-data';

interface StatsCardProps {
    title: string;
    value: string | number;
    subtitle?: string;
    icon: React.ReactNode;
    color: string;
    trend?: 'up' | 'down' | 'neutral';
}

function StatsCard({ title, value, subtitle, icon, color }: StatsCardProps) {
    return (
        <div
            className="relative overflow-hidden bg-card border border-border/30 shadow-lg hover:shadow-xl transition-all duration-300 group"
            style={{
                minHeight: '140px',
                background: 'linear-gradient(145deg, hsl(var(--card)) 0%, hsl(var(--card) / 0.8) 100%)',
            }}
        >
            {/* Gradient accent line at top */}
            <div
                className="absolute top-0 left-0 right-0 h-1"
                style={{ background: `linear-gradient(90deg, ${color}, ${color}80)` }}
            />

            {/* Subtle background glow */}
            <div
                className="absolute -right-8 -top-8 w-32 h-32 opacity-10 blur-2xl transition-opacity group-hover:opacity-20"
                style={{ background: color }}
            />

            <div className="relative p-5 h-full flex flex-col justify-between">
                {/* Header with icon */}
                <div className="flex items-start justify-between mb-3">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        {title}
                    </p>
                    <div
                        className="p-2.5 backdrop-blur-sm border border-white/10"
                        style={{
                            backgroundColor: `${color}15`,
                            boxShadow: `0 0 20px ${color}20`,
                        }}
                    >
                        <div style={{ color }} className="opacity-90">{icon}</div>
                    </div>
                </div>

                {/* Value */}
                <div className="space-y-1">
                    <p
                        className="text-3xl font-bold tracking-tight leading-none"
                        style={{ color }}
                    >
                        {value}
                    </p>
                    {subtitle && (
                        <p className="text-[11px] text-muted-foreground/80 font-medium">
                            {subtitle}
                        </p>
                    )}
                </div>
            </div>
        </div>
    );
}

interface MLStatsCardsProps {
    service?: string;
    refreshInterval?: number;
    // Real-time data from WebSocket
    realtimeStats?: {
        totalCommands: number;
        totalAttacks: number;
        highRisk: number;
        mediumRisk: number;
        lowRisk: number;
        avgAnomalyScore: number;
    };
    entries?: any[];
}

export function MLStatsCards({ service, refreshInterval = 3000, realtimeStats, entries }: MLStatsCardsProps) {
    const [apiStats, setApiStats] = useState<MLStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        // If we have real-time stats, no need to fetch from API
        if (realtimeStats && entries && entries.length > 0) {
            setLoading(false);
            return;
        }

        let mounted = true;

        async function fetchStats() {
            try {
                const data = await getMLStats(service);
                if (mounted) {
                    setApiStats(data);
                    setError(null);
                }
            } catch (err) {
                if (mounted) {
                    setError(err instanceof Error ? err.message : 'Failed to fetch stats');
                }
            } finally {
                if (mounted) {
                    setLoading(false);
                }
            }
        }

        fetchStats();
        const interval = setInterval(fetchStats, refreshInterval);

        return () => {
            mounted = false;
            clearInterval(interval);
        };
    }, [service, refreshInterval, realtimeStats, entries]);

    // Use real-time stats if available, otherwise fall back to API stats
    const hasRealtimeData = realtimeStats && entries && entries.length > 0;

    if (loading && !hasRealtimeData) {
        return (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
                {[...Array(6)].map((_, i) => (
                    <div
                        key={i}
                        className="h-32 animate-pulse rounded-xl border border-border/50 bg-muted/50"
                    />
                ))}
            </div>
        );
    }

    if (error && !hasRealtimeData) {
        return (
            <div className="rounded-xl border border-destructive/50 bg-destructive/10 p-6 text-center">
                <IconAlertTriangle className="mx-auto mb-2 h-8 w-8 text-destructive" />
                <p className="font-medium text-destructive">Failed to load ML stats</p>
                <p className="text-sm text-muted-foreground">{error}</p>
            </div>
        );
    }

    // Build display stats from either real-time or API data
    const stats = hasRealtimeData ? {
        total_sessions: entries.length,
        total_commands: realtimeStats.totalCommands,
        total_attacks: realtimeStats.totalAttacks,
        avg_anomaly_score: realtimeStats.avgAnomalyScore,
        high_risk_count: realtimeStats.highRisk,
        medium_risk_count: realtimeStats.mediumRisk,
        low_risk_count: realtimeStats.lowRisk,
        avg_inference_time_ms: 0,
        services_active: [...new Set(entries.map((e: any) => e.service))],
    } : apiStats;

    if (!stats) return null;

    const cards = [
        {
            title: 'Total Sessions',
            value: stats.total_sessions,
            subtitle: `${stats.services_active.length} active services`,
            icon: <IconServer className="h-6 w-6" />,
            color: '#6366f1',
        },
        {
            title: 'ML Predictions',
            value: stats.total_commands,
            subtitle: `${stats.total_attacks} attacks detected`,
            icon: <IconBrain className="h-6 w-6" />,
            color: '#8b5cf6',
        },
        {
            title: 'Avg Anomaly Score',
            value: `${(stats.avg_anomaly_score * 100).toFixed(1)}%`,
            subtitle: 'Across all commands',
            icon: <IconChartBar className="h-6 w-6" />,
            color: stats.avg_anomaly_score > 0.5 ? '#f59e0b' : '#22c55e',
        },
        {
            title: 'High Risk',
            value: stats.high_risk_count,
            subtitle: `${stats.medium_risk_count} medium, ${stats.low_risk_count} low`,
            icon: <IconAlertTriangle className="h-6 w-6" />,
            color: stats.high_risk_count > 0 ? '#ef4444' : '#22c55e',
        },
        {
            title: 'Avg Inference Time',
            value: `${stats.avg_inference_time_ms.toFixed(1)}ms`,
            subtitle: 'ML processing time',
            icon: <IconClock className="h-6 w-6" />,
            color: stats.avg_inference_time_ms > 100 ? '#f59e0b' : '#22c55e',
        },
        {
            title: 'Detection Rate',
            value: stats.total_attacks > 0
                ? `${((stats.total_attacks / stats.total_commands) * 100).toFixed(1)}%`
                : '0%',
            subtitle: 'Commands flagged as attacks',
            icon: <IconShieldCheck className="h-6 w-6" />,
            color: '#06b6d4',
        },
    ];

    return (
        <div className="grid gap-5 grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
            {cards.map((card) => (
                <StatsCard key={card.title} {...card} />
            ))}
        </div>
    );
}

export default MLStatsCards;
