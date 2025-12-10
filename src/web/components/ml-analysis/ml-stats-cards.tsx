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
        <div className="relative overflow-hidden border border-border/50 bg-card p-6 shadow-sm">
            {/* Gradient background */}
            <div
                className="absolute inset-0 opacity-5"
                style={{
                    background: `linear-gradient(135deg, ${color} 0%, transparent 60%)`,
                }}
            />

            <div className="relative flex items-start justify-between">
                <div className="space-y-2">
                    <p className="text-sm font-medium text-muted-foreground">{title}</p>
                    <p className="text-3xl font-bold tracking-tight" style={{ color }}>
                        {value}
                    </p>
                    {subtitle && (
                        <p className="text-xs text-muted-foreground">{subtitle}</p>
                    )}
                </div>
                <div
                    className="p-3"
                    style={{ backgroundColor: `${color}15` }}
                >
                    <div style={{ color }}>{icon}</div>
                </div>
            </div>
        </div>
    );
}

interface MLStatsCardsProps {
    service?: string;
    refreshInterval?: number;
}

export function MLStatsCards({ service, refreshInterval = 3000 }: MLStatsCardsProps) {
    const [stats, setStats] = useState<MLStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let mounted = true;

        async function fetchStats() {
            try {
                const data = await getMLStats(service);
                if (mounted) {
                    setStats(data);
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
    }, [service, refreshInterval]);

    if (loading) {
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

    if (error) {
        return (
            <div className="rounded-xl border border-destructive/50 bg-destructive/10 p-6 text-center">
                <IconAlertTriangle className="mx-auto mb-2 h-8 w-8 text-destructive" />
                <p className="font-medium text-destructive">Failed to load ML stats</p>
                <p className="text-sm text-muted-foreground">{error}</p>
            </div>
        );
    }

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
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
            {cards.map((card) => (
                <div key={card.title}>
                    <StatsCard {...card} />
                </div>
            ))}
        </div>
    );
}

export default MLStatsCards;
