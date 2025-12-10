'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
    PieChart,
    Pie,
    Cell,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    Legend,
} from 'recharts';
import { IconChartPie, IconChartBar } from '@tabler/icons-react';
import { MLStats, getMLStats } from '@/lib/ml-data';

const RISK_COLORS = {
    high: '#ef4444',
    medium: '#f59e0b',
    low: '#22c55e',
};

const ATTACK_TYPE_COLORS = [
    '#6366f1',
    '#8b5cf6',
    '#ec4899',
    '#f43f5e',
    '#f97316',
    '#eab308',
    '#22c55e',
    '#14b8a6',
    '#06b6d4',
    '#3b82f6',
];

interface MLMetricsChartsProps {
    service?: string;
    refreshInterval?: number;
    // Real-time data from WebSocket
    realtimeMetrics?: {
        riskDistribution: Record<string, number>;
        attackTypeDistribution: Record<string, number>;
    };
    entries?: any[];
}

export function MLMetricsCharts({ service, refreshInterval = 5000, realtimeMetrics, entries }: MLMetricsChartsProps) {
    const [apiStats, setApiStats] = useState<MLStats | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // If we have real-time data, skip API fetch
        if (realtimeMetrics && entries && entries.length > 0) {
            setLoading(false);
            return;
        }

        async function fetchStats() {
            try {
                const data = await getMLStats(service);
                setApiStats(data);
            } catch (err) {
                console.error('Failed to fetch ML stats:', err);
            } finally {
                setLoading(false);
            }
        }

        fetchStats();
        const interval = setInterval(fetchStats, refreshInterval);
        return () => clearInterval(interval);
    }, [service, refreshInterval, realtimeMetrics, entries]);

    const hasRealtimeData = realtimeMetrics && entries && entries.length > 0;

    if (loading && !hasRealtimeData) {
        return (
            <div className="grid gap-6 lg:grid-cols-2">
                <div className="h-80 animate-pulse border border-border/50 bg-muted/30" />
                <div className="h-80 animate-pulse border border-border/50 bg-muted/30" />
            </div>
        );
    }

    // Use real-time data if available
    let riskData: Array<{ name: string; value: number; color: string }>;
    let attackTypeData: Array<{ name: string; value: number; fill: string }>;

    if (hasRealtimeData) {
        // Build from real-time data
        riskData = Object.entries(realtimeMetrics.riskDistribution).map(([name, value]) => ({
            name: name.charAt(0).toUpperCase() + name.slice(1),
            value,
            color: RISK_COLORS[name as keyof typeof RISK_COLORS] || '#6b7280',
        }));

        attackTypeData = Object.entries(realtimeMetrics.attackTypeDistribution)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([name, value], index) => ({
                name: name.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
                value,
                fill: ATTACK_TYPE_COLORS[index % ATTACK_TYPE_COLORS.length],
            }));
    } else if (apiStats) {
        // Fall back to API data
        riskData = Object.entries(apiStats.risk_distribution).map(([name, value]) => ({
            name: name.charAt(0).toUpperCase() + name.slice(1),
            value,
            color: RISK_COLORS[name as keyof typeof RISK_COLORS] || '#6b7280',
        }));

        attackTypeData = Object.entries(apiStats.attack_type_distribution)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([name, value], index) => ({
                name: name.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
                value,
                fill: ATTACK_TYPE_COLORS[index % ATTACK_TYPE_COLORS.length],
            }));
    } else {
        riskData = [];
        attackTypeData = [];
    }

    return (
        <div className="grid gap-6 lg:grid-cols-2">
            {/* Risk Distribution Pie Chart */}
            <div className="border border-border/50 bg-card/50 p-6">
                <div className="flex items-center gap-2 mb-6">
                    <IconChartPie className="h-5 w-5 text-muted-foreground" />
                    <h3 className="font-semibold">Risk Level Distribution</h3>
                </div>

                {riskData.reduce((sum, d) => sum + d.value, 0) === 0 ? (
                    <div className="h-64 flex items-center justify-center text-muted-foreground">
                        No risk data available
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height={320}>
                        <PieChart margin={{ top: 20, right: 80, bottom: 20, left: 80 }}>
                            <Pie
                                data={riskData}
                                cx="50%"
                                cy="45%"
                                innerRadius={50}
                                outerRadius={80}
                                paddingAngle={4}
                                dataKey="value"
                                label={({ name, value, percent }) =>
                                    value > 0 ? `${name}: ${value}` : ''
                                }
                                labelLine={{ stroke: '#64748b', strokeWidth: 1 }}
                            >
                                {riskData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'hsl(var(--card))',
                                    border: '1px solid hsl(var(--border))',
                                    borderRadius: '0px',
                                    color: 'hsl(var(--foreground))',
                                }}
                                itemStyle={{ color: 'hsl(var(--foreground))' }}
                                labelStyle={{ color: 'hsl(var(--foreground))' }}
                            />
                            <Legend
                                verticalAlign="bottom"
                                height={36}
                                wrapperStyle={{ paddingTop: '16px' }}
                                formatter={(value) => <span style={{ color: '#94a3b8', fontSize: '12px' }}>{value}</span>}
                            />
                        </PieChart>
                    </ResponsiveContainer>
                )}
            </div>

            {/* Attack Types Bar Chart */}
            <div className="border border-border/50 bg-card/50 p-6">
                <div className="flex items-center gap-2 mb-6">
                    <IconChartBar className="h-5 w-5 text-muted-foreground" />
                    <h3 className="font-semibold">Attack Types Distribution</h3>
                </div>

                {attackTypeData.length === 0 ? (
                    <div className="h-64 flex items-center justify-center text-muted-foreground">
                        No attack data available
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height={250}>
                        <BarChart
                            data={attackTypeData}
                            layout="vertical"
                            margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                        >
                            <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={{ stroke: '#64748b' }} tickLine={{ stroke: '#64748b' }} />
                            <YAxis
                                dataKey="name"
                                type="category"
                                width={120}
                                tick={{ fill: '#94a3b8', fontSize: 11 }}
                                axisLine={{ stroke: '#64748b' }}
                                tickLine={{ stroke: '#64748b' }}
                            />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'hsl(var(--card))',
                                    border: '1px solid hsl(var(--border))',
                                    borderRadius: '0px',
                                    color: 'hsl(var(--foreground))',
                                }}
                                itemStyle={{ color: 'hsl(var(--foreground))' }}
                                labelStyle={{ color: 'hsl(var(--foreground))' }}
                            />
                            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                {attackTypeData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.fill} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}

export default MLMetricsCharts;
