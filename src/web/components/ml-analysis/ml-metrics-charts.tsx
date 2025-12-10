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
}

export function MLMetricsCharts({ service, refreshInterval = 10000 }: MLMetricsChartsProps) {
    const [stats, setStats] = useState<MLStats | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function fetchStats() {
            try {
                const data = await getMLStats(service);
                setStats(data);
            } catch (err) {
                console.error('Failed to fetch ML stats:', err);
            } finally {
                setLoading(false);
            }
        }

        fetchStats();
        const interval = setInterval(fetchStats, refreshInterval);
        return () => clearInterval(interval);
    }, [service, refreshInterval]);

    if (loading) {
        return (
            <div className="grid gap-6 lg:grid-cols-2">
                <div className="h-80 animate-pulse rounded-xl border border-border/50 bg-muted/30" />
                <div className="h-80 animate-pulse rounded-xl border border-border/50 bg-muted/30" />
            </div>
        );
    }

    if (!stats) return null;

    // Prepare risk distribution data
    const riskData = Object.entries(stats.risk_distribution).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: RISK_COLORS[name as keyof typeof RISK_COLORS] || '#6b7280',
    }));

    // Prepare attack type distribution data
    const attackTypeData = Object.entries(stats.attack_type_distribution)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([name, value], index) => ({
            name: name.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
            value,
            fill: ATTACK_TYPE_COLORS[index % ATTACK_TYPE_COLORS.length],
        }));

    return (
        <div className="grid gap-6 lg:grid-cols-2">
            {/* Risk Distribution Pie Chart */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-border/50 bg-card/50 backdrop-blur-sm p-6"
            >
                <div className="flex items-center gap-2 mb-6">
                    <IconChartPie className="h-5 w-5 text-primary" />
                    <h3 className="font-semibold">Risk Level Distribution</h3>
                </div>

                {riskData.reduce((sum, d) => sum + d.value, 0) === 0 ? (
                    <div className="h-64 flex items-center justify-center text-muted-foreground">
                        No risk data available
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                            <Pie
                                data={riskData}
                                cx="50%"
                                cy="50%"
                                innerRadius={60}
                                outerRadius={100}
                                paddingAngle={4}
                                dataKey="value"
                                label
                                nameKey="name"
                                labelLine
                            >
                                {riskData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'hsl(var(--card))',
                                    border: '1px solid hsl(var(--border))',
                                    borderRadius: '8px',
                                }}
                            />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                )}
            </motion.div>

            {/* Attack Types Bar Chart */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="rounded-xl border border-border/50 bg-card/50 backdrop-blur-sm p-6"
            >
                <div className="flex items-center gap-2 mb-6">
                    <IconChartBar className="h-5 w-5 text-primary" />
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
                            <XAxis type="number" tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} />
                            <YAxis
                                dataKey="name"
                                type="category"
                                width={120}
                                tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
                            />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'hsl(var(--card))',
                                    border: '1px solid hsl(var(--border))',
                                    borderRadius: '8px',
                                }}
                            />
                            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                {attackTypeData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={entry.fill} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </motion.div>
        </div>
    );
}

export default MLMetricsCharts;
