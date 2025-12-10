"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, ShieldAlert, Wifi, Globe, Server, AlertTriangle, Zap, Radio } from "lucide-react";
import { AreaChart, Area, ResponsiveContainer } from "recharts";
import { LogEntry } from "@/types/api";
import { useMemo } from "react";

interface StatsCardsProps {
    logs: LogEntry[];
    isConnected: boolean;
}

// Generate sparkline data from logs
function generateSparklineData(logs: LogEntry[], minutes: number = 30): { value: number }[] {
    const now = Date.now();
    const bucketSize = (minutes * 60 * 1000) / 12; // 12 data points
    const buckets = Array(12).fill(0);

    logs.forEach(log => {
        const logTime = new Date(log.timestamp).getTime();
        const age = now - logTime;
        if (age < minutes * 60 * 1000) {
            const bucketIndex = Math.min(11, Math.floor(age / bucketSize));
            buckets[11 - bucketIndex]++;
        }
    });

    return buckets.map(value => ({ value }));
}

export function StatsCards({ logs, isConnected }: StatsCardsProps) {
    const stats = useMemo(() => {
        const total = logs.length;

        // Count criticals: severity high/critical, or judgement MALICIOUS, or level ERROR/CRITICAL
        const criticals = logs.filter(l => {
            const sev = (l.severity || '').toLowerCase();
            if (sev === 'critical' || sev === 'high') return true;
            if ((l as any).judgement === 'MALICIOUS') return true;
            const level = (l.level || '').toUpperCase();
            return level === 'CRITICAL' || level === 'ERROR';
        }).length;

        // Count warnings: severity medium, or has attack_types, or level WARNING
        const warnings = logs.filter(l => {
            // Exclude items already counted as critical
            const sev = (l.severity || '').toLowerCase();
            if (sev === 'critical' || sev === 'high') return false;
            if ((l as any).judgement === 'MALICIOUS') return false;
            const level = (l.level || '').toUpperCase();
            if (level === 'CRITICAL' || level === 'ERROR') return false;

            if (sev === 'medium') return true;
            if (l.attack_types && l.attack_types.length > 0) return true;
            return level === 'WARNING';
        }).length;

        // Unique sensors
        const sensors = new Set(logs.map(l => l.sensor_name).filter(Boolean));
        const activeSensors = sensors.size;

        // Unique IPs
        const ips = new Set(logs.map(l => l.src_ip).filter(Boolean));
        const uniqueIPs = ips.size;

        // Protocol distribution
        const protocols: { [key: string]: number } = {};
        logs.forEach(l => {
            const proto = l.sensor_protocol?.toUpperCase() || 'UNKNOWN';
            protocols[proto] = (protocols[proto] || 0) + 1;
        });

        return { total, criticals, warnings, activeSensors, uniqueIPs, protocols };
    }, [logs]);

    const sparklineData = useMemo(() => generateSparklineData(logs), [logs]);
    const criticalSparkline = useMemo(() =>
        generateSparklineData(logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR')),
        [logs]
    );

    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {/* Total Events */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5">
                <div className="absolute inset-0 opacity-30">
                    <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={sparklineData}>
                            <defs>
                                <linearGradient id="totalGradient" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.4} />
                                    <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <Area
                                type="monotone"
                                dataKey="value"
                                stroke="hsl(var(--primary))"
                                strokeWidth={1.5}
                                fill="url(#totalGradient)"
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Total Events</CardTitle>
                    <div className="flex items-center gap-2">
                        {isConnected && (
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                            </span>
                        )}
                        <Activity className="h-4 w-4 text-muted-foreground" />
                    </div>
                </CardHeader>
                <CardContent className="relative">
                    <div className="text-3xl font-bold tracking-tight">{stats.total.toLocaleString()}</div>
                    <p className="text-xs text-muted-foreground mt-1">
                        Events in current session
                    </p>
                </CardContent>
            </Card>

            {/* Critical Threats */}
            <Card className={`relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 ${stats.criticals > 0 ? 'ring-1 ring-rose-500/20' : ''}`}>
                <div className="absolute inset-0 opacity-30">
                    <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={criticalSparkline}>
                            <defs>
                                <linearGradient id="criticalGradient" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.4} />
                                    <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <Area
                                type="monotone"
                                dataKey="value"
                                stroke="#f43f5e"
                                strokeWidth={1.5}
                                fill="url(#criticalGradient)"
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className={`text-sm font-medium ${stats.criticals > 0 ? 'text-rose-500' : ''}`}>
                        Critical Threats
                    </CardTitle>
                    <ShieldAlert className={`h-4 w-4 ${stats.criticals > 0 ? 'text-rose-500 animate-pulse' : 'text-muted-foreground'}`} />
                </CardHeader>
                <CardContent className="relative">
                    <div className={`text-3xl font-bold tracking-tight ${stats.criticals > 0 ? 'text-rose-500' : 'text-muted-foreground'}`}>
                        {stats.criticals}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                        Requires immediate attention
                    </p>
                </CardContent>
            </Card>

            {/* Warnings */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5">
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className={`text-sm font-medium ${stats.warnings > 0 ? 'text-amber-500' : ''}`}>
                        Warnings
                    </CardTitle>
                    <Zap className={`h-4 w-4 ${stats.warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}`} />
                </CardHeader>
                <CardContent className="relative">
                    <div className={`text-3xl font-bold tracking-tight ${stats.warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}`}>
                        {stats.warnings}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                        Suspicious activities
                    </p>
                </CardContent>
            </Card>

            {/* Active Sensors */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5">
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Active Sensors</CardTitle>
                    <Radio className="h-4 w-4 text-emerald-500" />
                </CardHeader>
                <CardContent className="relative">
                    <div className="text-3xl font-bold tracking-tight text-emerald-500">
                        {stats.activeSensors}
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                        {Object.entries(stats.protocols).slice(0, 3).map(([proto, count]) => (
                            <Badge key={proto} variant="outline" className="text-[10px] px-1.5 py-0 h-5 bg-muted/50">
                                {proto}: {count}
                            </Badge>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
