"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    Activity, ShieldAlert, Zap, Radio, Globe, Terminal,
    Users, Lock, Unlock, Command, AlertCircle, Skull
} from "lucide-react";
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

// Derive effective level from log entry (same logic as attack-table)
function getEffectiveLevel(log: LogEntry): string {
    if (log.severity) {
        const sev = log.severity.toLowerCase();
        if (sev === 'critical' || sev === 'high') return 'CRITICAL';
        if (sev === 'medium') return 'WARNING';
    }
    if ((log as any).judgement === 'MALICIOUS') return 'CRITICAL';
    if (log.attack_types && log.attack_types.length > 0) return 'WARNING';
    const level = log.level?.toUpperCase();
    if (level === 'CRITICAL' || level === 'ERROR') return 'CRITICAL';
    if (level === 'WARNING') return 'WARNING';
    return 'INFO';
}

export function StatsCards({ logs, isConnected }: StatsCardsProps) {
    const stats = useMemo(() => {
        const total = logs.length;

        // Count by effective level
        const criticals = logs.filter(l => getEffectiveLevel(l) === 'CRITICAL').length;
        const warnings = logs.filter(l => getEffectiveLevel(l) === 'WARNING').length;

        // Unique sensors
        const sensors = new Set(logs.map(l => l.sensor_name).filter(Boolean));
        const activeSensors = sensors.size;

        // Unique IPs
        const ips = new Set(logs.map(l => l.src_ip).filter((ip): ip is string => !!ip && ip !== '-'));
        const uniqueIPs = ips.size;

        // Protocol distribution
        const protocols: { [key: string]: number } = {};
        logs.forEach(l => {
            const proto = l.sensor_protocol?.toUpperCase() || 'UNKNOWN';
            protocols[proto] = (protocols[proto] || 0) + 1;
        });

        // Sessions with MALICIOUS judgement
        const maliciousSessions = logs.filter(l => (l as any).judgement === 'MALICIOUS').length;

        // Commands executed (User input messages)
        const commandsExecuted = logs.filter(l =>
            l.message === 'User input' && l.command
        ).length;

        // Authentication attempts
        const authAttempts = logs.filter(l =>
            l.message?.includes('authenticate') ||
            l.message?.includes('Authentication')
        ).length;

        const authSuccess = logs.filter(l =>
            l.message === 'Authentication success'
        ).length;

        const authFailed = logs.filter(l =>
            l.message === 'Authentication failed'
        ).length;

        // Unique users
        const users = new Set(logs.map(l => l.username).filter((u): u is string => !!u && u !== '-'));
        const uniqueUsers = users.size;

        // Connections per protocol
        const connections = logs.filter(l =>
            l.message?.includes('connection received') ||
            l.message?.includes('Connection received')
        ).length;

        return {
            total, criticals, warnings, activeSensors, uniqueIPs, protocols,
            maliciousSessions, commandsExecuted, authAttempts, authSuccess, authFailed,
            uniqueUsers, connections
        };
    }, [logs]);

    const sparklineData = useMemo(() => generateSparklineData(logs), [logs]);
    const criticalSparkline = useMemo(() =>
        generateSparklineData(logs.filter(l => getEffectiveLevel(l) === 'CRITICAL')),
        [logs]
    );

    return (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
            {/* Total Events */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none">
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
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className="text-xs font-medium">Total Events</CardTitle>
                    <div className="flex items-center gap-2">
                        {isConnected && (
                            <span className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                            </span>
                        )}
                        <Activity className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className="text-2xl font-bold tracking-tight">{stats.total.toLocaleString()}</div>
                    <p className="text-[10px] text-muted-foreground">
                        {stats.connections} connections
                    </p>
                </CardContent>
            </Card>

            {/* Critical Threats */}
            <Card className={`relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none ${stats.criticals > 0 ? 'ring-1 ring-rose-500/20' : ''}`}>
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
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className={`text-xs font-medium ${stats.criticals > 0 ? 'text-rose-500' : ''}`}>
                        Critical Threats
                    </CardTitle>
                    <ShieldAlert className={`h-3.5 w-3.5 ${stats.criticals > 0 ? 'text-rose-500 animate-pulse' : 'text-muted-foreground'}`} />
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className={`text-2xl font-bold tracking-tight ${stats.criticals > 0 ? 'text-rose-500' : 'text-muted-foreground'}`}>
                        {stats.criticals}
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                        {stats.maliciousSessions} malicious sessions
                    </p>
                </CardContent>
            </Card>

            {/* Warnings */}
            <Card className={`relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none ${stats.warnings > 0 ? 'ring-1 ring-amber-500/20' : ''}`}>
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className={`text-xs font-medium ${stats.warnings > 0 ? 'text-amber-500' : ''}`}>
                        Warnings
                    </CardTitle>
                    <Zap className={`h-3.5 w-3.5 ${stats.warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}`} />
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className={`text-2xl font-bold tracking-tight ${stats.warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}`}>
                        {stats.warnings}
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                        Suspicious activities
                    </p>
                </CardContent>
            </Card>

            {/* Authentication */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none">
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className="text-xs font-medium">Authentication</CardTitle>
                    <Lock className="h-3.5 w-3.5 text-cyan-500" />
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className="text-2xl font-bold tracking-tight text-cyan-500">
                        {stats.authAttempts}
                    </div>
                    <div className="flex gap-2 text-[10px] text-muted-foreground">
                        <span className="text-emerald-500">{stats.authSuccess} ✓</span>
                        <span className="text-rose-500">{stats.authFailed} ✗</span>
                    </div>
                </CardContent>
            </Card>

            {/* Commands Executed */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none">
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className="text-xs font-medium">Commands</CardTitle>
                    <Terminal className="h-3.5 w-3.5 text-purple-500" />
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className="text-2xl font-bold tracking-tight text-purple-500">
                        {stats.commandsExecuted}
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                        User commands captured
                    </p>
                </CardContent>
            </Card>

            {/* Unique IPs */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none">
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className="text-xs font-medium">Unique IPs</CardTitle>
                    <Globe className="h-3.5 w-3.5 text-blue-500" />
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className="text-2xl font-bold tracking-tight text-blue-500">
                        {stats.uniqueIPs}
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                        {stats.uniqueUsers} unique users
                    </p>
                </CardContent>
            </Card>

            {/* Active Sensors */}
            <Card className="relative overflow-hidden bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5 rounded-none lg:col-span-2 xl:col-span-6">
                <CardHeader className="relative flex flex-row items-center justify-between space-y-0 pb-1">
                    <CardTitle className="text-xs font-medium">Active Sensors</CardTitle>
                    <Radio className="h-3.5 w-3.5 text-emerald-500" />
                </CardHeader>
                <CardContent className="relative pt-0">
                    <div className="flex items-center gap-4">
                        <div className="text-2xl font-bold tracking-tight text-emerald-500">
                            {stats.activeSensors}
                        </div>
                        <div className="flex flex-wrap gap-1">
                            {Object.entries(stats.protocols).map(([proto, count]) => (
                                <Badge key={proto} variant="outline" className="text-[10px] px-1.5 py-0 h-5 bg-muted/50 rounded-none font-mono">
                                    {proto}: {count}
                                </Badge>
                            ))}
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
