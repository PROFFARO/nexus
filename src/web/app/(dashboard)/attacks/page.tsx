"use client"

import { useRealtimeAttacks } from "@/hooks/use-realtime"
import { AttackTable } from "@/components/attacks/attack-table"
import { StatsCards } from "@/components/attacks/stats-cards"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
    Activity,
    ShieldAlert,
    Zap,
    Radio,
    Globe,
    Terminal
} from "lucide-react"
import { useMemo } from "react"

export default function AttacksPage() {
    const { logs, isConnected } = useRealtimeAttacks()

    // Calculate top IPs
    const topIPs = useMemo(() => {
        const ipCounts: { [key: string]: number } = {}
        logs.forEach(log => {
            if (log.src_ip) {
                ipCounts[log.src_ip] = (ipCounts[log.src_ip] || 0) + 1
            }
        })
        return Object.entries(ipCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 5)
    }, [logs])

    // Protocol distribution
    const protocolDist = useMemo(() => {
        const dist: { [key: string]: number } = {}
        logs.forEach(log => {
            const proto = log.sensor_protocol?.toUpperCase() || 'UNKNOWN'
            dist[proto] = (dist[proto] || 0) + 1
        })
        return Object.entries(dist).sort(([, a], [, b]) => b - a)
    }, [logs])

    return (
        <div className="h-full w-full p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="space-y-1">
                    <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text">
                        Live Attacks
                    </h1>
                    <p className="text-muted-foreground">
                        Real-time surveillance of honeypot sensors
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    <Badge
                        variant={isConnected ? "default" : "destructive"}
                        className={`px-3 py-1.5 text-xs font-semibold ${isConnected ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30' : ''}`}
                    >
                        <span className="relative flex h-2 w-2 mr-2">
                            {isConnected && (
                                <>
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                                </>
                            )}
                            {!isConnected && (
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
                            )}
                        </span>
                        {isConnected ? "LIVE STREAM" : "DISCONNECTED"}
                    </Badge>
                </div>
            </div>

            {/* Stats Cards */}
            <StatsCards logs={logs} isConnected={isConnected} />

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                {/* Attack Feed - Takes 3 columns */}
                <Card className="lg:col-span-3 bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5">
                    <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="flex items-center gap-2">
                                    <Terminal className="h-4 w-4" />
                                    Attack Feed
                                </CardTitle>
                                <CardDescription>
                                    {logs.length} events captured
                                </CardDescription>
                            </div>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <ScrollArea className="h-[calc(100vh-420px)]">
                            <AttackTable logs={logs} />
                        </ScrollArea>
                    </CardContent>
                </Card>

                {/* Sidebar - Takes 1 column */}
                <div className="space-y-4">
                    {/* Top IPs */}
                    <Card className="bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5">
                        <CardHeader className="pb-3">
                            <CardTitle className="text-sm flex items-center gap-2">
                                <Globe className="h-4 w-4 text-blue-500" />
                                Top Source IPs
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2">
                            {topIPs.length === 0 ? (
                                <p className="text-xs text-muted-foreground">No data yet</p>
                            ) : (
                                topIPs.map(([ip, count], i) => (
                                    <div key={ip} className="flex items-center justify-between py-1.5 px-2 bg-muted/30 rounded">
                                        <span className="font-mono text-xs text-emerald-500">{ip}</span>
                                        <Badge variant="outline" className="text-[10px] px-1.5 h-5">
                                            {count}
                                        </Badge>
                                    </div>
                                ))
                            )}
                        </CardContent>
                    </Card>

                    {/* Protocol Distribution */}
                    <Card className="bg-card/60 backdrop-blur-xl border-white/10 dark:border-white/5">
                        <CardHeader className="pb-3">
                            <CardTitle className="text-sm flex items-center gap-2">
                                <Radio className="h-4 w-4 text-purple-500" />
                                Protocol Activity
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2">
                            {protocolDist.length === 0 ? (
                                <p className="text-xs text-muted-foreground">No data yet</p>
                            ) : (
                                protocolDist.map(([proto, count]) => {
                                    const total = logs.length || 1
                                    const pct = Math.round((count / total) * 100)
                                    return (
                                        <div key={proto} className="space-y-1">
                                            <div className="flex items-center justify-between text-xs">
                                                <span className="font-medium">{proto}</span>
                                                <span className="text-muted-foreground">{pct}%</span>
                                            </div>
                                            <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-gradient-to-r from-primary to-primary/50 rounded-full transition-all duration-500"
                                                    style={{ width: `${pct}%` }}
                                                />
                                            </div>
                                        </div>
                                    )
                                })
                            )}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    )
}