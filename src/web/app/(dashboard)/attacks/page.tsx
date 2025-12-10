"use client"

import { useRealtimeAttacks } from "@/hooks/use-realtime"
import { AttackTable } from "@/components/attacks/attack-table"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Activity, ShieldAlert, Zap } from "lucide-react"

export default function AttacksPage() {
    const { logs, isConnected } = useRealtimeAttacks()

    // Calculate stats on the fly
    const totalAttacks = logs.length
    const criticals = logs.filter(l => l.level === 'CRITICAL' || l.level === 'ERROR').length
    const warnings = logs.filter(l => l.level === 'WARNING').length

    return (
        <div className="h-full w-full p-6 space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Live Attacks</h1>
                    <p className="text-muted-foreground">Real-time surveillance of honeypot sensors.</p>
                </div>
                <div className="flex items-center gap-2">
                    <Badge variant={isConnected ? "default" : "destructive"} className="animate-pulse">
                        {isConnected ? "LIVE STREAM ACTIVE" : "DISCONNECTED"}
                    </Badge>
                </div>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Events</CardTitle>
                        <Activity className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{totalAttacks}</div>
                        <p className="text-xs text-muted-foreground">
                            Events in current session
                        </p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Critical Threats</CardTitle>
                        <ShieldAlert className="h-4 w-4 text-destructive" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-destructive">{criticals}</div>
                        <p className="text-xs text-muted-foreground">
                            Requires immediate attention
                        </p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Warnings</CardTitle>
                        <Zap className="h-4 w-4 text-yellow-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-yellow-500">{warnings}</div>
                        <p className="text-xs text-muted-foreground">
                            Suspicious activities
                        </p>
                    </CardContent>
                </Card>
            </div>

            <Card className="h-[calc(100vh-300px)]">
                <CardHeader>
                    <CardTitle>Attack Feed</CardTitle>
                </CardHeader>
                <CardContent className="h-full overflow-auto">
                    <AttackTable logs={logs} />
                </CardContent>
            </Card>
        </div>
    )
}