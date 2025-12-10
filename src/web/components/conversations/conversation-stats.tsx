"use client";

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    Activity,
    MessageSquare,
    ShieldAlert,
    Users,
    Zap
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ConversationStatsProps {
    stats: {
        totalSessions: number;
        activeSessions: number;
        totalMessages: number;
        threatsDetected: number;
    };
    isConnected: boolean;
}

export function ConversationStats({ stats, isConnected }: ConversationStatsProps) {
    return (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-4 bg-card/50 backdrop-blur-xl border-b border-white/10 dark:border-white/5">
            {/* Total Sessions */}
            <div className="flex items-center gap-3 p-3 bg-muted/30 rounded-none border border-white/5">
                <div className="p-2 bg-primary/20 rounded-none">
                    <Users className="h-4 w-4 text-primary" />
                </div>
                <div>
                    <p className="text-2xl font-bold tracking-tight">{stats.totalSessions}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Sessions</p>
                </div>
            </div>

            {/* Active Sessions */}
            <div className="flex items-center gap-3 p-3 bg-muted/30 rounded-none border border-white/5">
                <div className="p-2 bg-emerald-500/20 rounded-none relative">
                    <Activity className="h-4 w-4 text-emerald-500" />
                    {isConnected && (
                        <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                    )}
                </div>
                <div>
                    <p className="text-2xl font-bold tracking-tight text-emerald-500">{stats.activeSessions}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Active</p>
                </div>
            </div>

            {/* Total Messages */}
            <div className="flex items-center gap-3 p-3 bg-muted/30 rounded-none border border-white/5">
                <div className="p-2 bg-blue-500/20 rounded-none">
                    <MessageSquare className="h-4 w-4 text-blue-500" />
                </div>
                <div>
                    <p className="text-2xl font-bold tracking-tight text-blue-500">{stats.totalMessages}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Messages</p>
                </div>
            </div>

            {/* Threats Detected */}
            <div className={cn(
                "flex items-center gap-3 p-3 bg-muted/30 rounded-none border",
                stats.threatsDetected > 0 ? "border-rose-500/30" : "border-white/5"
            )}>
                <div className={cn(
                    "p-2 rounded-none",
                    stats.threatsDetected > 0
                        ? "bg-rose-500/20"
                        : "bg-muted/50"
                )}>
                    <ShieldAlert className={cn(
                        "h-4 w-4",
                        stats.threatsDetected > 0
                            ? "text-rose-500"
                            : "text-muted-foreground"
                    )} />
                </div>
                <div>
                    <p className={cn(
                        "text-2xl font-bold tracking-tight",
                        stats.threatsDetected > 0
                            ? "text-rose-500"
                            : "text-muted-foreground"
                    )}>
                        {stats.threatsDetected}
                    </p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Threats</p>
                </div>
            </div>
        </div>
    );
}
