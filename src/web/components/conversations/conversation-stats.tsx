"use client";

import { Badge } from "@/components/ui/badge";
import {
    Activity,
    MessageSquare,
    ShieldAlert,
    Users
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
        <div className="flex-shrink-0 grid grid-cols-2 md:grid-cols-4 gap-3 p-3 bg-gradient-to-r from-card/60 to-card/40 border-b border-border/50">
            {/* Total Sessions */}
            <div className="flex items-center gap-3 p-3 bg-gradient-to-br from-primary/10 to-primary/5 border border-primary/20">
                <div className="p-2.5 bg-gradient-to-br from-primary/25 to-primary/15">
                    <Users className="h-4 w-4 text-primary" />
                </div>
                <div>
                    <p className="text-2xl font-bold tracking-tight text-primary">{stats.totalSessions}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Sessions</p>
                </div>
            </div>

            {/* Active Sessions */}
            <div className="flex items-center gap-3 p-3 bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20">
                <div className="p-2.5 bg-gradient-to-br from-emerald-500/25 to-emerald-500/15 relative">
                    <Activity className="h-4 w-4 text-emerald-500" />
                    {isConnected && <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 border-2 border-card" />}
                </div>
                <div>
                    <p className="text-2xl font-bold tracking-tight text-emerald-600 dark:text-emerald-400">{stats.activeSessions}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Active</p>
                </div>
            </div>

            {/* Total Messages */}
            <div className="flex items-center gap-3 p-3 bg-gradient-to-br from-blue-500/10 to-blue-500/5 border border-blue-500/20">
                <div className="p-2.5 bg-gradient-to-br from-blue-500/25 to-blue-500/15">
                    <MessageSquare className="h-4 w-4 text-blue-500" />
                </div>
                <div>
                    <p className="text-2xl font-bold tracking-tight text-blue-600 dark:text-blue-400">{stats.totalMessages}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Messages</p>
                </div>
            </div>

            {/* Threats */}
            <div className={cn(
                "flex items-center gap-3 p-3 border transition-all",
                stats.threatsDetected > 0
                    ? "bg-gradient-to-br from-rose-500/15 to-rose-500/5 border-rose-500/30"
                    : "bg-gradient-to-br from-muted/30 to-muted/10 border-border/50"
            )}>
                <div className={cn(
                    "p-2.5",
                    stats.threatsDetected > 0
                        ? "bg-gradient-to-br from-rose-500/30 to-rose-500/20"
                        : "bg-gradient-to-br from-muted/50 to-muted/30"
                )}>
                    <ShieldAlert className={cn("h-4 w-4", stats.threatsDetected > 0 ? "text-rose-500" : "text-muted-foreground")} />
                </div>
                <div>
                    <p className={cn(
                        "text-2xl font-bold tracking-tight",
                        stats.threatsDetected > 0 ? "text-rose-600 dark:text-rose-400" : "text-muted-foreground"
                    )}>{stats.threatsDetected}</p>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Threats</p>
                </div>
            </div>
        </div>
    );
}
