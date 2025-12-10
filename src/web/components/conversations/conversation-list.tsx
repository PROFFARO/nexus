"use client";

import { ConversationSession } from "@/types/conversation";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
    Terminal,
    FolderOpen,
    Database,
    Network,
    Search,
    ShieldAlert,
    MessageSquare,
    Clock,
    User
} from "lucide-react";

interface ConversationListProps {
    sessions: ConversationSession[];
    selectedSessionId: string | null;
    onSelectSession: (id: string) => void;
    searchQuery: string;
    onSearchChange: (query: string) => void;
    isConnected: boolean;
}

function getProtocolIcon(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return <Terminal className="h-5 w-5" />;
        case 'ftp': return <FolderOpen className="h-5 w-5" />;
        case 'mysql': return <Database className="h-5 w-5" />;
        default: return <Network className="h-5 w-5" />;
    }
}

function getProtocolStyle(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return {
            bg: 'bg-gradient-to-br from-sky-500/25 to-sky-600/15',
            border: 'border-sky-500/40',
            text: 'text-sky-600 dark:text-sky-400',
            badge: 'bg-sky-500/20 text-sky-700 dark:text-sky-400 border-sky-500/30'
        };
        case 'ftp': return {
            bg: 'bg-gradient-to-br from-violet-500/25 to-violet-600/15',
            border: 'border-violet-500/40',
            text: 'text-violet-600 dark:text-violet-400',
            badge: 'bg-violet-500/20 text-violet-700 dark:text-violet-400 border-violet-500/30'
        };
        case 'mysql': return {
            bg: 'bg-gradient-to-br from-amber-500/25 to-amber-600/15',
            border: 'border-amber-500/40',
            text: 'text-amber-600 dark:text-amber-400',
            badge: 'bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-500/30'
        };
        default: return {
            bg: 'bg-gradient-to-br from-gray-500/25 to-gray-600/15',
            border: 'border-gray-500/40',
            text: 'text-gray-600 dark:text-gray-400',
            badge: 'bg-gray-500/20 text-gray-700 dark:text-gray-400 border-gray-500/30'
        };
    }
}

function getSeverityColor(severity?: string) {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'bg-rose-500';
        case 'high': return 'bg-orange-500';
        case 'medium': return 'bg-amber-500';
        case 'low': return 'bg-yellow-500';
        default: return '';
    }
}

function formatTime(timestamp: string): string {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function getLastMessage(session: ConversationSession): string {
    if (session.messages.length === 0) return 'No messages yet';
    const last = session.messages[session.messages.length - 1];
    const content = last.content || last.command || 'System message';
    return content.length > 40 ? content.slice(0, 40) + '...' : content;
}

export function ConversationList({
    sessions,
    selectedSessionId,
    onSelectSession,
    searchQuery,
    onSearchChange,
    isConnected
}: ConversationListProps) {
    return (
        <div className="flex flex-col h-full overflow-hidden">
            {/* Session List - No header, starts from top */}
            <div className="flex-1 overflow-y-auto">
                <div className="p-2 space-y-1">
                    {sessions.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12 text-center px-4">
                            <div className="p-5 bg-gradient-to-br from-muted/40 to-muted/20 mb-4 border border-border/30">
                                <MessageSquare className="h-8 w-8 text-muted-foreground" />
                            </div>
                            <p className="text-sm font-medium text-muted-foreground">No sessions yet</p>
                            <p className="text-xs text-muted-foreground/60 mt-1">Waiting for connections...</p>
                        </div>
                    ) : (
                        sessions.map((session) => {
                            const style = getProtocolStyle(session.protocol);
                            const isSelected = selectedSessionId === session.id;

                            return (
                                <button
                                    key={session.id}
                                    onClick={() => onSelectSession(session.id)}
                                    className={cn(
                                        "w-full p-3 text-left transition-all",
                                        "hover:bg-muted/50",
                                        "border-2",
                                        isSelected
                                            ? "bg-gradient-to-r from-primary/15 to-primary/5 border-primary/40"
                                            : "bg-card/50 border-transparent hover:border-border/50"
                                    )}
                                >
                                    <div className="flex items-start gap-3">
                                        {/* Protocol Avatar */}
                                        <div className={cn(
                                            "flex-shrink-0 flex items-center justify-center w-11 h-11 border-2 relative",
                                            style.bg, style.border, style.text
                                        )}>
                                            {getProtocolIcon(session.protocol)}
                                            {session.hasThreats && (
                                                <span className={cn(
                                                    "absolute -top-1 -right-1 w-3 h-3 border-2 border-card",
                                                    getSeverityColor(session.maxSeverity)
                                                )} />
                                            )}
                                        </div>

                                        {/* Content */}
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center justify-between gap-2 mb-1">
                                                <span className="font-mono text-sm font-bold text-emerald-600 dark:text-emerald-400 truncate">
                                                    {session.src_ip}
                                                </span>
                                                <span className="text-[11px] text-muted-foreground flex items-center gap-1 flex-shrink-0">
                                                    <Clock className="h-3 w-3" />
                                                    {formatTime(session.lastActivity)}
                                                </span>
                                            </div>

                                            <div className="flex items-center gap-2 mb-1.5">
                                                {session.username && (
                                                    <span className="flex items-center gap-1 text-xs text-muted-foreground">
                                                        <User className="h-3 w-3" />
                                                        {session.username}
                                                    </span>
                                                )}
                                                <Badge className={cn("text-[10px] px-2 py-0.5 uppercase font-bold rounded-none", style.badge)}>
                                                    {session.protocol}
                                                </Badge>
                                            </div>

                                            <p className="text-xs text-muted-foreground/70 truncate mb-2 font-mono">
                                                {getLastMessage(session)}
                                            </p>

                                            {/* Stats */}
                                            <div className="flex items-center gap-2">
                                                <span className="flex items-center gap-1 text-[10px] text-muted-foreground bg-muted/30 px-2 py-0.5">
                                                    <MessageSquare className="h-3 w-3" />
                                                    <span className="font-semibold">{session.messageCount}</span>
                                                </span>
                                                {session.hasThreats && (
                                                    <span className="flex items-center gap-1 text-[10px] text-rose-500 bg-rose-500/10 px-2 py-0.5">
                                                        <ShieldAlert className="h-3 w-3" />
                                                        <span className="font-semibold">{session.attackTypes.length}</span>
                                                    </span>
                                                )}
                                                {session.isActive && (
                                                    <Badge className="text-[10px] px-2 py-0.5 bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 font-bold rounded-none">
                                                        ACTIVE
                                                    </Badge>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </button>
                            );
                        })
                    )}
                </div>
            </div>
        </div>
    );
}
