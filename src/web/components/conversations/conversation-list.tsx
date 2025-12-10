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
    MessageSquare
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
        case 'ssh': return <Terminal className="h-4 w-4" />;
        case 'ftp': return <FolderOpen className="h-4 w-4" />;
        case 'mysql': return <Database className="h-4 w-4" />;
        default: return <Network className="h-4 w-4" />;
    }
}

function getProtocolColor(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return 'bg-sky-500/20 text-sky-400 border-sky-500/30';
        case 'ftp': return 'bg-violet-500/20 text-violet-400 border-violet-500/30';
        case 'mysql': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
        default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
}

function getSeverityIndicator(severity?: string) {
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
    if (session.messages.length === 0) return 'No messages';
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
        <div className="flex flex-col h-full bg-card/50">
            {/* Header */}
            <div className="flex-shrink-0 p-3 border-b border-border">
                <div className="flex items-center justify-between mb-2">
                    <h2 className="text-sm font-bold">Sessions</h2>
                    <div className="flex items-center gap-2">
                        {isConnected && (
                            <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
                        )}
                        <Badge variant="outline" className="text-[10px] px-1.5">
                            {sessions.length}
                        </Badge>
                    </div>
                </div>

                {/* Search */}
                <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input
                        placeholder="Search sessions..."
                        value={searchQuery}
                        onChange={(e) => onSearchChange(e.target.value)}
                        className="pl-8 h-8 text-sm bg-muted/30"
                    />
                </div>
            </div>

            {/* Session List - Scrollable */}
            <div className="flex-1 overflow-y-auto">
                <div className="p-2">
                    {sessions.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-8 text-center px-4">
                            <div className="p-3 bg-muted/30 rounded-full mb-3">
                                <MessageSquare className="h-6 w-6 text-muted-foreground" />
                            </div>
                            <p className="text-sm text-muted-foreground">No sessions yet</p>
                            <p className="text-xs text-muted-foreground/60 mt-1">Waiting for connections...</p>
                        </div>
                    ) : (
                        sessions.map((session) => (
                            <button
                                key={session.id}
                                onClick={() => onSelectSession(session.id)}
                                className={cn(
                                    "w-full p-3 mb-1 text-left transition-colors",
                                    "hover:bg-muted/50",
                                    "border border-transparent",
                                    selectedSessionId === session.id
                                        ? "bg-primary/10 border-primary/30"
                                        : "bg-transparent"
                                )}
                            >
                                <div className="flex items-start gap-2">
                                    {/* Protocol Avatar */}
                                    <div className={cn(
                                        "flex-shrink-0 flex items-center justify-center w-9 h-9 border relative",
                                        getProtocolColor(session.protocol)
                                    )}>
                                        {getProtocolIcon(session.protocol)}
                                        {session.hasThreats && (
                                            <span className={cn(
                                                "absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full",
                                                getSeverityIndicator(session.maxSeverity)
                                            )} />
                                        )}
                                    </div>

                                    {/* Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center justify-between gap-1">
                                            <span className="font-mono text-sm font-medium text-emerald-500 truncate">
                                                {session.src_ip}
                                            </span>
                                            <span className="text-[10px] text-muted-foreground flex-shrink-0">
                                                {formatTime(session.lastActivity)}
                                            </span>
                                        </div>

                                        <div className="flex items-center gap-1.5 mt-0.5">
                                            {session.username && (
                                                <span className="text-xs text-muted-foreground truncate">
                                                    @{session.username}
                                                </span>
                                            )}
                                            <Badge variant="outline" className="text-[9px] px-1 py-0 uppercase">
                                                {session.protocol}
                                            </Badge>
                                        </div>

                                        <p className="text-xs text-muted-foreground/70 truncate mt-1">
                                            {getLastMessage(session)}
                                        </p>

                                        {/* Stats row */}
                                        <div className="flex items-center gap-2 mt-1.5">
                                            <span className="flex items-center gap-0.5 text-[10px] text-muted-foreground">
                                                <MessageSquare className="h-3 w-3" />
                                                {session.messageCount}
                                            </span>
                                            {session.hasThreats && (
                                                <span className="flex items-center gap-0.5 text-[10px] text-rose-500">
                                                    <ShieldAlert className="h-3 w-3" />
                                                    {session.attackTypes.length}
                                                </span>
                                            )}
                                            {session.isActive && (
                                                <Badge className="text-[9px] px-1 py-0 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                                                    ACTIVE
                                                </Badge>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </button>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}
