"use client";

import { useMemo } from "react";
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
    Clock,
    MessageSquare
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

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

    // Less than 1 minute
    if (diff < 60000) return 'Just now';
    // Less than 1 hour
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    // Less than 24 hours
    if (diff < 86400000) return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    // More than 24 hours
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function getLastMessage(session: ConversationSession): string {
    if (session.messages.length === 0) return 'No messages';
    const last = session.messages[session.messages.length - 1];
    const content = last.content || last.command || 'System message';
    return content.length > 50 ? content.slice(0, 50) + '...' : content;
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
        <div className="flex flex-col h-full overflow-hidden bg-card/50 backdrop-blur-xl border-r border-white/10 dark:border-white/5">
            {/* Header */}
            <div className="p-4 border-b border-white/10 dark:border-white/5">
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-lg font-bold tracking-tight">Sessions</h2>
                    <div className="flex items-center gap-2">
                        {isConnected && (
                            <span className="relative flex h-2 w-2">
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                            </span>
                        )}
                        <Badge variant="outline" className="text-[10px] px-1.5 rounded-none">
                            {sessions.length}
                        </Badge>
                    </div>
                </div>

                {/* Search */}
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search sessions..."
                        value={searchQuery}
                        onChange={(e) => onSearchChange(e.target.value)}
                        className="pl-9 h-9 bg-muted/30 rounded-none border-white/10 focus:border-primary/50"
                    />
                </div>
            </div>

            {/* Session List */}
            <div className="flex-1 overflow-y-auto">
                <div className="p-2">
                    <AnimatePresence mode="popLayout">
                        {sessions.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-12 text-center px-4">
                                <div className="p-4 bg-muted/30 rounded-full mb-4">
                                    <MessageSquare className="h-8 w-8 text-muted-foreground" />
                                </div>
                                <p className="text-sm text-muted-foreground">No sessions yet</p>
                                <p className="text-xs text-muted-foreground/60 mt-1">Waiting for connections...</p>
                            </div>
                        ) : (
                            sessions.map((session, index) => (
                                <motion.div
                                    key={session.id}
                                    initial={{ opacity: 0, x: -20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, x: -20 }}
                                    transition={{ duration: 0.2, delay: index * 0.02 }}
                                >
                                    <button
                                        onClick={() => onSelectSession(session.id)}
                                        className={cn(
                                            "w-full p-3 mb-1 text-left rounded-none transition-all duration-200",
                                            "hover:bg-white/5 dark:hover:bg-white/5",
                                            "border border-transparent",
                                            selectedSessionId === session.id
                                                ? "bg-primary/10 border-primary/30 hover:bg-primary/15"
                                                : "bg-transparent"
                                        )}
                                    >
                                        <div className="flex items-start gap-3">
                                            {/* Protocol Avatar */}
                                            <div className={cn(
                                                "flex items-center justify-center w-10 h-10 rounded-none border",
                                                getProtocolColor(session.protocol),
                                                "relative"
                                            )}>
                                                {getProtocolIcon(session.protocol)}
                                                {/* Severity indicator dot */}
                                                {session.hasThreats && (
                                                    <span className={cn(
                                                        "absolute -top-1 -right-1 w-3 h-3 rounded-full",
                                                        getSeverityIndicator(session.maxSeverity)
                                                    )} />
                                                )}
                                            </div>

                                            {/* Content */}
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center justify-between gap-2">
                                                    <span className="font-mono text-sm font-medium text-emerald-500 truncate">
                                                        {session.src_ip}
                                                    </span>
                                                    <span className="text-[10px] text-muted-foreground flex-shrink-0">
                                                        {formatTime(session.lastActivity)}
                                                    </span>
                                                </div>

                                                <div className="flex items-center gap-2 mt-0.5">
                                                    {session.username && (
                                                        <span className="text-xs text-muted-foreground">
                                                            @{session.username}
                                                        </span>
                                                    )}
                                                    <Badge
                                                        variant="outline"
                                                        className="text-[9px] px-1 py-0 h-4 rounded-none uppercase"
                                                    >
                                                        {session.protocol}
                                                    </Badge>
                                                </div>

                                                <p className="text-xs text-muted-foreground/80 truncate mt-1">
                                                    {getLastMessage(session)}
                                                </p>

                                                {/* Bottom row with stats */}
                                                <div className="flex items-center gap-2 mt-2">
                                                    <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                                                        <MessageSquare className="h-3 w-3" />
                                                        {session.messageCount}
                                                    </span>
                                                    {session.hasThreats && (
                                                        <span className="flex items-center gap-1 text-[10px] text-rose-500">
                                                            <ShieldAlert className="h-3 w-3" />
                                                            {session.attackTypes.length}
                                                        </span>
                                                    )}
                                                    {session.isActive && (
                                                        <Badge className="text-[9px] px-1 py-0 h-4 rounded-none bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                                                            ACTIVE
                                                        </Badge>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    </button>
                                </motion.div>
                            ))
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
}
