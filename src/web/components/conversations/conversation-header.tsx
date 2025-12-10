"use client";

import { ConversationSession } from "@/types/conversation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
    Terminal,
    FolderOpen,
    Database,
    Network,
    Globe,
    User,
    Clock,
    Calendar,
    ShieldAlert,
    Download,
    Flag,
    MoreVertical,
    Copy,
    Check,
    ExternalLink,
    MessageSquare,
    Zap
} from "lucide-react";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { useState } from "react";

interface ConversationHeaderProps {
    session: ConversationSession | null;
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

function getSeverityBadge(severity?: string) {
    switch (severity?.toLowerCase()) {
        case 'critical':
            return <Badge className="rounded-none bg-rose-500/20 text-rose-400 border-rose-500/30">CRITICAL</Badge>;
        case 'high':
            return <Badge className="rounded-none bg-orange-500/20 text-orange-400 border-orange-500/30">HIGH</Badge>;
        case 'medium':
            return <Badge className="rounded-none bg-amber-500/20 text-amber-400 border-amber-500/30">MEDIUM</Badge>;
        case 'low':
            return <Badge className="rounded-none bg-yellow-500/20 text-yellow-400 border-yellow-500/30">LOW</Badge>;
        default:
            return null;
    }
}

function formatDuration(startTime: string): string {
    const start = new Date(startTime).getTime();
    const now = Date.now();
    const diff = now - start;

    const hours = Math.floor(diff / 3600000);
    const minutes = Math.floor((diff % 3600000) / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);

    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

export function ConversationHeader({ session }: ConversationHeaderProps) {
    const [copiedIP, setCopiedIP] = useState(false);

    if (!session) {
        return (
            <div className="h-16 border-b border-white/10 dark:border-white/5 bg-card/50 backdrop-blur-xl flex items-center justify-center">
                <span className="text-sm text-muted-foreground">Select a session to view details</span>
            </div>
        );
    }

    const handleCopyIP = () => {
        navigator.clipboard.writeText(session.src_ip);
        setCopiedIP(true);
        setTimeout(() => setCopiedIP(false), 1500);
    };

    return (
        <div className="border-b border-white/10 dark:border-white/5 bg-card/50 backdrop-blur-xl">
            <div className="px-4 py-3 flex items-center justify-between">
                {/* Left: Session Info */}
                <div className="flex items-center gap-4">
                    {/* Protocol Avatar */}
                    <div className={cn(
                        "flex items-center justify-center w-11 h-11 rounded-none border",
                        getProtocolColor(session.protocol)
                    )}>
                        {getProtocolIcon(session.protocol)}
                    </div>

                    {/* Session Details */}
                    <div>
                        <div className="flex items-center gap-2">
                            {/* IP Address */}
                            <button
                                onClick={handleCopyIP}
                                className="flex items-center gap-1.5 font-mono text-base font-semibold text-emerald-500 hover:text-emerald-400 transition-colors"
                            >
                                <Globe className="h-4 w-4" />
                                {session.src_ip}
                                {session.src_port && <span className="text-muted-foreground">:{session.src_port}</span>}
                                {copiedIP ? (
                                    <Check className="h-3.5 w-3.5 text-emerald-500" />
                                ) : (
                                    <Copy className="h-3.5 w-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                                )}
                            </button>

                            {/* Status Badge */}
                            {session.isActive ? (
                                <Badge className="rounded-none bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                                    <span className="relative flex h-1.5 w-1.5 mr-1.5">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                                    </span>
                                    ACTIVE
                                </Badge>
                            ) : (
                                <Badge variant="outline" className="rounded-none text-muted-foreground">
                                    CLOSED
                                </Badge>
                            )}
                        </div>

                        {/* Meta Info */}
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                            {session.username && (
                                <span className="flex items-center gap-1">
                                    <User className="h-3 w-3" />
                                    {session.username}
                                </span>
                            )}
                            <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {formatDuration(session.startTime)}
                            </span>
                            <span className="flex items-center gap-1">
                                <MessageSquare className="h-3 w-3" />
                                {session.messageCount} messages
                            </span>
                            <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 rounded-none uppercase">
                                {session.protocol}
                            </Badge>
                        </div>
                    </div>
                </div>

                {/* Right: Threat Info & Actions */}
                <div className="flex items-center gap-4">
                    {/* Threat Indicators */}
                    {session.hasThreats && (
                        <div className="flex items-center gap-2">
                            {getSeverityBadge(session.maxSeverity)}
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                                {session.attackTypes.slice(0, 3).map((type, i) => (
                                    <Badge
                                        key={i}
                                        variant="outline"
                                        className="text-[9px] px-1 py-0 h-4 rounded-none bg-rose-500/10 text-rose-400 border-rose-500/30"
                                    >
                                        {type}
                                    </Badge>
                                ))}
                                {session.attackTypes.length > 3 && (
                                    <Badge
                                        variant="outline"
                                        className="text-[9px] px-1 py-0 h-4 rounded-none"
                                    >
                                        +{session.attackTypes.length - 3}
                                    </Badge>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Action Buttons */}
                    <div className="flex items-center gap-1">
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 rounded-none"
                            title="Export Session"
                        >
                            <Download className="h-4 w-4" />
                        </Button>
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 rounded-none"
                            title="Flag Session"
                        >
                            <Flag className="h-4 w-4" />
                        </Button>
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-8 w-8 rounded-none">
                                    <MoreVertical className="h-4 w-4" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-[180px] bg-card/95 backdrop-blur-xl border-white/10 rounded-none">
                                <DropdownMenuItem className="rounded-none cursor-pointer gap-2">
                                    <Zap className="h-3.5 w-3.5" />
                                    Analyze with ML
                                </DropdownMenuItem>
                                <DropdownMenuItem className="rounded-none cursor-pointer gap-2">
                                    <ExternalLink className="h-3.5 w-3.5" />
                                    View Raw Logs
                                </DropdownMenuItem>
                                <DropdownMenuSeparator className="bg-white/10" />
                                <DropdownMenuItem className="rounded-none cursor-pointer gap-2 text-rose-400">
                                    <ShieldAlert className="h-3.5 w-3.5" />
                                    Block IP
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </div>
                </div>
            </div>
        </div>
    );
}
