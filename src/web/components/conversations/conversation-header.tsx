"use client";

import { useState, useEffect } from "react";
import { ConversationSession } from "@/types/conversation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator,
    DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import {
    Terminal,
    FolderOpen,
    Database,
    Network,
    Clock,
    MessageSquare,
    Download,
    Flag,
    MoreVertical,
    User,
    FileJson,
    FileText,
    Copy,
    Check,
    AlertTriangle,
    ExternalLink,
    FolderPlus,
    Square,
    CheckSquare
} from "lucide-react";
import { toast } from "sonner";

interface ConversationHeaderProps {
    session: ConversationSession | null;
}

const COLLECTIONS_KEY = 'honeypot_session_collections';
const FALSE_POSITIVES_KEY = 'honeypot_false_positives';

function getProtocolIcon(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return <Terminal className="h-4 w-4" />;
        case 'ftp': return <FolderOpen className="h-4 w-4" />;
        case 'mysql': return <Database className="h-4 w-4" />;
        default: return <Network className="h-4 w-4" />;
    }
}

function getProtocolStyle(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return 'bg-sky-500/20 border-sky-500/30 text-sky-600 dark:text-sky-400';
        case 'ftp': return 'bg-violet-500/20 border-violet-500/30 text-violet-600 dark:text-violet-400';
        case 'mysql': return 'bg-amber-500/20 border-amber-500/30 text-amber-600 dark:text-amber-400';
        default: return 'bg-gray-500/20 border-gray-500/30 text-gray-600 dark:text-gray-400';
    }
}

function getSeverityStyle(severity?: string) {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
        case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
        case 'medium': return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
        case 'low': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
        default: return '';
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

function exportToJSON(session: ConversationSession): void {
    const exportData = {
        session_info: {
            id: session.id, ip: session.src_ip, port: session.src_port, protocol: session.protocol,
            username: session.username, start_time: session.startTime, last_activity: session.lastActivity,
            is_active: session.isActive, message_count: session.messageCount, has_threats: session.hasThreats,
            max_severity: session.maxSeverity, attack_types: session.attackTypes
        },
        messages: session.messages.map(msg => ({
            id: msg.id, timestamp: msg.timestamp, type: msg.type, sender: msg.sender,
            content: msg.content, command: msg.command, attack_types: msg.attack_types, severity: msg.severity
        })),
        exported_at: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `session_${session.src_ip.replace(/\./g, '-')}_${session.protocol}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportToTXT(session: ConversationSession): void {
    let content = `HONEYPOT SESSION TRANSCRIPT\n${'='.repeat(40)}\n\n`;
    content += `Session: ${session.id}\nIP: ${session.src_ip}:${session.src_port || 'N/A'}\n`;
    content += `Protocol: ${session.protocol.toUpperCase()}\nUser: ${session.username || 'N/A'}\n`;
    content += `Start: ${new Date(session.startTime).toLocaleString()}\nMessages: ${session.messageCount}\n`;
    if (session.hasThreats) content += `Threats: ${session.maxSeverity} - ${session.attackTypes.join(', ')}\n`;
    content += `\n${'='.repeat(40)}\nTRANSCRIPT\n${'='.repeat(40)}\n\n`;
    session.messages.forEach(msg => {
        const time = new Date(msg.timestamp).toLocaleTimeString();
        const sender = msg.sender === 'attacker' ? 'ATTACKER' : 'HONEYPOT';
        content += `[${time}] ${sender}: ${msg.content || msg.command || ''}\n`;
    });
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `session_${session.src_ip.replace(/\./g, '-')}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function copySessionSummary(session: ConversationSession): void {
    const summary = `Session: ${session.src_ip} (${session.protocol.toUpperCase()})\nUser: ${session.username || 'N/A'}\nMessages: ${session.messageCount}\nThreats: ${session.hasThreats ? session.maxSeverity : 'None'}`;
    navigator.clipboard.writeText(summary);
}

function viewInNewTab(session: ConversationSession): void {
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${session.src_ip} - ${session.protocol}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0a0a0a;color:#fff;padding:2rem}.header{border-bottom:1px solid #333;padding-bottom:1rem;margin-bottom:2rem}h1{font-size:1.5rem;color:#10b981;font-family:monospace}.meta{color:#888;font-size:.875rem;margin-top:.5rem}.message{margin:.5rem 0;padding:1rem}.attacker{background:#1c1c1c;border-left:3px solid #ef4444}.honeypot{background:#0d9488;border-left:3px solid #10b981}.time{font-size:.75rem;color:#888}</style></head><body><div class="header"><h1>${session.src_ip}:${session.src_port || ''}</h1><div class="meta">${session.protocol.toUpperCase()} | ${session.messageCount} messages | ${session.username || 'N/A'}</div></div>${session.messages.map(m => `<div class="message ${m.sender === 'attacker' ? 'attacker' : 'honeypot'}"><div class="time">${new Date(m.timestamp).toLocaleTimeString()}</div><div>${m.content || m.command || ''}</div></div>`).join('')}</body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    window.open(URL.createObjectURL(blob), '_blank');
}

// Toggle false positive
function toggleFalsePositive(session: ConversationSession, isCurrentlyReported: boolean): boolean {
    const data = localStorage.getItem(FALSE_POSITIVES_KEY);
    let reports: any[] = data ? JSON.parse(data) : [];

    if (isCurrentlyReported) {
        // Remove from reports
        reports = reports.filter(r => r.session_id !== session.id);
        localStorage.setItem(FALSE_POSITIVES_KEY, JSON.stringify(reports));
        return false;
    } else {
        // Add to reports
        reports.push({ session_id: session.id, ip: session.src_ip, protocol: session.protocol, reported_at: new Date().toISOString() });
        localStorage.setItem(FALSE_POSITIVES_KEY, JSON.stringify(reports));
        return true;
    }
}

// Toggle collection
function toggleCollection(session: ConversationSession, isCurrentlySaved: boolean): boolean {
    const data = localStorage.getItem(COLLECTIONS_KEY);
    let collections: any[] = data ? JSON.parse(data) : [];

    if (isCurrentlySaved) {
        // Remove from collection
        collections = collections.filter(c => c.session_id !== session.id);
        localStorage.setItem(COLLECTIONS_KEY, JSON.stringify(collections));
        return false;
    } else {
        // Add to collection
        collections.push({ session_id: session.id, ip: session.src_ip, protocol: session.protocol, added_at: new Date().toISOString() });
        localStorage.setItem(COLLECTIONS_KEY, JSON.stringify(collections));
        return true;
    }
}

export function ConversationHeader({ session }: ConversationHeaderProps) {
    const [isFlagged, setIsFlagged] = useState(false);
    const [copied, setCopied] = useState(false);
    const [isInCollection, setIsInCollection] = useState(false);
    const [isReported, setIsReported] = useState(false);

    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        if (typeof window === 'undefined' || !session) return;
        const collections = JSON.parse(localStorage.getItem(COLLECTIONS_KEY) || '[]');
        const reports = JSON.parse(localStorage.getItem(FALSE_POSITIVES_KEY) || '[]');
        setIsInCollection(collections.some((c: any) => c.session_id === session.id));
        setIsReported(reports.some((r: any) => r.session_id === session.id));
        setIsFlagged(false); // Reset flag on session change
    }, [session?.id]);

    if (!session) {
        return (
            <div className="flex-shrink-0 h-14 flex items-center justify-center border-b border-border/50 bg-card/30">
                <p className="text-sm text-muted-foreground">Select a session to view details</p>
            </div>
        );
    }

    const handleToggleFalsePositive = () => {
        const newState = toggleFalsePositive(session, isReported);
        setIsReported(newState);
        toast.success(newState ? "Marked as False Positive" : "Removed False Positive");
    };

    const handleToggleCollection = () => {
        const newState = toggleCollection(session, isInCollection);
        setIsInCollection(newState);
        toast.success(newState ? "Added to Collection" : "Removed from Collection");
    };

    return (
        <div className="flex-shrink-0 flex items-center justify-between gap-4 px-4 py-2 border-b border-border/50 bg-card/50 min-h-[56px]">
            {/* Left: Session Info */}
            <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className={cn("flex-shrink-0 p-2 border", getProtocolStyle(session.protocol))}>
                    {getProtocolIcon(session.protocol)}
                </div>

                <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-base font-bold text-emerald-500 truncate">
                            {session.src_ip}
                        </span>
                        {session.src_port && (
                            <span className="text-xs text-muted-foreground font-mono">:{session.src_port}</span>
                        )}
                        <Badge className={cn(
                            "px-2 py-0.5 text-[10px] font-bold rounded-none",
                            session.isActive ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-muted text-muted-foreground"
                        )}>
                            {session.isActive ? "●ACTIVE" : "CLOSED"}
                        </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                        {session.username && (
                            <span className="flex items-center gap-1"><User className="h-3 w-3" />{session.username}</span>
                        )}
                        <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{formatDuration(session.startTime)}</span>
                        <span className="flex items-center gap-1"><MessageSquare className="h-3 w-3" />{session.messageCount}</span>
                    </div>
                </div>
            </div>

            {/* Middle: Threats */}
            {session.hasThreats && (
                <div className="flex items-center gap-1.5 flex-shrink-0 max-w-[300px] overflow-x-auto">
                    {session.maxSeverity && (
                        <Badge className={cn("px-2 py-0.5 text-[10px] font-bold uppercase rounded-none flex-shrink-0", getSeverityStyle(session.maxSeverity))}>
                            {session.maxSeverity}
                        </Badge>
                    )}
                    {session.attackTypes.slice(0, 2).map((type, i) => (
                        <Badge key={i} className="px-2 py-0.5 text-[10px] bg-rose-500/15 text-rose-400 border-rose-500/30 rounded-none flex-shrink-0 truncate max-w-[120px]">
                            {type}
                        </Badge>
                    ))}
                    {session.attackTypes.length > 2 && (
                        <Badge className="px-1.5 py-0.5 text-[10px] bg-muted text-muted-foreground rounded-none flex-shrink-0">
                            +{session.attackTypes.length - 2}
                        </Badge>
                    )}
                </div>
            )}

            {/* Right: Actions */}
            <div className="flex items-center gap-0.5 flex-shrink-0 pl-2 border-l border-border/50">
                {mounted ? (
                    <>
                        {/* Export */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-8 w-8 rounded-none">
                                    <Download className="h-4 w-4" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-[160px] bg-card border-border rounded-none">
                                <DropdownMenuItem onClick={() => { exportToJSON(session); toast.success("Exported JSON"); }} className="rounded-none gap-2 text-sm">
                                    <FileJson className="h-4 w-4 text-blue-500" /> JSON
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => { exportToTXT(session); toast.success("Exported TXT"); }} className="rounded-none gap-2 text-sm">
                                    <FileText className="h-4 w-4 text-emerald-500" /> TXT
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem onClick={() => { copySessionSummary(session); setCopied(true); setTimeout(() => setCopied(false), 2000); toast.success("Copied"); }} className="rounded-none gap-2 text-sm">
                                    {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />} Copy
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>

                        {/* Flag */}
                        <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => { setIsFlagged(!isFlagged); toast.success(isFlagged ? "Unflagged" : "Flagged for review"); }}
                            className={cn("h-8 w-8 rounded-none", isFlagged && "bg-amber-500/20 text-amber-500")}
                        >
                            <Flag className="h-4 w-4" />
                        </Button>

                        {/* More */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-8 w-8 rounded-none">
                                    <MoreVertical className="h-4 w-4" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-[220px] bg-card border-border rounded-none p-1">
                                <DropdownMenuLabel className="text-xs text-muted-foreground">Session Actions</DropdownMenuLabel>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                    onClick={() => { viewInNewTab(session); toast.success("Opened in new tab"); }}
                                    className="rounded-none gap-3 text-sm py-2.5"
                                >
                                    <ExternalLink className="h-4 w-4 text-blue-500" />
                                    <span className="flex-1">Open in New Tab</span>
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                    onClick={handleToggleFalsePositive}
                                    className="rounded-none gap-3 text-sm py-2.5"
                                >
                                    {isReported ? <CheckSquare className="h-4 w-4 text-emerald-500" /> : <Square className="h-4 w-4 text-muted-foreground" />}
                                    <span className="flex-1">False Positive</span>
                                    {isReported && <Badge className="text-[9px] px-1.5 py-0 bg-emerald-500/20 text-emerald-500 border-emerald-500/30 rounded-none">ON</Badge>}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                    onClick={handleToggleCollection}
                                    className="rounded-none gap-3 text-sm py-2.5"
                                >
                                    {isInCollection ? <CheckSquare className="h-4 w-4 text-emerald-500" /> : <Square className="h-4 w-4 text-muted-foreground" />}
                                    <span className="flex-1">Save to Collection</span>
                                    {isInCollection && <Badge className="text-[9px] px-1.5 py-0 bg-emerald-500/20 text-emerald-500 border-emerald-500/30 rounded-none">ON</Badge>}
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </>
                ) : (
                    <div className="flex items-center gap-0.5 opacity-0">
                        {/* Placeholder while mounting to avoid layout shift */}
                        <div className="h-8 w-8" />
                        <div className="h-8 w-8" />
                        <div className="h-8 w-8" />
                    </div>
                )}
            </div>
        </div>
    );
}
