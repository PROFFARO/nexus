"use client";

import {
    Drawer,
    DrawerClose,
    DrawerContent,
    DrawerDescription,
    DrawerFooter,
    DrawerHeader,
    DrawerTitle,
} from "@/components/ui/drawer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ParsedAttack } from "@/lib/logs";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import {
    Terminal,
    X,
    ShieldAlert,
    Activity,
    Globe,
    Clock,
    Server,
    AlertTriangle,
    Info,
    FileJson,
    Fingerprint,
    MapPin,
    Zap,
    Bug,
    Copy,
    CheckCircle2,
    Network,
    Database,
    FolderOpen,
    Eye,
    User
} from "lucide-react";
import { useState, useEffect } from "react";

interface AttackDetailsProps {
    attack: ParsedAttack | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function AttackDetailsSheet({ attack, open, onOpenChange }: AttackDetailsProps) {
    const [copied, setCopied] = useState(false);
    const [currentAttack, setCurrentAttack] = useState<ParsedAttack | null>(attack);

    useEffect(() => {
        if (attack) {
            setCurrentAttack(attack);
        }
    }, [attack]);

    if (!currentAttack) return null;

    const copyToClipboard = () => {
        navigator.clipboard.writeText(JSON.stringify(currentAttack, null, 2));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const getSeverityConfig = (severity?: string) => {
        switch (severity?.toLowerCase()) {
            case 'critical': return { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', label: 'CRITICAL' };
            case 'high': return { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30', label: 'HIGH' };
            case 'medium': return { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', label: 'MEDIUM' };
            case 'low': return { color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/30', label: 'LOW' };
            default: return { color: 'text-slate-500', bg: 'bg-slate-500/10', border: 'border-slate-500/30', label: 'INFO' };
        }
    };

    const getProtocolIcon = (protocol: string) => {
        switch (protocol?.toLowerCase()) {
            case 'ssh': return <Terminal className="h-5 w-5" />;
            case 'ftp': return <FolderOpen className="h-5 w-5" />;
            case 'mysql': return <Database className="h-5 w-5" />;
            default: return <Network className="h-5 w-5" />;
        }
    };

    const severityConfig = getSeverityConfig(currentAttack.attack_details?.severity);
    const formattedDate = new Date(currentAttack.timestamp).toLocaleDateString('en-US', {
        weekday: 'short', year: 'numeric', month: 'short', day: 'numeric'
    });
    const formattedTime = new Date(currentAttack.timestamp).toLocaleTimeString('en-US', {
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
    });

    return (
        <Drawer open={open} onOpenChange={onOpenChange} direction="right">
            <DrawerContent className="h-full w-[95vw] max-w-xl ml-auto inset-y-0 right-0 left-auto rounded-none border-l fixed">
                <div className="flex flex-col h-full">

                    {/* Header - Fixed */}
                    <div className="shrink-0 px-5 pt-5 pb-4 border-b border-border bg-background">
                        <div className="flex items-start justify-between gap-3">
                            <div className="flex items-start gap-3 min-w-0">
                                <div className={`shrink-0 p-2 rounded-none ${severityConfig.bg} ${severityConfig.border} border`}>
                                    <ShieldAlert className={`h-5 w-5 ${severityConfig.color}`} />
                                </div>
                                <div className="min-w-0">
                                    <h2 className="text-lg font-bold tracking-tight flex items-center gap-2 flex-wrap">
                                        Event Details
                                        <Badge className={`${severityConfig.bg} ${severityConfig.color} ${severityConfig.border} border text-[10px] font-bold rounded-none`}>
                                            {severityConfig.label}
                                        </Badge>
                                    </h2>
                                    <p className="text-xs text-muted-foreground flex items-center gap-2 mt-1">
                                        <Clock className="h-3 w-3" />
                                        {formattedDate} • {formattedTime}
                                    </p>
                                </div>
                            </div>
                            <DrawerClose asChild>
                                <Button variant="ghost" size="icon" className="shrink-0 h-8 w-8 rounded-none">
                                    <X className="h-4 w-4" />
                                </Button>
                            </DrawerClose>
                        </div>
                    </div>

                    {/* Content - Scrollable */}
                    <div className="flex-1 overflow-y-auto min-h-0">
                        <div className="px-5 py-5 space-y-5">

                            {/* Key Stats Grid */}
                            <div className="grid grid-cols-2 gap-3">
                                <div className="p-3 border border-border bg-muted/20 rounded-none">
                                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground mb-1 uppercase tracking-wider font-medium">
                                        <Activity className="h-3 w-3" /> Protocol
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <div className="p-1 bg-primary/10 text-primary rounded-none">
                                            {getProtocolIcon(currentAttack.protocol)}
                                        </div>
                                        <span className="text-lg font-bold uppercase">{currentAttack.protocol || 'N/A'}</span>
                                    </div>
                                </div>

                                <div className="p-3 border border-border bg-muted/20 rounded-none">
                                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground mb-1 uppercase tracking-wider font-medium">
                                        <Globe className="h-3 w-3" /> Source IP
                                    </div>
                                    <div className="text-lg font-bold font-mono text-primary truncate">
                                        {currentAttack.src_ip || 'Local'}
                                    </div>
                                </div>

                                <div className="p-3 border border-border bg-muted/20 rounded-none">
                                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground mb-1 uppercase tracking-wider font-medium">
                                        <User className="h-3 w-3" /> Username
                                    </div>
                                    <div className="text-lg font-bold font-mono truncate">
                                        {currentAttack.username || '—'}
                                    </div>
                                </div>

                                <div className="p-3 border border-border bg-muted/20 rounded-none">
                                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground mb-1 uppercase tracking-wider font-medium">
                                        <Eye className="h-3 w-3" /> Detection
                                    </div>
                                    <div className="flex items-center gap-1.5">
                                        {currentAttack.is_attack ? (
                                            <>
                                                <AlertTriangle className="h-4 w-4 text-red-500" />
                                                <span className="text-base font-bold text-red-500">ATTACK</span>
                                            </>
                                        ) : (
                                            <>
                                                <Info className="h-4 w-4 text-blue-500" />
                                                <span className="text-base font-bold text-blue-500">LOGGED</span>
                                            </>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Attack Types */}
                            {currentAttack.attack_details?.attack_types && currentAttack.attack_details.attack_types.length > 0 && (
                                <div className="p-4 border border-border bg-muted/10 rounded-none space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                                        <Bug className="h-3.5 w-3.5 text-red-500" /> Attack Vectors
                                    </h3>
                                    <div className="flex flex-wrap gap-1.5">
                                        {currentAttack.attack_details.attack_types.map((type, i) => (
                                            <Badge key={i} variant="outline" className="px-2 py-1 text-xs bg-red-500/5 text-red-500 border-red-500/30 rounded-none">
                                                <Zap className="h-2.5 w-2.5 mr-1" /> {type}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Command/Request */}
                            {(currentAttack.command || currentAttack.payload) && (
                                <div className="p-4 border border-border bg-muted/10 rounded-none space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                                        <Terminal className="h-3.5 w-3.5 text-green-500" /> Command / Request
                                    </h3>
                                    <div className="border border-zinc-800 bg-zinc-950 rounded-none overflow-hidden">
                                        <div className="h-6 bg-zinc-900 border-b border-zinc-800 flex items-center px-2 gap-1.5">
                                            <div className="w-2 h-2 rounded-full bg-red-500/60" />
                                            <div className="w-2 h-2 rounded-full bg-yellow-500/60" />
                                            <div className="w-2 h-2 rounded-full bg-green-500/60" />
                                        </div>
                                        <pre className="p-3 font-mono text-xs text-green-400/90 whitespace-pre-wrap break-all max-h-40 overflow-auto">
                                            {currentAttack.command || currentAttack.payload}
                                        </pre>
                                    </div>
                                </div>
                            )}

                            {/* Response */}
                            {currentAttack.response && (
                                <div className="p-4 border border-border bg-muted/10 rounded-none space-y-3">
                                    <h3 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                                        <Server className="h-3.5 w-3.5 text-purple-500" /> Response
                                    </h3>
                                    <div className="p-3 bg-muted/30 border border-border rounded-none">
                                        <pre className="font-mono text-xs text-muted-foreground whitespace-pre-wrap break-all max-h-32 overflow-auto">
                                            {currentAttack.response}
                                        </pre>
                                    </div>
                                </div>
                            )}

                            {/* Message */}
                            <div className="p-4 border border-border bg-muted/10 rounded-none space-y-3">
                                <h3 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                                    <Info className="h-3.5 w-3.5 text-blue-500" /> Event Message
                                </h3>
                                <p className="text-sm text-muted-foreground leading-relaxed">
                                    {currentAttack.message || 'No message available'}
                                </p>
                            </div>

                            {/* Metadata */}
                            <div className="p-4 border border-border bg-muted/10 rounded-none space-y-3">
                                <h3 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                                    <Fingerprint className="h-3.5 w-3.5 text-cyan-500" /> Metadata
                                </h3>
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                    <div className="p-2 bg-muted/30 border border-border rounded-none">
                                        <div className="text-[10px] text-muted-foreground mb-0.5">Event ID</div>
                                        <div className="font-mono font-medium truncate">{currentAttack.id.slice(0, 20)}</div>
                                    </div>
                                    <div className="p-2 bg-muted/30 border border-border rounded-none">
                                        <div className="text-[10px] text-muted-foreground mb-0.5">Log Level</div>
                                        <div className="font-mono font-medium">{currentAttack.level || 'INFO'}</div>
                                    </div>
                                    <div className="p-2 bg-muted/30 border border-border rounded-none">
                                        <div className="text-[10px] text-muted-foreground mb-0.5">Session</div>
                                        <div className="font-mono font-medium truncate">{currentAttack.session_id || '—'}</div>
                                    </div>
                                    {currentAttack.attack_details?.threat_score !== undefined && (
                                        <div className="p-2 bg-muted/30 border border-border rounded-none">
                                            <div className="text-[10px] text-muted-foreground mb-0.5">Threat Score</div>
                                            <div className="font-mono font-medium text-red-500">{currentAttack.attack_details.threat_score}/100</div>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Raw JSON */}
                            <div className="p-4 border border-border bg-muted/10 rounded-none space-y-3">
                                <div className="flex items-center justify-between">
                                    <h3 className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                                        <FileJson className="h-3.5 w-3.5 text-cyan-500" /> Raw JSON
                                    </h3>
                                    <Button variant="ghost" size="sm" onClick={copyToClipboard} className="h-6 px-2 text-[10px] rounded-none">
                                        {copied ? <><CheckCircle2 className="h-3 w-3 mr-1 text-green-500" /> Copied</> : <><Copy className="h-3 w-3 mr-1" /> Copy</>}
                                    </Button>
                                </div>
                                <div className="rounded-lg overflow-hidden max-h-64 overflow-y-auto">
                                    <SyntaxHighlighter
                                        language="json"
                                        style={oneDark}
                                        showLineNumbers={true}
                                        customStyle={{
                                            margin: 0,
                                            fontSize: '10px',
                                            borderRadius: '0.5rem',
                                            background: 'hsl(var(--muted) / 0.3)',
                                        }}
                                        lineNumberStyle={{
                                            minWidth: '2.5em',
                                            paddingRight: '1em',
                                            color: 'hsl(var(--muted-foreground))',
                                            opacity: 0.5,
                                        }}
                                    >
                                        {JSON.stringify(currentAttack, null, 2)}
                                    </SyntaxHighlighter>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Footer - Fixed */}
                    <div className="shrink-0 px-5 py-4 border-t border-border bg-background">
                        <DrawerClose asChild>
                            <Button variant="default" className="w-full rounded-none">
                                Close
                            </Button>
                        </DrawerClose>
                    </div>
                </div>
            </DrawerContent>
        </Drawer>
    );
}
