"use client";

import { useEffect, useRef, useState } from "react";
import { ConversationSession, ConversationMessage } from "@/types/conversation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
    Copy,
    Check,
    ShieldAlert,
    Terminal,
    Bot,
    User,
    Clock,
    ChevronDown,
    AlertTriangle,
    MessageSquare
} from "lucide-react";

interface ConversationChatProps {
    session: ConversationSession | null;
    isConnected: boolean;
}

function formatMessageTime(timestamp: string): string {
    return new Date(timestamp).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
}

function getSeverityBadge(severity?: string) {
    const baseClass = "text-[10px] px-2 py-0.5 font-semibold rounded-none";
    switch (severity?.toLowerCase()) {
        case 'critical':
            return <Badge className={cn(baseClass, "bg-rose-500/20 text-rose-400 border-rose-500/40")}>CRITICAL</Badge>;
        case 'high':
            return <Badge className={cn(baseClass, "bg-orange-500/20 text-orange-400 border-orange-500/40")}>HIGH</Badge>;
        case 'medium':
            return <Badge className={cn(baseClass, "bg-amber-500/20 text-amber-400 border-amber-500/40")}>MEDIUM</Badge>;
        case 'low':
            return <Badge className={cn(baseClass, "bg-yellow-500/20 text-yellow-400 border-yellow-500/40")}>LOW</Badge>;
        default:
            return null;
    }
}

function MessageBubble({ message }: { message: ConversationMessage }) {
    const [copied, setCopied] = useState(false);
    const isAttacker = message.sender === 'attacker';

    const handleCopy = () => {
        navigator.clipboard.writeText(message.content || message.command || '');
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    // System messages
    if (message.type === 'system' || message.type === 'auth') {
        return (
            <div className="flex justify-center my-3 px-6">
                <div className="flex items-center gap-2 px-4 py-2 bg-muted/50 border border-border/30">
                    <span className="text-sm text-muted-foreground">{message.content}</span>
                </div>
            </div>
        );
    }

    // Session summary
    if (message.type === 'session_summary') {
        return (
            <div className="mx-6 my-4">
                <div className="p-4 bg-gradient-to-r from-primary/10 to-accent/10 border border-primary/20">
                    <div className="flex items-center gap-2 mb-2">
                        <ShieldAlert className="h-4 w-4 text-primary" />
                        <span className="text-sm font-bold text-primary">Session Analysis</span>
                    </div>
                    <p className="text-sm text-foreground/80 leading-relaxed whitespace-pre-wrap">{message.content}</p>
                </div>
            </div>
        );
    }

    return (
        <div className={cn("flex mb-3 px-6", isAttacker ? "justify-start" : "justify-end")}>
            <div className={cn(
                "group relative flex items-end gap-2 max-w-[70%]",
                isAttacker ? "flex-row" : "flex-row-reverse"
            )}>
                {/* Avatar */}
                <div className={cn(
                    "flex-shrink-0 flex items-center justify-center w-9 h-9 border-2",
                    isAttacker
                        ? "bg-gradient-to-br from-rose-500/30 to-rose-600/20 border-rose-500/40 text-rose-400"
                        : "bg-gradient-to-br from-emerald-500/30 to-emerald-600/20 border-emerald-500/40 text-emerald-400"
                )}>
                    {isAttacker ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
                </div>

                {/* Bubble */}
                <div className={cn(
                    "relative px-4 py-3",
                    isAttacker
                        ? "bg-gradient-to-br from-zinc-800 to-zinc-900 text-zinc-100"
                        : "bg-gradient-to-br from-teal-600 to-teal-700 text-white"
                )}>
                    {/* Content */}
                    {message.type === 'command' && message.command ? (
                        <code className="block font-mono text-sm leading-relaxed whitespace-pre-wrap break-all">
                            <span className="text-emerald-400 font-bold mr-1.5">$</span>
                            {message.command}
                        </code>
                    ) : (
                        <div className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                            {message.content}
                        </div>
                    )}

                    {/* Attack indicators */}
                    {message.attack_types && message.attack_types.length > 0 && (
                        <div className="flex flex-wrap items-center gap-2 mt-2 pt-2 border-t border-white/15">
                            <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                            {message.attack_types.slice(0, 3).map((type, i) => (
                                <Badge key={i} className="text-[9px] px-2 py-0.5 bg-rose-500/30 text-rose-200 border-rose-500/50 rounded-none">
                                    {type}
                                </Badge>
                            ))}
                            {getSeverityBadge(message.severity)}
                        </div>
                    )}

                    {/* Footer */}
                    <div className={cn("flex items-center gap-2 mt-2", isAttacker ? "justify-end" : "justify-start")}>
                        <span className="text-[10px] opacity-50 flex items-center gap-1">
                            <Clock className="h-2.5 w-2.5" />
                            {formatMessageTime(message.timestamp)}
                        </span>
                        <button
                            onClick={handleCopy}
                            className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-white/10"
                        >
                            {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3 opacity-50" />}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export function ConversationChat({ session, isConnected }: ConversationChatProps) {
    const scrollRef = useRef<HTMLDivElement>(null);
    const [showScrollButton, setShowScrollButton] = useState(false);

    useEffect(() => {
        if (scrollRef.current && session?.messages) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [session?.messages?.length]);

    const scrollToBottom = () => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
            setShowScrollButton(false);
        }
    };

    const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
        const element = e.target as HTMLDivElement;
        const isNearBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 100;
        setShowScrollButton(!isNearBottom);
    };

    if (!session) {
        return (
            <div className="flex-1 flex flex-col items-center justify-center bg-gradient-to-br from-muted/5 via-background to-muted/10">
                <div className="text-center p-12">
                    <div className="relative inline-block mb-6">
                        <div className="p-8 bg-gradient-to-br from-muted/40 to-muted/20 border border-border/30">
                            <Terminal className="h-16 w-16 text-muted-foreground" />
                        </div>
                        <div className="absolute -bottom-2 -right-2 p-2 bg-primary/20 border border-primary/30">
                            <MessageSquare className="h-6 w-6 text-primary" />
                        </div>
                    </div>
                    <h3 className="text-2xl font-bold mb-3">Select a Session</h3>
                    <p className="text-base text-muted-foreground max-w-md">
                        Choose a session from the list to view the conversation between attacker and honeypot.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex-1 flex flex-col min-h-0 relative overflow-hidden">
            {/* Background pattern */}
            <div
                className="absolute inset-0 opacity-[0.02] dark:opacity-[0.03] pointer-events-none"
                style={{
                    backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
                    backgroundSize: '20px 20px',
                }}
            />

            {/* Scrollable Messages */}
            <div
                ref={scrollRef}
                onScroll={handleScroll}
                className="flex-1 overflow-y-auto py-4 relative"
            >
                {/* Date Header */}
                <div className="flex justify-center mb-4 sticky top-0 z-10">
                    <div className="px-4 py-1.5 bg-muted/80 backdrop-blur-sm border border-border/30">
                        <span className="text-xs text-muted-foreground font-semibold">
                            {new Date(session.startTime).toLocaleDateString('en-US', {
                                weekday: 'long',
                                month: 'long',
                                day: 'numeric',
                                year: 'numeric'
                            })}
                        </span>
                    </div>
                </div>

                {/* Messages */}
                {session.messages.map((message) => (
                    <MessageBubble key={message.id} message={message} />
                ))}

                <div className="h-6" />
            </div>

            {/* Scroll Button */}
            {showScrollButton && (
                <div className="absolute bottom-4 right-4 z-20">
                    <Button
                        size="icon"
                        onClick={scrollToBottom}
                        className="h-10 w-10 rounded-none bg-primary hover:bg-primary/90 border-2 border-primary/30"
                    >
                        <ChevronDown className="h-4 w-4" />
                    </Button>
                </div>
            )}

            {/* Connection Lost */}
            {!isConnected && (
                <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20">
                    <div className="flex items-center gap-2 px-4 py-2 bg-rose-500/20 border border-rose-500/30">
                        <span className="w-2 h-2 bg-rose-500 animate-pulse" />
                        <span className="text-sm text-rose-500 font-semibold">Connection Lost - Reconnecting...</span>
                    </div>
                </div>
            )}
        </div>
    );
}
