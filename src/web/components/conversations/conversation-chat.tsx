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
    ChevronDown
} from "lucide-react";

interface ConversationChatProps {
    session: ConversationSession | null;
    isConnected: boolean;
}

// Format timestamp for chat bubbles
function formatMessageTime(timestamp: string): string {
    return new Date(timestamp).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
}

// Get severity badge styling
function getSeverityBadge(severity?: string) {
    switch (severity?.toLowerCase()) {
        case 'critical':
            return <Badge className="text-[9px] px-1.5 py-0 bg-rose-500/20 text-rose-400 border-rose-500/30">CRITICAL</Badge>;
        case 'high':
            return <Badge className="text-[9px] px-1.5 py-0 bg-orange-500/20 text-orange-400 border-orange-500/30">HIGH</Badge>;
        case 'medium':
            return <Badge className="text-[9px] px-1.5 py-0 bg-amber-500/20 text-amber-400 border-amber-500/30">MEDIUM</Badge>;
        case 'low':
            return <Badge className="text-[9px] px-1.5 py-0 bg-yellow-500/20 text-yellow-400 border-yellow-500/30">LOW</Badge>;
        default:
            return null;
    }
}

// Message Bubble Component
function MessageBubble({ message }: { message: ConversationMessage }) {
    const [copied, setCopied] = useState(false);
    const isAttacker = message.sender === 'attacker';

    const handleCopy = () => {
        navigator.clipboard.writeText(message.content || message.command || '');
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    // System messages have different styling
    if (message.type === 'system' || message.type === 'auth') {
        return (
            <div className="flex justify-center my-3">
                <div className="px-4 py-2 bg-muted/50 rounded-full max-w-[80%]">
                    <span className="text-xs text-muted-foreground break-words">
                        {message.content}
                    </span>
                </div>
            </div>
        );
    }

    // Session summary messages
    if (message.type === 'session_summary') {
        return (
            <div className="mx-4 my-4">
                <div className="p-4 bg-gradient-to-r from-primary/10 to-accent/10 border border-primary/20">
                    <div className="flex items-center gap-2 mb-2">
                        <ShieldAlert className="h-4 w-4 text-primary" />
                        <span className="text-sm font-semibold text-primary">Session Analysis</span>
                    </div>
                    <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap break-words">
                        {message.content}
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className={cn(
            "flex mb-3 px-4",
            isAttacker ? "justify-start" : "justify-end"
        )}>
            <div className={cn(
                "group relative flex items-start gap-2",
                isAttacker ? "flex-row" : "flex-row-reverse"
            )}>
                {/* Avatar */}
                <div className={cn(
                    "flex-shrink-0 flex items-center justify-center w-8 h-8 border",
                    isAttacker
                        ? "bg-rose-500/20 text-rose-400 border-rose-500/30"
                        : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                )}>
                    {isAttacker ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
                </div>

                {/* Bubble */}
                <div className={cn(
                    "relative px-4 py-3 max-w-xl",
                    isAttacker
                        ? "bg-zinc-800 text-zinc-100"
                        : "bg-teal-600 text-white"
                )}>
                    {/* Content */}
                    {message.type === 'command' && message.command ? (
                        <code className="block font-mono text-sm leading-relaxed whitespace-pre-wrap break-all">
                            <span className="text-emerald-300 mr-1">$</span>
                            {message.command}
                        </code>
                    ) : (
                        <div className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                            {message.content}
                        </div>
                    )}

                    {/* Attack indicators */}
                    {message.attack_types && message.attack_types.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t border-white/10">
                            <ShieldAlert className="h-3 w-3 text-rose-400" />
                            {message.attack_types.slice(0, 2).map((type, i) => (
                                <Badge
                                    key={i}
                                    className="text-[8px] px-1.5 py-0 bg-rose-500/30 text-rose-300 border-rose-500/50"
                                >
                                    {type}
                                </Badge>
                            ))}
                            {getSeverityBadge(message.severity)}
                        </div>
                    )}

                    {/* Timestamp and copy button */}
                    <div className={cn(
                        "flex items-center gap-2 mt-2 pt-1",
                        isAttacker ? "justify-end" : "justify-start"
                    )}>
                        <span className="text-[10px] opacity-60 flex items-center gap-1">
                            <Clock className="h-2.5 w-2.5" />
                            {formatMessageTime(message.timestamp)}
                        </span>
                        <button
                            onClick={handleCopy}
                            className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5"
                        >
                            {copied ? (
                                <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                                <Copy className="h-3 w-3 opacity-60 hover:opacity-100" />
                            )}
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

    // Auto-scroll to bottom when new messages arrive
    useEffect(() => {
        if (scrollRef.current && session?.messages) {
            const element = scrollRef.current;
            // Always scroll to bottom on new messages
            element.scrollTop = element.scrollHeight;
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
            <div className="flex-1 flex flex-col items-center justify-center bg-muted/20">
                <div className="text-center p-8">
                    <div className="p-6 bg-muted/30 rounded-full mb-4 inline-block">
                        <Terminal className="h-12 w-12 text-muted-foreground" />
                    </div>
                    <h3 className="text-xl font-semibold mb-2">Select a Session</h3>
                    <p className="text-sm text-muted-foreground max-w-sm">
                        Choose a session from the list to view the conversation between attacker and honeypot.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex-1 flex flex-col min-h-0 relative bg-muted/10">
            {/* Scrollable Messages Area */}
            <div
                ref={scrollRef}
                onScroll={handleScroll}
                className="flex-1 overflow-y-auto py-4"
            >
                {/* Date Header */}
                <div className="flex justify-center mb-4 sticky top-0 z-10">
                    <div className="px-4 py-1.5 bg-muted/80 backdrop-blur-sm rounded-full">
                        <span className="text-xs text-muted-foreground font-medium">
                            {new Date(session.startTime).toLocaleDateString('en-US', {
                                weekday: 'long',
                                month: 'short',
                                day: 'numeric'
                            })}
                        </span>
                    </div>
                </div>

                {/* Messages */}
                {session.messages.map((message) => (
                    <MessageBubble key={message.id} message={message} />
                ))}

                {/* Bottom padding for scroll */}
                <div className="h-4" />
            </div>

            {/* Scroll to Bottom Button */}
            {showScrollButton && (
                <div className="absolute bottom-4 right-4 z-20">
                    <Button
                        size="icon"
                        variant="secondary"
                        onClick={scrollToBottom}
                        className="rounded-full shadow-lg bg-card border"
                    >
                        <ChevronDown className="h-4 w-4" />
                    </Button>
                </div>
            )}

            {/* Connection Status */}
            {!isConnected && (
                <div className="absolute top-4 left-1/2 -translate-x-1/2 px-4 py-2 bg-rose-500/20 border border-rose-500/30 z-20">
                    <span className="text-xs text-rose-400 font-medium">Disconnected - Reconnecting...</span>
                </div>
            )}
        </div>
    );
}
