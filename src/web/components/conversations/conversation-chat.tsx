"use client";

import { useEffect, useRef } from "react";
import { ConversationSession, ConversationMessage } from "@/types/conversation";
import { ScrollArea } from "@/components/ui/scroll-area";
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
import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";

interface ConversationChatProps {
    session: ConversationSession | null;
    isConnected: boolean;
}

// Format timestamp for chat bubbles (WhatsApp style)
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
            return <Badge className="text-[9px] px-1 py-0 h-4 rounded-none bg-rose-500/20 text-rose-400 border-rose-500/30">CRITICAL</Badge>;
        case 'high':
            return <Badge className="text-[9px] px-1 py-0 h-4 rounded-none bg-orange-500/20 text-orange-400 border-orange-500/30">HIGH</Badge>;
        case 'medium':
            return <Badge className="text-[9px] px-1 py-0 h-4 rounded-none bg-amber-500/20 text-amber-400 border-amber-500/30">MEDIUM</Badge>;
        case 'low':
            return <Badge className="text-[9px] px-1 py-0 h-4 rounded-none bg-yellow-500/20 text-yellow-400 border-yellow-500/30">LOW</Badge>;
        default:
            return null;
    }
}

// Message Bubble Component
function MessageBubble({ message, isLast }: { message: ConversationMessage; isLast: boolean }) {
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
            <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className="flex justify-center my-2"
            >
                <div className="px-3 py-1.5 bg-muted/50 rounded-full">
                    <span className="text-xs text-muted-foreground">
                        {message.content}
                    </span>
                </div>
            </motion.div>
        );
    }

    // Session summary messages
    if (message.type === 'session_summary') {
        return (
            <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className="mx-4 my-3"
            >
                <div className="p-4 bg-gradient-to-r from-primary/10 to-accent/10 border border-primary/20 rounded-none">
                    <div className="flex items-center gap-2 mb-2">
                        <ShieldAlert className="h-4 w-4 text-primary" />
                        <span className="text-sm font-semibold text-primary">Session Analysis</span>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                        {message.content}
                    </p>
                </div>
            </motion.div>
        );
    }

    return (
        <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.2 }}
            className={cn(
                "flex mb-2 px-4",
                isAttacker ? "justify-start" : "justify-end"
            )}
        >
            <div className={cn(
                "group max-w-[75%] relative",
                isAttacker ? "pr-8" : "pl-8"
            )}>
                {/* Avatar */}
                <div className={cn(
                    "absolute top-0 w-6 h-6 rounded-none flex items-center justify-center",
                    isAttacker
                        ? "left-0 -translate-x-8 bg-rose-500/20 text-rose-400 border border-rose-500/30"
                        : "right-0 translate-x-8 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                )}>
                    {isAttacker ? <User className="h-3 w-3" /> : <Bot className="h-3 w-3" />}
                </div>

                {/* Bubble */}
                <div className={cn(
                    "relative px-4 py-2.5 rounded-none",
                    isAttacker
                        ? "bg-zinc-800 dark:bg-zinc-800 text-zinc-100 chat-bubble-attacker"
                        : "bg-gradient-to-br from-teal-600 to-teal-700 dark:from-teal-600 dark:to-teal-700 text-white chat-bubble-response"
                )}>
                    {/* Bubble tail */}
                    <div className={cn(
                        "absolute top-3 w-0 h-0",
                        isAttacker
                            ? "left-0 -translate-x-full border-t-[6px] border-t-transparent border-b-[6px] border-b-transparent border-r-[8px] border-r-zinc-800"
                            : "right-0 translate-x-full border-t-[6px] border-t-transparent border-b-[6px] border-b-transparent border-l-[8px] border-l-teal-600"
                    )} />

                    {/* Command content */}
                    {message.type === 'command' && message.command && (
                        <code className="block font-mono text-sm leading-relaxed break-all">
                            <span className="text-emerald-300 mr-1">$</span>
                            {message.command}
                        </code>
                    )}

                    {/* Response content */}
                    {message.type === 'response' && (
                        <div className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                            {message.content}
                        </div>
                    )}

                    {/* Generic content */}
                    {message.type !== 'command' && message.type !== 'response' && (
                        <div className="text-sm leading-relaxed break-words">
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
                                    className="text-[8px] px-1 py-0 h-3.5 rounded-none bg-rose-500/30 text-rose-300 border-rose-500/50"
                                >
                                    {type}
                                </Badge>
                            ))}
                            {getSeverityBadge(message.severity)}
                        </div>
                    )}

                    {/* Timestamp and copy button */}
                    <div className={cn(
                        "flex items-center gap-2 mt-1.5 pt-1",
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
        </motion.div>
    );
}

// Typing Indicator Component
function TypingIndicator() {
    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="flex justify-end px-4 mb-2"
        >
            <div className="bg-gradient-to-br from-teal-600 to-teal-700 px-4 py-3 rounded-none">
                <div className="flex gap-1">
                    <motion.span
                        animate={{ y: [0, -4, 0] }}
                        transition={{ duration: 0.6, repeat: Infinity, delay: 0 }}
                        className="w-2 h-2 bg-white/60 rounded-full"
                    />
                    <motion.span
                        animate={{ y: [0, -4, 0] }}
                        transition={{ duration: 0.6, repeat: Infinity, delay: 0.15 }}
                        className="w-2 h-2 bg-white/60 rounded-full"
                    />
                    <motion.span
                        animate={{ y: [0, -4, 0] }}
                        transition={{ duration: 0.6, repeat: Infinity, delay: 0.3 }}
                        className="w-2 h-2 bg-white/60 rounded-full"
                    />
                </div>
            </div>
        </motion.div>
    );
}

export function ConversationChat({ session, isConnected }: ConversationChatProps) {
    const scrollRef = useRef<HTMLDivElement>(null);
    const [showScrollButton, setShowScrollButton] = useState(false);
    const [isTyping, setIsTyping] = useState(false);

    // Auto-scroll to bottom when new messages arrive
    useEffect(() => {
        if (scrollRef.current) {
            const element = scrollRef.current;
            const isNearBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 100;

            if (isNearBottom) {
                element.scrollTop = element.scrollHeight;
            } else {
                setShowScrollButton(true);
            }
        }
    }, [session?.messages]);

    // Typing indicator simulation
    useEffect(() => {
        if (session?.messages) {
            const lastMessage = session.messages[session.messages.length - 1];
            if (lastMessage?.sender === 'attacker') {
                setIsTyping(true);
                const timer = setTimeout(() => setIsTyping(false), 1500);
                return () => clearTimeout(timer);
            }
        }
    }, [session?.messages.length]);

    const scrollToBottom = () => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
            setShowScrollButton(false);
        }
    };

    if (!session) {
        return (
            <div className="flex-1 flex flex-col items-center justify-center bg-background/50 backdrop-blur-xl">
                <div className="text-center">
                    <div className="p-6 bg-muted/30 rounded-full mb-4 inline-block">
                        <Terminal className="h-12 w-12 text-muted-foreground" />
                    </div>
                    <h3 className="text-xl font-semibold mb-2">Select a Session</h3>
                    <p className="text-sm text-muted-foreground max-w-xs">
                        Choose a session from the list to view the conversation between attacker and honeypot.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="flex-1 flex flex-col bg-background/50 backdrop-blur-xl relative">
            {/* Chat Background Pattern */}
            <div
                className="absolute inset-0 opacity-[0.02] dark:opacity-[0.03] pointer-events-none"
                style={{
                    backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23000000' fill-opacity='0.4'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
                }}
            />

            {/* Messages Area */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto py-4 relative"
                onScroll={(e) => {
                    const element = e.target as HTMLDivElement;
                    const isNearBottom = element.scrollHeight - element.scrollTop - element.clientHeight < 100;
                    setShowScrollButton(!isNearBottom);
                }}
            >
                {/* Date Header */}
                <div className="flex justify-center mb-4">
                    <div className="px-3 py-1 bg-muted/70 rounded-full">
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
                <AnimatePresence mode="popLayout">
                    {session.messages.map((message, index) => (
                        <MessageBubble
                            key={message.id}
                            message={message}
                            isLast={index === session.messages.length - 1}
                        />
                    ))}
                </AnimatePresence>

                {/* Typing Indicator */}
                <AnimatePresence>
                    {isTyping && <TypingIndicator />}
                </AnimatePresence>
            </div>

            {/* Scroll to Bottom Button */}
            <AnimatePresence>
                {showScrollButton && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 10 }}
                        className="absolute bottom-4 right-4"
                    >
                        <Button
                            size="icon"
                            variant="secondary"
                            onClick={scrollToBottom}
                            className="rounded-full shadow-lg bg-card/90 backdrop-blur-sm border border-white/10"
                        >
                            <ChevronDown className="h-4 w-4" />
                        </Button>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Connection Status */}
            {!isConnected && (
                <div className="absolute top-4 left-1/2 -translate-x-1/2 px-4 py-2 bg-rose-500/20 border border-rose-500/30 rounded-none">
                    <span className="text-xs text-rose-400 font-medium">Disconnected - Reconnecting...</span>
                </div>
            )}
        </div>
    );
}
