"use client";

import { useState, useCallback } from "react";
import { useRealtimeConversations } from "@/hooks/use-realtime-conversations";
import { ConversationList } from "@/components/conversations/conversation-list";
import { ConversationChat } from "@/components/conversations/conversation-chat";
import { ConversationHeader } from "@/components/conversations/conversation-header";
import { ConversationStats } from "@/components/conversations/conversation-stats";
import { ConversationFiltersBar } from "@/components/conversations/conversation-filters";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    MessageSquare,
    Radio,
    Trash2,
    PanelLeftClose,
    PanelLeft
} from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

export default function ConversationsPage() {
    const {
        sessions,
        isConnected,
        selectedSessionId,
        setSelectedSessionId,
        filters,
        setFilters,
        filteredSessions,
        activeSession,
        stats,
        clearAll
    } = useRealtimeConversations();

    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [showFilters, setShowFilters] = useState(true);

    const handleSearchChange = useCallback((query: string) => {
        setFilters({ ...filters, searchQuery: query });
    }, [filters, setFilters]);

    return (
        <div className="h-full w-full flex flex-col overflow-hidden bg-background">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 dark:border-white/5 bg-card/30 backdrop-blur-xl">
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-primary/20 rounded-none">
                            <MessageSquare className="h-5 w-5 text-primary" />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold tracking-tight">Live Conversations</h1>
                            <p className="text-sm text-muted-foreground">
                                Real-time honeypot session monitoring
                            </p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    {/* Connection Status */}
                    <Badge
                        variant={isConnected ? "default" : "destructive"}
                        className={cn(
                            "px-3 py-1.5 text-xs font-semibold rounded-none",
                            isConnected
                                ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/30"
                                : ""
                        )}
                    >
                        <span className="relative flex h-2 w-2 mr-2">
                            <span className={cn(
                                "relative inline-flex rounded-full h-2 w-2",
                                isConnected ? "bg-emerald-500" : "bg-rose-500"
                            )}></span>
                        </span>
                        {isConnected ? "LIVE" : "DISCONNECTED"}
                    </Badge>

                    {/* Toggle Sidebar */}
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                        className="h-9 w-9 rounded-none"
                    >
                        {sidebarCollapsed ? (
                            <PanelLeft className="h-4 w-4" />
                        ) : (
                            <PanelLeftClose className="h-4 w-4" />
                        )}
                    </Button>

                    {/* Clear All */}
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={clearAll}
                        className="h-9 rounded-none text-muted-foreground hover:text-rose-500"
                    >
                        <Trash2 className="h-4 w-4 mr-1.5" />
                        Clear
                    </Button>
                </div>
            </div>

            {/* Stats Bar */}
            <ConversationStats stats={stats} isConnected={isConnected} />

            {/* Filters Bar */}
            <AnimatePresence>
                {showFilters && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                    >
                        <ConversationFiltersBar
                            filters={filters}
                            onFiltersChange={setFilters}
                            totalCount={sessions.length}
                            filteredCount={filteredSessions.length}
                        />
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Main Content - Split View */}
            <div className="flex-1 flex overflow-hidden">
                {/* Session List Sidebar */}
                <AnimatePresence mode="wait">
                    {!sidebarCollapsed && (
                        <motion.div
                            initial={{ width: 0, opacity: 0 }}
                            animate={{ width: 360, opacity: 1 }}
                            exit={{ width: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="flex-shrink-0 overflow-hidden"
                        >
                            <ConversationList
                                sessions={filteredSessions}
                                selectedSessionId={selectedSessionId}
                                onSelectSession={setSelectedSessionId}
                                searchQuery={filters.searchQuery}
                                onSearchChange={handleSearchChange}
                                isConnected={isConnected}
                            />
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Chat Area */}
                <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
                    {/* Session Header */}
                    <ConversationHeader session={activeSession} />

                    {/* Chat Messages */}
                    <ConversationChat
                        session={activeSession}
                        isConnected={isConnected}
                    />
                </div>
            </div>
        </div>
    );
}
