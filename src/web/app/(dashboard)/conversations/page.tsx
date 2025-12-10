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
    Trash2,
    PanelLeftClose,
    PanelLeft,
    Filter
} from "lucide-react";
import { cn } from "@/lib/utils";

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
        <div className="h-screen w-full flex flex-col bg-background">
            {/* Header - Fixed height */}
            <header className="flex-shrink-0 flex items-center justify-between px-4 py-3 border-b border-border bg-card/50">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-primary/20 rounded-sm">
                        <MessageSquare className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                        <h1 className="text-xl font-bold">Live Conversations</h1>
                        <p className="text-xs text-muted-foreground">
                            Real-time honeypot session monitoring
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    {/* Connection Status */}
                    <Badge
                        variant={isConnected ? "default" : "destructive"}
                        className={cn(
                            "px-2.5 py-1 text-xs font-medium",
                            isConnected
                                ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/30"
                                : ""
                        )}
                    >
                        <span className={cn(
                            "inline-block w-2 h-2 rounded-full mr-1.5",
                            isConnected ? "bg-emerald-500" : "bg-rose-500"
                        )} />
                        {isConnected ? "LIVE" : "OFFLINE"}
                    </Badge>

                    {/* Toggle Filters */}
                    <Button
                        variant={showFilters ? "secondary" : "ghost"}
                        size="sm"
                        onClick={() => setShowFilters(!showFilters)}
                        className="h-8"
                    >
                        <Filter className="h-4 w-4" />
                    </Button>

                    {/* Toggle Sidebar */}
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                        className="h-8 w-8"
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
                        className="h-8 text-muted-foreground hover:text-rose-500"
                    >
                        <Trash2 className="h-4 w-4 mr-1" />
                        Clear
                    </Button>
                </div>
            </header>

            {/* Stats Bar - Fixed height */}
            <ConversationStats stats={stats} isConnected={isConnected} />

            {/* Filters Bar - Collapsible */}
            {showFilters && (
                <ConversationFiltersBar
                    filters={filters}
                    onFiltersChange={setFilters}
                    totalCount={sessions.length}
                    filteredCount={filteredSessions.length}
                />
            )}

            {/* Main Content - Fills remaining height */}
            <div className="flex-1 flex min-h-0">
                {/* Session List Sidebar */}
                {!sidebarCollapsed && (
                    <aside className="w-80 flex-shrink-0 border-r border-border">
                        <ConversationList
                            sessions={filteredSessions}
                            selectedSessionId={selectedSessionId}
                            onSelectSession={setSelectedSessionId}
                            searchQuery={filters.searchQuery}
                            onSearchChange={handleSearchChange}
                            isConnected={isConnected}
                        />
                    </aside>
                )}

                {/* Chat Area - Takes remaining width */}
                <main className="flex-1 flex flex-col min-w-0 min-h-0">
                    {/* Session Header */}
                    <ConversationHeader session={activeSession} />

                    {/* Chat Messages - Scrollable */}
                    <ConversationChat
                        session={activeSession}
                        isConnected={isConnected}
                    />
                </main>
            </div>
        </div>
    );
}
