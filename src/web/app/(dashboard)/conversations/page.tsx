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
    Filter,
    Wifi,
    WifiOff
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
        <div className="h-screen flex flex-col bg-gradient-to-br from-background via-background to-muted/20 overflow-hidden">
            {/* Header - Compact */}
            <header className="flex-shrink-0 flex items-center justify-between px-6 py-3 border-b border-border/50 bg-gradient-to-r from-card/80 to-card/60">
                <div className="flex items-center gap-4">
                    <div className="relative">
                        <div className="p-3 bg-gradient-to-br from-primary/30 to-primary/10 border border-primary/20">
                            <MessageSquare className="h-6 w-6 text-primary" />
                        </div>
                        {isConnected && (
                            <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-emerald-500 border-2 border-card" />
                        )}
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold">Live Conversations</h1>
                        <p className="text-sm text-muted-foreground">Real-time honeypot session monitoring</p>
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    {/* Connection Status */}
                    <div className={cn(
                        "flex items-center gap-2 px-4 py-2 border transition-all",
                        isConnected
                            ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400"
                            : "bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400"
                    )}>
                        {isConnected ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
                        <span className="text-sm font-semibold">{isConnected ? "CONNECTED" : "OFFLINE"}</span>
                    </div>

                    {/* Toggle Filters */}
                    <Button
                        variant={showFilters ? "default" : "outline"}
                        size="sm"
                        onClick={() => setShowFilters(!showFilters)}
                        className={cn(
                            "h-10 px-4 rounded-none transition-all",
                            showFilters && "bg-primary/90 hover:bg-primary"
                        )}
                    >
                        <Filter className="h-4 w-4 mr-2" />
                        Filters
                    </Button>

                    {/* Toggle Sidebar */}
                    <Button
                        variant="outline"
                        size="icon"
                        onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                        className="h-10 w-10 rounded-none border-border/50"
                    >
                        {sidebarCollapsed ? <PanelLeft className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
                    </Button>

                    {/* Clear All */}
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={clearAll}
                        className="h-10 px-4 rounded-none text-muted-foreground hover:text-rose-500 hover:bg-rose-500/10"
                    >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Clear All
                    </Button>
                </div>
            </header>

            {/* Stats Bar - Compact */}
            <ConversationStats stats={stats} isConnected={isConnected} />

            {/* Filters Bar */}
            {showFilters && (
                <ConversationFiltersBar
                    filters={filters}
                    onFiltersChange={setFilters}
                    totalCount={sessions.length}
                    filteredCount={filteredSessions.length}
                />
            )}

            {/* Main Content - Takes ALL remaining height */}
            <div className="flex-1 flex min-h-0 overflow-hidden">
                {/* Session List Sidebar - Full height */}
                {!sidebarCollapsed && (
                    <aside className="w-[400px] flex-shrink-0 border-r border-border/50 bg-gradient-to-b from-card/50 to-muted/20 overflow-hidden">
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

                {/* Chat Area - Full remaining width and height */}
                <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden bg-gradient-to-br from-muted/5 via-background to-muted/10">
                    <ConversationHeader session={activeSession} />
                    <ConversationChat session={activeSession} isConnected={isConnected} />
                </main>
            </div>
        </div>
    );
}
