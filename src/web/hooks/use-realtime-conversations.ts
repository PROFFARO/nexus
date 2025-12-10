import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import { LogEntry } from '../types/api';
import {
    ConversationMessage,
    ConversationSession,
    ConversationFilters,
    defaultFilters,
    getMessageTypeFromLog,
    getSenderFromLog,
    getMessageContent,
    isConversationRelevant
} from '../types/conversation';

interface UseRealtimeConversationsReturn {
    sessions: ConversationSession[];
    allMessages: ConversationMessage[];
    isConnected: boolean;
    selectedSessionId: string | null;
    setSelectedSessionId: (id: string | null) => void;
    filters: ConversationFilters;
    setFilters: (filters: ConversationFilters) => void;
    filteredSessions: ConversationSession[];
    activeSession: ConversationSession | null;
    stats: {
        totalSessions: number;
        activeSessions: number;
        totalMessages: number;
        threatsDetected: number;
    };
    clearAll: () => void;
}

// Generate unique ID for messages
function generateMessageId(): string {
    return `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Convert LogEntry to ConversationMessage
function logToMessage(log: LogEntry): ConversationMessage {
    return {
        id: generateMessageId(),
        timestamp: log.timestamp,
        type: getMessageTypeFromLog(log),
        sender: getSenderFromLog(log),
        content: getMessageContent(log),
        command: log.command,
        response: log.response,
        protocol: log.sensor_protocol?.toLowerCase(),
        username: log.username,
        attack_types: log.attack_types,
        severity: log.severity,
        threat_score: log.threat_score,
        raw: log
    };
}

// Get or create session ID from log entry
function getSessionKey(log: LogEntry): string {
    // Use session_id if available
    if (log.session_id) return log.session_id;
    // Fall back to task_name if it's a session identifier
    if (log.task_name?.startsWith('session-')) return log.task_name;
    // Create composite key from IP + protocol
    const ip = log.src_ip || 'unknown';
    const proto = log.sensor_protocol || 'unknown';
    return `${proto}-${ip}`;
}

export function useRealtimeConversations(): UseRealtimeConversationsReturn {
    const [sessionsMap, setSessionsMap] = useState<Map<string, ConversationSession>>(new Map());
    const [isConnected, setIsConnected] = useState(false);
    const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
    const [filters, setFilters] = useState<ConversationFilters>(defaultFilters);
    const wsRef = useRef<WebSocket | null>(null);

    // WebSocket connection
    useEffect(() => {
        const connect = () => {
            const ws = new WebSocket('ws://localhost:8000/ws/attacks');

            ws.onopen = () => {
                console.log('Connected to Nexus Conversations Stream');
                setIsConnected(true);
            };

            ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    if (message.type === 'log_entry') {
                        const log: LogEntry = message.data;

                        // Filter for conversation-relevant entries
                        if (!isConversationRelevant(log)) return;

                        const sessionKey = getSessionKey(log);
                        const newMessage = logToMessage(log);

                        setSessionsMap(prev => {
                            const updated = new Map(prev);
                            const existing = updated.get(sessionKey);

                            if (existing) {
                                // Update existing session
                                const hasNewThreats = Boolean(log.attack_types && log.attack_types.length > 0);
                                updated.set(sessionKey, {
                                    ...existing,
                                    messages: [...existing.messages, newMessage],
                                    messageCount: existing.messageCount + 1,
                                    lastActivity: log.timestamp,
                                    isActive: true,
                                    hasThreats: existing.hasThreats || hasNewThreats,
                                    maxSeverity: hasNewThreats && log.severity ?
                                        (compareSeverity(log.severity, existing.maxSeverity) > 0 ? log.severity : existing.maxSeverity)
                                        : existing.maxSeverity,
                                    attackTypes: hasNewThreats ?
                                        [...new Set([...existing.attackTypes, ...(log.attack_types || [])])]
                                        : existing.attackTypes,
                                    username: log.username || existing.username
                                });
                            } else {
                                // Create new session
                                const protocol = (log.sensor_protocol?.toLowerCase() || 'unknown') as 'ssh' | 'ftp' | 'mysql' | 'unknown';
                                const hasThreats = Boolean(log.attack_types && log.attack_types.length > 0);

                                updated.set(sessionKey, {
                                    id: sessionKey,
                                    src_ip: log.src_ip || 'Unknown',
                                    src_port: log.src_port,
                                    protocol,
                                    username: log.username,
                                    startTime: log.timestamp,
                                    lastActivity: log.timestamp,
                                    messages: [newMessage],
                                    messageCount: 1,
                                    isActive: true,
                                    hasThreats,
                                    maxSeverity: log.severity,
                                    attackTypes: log.attack_types || []
                                });
                            }

                            return updated;
                        });
                    }
                } catch (e) {
                    console.error('Error parsing WebSocket message', e);
                }
            };

            ws.onclose = () => {
                setIsConnected(false);
                // Reconnect after 3 seconds
                setTimeout(connect, 3000);
            };

            ws.onerror = (error) => {
                console.error('WebSocket error', error);
                ws.close();
            };

            wsRef.current = ws;
        };

        connect();

        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, []);

    // Convert map to array of sessions
    const sessions = useMemo(() =>
        Array.from(sessionsMap.values()).sort((a, b) =>
            new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime()
        ),
        [sessionsMap]
    );

    // All messages flattened
    const allMessages = useMemo(() =>
        sessions.flatMap(s => s.messages),
        [sessions]
    );

    // Apply filters to sessions
    const filteredSessions = useMemo(() => {
        return sessions.filter(session => {
            // Protocol filter
            if (filters.protocol !== 'all' && session.protocol !== filters.protocol) {
                return false;
            }

            // Severity filter
            if (filters.severity !== 'all') {
                if (filters.severity === 'info' && session.hasThreats) return false;
                if (filters.severity !== 'info' && session.maxSeverity !== filters.severity) return false;
            }

            // Time range filter
            if (filters.timeRange !== 'all') {
                const now = Date.now();
                const lastActivity = new Date(session.lastActivity).getTime();
                let cutoff = 0;

                switch (filters.timeRange) {
                    case '1h': cutoff = now - (60 * 60 * 1000); break;
                    case '24h': cutoff = now - (24 * 60 * 60 * 1000); break;
                    case '7d': cutoff = now - (7 * 24 * 60 * 60 * 1000); break;
                    case 'custom':
                        if (filters.customStartDate) cutoff = filters.customStartDate.getTime();
                        break;
                }

                if (lastActivity < cutoff) return false;
            }

            // Active only filter
            if (filters.showActiveOnly && !session.isActive) {
                return false;
            }

            // IP filter
            if (filters.ipFilter && !session.src_ip.includes(filters.ipFilter)) {
                return false;
            }

            // Username filter
            if (filters.usernameFilter && session.username &&
                !session.username.toLowerCase().includes(filters.usernameFilter.toLowerCase())) {
                return false;
            }

            // Search query - search in messages
            if (filters.searchQuery) {
                const query = filters.searchQuery.toLowerCase();
                const hasMatch = session.messages.some(m =>
                    m.content.toLowerCase().includes(query) ||
                    m.command?.toLowerCase().includes(query)
                );
                if (!hasMatch) return false;
            }

            return true;
        }).sort((a, b) => {
            switch (filters.sortBy) {
                case 'oldest':
                    return new Date(a.startTime).getTime() - new Date(b.startTime).getTime();
                case 'mostActive':
                    return b.messageCount - a.messageCount;
                case 'highestThreat':
                    return (compareSeverity(b.maxSeverity, a.maxSeverity));
                case 'newest':
                default:
                    return new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime();
            }
        });
    }, [sessions, filters]);

    // Get active/selected session
    const activeSession = useMemo(() =>
        selectedSessionId ? sessionsMap.get(selectedSessionId) || null : null,
        [selectedSessionId, sessionsMap]
    );

    // Stats
    const stats = useMemo(() => ({
        totalSessions: sessions.length,
        activeSessions: sessions.filter(s => s.isActive).length,
        totalMessages: allMessages.length,
        threatsDetected: sessions.filter(s => s.hasThreats).length
    }), [sessions, allMessages]);

    // Clear all data
    const clearAll = useCallback(() => {
        setSessionsMap(new Map());
        setSelectedSessionId(null);
    }, []);

    return {
        sessions,
        allMessages,
        isConnected,
        selectedSessionId,
        setSelectedSessionId,
        filters,
        setFilters,
        filteredSessions,
        activeSession,
        stats,
        clearAll
    };
}

// Helper to compare severity levels
function compareSeverity(a?: string, b?: string): number {
    const order: Record<string, number> = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    };
    return (order[a?.toLowerCase() || ''] || 0) - (order[b?.toLowerCase() || ''] || 0);
}
