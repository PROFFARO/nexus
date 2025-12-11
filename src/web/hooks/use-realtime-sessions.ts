import { useState, useEffect, useCallback, useMemo } from 'react';
import {
    SessionSummary,
    MLStats,
    SessionFilters,
    ComputedSessionStats,
    defaultSessionFilters
} from '../types/session';

const API_BASE = 'http://localhost:8000/ml';

interface UseRealtimeSessionsReturn {
    sessions: SessionSummary[];
    stats: MLStats | null;
    computedStats: ComputedSessionStats;
    isLoading: boolean;
    error: string | null;
    selectedSessionId: string | null;
    setSelectedSessionId: (id: string | null) => void;
    filters: SessionFilters;
    setFilters: (filters: SessionFilters) => void;
    filteredSessions: SessionSummary[];
    selectedSession: SessionSummary | null;
    refreshSessions: () => void;
    clearAll: () => void;
}

export function useRealtimeSessions(): UseRealtimeSessionsReturn {
    const [sessions, setSessions] = useState<SessionSummary[]>([]);
    const [stats, setStats] = useState<MLStats | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
    const [filters, setFilters] = useState<SessionFilters>(defaultSessionFilters);
    const [refreshKey, setRefreshKey] = useState(0);

    // Fetch sessions from API
    const fetchSessions = useCallback(async () => {
        setIsLoading(true);
        setError(null);

        try {
            // Fetch sessions
            const sessionsRes = await fetch(`${API_BASE}/sessions?limit=100`);
            if (!sessionsRes.ok) throw new Error(`Failed to fetch sessions: ${sessionsRes.status}`);
            const sessionsData: SessionSummary[] = await sessionsRes.json();
            setSessions(sessionsData);

            // Fetch stats
            const statsRes = await fetch(`${API_BASE}/stats`);
            if (statsRes.ok) {
                const statsData: MLStats = await statsRes.json();
                setStats(statsData);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to fetch sessions');
            console.error('Error fetching sessions:', err);
        } finally {
            setIsLoading(false);
        }
    }, []);

    // Initial fetch and periodic refresh
    useEffect(() => {
        fetchSessions();

        // Refresh every 10 seconds
        const interval = setInterval(fetchSessions, 10000);

        return () => clearInterval(interval);
    }, [fetchSessions, refreshKey]);

    // Filter sessions
    const filteredSessions = useMemo(() => {
        return sessions.filter(session => {
            // Service filter
            if (filters.service !== 'all' && session.service !== filters.service) {
                return false;
            }

            // Risk level filter
            if (filters.riskLevel !== 'all' && session.risk_level !== filters.riskLevel) {
                return false;
            }

            // Search query
            if (filters.searchQuery) {
                const query = filters.searchQuery.toLowerCase();
                const matchesId = session.session_id.toLowerCase().includes(query);
                const matchesIp = session.client_ip.toLowerCase().includes(query);
                const matchesUser = session.username?.toLowerCase().includes(query);
                const matchesCommand = session.attacks.some(a =>
                    a.command.toLowerCase().includes(query)
                );

                if (!matchesId && !matchesIp && !matchesUser && !matchesCommand) {
                    return false;
                }
            }

            return true;
        });
    }, [sessions, filters]);

    // Get selected session
    const selectedSession = useMemo(() => {
        if (!selectedSessionId) return null;
        return sessions.find(s => s.session_id === selectedSessionId) || null;
    }, [sessions, selectedSessionId]);

    // Compute stats for UI
    const computedStats = useMemo((): ComputedSessionStats => {
        const uniqueIPs = new Set(sessions.map(s => s.client_ip).filter(Boolean));

        return {
            totalSessions: sessions.length,
            activeSessions: 0, // API doesn't track active sessions
            totalCommands: sessions.reduce((sum, s) => sum + s.total_commands, 0),
            totalAttacks: sessions.reduce((sum, s) => sum + s.attack_count, 0),
            uniqueAttackers: uniqueIPs.size,
            byService: {
                ssh: sessions.filter(s => s.service === 'ssh').length,
                ftp: sessions.filter(s => s.service === 'ftp').length,
                mysql: sessions.filter(s => s.service === 'mysql').length,
            },
            byRiskLevel: {
                high: sessions.filter(s => s.risk_level === 'high').length,
                medium: sessions.filter(s => s.risk_level === 'medium').length,
                low: sessions.filter(s => s.risk_level === 'low').length,
            }
        };
    }, [sessions]);

    // Refresh sessions
    const refreshSessions = useCallback(() => {
        setRefreshKey(k => k + 1);
    }, []);

    // Clear all (just resets state, doesn't delete files)
    const clearAll = useCallback(() => {
        setSessions([]);
        setStats(null);
        setSelectedSessionId(null);
    }, []);

    return {
        sessions,
        stats,
        computedStats,
        isLoading,
        error,
        selectedSessionId,
        setSelectedSessionId,
        filters,
        setFilters,
        filteredSessions,
        selectedSession,
        refreshSessions,
        clearAll
    };
}
