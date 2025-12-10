'use client';

import { useEffect, useState, useMemo } from 'react';
import {
    useReactTable,
    getCoreRowModel,
    getSortedRowModel,
    getFilteredRowModel,
    flexRender,
    createColumnHelper,
    SortingState,
    ColumnFiltersState,
} from '@tanstack/react-table';
import {
    IconArrowUp,
    IconArrowDown,
    IconFilter,
    IconRefresh,
    IconInfoCircle,
    IconPlugConnected,
    IconPlugConnectedX,
} from '@tabler/icons-react';
import {
    AttackAnalysis,
    SessionSummary,
    getMLSessions,
    formatTimestamp,
    getRiskLevelColor,
    formatAnomalyScore,
} from '@/lib/ml-data';
import { useRealtimeMLAnalysis, MLAnalysisEntry } from '@/hooks/use-realtime-ml';
import { Badge } from '@/components/ui/badge';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';

// Unified table entry type - contains all ML metrics from real-time data
interface TableEntry {
    id: string;
    timestamp: string;
    service: string;
    command: string;
    session_id?: string;
    src_ip?: string;
    username?: string;
    isRealtime?: boolean;

    // ML metrics (all from real data, no hardcoded values)
    ml_anomaly_score: number;
    ml_confidence: number;
    ml_inference_time_ms: number;
    ml_risk_level: string;
    ml_labels: string[];
    ml_reason: string;

    // Attack info
    severity: string;
    attack_types: string[];
    threat_score: number;
    indicators: string[];
    response?: string;
}

const columnHelper = createColumnHelper<TableEntry>();

interface AttackAnalysisTableProps {
    service?: string;
    onSelectAttack?: (attack: AttackAnalysis, session?: { session_id: string; service: string; src_ip?: string; username?: string }) => void;
}

export function AttackAnalysisTable({
    service,
    onSelectAttack,
}: AttackAnalysisTableProps) {
    const [sessions, setSessions] = useState<SessionSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [sorting, setSorting] = useState<SortingState>([
        { id: 'timestamp', desc: true },
    ]);
    const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
    const [selectedService, setSelectedService] = useState<string | undefined>(service);
    const [isRefreshing, setIsRefreshing] = useState(false);

    // Use real-time WebSocket hook
    const { entries: realtimeEntries, isConnected, stats } = useRealtimeMLAnalysis();

    // Transform real-time entries to table format
    const realtimeTableEntries = useMemo((): TableEntry[] => {
        return realtimeEntries
            .filter(e => !selectedService || e.service === selectedService)
            .map(e => ({
                id: e.id,
                timestamp: e.timestamp,
                service: e.service,
                command: e.command,
                session_id: e.session_id,
                src_ip: e.src_ip,
                username: e.username,
                isRealtime: true,
                response: e.response,

                // ML metrics from real data
                ml_anomaly_score: e.ml_anomaly_score,
                ml_confidence: e.ml_confidence,
                ml_inference_time_ms: e.ml_inference_time_ms,
                ml_risk_level: e.ml_risk_level,
                ml_labels: e.ml_labels,
                ml_reason: e.ml_reason,

                // Attack info
                severity: e.severity,
                attack_types: e.attack_types,
                threat_score: e.threat_score,
                indicators: e.indicators,
            }));
    }, [realtimeEntries, selectedService]);

    // Transform session-based entries to table format  
    const sessionTableEntries = useMemo((): TableEntry[] => {
        const entries: TableEntry[] = [];
        for (const session of sessions) {
            if (selectedService && session.service !== selectedService) continue;
            for (const attack of session.attacks) {
                const ml = attack.ml_metrics;
                const anomalyScore = ml?.ml_anomaly_score ?? 0;

                // Compute confidence - use ML value, or derive from anomaly score
                const rawConfidence = ml?.ml_confidence;
                const confidence = rawConfidence !== undefined && rawConfidence !== null && rawConfidence > 0
                    ? rawConfidence
                    : (anomalyScore > 0 ? Math.min(0.95, 0.5 + anomalyScore * 0.5) : 0);

                // Compute threat score - use attack value, or derive from anomaly
                // Check existing data
                const rawThreat = attack.threat_score ?? ml?.ml_threat_score;
                const threatScore = rawThreat !== undefined && rawThreat !== null && rawThreat > 0
                    ? (rawThreat > 1 ? rawThreat : rawThreat * 100)  // Normalize to 0-100
                    : anomalyScore * 100;  // Fallback to anomaly percentage

                entries.push({
                    id: `${session.session_id}-${attack.timestamp}`,
                    timestamp: attack.timestamp,
                    service: session.service,
                    command: attack.command,
                    session_id: session.session_id,
                    src_ip: session.client_ip,
                    username: session.username,
                    isRealtime: false,
                    response: attack.response,

                    // ML metrics from session data - with computed fallbacks
                    ml_anomaly_score: anomalyScore,
                    ml_confidence: confidence,
                    ml_inference_time_ms: ml?.ml_inference_time_ms ?? 0,
                    ml_risk_level: ml?.ml_risk_level ?? (anomalyScore > 0.7 ? 'high' : anomalyScore > 0.4 ? 'medium' : 'low'),
                    ml_labels: ml?.ml_labels ?? [],
                    ml_reason: ml?.ml_reason ?? '',

                    // Attack info
                    severity: attack.severity,
                    attack_types: attack.attack_types ?? [],
                    threat_score: threatScore,
                    indicators: attack.indicators ?? [],
                });
            }
        }
        return entries;
    }, [sessions, selectedService]);

    // Combine and deduplicate entries - real-time takes priority (omitted as it uses updated lists)
    const allEntries = useMemo((): TableEntry[] => {
        const seenKeys = new Set<string>();
        const combined: TableEntry[] = [];

        // Helper to create a normalized deduplication key
        const createDedupeKey = (entry: TableEntry): string => {
            const cmd = entry.command || '';
            const normalizedCommand = cmd.trim().toLowerCase();
            if (entry.session_id) {
                return `${entry.session_id}-${normalizedCommand}`;
            }
            const timestamp = entry.timestamp || '';
            const datePart = timestamp.slice(0, 16);
            return `${datePart}-${normalizedCommand}`;
        };

        for (const entry of realtimeTableEntries) {
            const key = createDedupeKey(entry);
            if (!seenKeys.has(key)) {
                seenKeys.add(key);
                combined.push(entry);
            }
        }

        for (const entry of sessionTableEntries) {
            const key = createDedupeKey(entry);
            if (!seenKeys.has(key)) {
                seenKeys.add(key);
                combined.push(entry);
            }
        }

        combined.sort((a, b) => {
            const timeA = new Date(a.timestamp || 0).getTime();
            const timeB = new Date(b.timestamp || 0).getTime();
            return timeB - timeA;
        });

        return combined;
    }, [realtimeTableEntries, sessionTableEntries]);

    const columns = useMemo(
    () => [
        columnHelper.accessor('timestamp', {
            header: 'Time',
            cell: (info) => (
                <div className="flex items-center gap-1">
                    {info.row.original.isRealtime && (
                        <span className="relative flex h-2 w-2 mr-1">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                        </span>
                    )}
                    <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(info.getValue())}
                    </span>
                </div>
            ),
        }),
        columnHelper.accessor('service', {
            header: 'Service',
            cell: (info) => {
                const service = info.getValue();
                const colors: Record<string, string> = {
                    ssh: '#22c55e',
                    ftp: '#3b82f6',
                    mysql: '#f59e0b',
                };
                return (
                    <Badge
                        variant="outline"
                        className="uppercase font-mono text-xs rounded-none"
                        style={{ borderColor: colors[service || ''] || '#6b7280', color: colors[service || ''] }}
                    >
                        {service}
                    </Badge>
                );
            },
        }),
        columnHelper.accessor('command', {
            header: 'Command',
            cell: (info) => (
                <code className="text-xs font-mono bg-muted/50 px-2 py-1 max-w-[300px] truncate block">
                    {(info.getValue() || '').slice(0, 50)}{(info.getValue() || '').length > 50 ? '...' : ''}
                </code>
            ),
        }),
        columnHelper.accessor('ml_anomaly_score', {
            header: ({ column }) => (
                <button
                    className="flex items-center gap-1 hover:text-primary"
                    onClick={() => column.toggleSorting()}
                >
                    ML Score
                    {column.getIsSorted() === 'asc' ? (
                        <IconArrowUp className="h-3 w-3" />
                    ) : column.getIsSorted() === 'desc' ? (
                        <IconArrowDown className="h-3 w-3" />
                    ) : null}
                </button>
            ),
            cell: (info) => {
                const score = info.getValue() || 0;
                const color = score > 0.7 ? '#ef4444' : score > 0.4 ? '#f59e0b' : '#22c55e';
                return (
                    <div className="flex items-center gap-2">
                        <div
                            className="h-1.5 w-12 bg-muted overflow-hidden"
                            title={`${(score * 100).toFixed(1)}%`}
                        >
                            <div
                                className="h-full transition-all duration-300"
                                style={{
                                    width: `${score * 100}%`,
                                    backgroundColor: color,
                                }}
                            />
                        </div>
                        <span className="text-xs font-mono" style={{ color }}>
                            {formatAnomalyScore(score)}
                        </span>
                    </div>
                );
            },
        }),
        columnHelper.accessor('severity', {
            header: 'Severity',
            cell: (info) => {
                const severity = info.getValue();
                const colors: Record<string, string> = {
                    critical: '#ef4444',
                    high: '#f97316',
                    medium: '#f59e0b',
                    low: '#22c55e',
                };
                return (
                    <Badge
                        variant="outline"
                        className="capitalize text-xs rounded-none"
                        style={{
                            borderColor: colors[severity] || '#6b7280',
                            color: colors[severity] || '#6b7280',
                        }}
                    >
                        {severity || 'Low'}
                    </Badge>
                );
            },
        }),
        columnHelper.accessor('attack_types', {
            header: 'Attack Types',
            cell: (info) => {
                const types = info.getValue() || [];
                if (types.length === 0) {
                    return <span className="text-xs text-muted-foreground">—</span>;
                }
                return (
                    <div className="flex gap-1 flex-wrap max-w-[200px]">
                        {types.slice(0, 2).map((type, idx) => (
                            <Badge key={`${type}-${idx}`} variant="secondary" className="text-xs rounded-none">
                                {type}
                            </Badge>
                        ))}
                        {types.length > 2 && (
                            <Badge variant="outline" className="text-xs rounded-none">
                                +{types.length - 2}
                            </Badge>
                        )}
                    </div>
                );
            },
        }),
        columnHelper.accessor('ml_risk_level', {
            header: 'Risk',
            cell: (info) => {
                const level = info.getValue();
                const color = getRiskLevelColor(level);
                return (
                    <div className="flex items-center gap-1.5">
                        <div
                            className="h-2.5 w-2.5 rounded-full animate-pulse"
                            style={{ backgroundColor: color }}
                        />
                        <span className="text-xs capitalize" style={{ color }}>
                            {level}
                        </span>
                    </div>
                );
            },
        }),
        columnHelper.display({
            id: 'actions',
            header: '',
            cell: ({ row }) => (
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        // Convert to AttackAnalysis format using REAL data from entry
                        const entry = row.original;
                        const attackAnalysis: AttackAnalysis = {
                            command: entry.command,
                            timestamp: entry.timestamp,
                            attack_types: entry.attack_types,
                            severity: entry.severity as 'low' | 'medium' | 'high' | 'critical',
                            indicators: entry.indicators,
                            vulnerabilities: [],
                            threat_score: entry.threat_score,
                            alert_triggered: false,
                            attack_vectors: [],
                            pattern_matches: [],
                            ml_metrics: {
                                ml_anomaly_score: entry.ml_anomaly_score,
                                ml_labels: entry.ml_labels,
                                ml_cluster: -1,
                                ml_reason: entry.ml_reason,
                                ml_confidence: entry.ml_confidence,
                                ml_risk_score: entry.ml_anomaly_score,
                                ml_inference_time_ms: entry.ml_inference_time_ms,
                                ml_risk_level: entry.ml_risk_level as 'low' | 'medium' | 'high' | 'critical',
                                ml_threat_score: entry.threat_score,
                                ml_risk_color: getRiskLevelColor(entry.ml_risk_level),
                            },
                            response: entry.response,
                        };
                        onSelectAttack?.(attackAnalysis, {
                            session_id: entry.session_id || '',
                            service: entry.service || '',
                            src_ip: entry.src_ip,
                            username: entry.username,
                        });
                    }}
                    className="p-1.5 hover:bg-muted transition-colors text-muted-foreground hover:text-primary"
                >
                    <IconInfoCircle className="h-4 w-4" />
                </button>
            ),
        }),
    ],
    [onSelectAttack]
);

const table = useReactTable({
    data: allEntries,
    columns,
    state: {
        sorting,
        columnFilters,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
});

async function fetchData() {
    try {
        setIsRefreshing(true);
        const data = await getMLSessions({ service: selectedService, limit: 100 });
        setSessions(data);
    } catch (err) {
        console.error('Failed to fetch ML sessions:', err);
    } finally {
        setLoading(false);
        setIsRefreshing(false);
    }
}

// Initial fetch and periodic refresh for historical data
useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh historical every 10s
    return () => clearInterval(interval);
}, [selectedService]);

const services = ['all', 'ssh', 'ftp', 'mysql'];

return (
    <div className="space-y-4">
        {/* Toolbar */}
        <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
                <IconFilter className="h-4 w-4 text-muted-foreground" />
                <div className="flex border border-border/50 overflow-hidden">
                    {services.map((svc) => (
                        <button
                            key={svc}
                            onClick={() => setSelectedService(svc === 'all' ? undefined : svc)}
                            className={`px-4 py-1.5 text-sm font-medium transition-all ${(selectedService === svc || (svc === 'all' && !selectedService))
                                ? 'bg-primary text-primary-foreground'
                                : 'bg-transparent hover:bg-muted text-muted-foreground'
                                }`}
                        >
                            {svc.toUpperCase()}
                        </button>
                    ))}
                </div>
            </div>

            <div className="flex items-center gap-4">
                {/* Real-time connection status */}
                <div className="flex items-center gap-2">
                    {isConnected ? (
                        <>
                            <IconPlugConnected className="h-4 w-4 text-green-500" />
                            <span className="text-xs text-green-600">Live</span>
                        </>
                    ) : (
                        <>
                            <IconPlugConnectedX className="h-4 w-4 text-red-500" />
                            <span className="text-xs text-red-600">Disconnected</span>
                        </>
                    )}
                </div>

                <span className="text-sm text-muted-foreground">
                    {allEntries.length} attacks ({realtimeTableEntries.length} live)
                </span>
                <button
                    onClick={fetchData}
                    disabled={isRefreshing}
                    className="p-2 hover:bg-muted transition-colors text-muted-foreground hover:text-primary disabled:opacity-50"
                >
                    <IconRefresh className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
                </button>
            </div>
        </div>

        {/* Table */}
        <div className="border border-border/50 overflow-hidden bg-card/50">
            {loading && allEntries.length === 0 ? (
                <div className="p-12 text-center">
                    <div className="h-8 w-8 mx-auto mb-4 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                    <p className="text-muted-foreground">Loading ML analysis data...</p>
                </div>
            ) : allEntries.length === 0 ? (
                <div className="p-12 text-center">
                    <IconInfoCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
                    <p className="text-lg font-medium text-muted-foreground">No attack data available</p>
                    <p className="text-sm text-muted-foreground/70 mt-1">
                        Start a honeypot service and wait for connections
                    </p>
                </div>
            ) : (
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id} className="hover:bg-transparent border-border/50">
                                {headerGroup.headers.map((header) => (
                                    <TableHead key={header.id} className="text-xs font-semibold text-muted-foreground">
                                        {flexRender(
                                            header.column.columnDef.header,
                                            header.getContext()
                                        )}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows.map((row) => (
                            <tr
                                key={row.id}
                                onClick={() => {
                                    // Convert to AttackAnalysis format using REAL data from entry
                                    const entry = row.original;
                                    const attackAnalysis: AttackAnalysis = {
                                        command: entry.command,
                                        timestamp: entry.timestamp,
                                        attack_types: entry.attack_types,
                                        severity: entry.severity as 'low' | 'medium' | 'high' | 'critical',
                                        indicators: entry.indicators,
                                        vulnerabilities: [],
                                        threat_score: entry.threat_score,
                                        alert_triggered: false,
                                        attack_vectors: [],
                                        pattern_matches: [],
                                        ml_metrics: {
                                            ml_anomaly_score: entry.ml_anomaly_score,
                                            ml_labels: entry.ml_labels,
                                            ml_cluster: -1,
                                            ml_reason: entry.ml_reason,
                                            ml_confidence: entry.ml_confidence,
                                            ml_risk_score: entry.ml_anomaly_score,
                                            ml_inference_time_ms: entry.ml_inference_time_ms,
                                            ml_risk_level: entry.ml_risk_level as 'low' | 'medium' | 'high' | 'critical',
                                            ml_threat_score: entry.threat_score,
                                            ml_risk_color: getRiskLevelColor(entry.ml_risk_level),
                                        },
                                    };
                                    onSelectAttack?.(attackAnalysis, {
                                        session_id: entry.session_id || '',
                                        service: entry.service || '',
                                        src_ip: entry.src_ip,
                                        username: entry.username,
                                    });
                                }}
                                className={`cursor-pointer hover:bg-muted/50 transition-colors border-b border-border/30 ${row.original.isRealtime ? 'bg-green-500/5' : ''
                                    }`}
                            >
                                {row.getVisibleCells().map((cell) => (
                                    <TableCell key={cell.id} className="py-3">
                                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                    </TableCell>
                                ))}
                            </tr>
                        ))}
                    </TableBody>
                </Table>
            )}
        </div>
    </div>
);
}

export default AttackAnalysisTable;
