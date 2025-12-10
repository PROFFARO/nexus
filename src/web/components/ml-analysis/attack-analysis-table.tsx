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
import { motion, AnimatePresence } from 'framer-motion';
import {
    IconArrowUp,
    IconArrowDown,
    IconFilter,
    IconRefresh,
    IconExternalLink,
    IconInfoCircle,
} from '@tabler/icons-react';
import {
    AttackAnalysis,
    SessionSummary,
    getMLSessions,
    formatTimestamp,
    getRiskLevelColor,
    formatAnomalyScore,
} from '@/lib/ml-data';
import { Badge } from '@/components/ui/badge';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';

const columnHelper = createColumnHelper<AttackAnalysis & { session_id?: string; service?: string }>();

interface AttackAnalysisTableProps {
    service?: string;
    onSelectAttack?: (attack: AttackAnalysis, session?: { session_id: string; service: string }) => void;
    refreshInterval?: number;
}

export function AttackAnalysisTable({
    service,
    onSelectAttack,
    refreshInterval = 10000,
}: AttackAnalysisTableProps) {
    const [sessions, setSessions] = useState<SessionSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [sorting, setSorting] = useState<SortingState>([
        { id: 'ml_score', desc: true },
    ]);
    const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
    const [selectedService, setSelectedService] = useState<string | undefined>(service);
    const [isRefreshing, setIsRefreshing] = useState(false);

    // Flatten sessions into attacks
    const attacks = useMemo(() => {
        const allAttacks: (AttackAnalysis & { session_id: string; service: string })[] = [];

        for (const session of sessions) {
            for (const attack of session.attacks) {
                allAttacks.push({
                    ...attack,
                    session_id: session.session_id,
                    service: session.service,
                });
            }
        }

        return allAttacks;
    }, [sessions]);

    const columns = useMemo(
        () => [
            columnHelper.accessor('timestamp', {
                header: 'Time',
                cell: (info) => (
                    <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(info.getValue())}
                    </span>
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
                            className="uppercase font-mono text-xs"
                            style={{ borderColor: colors[service || ''] || '#6b7280', color: colors[service || ''] }}
                        >
                            {service}
                        </Badge>
                    );
                },
            }),
            columnHelper.accessor('command', {
                header: 'Command',
                cell: (info) => {
                    const cmd = info.getValue() || '';
                    return (
                        <code className="text-xs bg-muted px-2 py-1 rounded font-mono max-w-[300px] truncate block">
                            {cmd.slice(0, 60)}{cmd.length > 60 ? '...' : ''}
                        </code>
                    );
                },
            }),
            columnHelper.accessor((row) => row.ml_metrics?.ml_anomaly_score ?? 0, {
                id: 'ml_score',
                header: ({ column }) => (
                    <button
                        onClick={() => column.toggleSorting()}
                        className="flex items-center gap-1 font-medium hover:text-primary transition-colors"
                    >
                        ML Score
                        {column.getIsSorted() === 'asc' ? (
                            <IconArrowUp className="h-4 w-4" />
                        ) : column.getIsSorted() === 'desc' ? (
                            <IconArrowDown className="h-4 w-4" />
                        ) : null}
                    </button>
                ),
                cell: (info) => {
                    const score = info.getValue();
                    const color = score > 0.7 ? '#ef4444' : score > 0.4 ? '#f59e0b' : '#22c55e';
                    return (
                        <div className="flex items-center gap-2">
                            <div
                                className="h-2 rounded-full"
                                style={{
                                    width: `${Math.max(score * 60, 8)}px`,
                                    backgroundColor: color,
                                }}
                            />
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
                    const color = getRiskLevelColor(severity);
                    return (
                        <Badge
                            variant="outline"
                            className="capitalize text-xs"
                            style={{ borderColor: color, color }}
                        >
                            {severity}
                        </Badge>
                    );
                },
            }),
            columnHelper.accessor('attack_types', {
                header: 'Attack Types',
                cell: (info) => {
                    const types = info.getValue() || [];
                    if (!types.length) return <span className="text-muted-foreground text-xs">—</span>;
                    return (
                        <div className="flex flex-wrap gap-1">
                            {types.slice(0, 2).map((type, idx) => (
                                <Badge key={`${type}-${idx}`} variant="secondary" className="text-xs">
                                    {type.replace(/_/g, ' ')}
                                </Badge>
                            ))}
                            {types.length > 2 && (
                                <Badge variant="outline" className="text-xs">
                                    +{types.length - 2}
                                </Badge>
                            )}
                        </div>
                    );
                },
            }),
            columnHelper.accessor((row) => row.ml_metrics?.ml_risk_level ?? 'low', {
                id: 'risk_level',
                header: 'Risk',
                cell: (info) => {
                    const level = info.getValue();
                    const color = getRiskLevelColor(level);
                    return (
                        <div
                            className="flex items-center gap-1.5"
                        >
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
                            onSelectAttack?.(row.original, {
                                session_id: row.original.session_id || '',
                                service: row.original.service || '',
                            });
                        }}
                        className="p-1.5 rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-primary"
                    >
                        <IconInfoCircle className="h-4 w-4" />
                    </button>
                ),
            }),
        ],
        [onSelectAttack]
    );

    const table = useReactTable({
        data: attacks,
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

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, refreshInterval);
        return () => clearInterval(interval);
    }, [selectedService, refreshInterval]);

    const services = ['all', 'ssh', 'ftp', 'mysql'];

    return (
        <div className="space-y-4">
            {/* Toolbar */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <IconFilter className="h-4 w-4 text-muted-foreground" />
                    <div className="flex rounded-lg border border-border/50 overflow-hidden">
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
                    <span className="text-sm text-muted-foreground">
                        {attacks.length} attacks from {sessions.length} sessions
                    </span>
                    <button
                        onClick={fetchData}
                        disabled={isRefreshing}
                        className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-primary disabled:opacity-50"
                    >
                        <IconRefresh className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {/* Table */}
            <div className="rounded-xl border border-border/50 overflow-hidden bg-card/50 backdrop-blur-sm">
                {loading ? (
                    <div className="p-12 text-center">
                        <div className="h-8 w-8 mx-auto mb-4 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                        <p className="text-muted-foreground">Loading ML analysis data...</p>
                    </div>
                ) : attacks.length === 0 ? (
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
                            <AnimatePresence mode="popLayout">
                                {table.getRowModel().rows.map((row) => (
                                    <motion.tr
                                        key={row.id}
                                        initial={{ opacity: 0, x: -10 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        exit={{ opacity: 0, x: 10 }}
                                        onClick={() => onSelectAttack?.(row.original, {
                                            session_id: row.original.session_id || '',
                                            service: row.original.service || '',
                                        })}
                                        className="cursor-pointer hover:bg-muted/50 transition-colors border-b border-border/30"
                                    >
                                        {row.getVisibleCells().map((cell) => (
                                            <TableCell key={cell.id} className="py-3">
                                                {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                            </TableCell>
                                        ))}
                                    </motion.tr>
                                ))}
                            </AnimatePresence>
                        </TableBody>
                    </Table>
                )}
            </div>
        </div>
    );
}

export default AttackAnalysisTable;
