"use client";

import { useState, useMemo } from "react";
import {
    ColumnDef,
    flexRender,
    getCoreRowModel,
    getFilteredRowModel,
    getSortedRowModel,
    SortingState,
    useReactTable,
    ColumnFiltersState,
} from "@tanstack/react-table";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { LogEntry } from "@/types/api";
import {
    ArrowUpDown,
    Search,
    Filter,
    Copy,
    Check,
    Terminal,
    Database,
    FolderOpen,
    Network
} from "lucide-react";
import { AttackDetailsSheet } from "./attack-details-sheet";

interface AttackTableProps {
    logs: LogEntry[];
}

// Decode command from base64 if needed
function decodeCommand(log: LogEntry): string {
    if (log.command) return log.command;
    if (log.details) {
        try {
            return atob(log.details);
        } catch {
            return log.details;
        }
    }
    return log.message || '-';
}

function getProtocolIcon(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return <Terminal className="h-3 w-3" />;
        case 'ftp': return <FolderOpen className="h-3 w-3" />;
        case 'mysql': return <Database className="h-3 w-3" />;
        default: return <Network className="h-3 w-3" />;
    }
}

// Derive effective severity level from log entry
function getEffectiveLevel(log: LogEntry): string {
    // First check explicit severity field
    if (log.severity) {
        const sev = log.severity.toLowerCase();
        if (sev === 'critical' || sev === 'high') return 'CRITICAL';
        if (sev === 'medium') return 'WARNING';
    }

    // Check judgement field (e.g., "MALICIOUS" from session summary)
    if ((log as any).judgement === 'MALICIOUS') return 'CRITICAL';

    // Check if attack_types present
    if (log.attack_types && log.attack_types.length > 0) return 'WARNING';

    // Check explicit level field
    const level = log.level?.toUpperCase();
    if (level === 'CRITICAL' || level === 'ERROR') return 'CRITICAL';
    if (level === 'WARNING') return 'WARNING';

    return 'INFO';
}

function getLevelBadge(log: LogEntry) {
    const effectiveLevel = getEffectiveLevel(log);
    switch (effectiveLevel) {
        case 'CRITICAL':
            return <Badge className="bg-rose-500/10 text-rose-500 border-rose-500/30 hover:bg-rose-500/20 rounded-sm">{effectiveLevel}</Badge>;
        case 'WARNING':
            return <Badge className="bg-amber-500/10 text-amber-500 border-amber-500/30 hover:bg-amber-500/20 rounded-sm">{effectiveLevel}</Badge>;
        default:
            return <Badge variant="outline" className="bg-blue-500/10 text-blue-500 border-blue-500/30 rounded-sm">INFO</Badge>;
    }
}

export function AttackTable({ logs }: AttackTableProps) {
    const [sorting, setSorting] = useState<SortingState>([]);
    const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
    const [globalFilter, setGlobalFilter] = useState("");
    const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
    const [copiedIP, setCopiedIP] = useState<string | null>(null);

    const copyIP = (ip: string) => {
        navigator.clipboard.writeText(ip);
        setCopiedIP(ip);
        setTimeout(() => setCopiedIP(null), 1500);
    };

    const columns: ColumnDef<LogEntry>[] = useMemo(() => [
        {
            accessorKey: "timestamp",
            header: ({ column }) => (
                <Button
                    variant="ghost"
                    size="sm"
                    className="-ml-3 h-8 text-xs font-semibold"
                    onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
                >
                    Timestamp
                    <ArrowUpDown className="ml-1 h-3 w-3" />
                </Button>
            ),
            cell: ({ row }) => {
                const ts = new Date(row.getValue("timestamp"));
                return (
                    <span className="font-mono text-xs text-muted-foreground">
                        {ts.toLocaleTimeString('en-US', { hour12: false })}
                    </span>
                );
            },
        },
        {
            accessorKey: "level",
            header: "Level",
            cell: ({ row }) => getLevelBadge(row.original),
            filterFn: (row, id, value) => {
                if (value === "ALL") return true;
                const effectiveLevel = getEffectiveLevel(row.original);
                return effectiveLevel === value;
            },
        },
        {
            accessorKey: "sensor_protocol",
            header: "Sensor",
            cell: ({ row }) => {
                const protocol = row.getValue("sensor_protocol") as string;
                return (
                    <div className="flex items-center gap-1.5">
                        <span className="p-1 bg-muted rounded">
                            {getProtocolIcon(protocol)}
                        </span>
                        <span className="text-xs font-medium uppercase">{protocol || '-'}</span>
                    </div>
                );
            },
        },
        {
            accessorKey: "src_ip",
            header: "Source",
            cell: ({ row }) => {
                const ip = row.original.src_ip;
                const port = row.original.src_port;
                if (!ip) return <span className="text-muted-foreground">-</span>;

                return (
                    <button
                        onClick={(e) => {
                            e.stopPropagation();
                            copyIP(ip);
                        }}
                        className="group flex items-center gap-1 font-mono text-xs text-emerald-500 hover:text-emerald-400 transition-colors"
                    >
                        {ip}{port ? `:${port}` : ''}
                        {copiedIP === ip ? (
                            <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                            <Copy className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                        )}
                    </button>
                );
            },
        },
        {
            id: "request",
            header: "Request",
            cell: ({ row }) => {
                const cmd = decodeCommand(row.original);
                return (
                    <code className="text-xs bg-muted/50 px-1.5 py-0.5 rounded max-w-[200px] truncate block font-mono">
                        {cmd.slice(0, 40)}{cmd.length > 40 ? '...' : ''}
                    </code>
                );
            },
        },
        {
            accessorKey: "message",
            header: "Message",
            cell: ({ row }) => (
                <span className="text-xs text-muted-foreground max-w-[200px] truncate block">
                    {row.getValue("message")}
                </span>
            ),
        },
    ], [copiedIP]);

    const table = useReactTable({
        data: logs,
        columns,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        onSortingChange: setSorting,
        onColumnFiltersChange: setColumnFilters,
        onGlobalFilterChange: setGlobalFilter,
        state: {
            sorting,
            columnFilters,
            globalFilter,
        },
    });

    // Extract session from task_name if it starts with "session-" or use session_id
    const getSessionId = (log: LogEntry): string => {
        if (log.session_id) return log.session_id;
        if (log.task_name && log.task_name.startsWith('session-')) return log.task_name;
        return log.task_name || '';
    };

    // Convert LogEntry to ParsedAttack format for the sheet
    const convertToAttack = (log: LogEntry): any => ({
        id: log.session_id || log.task_name || crypto.randomUUID(),
        timestamp: log.timestamp,
        level: log.level,
        message: log.message,
        protocol: (log.sensor_protocol?.toLowerCase() || 'unknown') as 'ssh' | 'ftp' | 'mysql' | 'unknown',
        src_ip: log.src_ip,
        src_port: log.src_port,
        dst_port: log.dst_port,
        username: log.username || '',
        command: decodeCommand(log),
        payload: log.details,
        response: log.response,
        session_id: getSessionId(log),
        is_attack: log.attack_types && log.attack_types.length > 0,
        attack_details: {
            attack_types: log.attack_types,
            severity: log.severity,
            threat_score: log.threat_score,
            indicators: log.indicators,
        },
        raw: log,
    });

    if (logs.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="p-4 bg-muted/30 rounded-full mb-4">
                    <Terminal className="h-8 w-8 text-muted-foreground" />
                </div>
                <h3 className="text-lg font-semibold mb-1">No attacks detected yet</h3>
                <p className="text-sm text-muted-foreground">Waiting for live stream data...</p>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            {/* Toolbar */}
            <div className="flex items-center gap-2">
                <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search IP, message..."
                        value={globalFilter ?? ""}
                        onChange={(e) => setGlobalFilter(e.target.value)}
                        className="pl-9 h-9 bg-muted/30 rounded-sm"
                    />
                </div>
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm" className="h-9 gap-1 rounded-sm">
                            <Filter className="h-3.5 w-3.5" />
                            Level
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        {["ALL", "INFO", "WARNING", "ERROR", "CRITICAL"].map((level) => (
                            <DropdownMenuItem
                                key={level}
                                onClick={() => table.getColumn("level")?.setFilterValue(level === "ALL" ? "" : level)}
                            >
                                {level}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>

            {/* Table */}
            <div className="rounded-sm border border-white/10 dark:border-white/5 overflow-hidden bg-card/40 backdrop-blur-sm">
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id} className="border-white/10 hover:bg-transparent">
                                {headerGroup.headers.map((header) => (
                                    <TableHead key={header.id} className="text-xs font-semibold text-muted-foreground">
                                        {header.isPlaceholder
                                            ? null
                                            : flexRender(header.column.columnDef.header, header.getContext())}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows.map((row) => (
                            <TableRow
                                key={row.id}
                                className="cursor-pointer border-white/5 hover:bg-muted/30 transition-colors"
                                onClick={() => setSelectedLog(row.original)}
                            >
                                {row.getVisibleCells().map((cell) => (
                                    <TableCell key={cell.id} className="py-3">
                                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                    </TableCell>
                                ))}
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </div>

            {/* Details Sheet */}
            <AttackDetailsSheet
                attack={selectedLog ? convertToAttack(selectedLog) : null}
                open={!!selectedLog}
                onOpenChange={(open) => !open && setSelectedLog(null)}
            />
        </div>
    );
}
