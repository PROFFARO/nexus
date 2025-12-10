"use client"

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { LogEntry } from "@/types/api"
import { format } from "date-fns"
import { useState } from "react"
import { AttackDetail } from "./attack-detail"

export function AttackTable({ logs }: { logs: LogEntry[] }) {
    const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)

    if (logs.length === 0) {
        return <div className="p-8 text-center text-muted-foreground">No attacks detected yet. Waiting for live stream...</div>
    }

    return (
        <div className="rounded-md border">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="w-[180px]">Timestamp</TableHead>
                        <TableHead>Level</TableHead>
                        <TableHead>Sensor</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Message</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {logs.map((log, index) => (
                        <TableRow
                            key={index}
                            className="cursor-pointer hover:bg-muted/50"
                            onClick={() => setSelectedLog(log)}
                        >
                            <TableCell className="font-mono text-xs text-muted-foreground">
                                {new Date(log.timestamp).toLocaleTimeString()}
                            </TableCell>
                            <TableCell>
                                <Badge variant={getBadgeVariant(log.level)}>
                                    {log.level}
                                </Badge>
                            </TableCell>
                            <TableCell className="text-xs">
                                {log.sensor_protocol?.toUpperCase() || '-'}
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                                {log.src_ip || '-'}
                            </TableCell>
                            <TableCell className="max-w-[400px] truncate" title={log.message}>
                                {log.message}
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>

            <AttackDetail
                log={selectedLog}
                open={!!selectedLog}
                onOpenChange={(open) => !open && setSelectedLog(null)}
            />
        </div>
    )
}

function getBadgeVariant(level: string): "default" | "secondary" | "destructive" | "outline" {
    switch (level?.toUpperCase()) {
        case 'CRITICAL':
        case 'ERROR':
            return 'destructive'
        case 'WARNING':
            return 'secondary'
        default:
            return 'outline'
    }
}
