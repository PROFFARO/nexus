"use client"

import { LogEntry } from "@/types/api"
import {
    Sheet,
    SheetContent,
    SheetDescription,
    SheetHeader,
    SheetTitle,
} from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"

interface AttackDetailProps {
    log: LogEntry | null
    open: boolean
    onOpenChange: (open: boolean) => void
}

export function AttackDetail({ log, open, onOpenChange }: AttackDetailProps) {
    if (!log) return null

    return (
        <Sheet open={open} onOpenChange={onOpenChange}>
            <SheetContent className="w-[400px] sm:w-[540px] overflow-auto">
                <SheetHeader>
                    <SheetTitle className="flex items-center gap-2">
                        Attack Details
                        <Badge variant="outline">{log.level}</Badge>
                    </SheetTitle>
                    <SheetDescription>
                        {new Date(log.timestamp).toLocaleString()}
                    </SheetDescription>
                </SheetHeader>

                <div className="mt-6 space-y-6">
                    {/* Key Information */}
                    <div className="space-y-2">
                        <h4 className="font-medium text-sm text-muted-foreground">Source Identity</h4>
                        <div className="grid grid-cols-2 gap-4 rounded-lg border p-4">
                            <div>
                                <label className="text-xs text-muted-foreground">IP Address</label>
                                <div className="font-mono">{log.src_ip || 'N/A'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground">Port</label>
                                <div className="font-mono">{log.src_port || 'N/A'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground">Sensor</label>
                                <div>{log.sensor_name || 'Generic'}</div>
                            </div>
                            <div>
                                <label className="text-xs text-muted-foreground">Protocol</label>
                                <div className="uppercase">{log.sensor_protocol || 'N/A'}</div>
                            </div>
                        </div>
                    </div>

                    {/* Message / Payload */}
                    <div className="space-y-2">
                        <h4 className="font-medium text-sm text-muted-foreground">Payload / Message</h4>
                        <div className="rounded-lg bg-muted p-4 font-mono text-xs break-all whitespace-pre-wrap">
                            {log.message}
                        </div>
                    </div>

                    {/* Attack Specifics */}
                    {log.attack_types && log.attack_types.length > 0 && (
                        <div className="space-y-2">
                            <h4 className="font-medium text-sm text-muted-foreground">Detected Patterns</h4>
                            <div className="flex flex-wrap gap-2">
                                {log.attack_types.map((type, i) => (
                                    <Badge key={i} variant="secondary">{type}</Badge>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* CVE Detection - Mocked if not present in generic logs, but ready for data */}
                    {log.indicators && log.indicators.length > 0 && (
                        <div className="space-y-2">
                            <h4 className="font-medium text-sm text-muted-foreground">Indicators & CVEs</h4>
                            <div className="space-y-2">
                                {log.indicators.map((ind, i) => (
                                    <div key={i} className="flex items-start gap-2 text-sm">
                                        <span className="text-destructive">•</span>
                                        <span>{ind}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* AI Analysis (If present) */}
                    {log.ai_analysis && (
                        <div className="space-y-2">
                            <h4 className="font-medium text-sm text-muted-foreground">AI Analysis</h4>
                            <div className="rounded-lg border border-purple-200 bg-purple-50/50 p-4 text-sm dark:border-purple-900 dark:bg-purple-900/20">
                                {log.ai_analysis}
                            </div>
                        </div>
                    )}

                    {/* Technical Metadata */}
                    <div className="space-y-2">
                        <h4 className="font-medium text-sm text-muted-foreground">Raw Data</h4>
                        <ScrollArea className="h-[200px] w-full rounded-md border p-4">
                            <pre className="text-xs font-mono">
                                {JSON.stringify(log, null, 2)}
                            </pre>
                        </ScrollArea>
                    </div>
                </div>
            </SheetContent>
        </Sheet>
    )
}
