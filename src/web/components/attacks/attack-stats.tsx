import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, ShieldAlert, Wifi, Globe, Server, AlertTriangle } from "lucide-react";

interface LogStats {
    total_events: number;
    total_attacks: number;
    attacks_by_protocol: { [key: string]: number };
    events_by_protocol: { [key: string]: number };
    severity_counts: { [key: string]: number };
    top_ips: { [key: string]: number };
    recent_critical: number;
}

interface AttackStatsProps {
    stats: LogStats;
    loading?: boolean;
}

export function AttackStats({ stats, loading }: AttackStatsProps) {
    if (loading) {
        return (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                {[...Array(4)].map((_, i) => (
                    <Card key={i} className="animate-pulse bg-muted/20 rounded-none">
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                            <div className="h-4 w-24 bg-muted rounded" />
                        </CardHeader>
                        <CardContent>
                            <div className="h-8 w-16 bg-muted rounded" />
                        </CardContent>
                    </Card>
                ))}
            </div>
        );
    }

    // Calculate top protocol
    const topProtocol = Object.entries(stats.events_by_protocol)
        .sort(([, a], [, b]) => b - a)[0];

    // Calculate critical + high threats
    const criticalThreats = (stats.severity_counts['critical'] || 0) + (stats.severity_counts['high'] || 0);

    // Calculate unique IPs
    const uniqueIPs = Object.keys(stats.top_ips).length;

    return (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {/* Total Events */}
            <Card className="bg-gradient-to-br from-primary/5 to-transparent border-primary/20 rounded-none">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Total Events</CardTitle>
                    <Activity className="h-4 w-4 text-primary" />
                </CardHeader>
                <CardContent>
                    <div className="text-3xl font-bold text-primary">{stats.total_events.toLocaleString()}</div>
                    <p className="text-xs text-muted-foreground mt-1">
                        {stats.total_attacks} attacks detected
                    </p>
                </CardContent>
            </Card>

            {/* Top Protocol */}
            <Card className="rounded-none">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Top Protocol</CardTitle>
                    <Server className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className="text-3xl font-bold uppercase">
                        {topProtocol?.[0] || 'N/A'}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                        {topProtocol?.[1]?.toLocaleString() || 0} events
                    </p>
                </CardContent>
            </Card>

            {/* Critical Threats */}
            <Card className={`rounded-none ${criticalThreats > 0 ? 'bg-gradient-to-br from-red-500/10 to-transparent border-red-500/20' : ''}`}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className={`text-sm font-medium ${criticalThreats > 0 ? 'text-red-500' : ''}`}>
                        Critical Threats
                    </CardTitle>
                    <AlertTriangle className={`h-4 w-4 ${criticalThreats > 0 ? 'text-red-500' : 'text-muted-foreground'}`} />
                </CardHeader>
                <CardContent>
                    <div className={`text-3xl font-bold ${criticalThreats > 0 ? 'text-red-500' : 'text-muted-foreground'}`}>
                        {criticalThreats}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                        High + Critical severity
                    </p>
                </CardContent>
            </Card>

            {/* Unique Sources */}
            <Card className="rounded-none">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Unique Sources</CardTitle>
                    <Globe className="h-4 w-4 text-blue-500" />
                </CardHeader>
                <CardContent>
                    <div className="text-3xl font-bold text-blue-500">
                        {uniqueIPs}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                        Distinct IP addresses
                    </p>
                </CardContent>
            </Card>
        </div>
    );
}
