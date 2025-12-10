'use client';

import { useState, useMemo } from 'react';
import { IconRefresh, IconWifi, IconWifiOff } from '@tabler/icons-react';
import {
    MLStatsCards,
    AttackAnalysisTable,
    AttackDetailModal,
    MLMetricsCharts,
} from '@/components/ml-analysis';
import { AttackAnalysis } from '@/lib/ml-data';
import { useRealtimeMLAnalysis } from '@/hooks/use-realtime-ml';

export default function MLAnalysisPage() {
    const [selectedAttack, setSelectedAttack] = useState<AttackAnalysis | null>(null);
    const [selectedSession, setSelectedSession] = useState<{ session_id: string; service: string } | undefined>();
    const [isModalOpen, setIsModalOpen] = useState(false);

    // Use real-time ML analysis hook for WebSocket data
    const { entries, isConnected, stats } = useRealtimeMLAnalysis();

    // Compute real-time metrics for charts from entries
    const realtimeMetrics = useMemo(() => {
        // Risk distribution
        const riskDistribution: Record<string, number> = { high: 0, medium: 0, low: 0 };
        // Attack type distribution
        const attackTypeDistribution: Record<string, number> = {};

        entries.forEach(entry => {
            // Count risk levels
            const risk = entry.ml_risk_level?.toLowerCase() || 'low';
            if (risk === 'critical' || risk === 'high') {
                riskDistribution.high = (riskDistribution.high || 0) + 1;
            } else if (risk === 'medium') {
                riskDistribution.medium = (riskDistribution.medium || 0) + 1;
            } else {
                riskDistribution.low = (riskDistribution.low || 0) + 1;
            }

            // Count attack types
            entry.attack_types?.forEach(type => {
                attackTypeDistribution[type] = (attackTypeDistribution[type] || 0) + 1;
            });
        });

        return {
            riskDistribution,
            attackTypeDistribution,
        };
    }, [entries]);

    function handleSelectAttack(attack: AttackAnalysis, session?: { session_id: string; service: string }) {
        setSelectedAttack(attack);
        setSelectedSession(session);
        setIsModalOpen(true);
    }

    return (
        <div className="min-h-screen bg-background">
            <div className="container max-w-[1600px] mx-auto py-8 px-4 space-y-8">
                {/* Header - matching Live Attacks style */}
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-foreground">
                            Real-Time ML Analysis
                        </h1>
                        <p className="text-sm text-muted-foreground">
                            Machine learning threat detection and attack analysis
                        </p>
                    </div>

                    <div className="flex items-center gap-4">
                        {/* Connection status indicator */}
                        <div className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium ${isConnected ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'}`}>
                            {isConnected ? <IconWifi className="h-4 w-4" /> : <IconWifiOff className="h-4 w-4" />}
                            {isConnected ? 'Live' : 'Disconnected'}
                        </div>
                    </div>
                </div>

                {/* Stats Cards - using real-time data */}
                <section>
                    <MLStatsCards realtimeStats={stats} entries={entries} />
                </section>

                {/* Charts - using real-time data */}
                <section>
                    <MLMetricsCharts realtimeMetrics={realtimeMetrics} entries={entries} />
                </section>

                {/* Attack Analysis Table */}
                <section>
                    <div className="mb-4">
                        <h2 className="text-xl font-semibold">Attack Analysis</h2>
                        <p className="text-sm text-muted-foreground">
                            Real-time ML predictions on detected threats and attacks ({entries.length} entries)
                        </p>
                    </div>
                    <AttackAnalysisTable
                        onSelectAttack={handleSelectAttack}
                    />
                </section>

                {/* Attack Detail Modal */}
                <AttackDetailModal
                    attack={selectedAttack}
                    session={selectedSession}
                    isOpen={isModalOpen}
                    onClose={() => {
                        setIsModalOpen(false);
                        setSelectedAttack(null);
                        setSelectedSession(undefined);
                    }}
                />
            </div>
        </div>
    );
}

