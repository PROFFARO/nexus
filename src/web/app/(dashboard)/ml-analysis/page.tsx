'use client';

import { useState } from 'react';
import { IconRefresh } from '@tabler/icons-react';
import {
    MLStatsCards,
    AttackAnalysisTable,
    AttackDetailModal,
    MLMetricsCharts,
} from '@/components/ml-analysis';
import { AttackAnalysis } from '@/lib/ml-data';

export default function MLAnalysisPage() {
    const [selectedAttack, setSelectedAttack] = useState<AttackAnalysis | null>(null);
    const [selectedSession, setSelectedSession] = useState<{ session_id: string; service: string } | undefined>();
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isRefreshing, setIsRefreshing] = useState(false);

    function handleSelectAttack(attack: AttackAnalysis, session?: { session_id: string; service: string }) {
        setSelectedAttack(attack);
        setSelectedSession(session);
        setIsModalOpen(true);
    }

    function handleRefresh() {
        setIsRefreshing(true);
        setTimeout(() => setIsRefreshing(false), 1000);
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
                        <button
                            onClick={handleRefresh}
                            disabled={isRefreshing}
                            className="p-2 hover:bg-muted transition-colors text-muted-foreground hover:text-primary disabled:opacity-50"
                            title="Refresh data"
                        >
                            <IconRefresh className={`h-5 w-5 ${isRefreshing ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                </div>

                {/* Stats Cards */}
                <section>
                    <MLStatsCards key={isRefreshing ? 'refresh' : 'normal'} />
                </section>

                {/* Charts */}
                <section>
                    <MLMetricsCharts />
                </section>

                {/* Attack Analysis Table */}
                <section>
                    <div className="mb-4">
                        <h2 className="text-xl font-semibold">Attack Analysis</h2>
                        <p className="text-sm text-muted-foreground">
                            Real-time ML predictions on detected threats and attacks
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
