'use client';

import { useState, useEffect } from 'react';
import {
    IconRefresh,
    IconServer,
    IconSettings,
} from '@tabler/icons-react';
import {
    MLStatsCards,
    AttackAnalysisTable,
    AttackDetailModal,
    MLMetricsCharts,
} from '@/components/ml-analysis';
import { AttackAnalysis, getActiveServices, ActiveService } from '@/lib/ml-data';
import { Badge } from '@/components/ui/badge';

export default function MLAnalysisPage() {
    const [selectedAttack, setSelectedAttack] = useState<AttackAnalysis | null>(null);
    const [selectedSession, setSelectedSession] = useState<{ session_id: string; service: string } | undefined>();
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [activeServices, setActiveServices] = useState<ActiveService[]>([]);
    const [serviceFilter, setServiceFilter] = useState<string | undefined>();
    const [isRefreshing, setIsRefreshing] = useState(false);

    useEffect(() => {
        async function fetchServices() {
            try {
                const services = await getActiveServices();
                setActiveServices(services);
            } catch (err) {
                console.error('Failed to fetch active services:', err);
            }
        }

        fetchServices();
        const interval = setInterval(fetchServices, 30000);
        return () => clearInterval(interval);
    }, []);

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
                        {/* Active Services Indicator */}
                        <div className="flex items-center gap-2 border border-border/50 bg-card/50 px-4 py-2">
                            <IconServer className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm text-muted-foreground">Active:</span>
                            {activeServices.length > 0 ? (
                                <div className="flex gap-1">
                                    {activeServices.map((svc) => (
                                        <Badge
                                            key={svc.service}
                                            variant="outline"
                                            className="uppercase text-xs cursor-pointer hover:bg-primary/10 rounded-none"
                                            onClick={() => setServiceFilter(
                                                serviceFilter === svc.service ? undefined : svc.service
                                            )}
                                            style={{
                                                borderColor: serviceFilter === svc.service ? 'hsl(var(--primary))' : undefined,
                                                backgroundColor: serviceFilter === svc.service ? 'hsl(var(--primary) / 0.1)' : undefined,
                                            }}
                                        >
                                            {svc.service} ({svc.session_count})
                                        </Badge>
                                    ))}
                                </div>
                            ) : (
                                <span className="text-xs text-muted-foreground">No sessions</span>
                            )}
                        </div>

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

                {/* LLM Configuration Info */}
                {activeServices.length > 0 && (
                    <div className="flex flex-wrap gap-4">
                        {activeServices.map((svc) => (
                            <div
                                key={svc.service}
                                className="flex items-center gap-2 border border-border/30 bg-muted/30 px-3 py-1.5 text-xs"
                            >
                                <IconSettings className="h-3 w-3 text-muted-foreground" />
                                <span className="uppercase font-medium">{svc.service}</span>
                                <span className="text-muted-foreground">LLM:</span>
                                <Badge variant="secondary" className="text-xs rounded-none">
                                    {svc.config.llm_provider} / {svc.config.model_name}
                                </Badge>
                            </div>
                        ))}
                    </div>
                )}

                {/* Stats Cards */}
                <section>
                    <MLStatsCards service={serviceFilter} key={isRefreshing ? 'refresh' : 'normal'} />
                </section>

                {/* Charts */}
                <section>
                    <MLMetricsCharts service={serviceFilter} />
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
                        service={serviceFilter}
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
