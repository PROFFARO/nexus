'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    IconX,
    IconBrain,
    IconShieldExclamation,
    IconClock,
    IconExternalLink,
    IconSparkles,
    IconLoader2,
    IconAlertTriangle,
    IconTarget,
    IconFingerprint,
    IconCode,
} from '@tabler/icons-react';
import {
    AttackAnalysis,
    generateSessionSummary,
    lookupCVE,
    LLMSummary,
    CVELookupResult,
    getRiskLevelColor,
    formatTimestamp,
    formatAnomalyScore,
} from '@/lib/ml-data';
import { Badge } from '@/components/ui/badge';

interface AttackDetailModalProps {
    attack: AttackAnalysis | null;
    session?: { session_id: string; service: string };
    isOpen: boolean;
    onClose: () => void;
}

export function AttackDetailModal({
    attack,
    session,
    isOpen,
    onClose,
}: AttackDetailModalProps) {
    const [llmSummary, setLlmSummary] = useState<LLMSummary | null>(null);
    const [loadingSummary, setLoadingSummary] = useState(false);
    const [cveResults, setCveResults] = useState<Record<string, CVELookupResult>>({});
    const [loadingCve, setLoadingCve] = useState<string | null>(null);

    // Reset state when modal closes
    useEffect(() => {
        if (!isOpen) {
            setLlmSummary(null);
            setCveResults({});
        }
    }, [isOpen]);

    async function handleGenerateSummary() {
        if (!session) return;
        setLoadingSummary(true);
        try {
            const summary = await generateSessionSummary(session.session_id, session.service);
            setLlmSummary(summary);
        } catch (err) {
            console.error('Failed to generate summary:', err);
        } finally {
            setLoadingSummary(false);
        }
    }

    async function handleLookupCve(cveId: string) {
        setLoadingCve(cveId);
        try {
            const result = await lookupCVE(cveId);
            setCveResults((prev) => ({ ...prev, [cveId]: result }));
        } catch (err) {
            console.error('CVE lookup failed:', err);
        } finally {
            setLoadingCve(null);
        }
    }

    if (!attack) return null;

    const ml = attack.ml_metrics;
    const riskColor = ml ? getRiskLevelColor(ml.ml_risk_level) : '#6b7280';

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                        className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
                    />

                    {/* Modal */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: 20 }}
                        className="fixed inset-4 z-50 mx-auto max-w-4xl overflow-hidden rounded-2xl border border-border/50 bg-card shadow-2xl md:inset-x-auto md:inset-y-8 md:max-h-[90vh]"
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between border-b border-border/50 bg-muted/30 px-6 py-4">
                            <div className="flex items-center gap-3">
                                <div
                                    className="rounded-lg p-2"
                                    style={{ backgroundColor: `${riskColor}20` }}
                                >
                                    <IconShieldExclamation className="h-5 w-5" style={{ color: riskColor }} />
                                </div>
                                <div>
                                    <h2 className="text-lg font-semibold">Attack Analysis</h2>
                                    <p className="text-sm text-muted-foreground">
                                        {session?.service?.toUpperCase()} • {formatTimestamp(attack.timestamp)}
                                    </p>
                                </div>
                            </div>
                            <button
                                onClick={onClose}
                                className="rounded-lg p-2 hover:bg-muted transition-colors"
                            >
                                <IconX className="h-5 w-5" />
                            </button>
                        </div>

                        {/* Content */}
                        <div className="max-h-[calc(90vh-80px)] overflow-y-auto p-6 space-y-6">
                            {/* Command */}
                            <div>
                                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                    Command
                                </label>
                                <code className="mt-2 block rounded-lg bg-muted/50 border border-border/50 p-4 font-mono text-sm overflow-x-auto">
                                    {attack.command}
                                </code>
                            </div>

                            {/* ML Metrics Grid */}
                            {ml && (
                                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                                    <MetricCard
                                        icon={<IconBrain className="h-5 w-5" />}
                                        label="Anomaly Score"
                                        value={formatAnomalyScore(ml.ml_anomaly_score)}
                                        color={ml.ml_anomaly_score > 0.7 ? '#ef4444' : ml.ml_anomaly_score > 0.4 ? '#f59e0b' : '#22c55e'}
                                    />
                                    <MetricCard
                                        icon={<IconTarget className="h-5 w-5" />}
                                        label="Threat Score"
                                        value={`${ml.ml_threat_score}/100`}
                                        color={ml.ml_threat_score > 70 ? '#ef4444' : ml.ml_threat_score > 40 ? '#f59e0b' : '#22c55e'}
                                    />
                                    <MetricCard
                                        icon={<IconFingerprint className="h-5 w-5" />}
                                        label="Confidence"
                                        value={`${(ml.ml_confidence * 100).toFixed(1)}%`}
                                        color="#6366f1"
                                    />
                                    <MetricCard
                                        icon={<IconClock className="h-5 w-5" />}
                                        label="Inference Time"
                                        value={`${ml.ml_inference_time_ms.toFixed(1)}ms`}
                                        color="#06b6d4"
                                    />
                                </div>
                            )}

                            {/* ML Reason */}
                            {ml?.ml_reason && (
                                <div className="rounded-lg border border-border/50 bg-muted/30 p-4">
                                    <div className="flex items-center gap-2 mb-2">
                                        <IconBrain className="h-4 w-4 text-primary" />
                                        <span className="text-sm font-medium">ML Analysis Reason</span>
                                    </div>
                                    <p className="text-sm text-muted-foreground">{ml.ml_reason}</p>
                                    {(ml.ml_labels?.length || 0) > 0 && (
                                        <div className="flex flex-wrap gap-1 mt-3">
                                            {(ml.ml_labels || []).map((label, idx) => (
                                                <Badge key={`${label}-${idx}`} variant="secondary" className="text-xs">
                                                    {label}
                                                </Badge>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Attack Types & Indicators */}
                            {((attack.attack_types?.length || 0) > 0 || (attack.indicators?.length || 0) > 0) && (
                                <div className="grid gap-4 sm:grid-cols-2">
                                    {(attack.attack_types?.length || 0) > 0 && (
                                        <div>
                                            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                                Attack Types
                                            </label>
                                            <div className="flex flex-wrap gap-2 mt-2">
                                                {(attack.attack_types || []).map((type, idx) => (
                                                    <Badge
                                                        key={`${type}-${idx}`}
                                                        variant="destructive"
                                                        className="text-xs"
                                                    >
                                                        {type.replace(/_/g, ' ')}
                                                    </Badge>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    {(attack.indicators?.length || 0) > 0 && (
                                        <div>
                                            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                                Indicators
                                            </label>
                                            <div className="flex flex-wrap gap-2 mt-2">
                                                {(attack.indicators || []).slice(0, 10).map((ind, idx) => (
                                                    <Badge key={`${ind}-${idx}`} variant="outline" className="text-xs">
                                                        {ind.replace(/_/g, ' ')}
                                                    </Badge>
                                                ))}
                                                {(attack.indicators?.length || 0) > 10 && (
                                                    <Badge variant="secondary" className="text-xs">
                                                        +{(attack.indicators?.length || 0) - 10} more
                                                    </Badge>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Pattern Matches */}
                            {(attack.pattern_matches?.length || 0) > 0 && (
                                <div>
                                    <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                        Pattern Matches
                                    </label>
                                    <div className="mt-2 space-y-2">
                                        {(attack.pattern_matches || []).map((match, i) => (
                                            <div
                                                key={i}
                                                className="flex items-center justify-between rounded-lg border border-border/50 bg-muted/20 p-3"
                                            >
                                                <div className="flex items-center gap-3">
                                                    <IconCode className="h-4 w-4 text-muted-foreground" />
                                                    <code className="text-xs font-mono">{match.pattern}</code>
                                                </div>
                                                <Badge
                                                    variant="outline"
                                                    className="text-xs capitalize"
                                                    style={{
                                                        borderColor: getRiskLevelColor(match.severity),
                                                        color: getRiskLevelColor(match.severity),
                                                    }}
                                                >
                                                    {match.type} • {match.severity}
                                                </Badge>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Vulnerabilities */}
                            {(attack.vulnerabilities?.length || 0) > 0 && (
                                <div>
                                    <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                        Vulnerabilities
                                    </label>
                                    <div className="mt-2 space-y-2">
                                        {(attack.vulnerabilities || []).map((vuln, i) => (
                                            <div
                                                key={i}
                                                className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4"
                                            >
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className="font-medium text-sm">{vuln.vuln_name}</span>
                                                    {vuln.cvss_score && (
                                                        <Badge variant="destructive">
                                                            CVSS: {vuln.cvss_score}
                                                        </Badge>
                                                    )}
                                                </div>
                                                <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                                {vuln.vulnerability_id && (
                                                    <button
                                                        onClick={() => handleLookupCve(vuln.vulnerability_id)}
                                                        disabled={loadingCve === vuln.vulnerability_id}
                                                        className="mt-2 flex items-center gap-2 text-xs text-primary hover:underline"
                                                    >
                                                        {loadingCve === vuln.vulnerability_id ? (
                                                            <IconLoader2 className="h-3 w-3 animate-spin" />
                                                        ) : (
                                                            <IconExternalLink className="h-3 w-3" />
                                                        )}
                                                        Lookup {vuln.vulnerability_id}
                                                    </button>
                                                )}
                                                {cveResults[vuln.vulnerability_id] && (
                                                    <div className="mt-2 rounded border border-border/50 bg-muted/50 p-2 text-xs">
                                                        {cveResults[vuln.vulnerability_id].found ? (
                                                            <span>CVE data loaded. {cveResults[vuln.vulnerability_id].data?.summary?.slice(0, 200)}...</span>
                                                        ) : (
                                                            <span className="text-muted-foreground">CVE not found</span>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* LLM Summary Section */}
                            <div className="rounded-xl border border-primary/30 bg-primary/5 p-6">
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center gap-2">
                                        <IconSparkles className="h-5 w-5 text-primary" />
                                        <span className="font-semibold">AI-Powered Summary</span>
                                    </div>
                                    {!llmSummary && (
                                        <button
                                            onClick={handleGenerateSummary}
                                            disabled={loadingSummary || !session}
                                            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
                                        >
                                            {loadingSummary ? (
                                                <>
                                                    <IconLoader2 className="h-4 w-4 animate-spin" />
                                                    Generating...
                                                </>
                                            ) : (
                                                <>
                                                    <IconSparkles className="h-4 w-4" />
                                                    Generate Summary
                                                </>
                                            )}
                                        </button>
                                    )}
                                </div>

                                {llmSummary ? (
                                    <div className="space-y-4">
                                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                            <span>Generated by</span>
                                            <Badge variant="outline">{llmSummary.llm_provider}</Badge>
                                            <Badge variant="secondary">{llmSummary.model}</Badge>
                                        </div>
                                        <p className="text-sm">{llmSummary.summary.overview}</p>
                                        <p className="text-sm font-medium" style={{ color: riskColor }}>
                                            {llmSummary.summary.risk_assessment}
                                        </p>
                                        <p className="text-sm text-muted-foreground">
                                            <strong>Recommendation:</strong> {llmSummary.summary.recommendation}
                                        </p>
                                    </div>
                                ) : (
                                    <p className="text-sm text-muted-foreground">
                                        Click "Generate Summary" to get an AI-powered analysis of this attack using the configured LLM provider.
                                    </p>
                                )}
                            </div>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
}

interface MetricCardProps {
    icon: React.ReactNode;
    label: string;
    value: string;
    color: string;
}

function MetricCard({ icon, label, value, color }: MetricCardProps) {
    return (
        <div className="rounded-lg border border-border/50 bg-muted/20 p-4">
            <div className="flex items-center gap-2 mb-2">
                <div style={{ color }}>{icon}</div>
                <span className="text-xs text-muted-foreground">{label}</span>
            </div>
            <p className="text-xl font-bold" style={{ color }}>{value}</p>
        </div>
    );
}

export default AttackDetailModal;
