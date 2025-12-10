'use client';

import { useState, useEffect } from 'react';
import {
    IconX,
    IconBrain,
    IconShieldExclamation,
    IconClock,
    IconSparkles,
    IconLoader2,
    IconTarget,
    IconFingerprint,
    IconCode,
    IconNetwork,
    IconUser,
    IconCalendar,
    IconAlertTriangle,
    IconCheck,
    IconExclamationCircle,
    IconServer,
    IconTerminal2,
    IconClipboard,
    IconClipboardCheck,
} from '@tabler/icons-react';
import {
    AttackAnalysis,
    getRiskLevelColor,
    formatTimestamp,
    formatAnomalyScore,
} from '@/lib/ml-data';
import { Badge } from '@/components/ui/badge';

interface AttackDetailModalProps {
    attack: AttackAnalysis | null;
    session?: { session_id: string; service: string; src_ip?: string; username?: string };
    isOpen: boolean;
    onClose: () => void;
}

interface LLMAnalysis {
    success: boolean;
    provider: string;
    model: string;
    generated_at: string;
    analysis: {
        executive_summary: string;
        threat_assessment: {
            classification: string;
            confidence: number;
            reasoning: string;
        };
        attack_analysis: {
            primary_attack_type: string;
            attack_chain_phase: string;
            mitre_techniques: string[];
            attacker_intent: string;
        };
        risk_indicators: string[];
        recommendations: string[];
        forensic_notes: string;
        _fallback?: boolean;
    };
}

export function AttackDetailModal({
    attack,
    session,
    isOpen,
    onClose,
}: AttackDetailModalProps) {
    const [llmAnalysis, setLlmAnalysis] = useState<LLMAnalysis | null>(null);
    const [loadingLLM, setLoadingLLM] = useState(false);
    const [llmError, setLlmError] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);

    // Reset state when modal closes
    useEffect(() => {
        if (!isOpen) {
            setLlmAnalysis(null);
            setLlmError(null);
        }
    }, [isOpen]);

    async function handleGenerateAnalysis() {
        if (!attack) return;
        setLoadingLLM(true);
        setLlmError(null);

        try {
            const response = await fetch('/api/ml/summary', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command: attack.command,
                    timestamp: attack.timestamp,
                    service: session?.service,
                    session_id: session?.session_id,
                    attack_types: attack.attack_types,
                    severity: attack.severity,
                    ml_anomaly_score: attack.ml_metrics?.ml_anomaly_score,
                    ml_risk_level: attack.ml_metrics?.ml_risk_level,
                    ml_confidence: attack.ml_metrics?.ml_confidence,
                    ml_reason: attack.ml_metrics?.ml_reason,
                    indicators: attack.indicators,
                    pattern_matches: attack.pattern_matches,
                    vulnerabilities: attack.vulnerabilities,
                    src_ip: session?.src_ip,
                    username: session?.username,
                }),
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();
            setLlmAnalysis(data);
        } catch (err) {
            console.error('LLM analysis failed:', err);
            setLlmError(err instanceof Error ? err.message : 'Analysis failed');
        } finally {
            setLoadingLLM(false);
        }
    }

    function copyCommand() {
        if (attack?.command) {
            navigator.clipboard.writeText(attack.command);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        }
    }

    if (!attack || !isOpen) return null;

    const ml = attack.ml_metrics;
    const riskColor = ml ? getRiskLevelColor(ml.ml_risk_level) : '#6b7280';

    return (
        <>
            {/* Backdrop - covers entire viewport */}
            <div
                onClick={onClose}
                className="fixed inset-0 z-[999] bg-black/80"
                style={{
                    backdropFilter: 'blur(8px)',
                    WebkitBackdropFilter: 'blur(8px)',
                }}
            />

            {/* Modal Container */}
            <div
                className="fixed z-[1000] flex flex-col overflow-hidden bg-background border border-border shadow-2xl"
                style={{
                    top: '50%',
                    left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: 'min(94vw, 900px)',
                    maxHeight: '85vh',
                }}
            >
                {/* Top accent line */}
                <div
                    className="h-1 w-full"
                    style={{ background: `linear-gradient(90deg, ${riskColor}, ${riskColor}40)` }}
                />

                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 shrink-0 border-b border-border bg-muted/50">
                    <div className="flex items-center gap-4">
                        <div
                            className="p-3 border border-border"
                            style={{ backgroundColor: `${riskColor}15` }}
                        >
                            <IconShieldExclamation className="h-6 w-6" style={{ color: riskColor }} />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold tracking-tight">Attack Analysis</h2>
                            <div className="flex items-center gap-3 mt-1.5">
                                <Badge
                                    variant="outline"
                                    className="uppercase font-mono text-xs px-2.5 py-0.5 border-2 font-semibold"
                                    style={{ borderColor: riskColor, color: riskColor }}
                                >
                                    {session?.service || 'UNKNOWN'}
                                </Badge>
                                <span className="text-sm text-muted-foreground/80 font-medium">
                                    {formatTimestamp(attack.timestamp)}
                                </span>
                            </div>
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-muted transition-colors"
                        aria-label="Close modal"
                    >
                        <IconX className="h-5 w-5 text-muted-foreground hover:text-foreground" />
                    </button>
                </div>

                {/* Scrollable Content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-background">
                    {/* Command Section */}
                    <Section title="COMMAND" icon={<IconTerminal2 className="h-4 w-4" />}>
                        <div className="relative">
                            <code className="block bg-zinc-900 dark:bg-zinc-950 border border-border p-4 font-mono text-sm text-emerald-600 dark:text-emerald-400 overflow-x-auto whitespace-pre-wrap break-all">
                                {attack.command}
                            </code>
                            <button
                                onClick={copyCommand}
                                className="absolute top-2 right-2 p-1.5 bg-zinc-700 hover:bg-zinc-600 transition-colors text-zinc-300 hover:text-white"
                            >
                                {copied ? <IconClipboardCheck className="h-4 w-4 text-emerald-400" /> : <IconClipboard className="h-4 w-4" />}
                            </button>
                        </div>
                    </Section>

                    {/* Session Metadata */}
                    <Section title="SESSION METADATA" icon={<IconServer className="h-4 w-4" />}>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <MetadataItem icon={<IconNetwork className="h-4 w-4" />} label="Source IP" value={session?.src_ip || 'Unknown'} />
                            <MetadataItem icon={<IconUser className="h-4 w-4" />} label="Username" value={session?.username || 'N/A'} />
                            <MetadataItem icon={<IconCalendar className="h-4 w-4" />} label="Timestamp" value={formatTimestamp(attack.timestamp)} />
                            <MetadataItem icon={<IconServer className="h-4 w-4" />} label="Session ID" value={session?.session_id?.slice(0, 12) + '...' || 'N/A'} />
                        </div>
                    </Section>

                    {/* ML Metrics Grid */}
                    {ml && (
                        <Section title="ML ANALYSIS METRICS" icon={<IconBrain className="h-4 w-4" />}>
                            <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
                                <MetricCard
                                    icon={<IconBrain className="h-5 w-5" />}
                                    label="Anomaly Score"
                                    value={formatAnomalyScore(ml.ml_anomaly_score)}
                                    color={ml.ml_anomaly_score > 0.7 ? '#ef4444' : ml.ml_anomaly_score > 0.4 ? '#f59e0b' : '#22c55e'}
                                />
                                <MetricCard
                                    icon={<IconTarget className="h-5 w-5" />}
                                    label="Threat Score"
                                    value={(() => {
                                        // Use attack.threat_score first, then ml_threat_score, then derive from anomaly
                                        const rawScore = attack.threat_score || ml.ml_threat_score || (ml.ml_anomaly_score * 100);
                                        const score = rawScore > 1 ? rawScore : rawScore * 100;
                                        return `${score.toFixed(1)}%`;
                                    })()}
                                    color={(() => {
                                        const rawScore = attack.threat_score || ml.ml_threat_score || (ml.ml_anomaly_score * 100);
                                        const score = rawScore > 1 ? rawScore : rawScore * 100;
                                        return score > 70 ? '#ef4444' : score > 40 ? '#f59e0b' : '#22c55e';
                                    })()}
                                />
                                <MetricCard
                                    icon={<IconFingerprint className="h-5 w-5" />}
                                    label="Confidence"
                                    value={(() => {
                                        // Use ml_confidence, or derive from anomaly score
                                        const conf = ml.ml_confidence || (ml.ml_anomaly_score > 0 ? Math.min(0.95, 0.5 + ml.ml_anomaly_score * 0.5) : 0);
                                        const confPercent = conf > 1 ? conf : conf * 100;
                                        return `${confPercent.toFixed(1)}%`;
                                    })()}
                                    color="#6366f1"
                                />
                                <MetricCard
                                    icon={<IconClock className="h-5 w-5" />}
                                    label="Inference Time"
                                    value={`${(ml.ml_inference_time_ms || 0).toFixed(2)}ms`}
                                    color="#06b6d4"
                                />
                            </div>

                            {/* Risk Level Indicator */}
                            <div className="mt-4 flex items-center gap-3 p-3 border border-border bg-card">
                                <div className="h-3 w-3 animate-pulse" style={{ backgroundColor: riskColor }} />
                                <span className="text-sm font-medium text-foreground">Risk Level:</span>
                                <span className="text-sm font-bold uppercase" style={{ color: riskColor }}>
                                    {ml.ml_risk_level || 'Unknown'}
                                </span>
                            </div>
                        </Section>
                    )}

                    {/* ML Classification Reason */}
                    {ml?.ml_reason && (
                        <Section title="ML CLASSIFICATION REASON" icon={<IconCode className="h-4 w-4" />}>
                            <p className="text-sm text-muted-foreground bg-muted/30 p-4 border border-border">
                                {ml.ml_reason}
                            </p>
                            {(ml.ml_labels?.length || 0) > 0 && (
                                <div className="flex flex-wrap gap-1 mt-3">
                                    {(ml.ml_labels || []).map((label, idx) => (
                                        <Badge key={`${label}-${idx}`} variant="secondary" className="text-xs">
                                            {label}
                                        </Badge>
                                    ))}
                                </div>
                            )}
                        </Section>
                    )}

                    {/* Attack Types & Indicators */}
                    {((attack.attack_types?.length || 0) > 0 || (attack.indicators?.length || 0) > 0) && (
                        <div className="grid gap-6 md:grid-cols-2">
                            {(attack.attack_types?.length || 0) > 0 && (
                                <Section title="ATTACK TYPES" icon={<IconAlertTriangle className="h-4 w-4" />}>
                                    <div className="flex flex-wrap gap-2">
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
                                </Section>
                            )}
                            {(attack.indicators?.length || 0) > 0 && (
                                <Section title="INDICATORS" icon={<IconFingerprint className="h-4 w-4" />}>
                                    <div className="flex flex-wrap gap-2">
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
                                </Section>
                            )}
                        </div>
                    )}

                    {/* Pattern Matches */}
                    {(attack.pattern_matches?.length || 0) > 0 && (
                        <Section title="PATTERN MATCHES" icon={<IconCode className="h-4 w-4" />}>
                            <div className="space-y-2">
                                {(attack.pattern_matches || []).map((match, i) => (
                                    <div
                                        key={i}
                                        className="flex items-center justify-between border border-border bg-muted/20 p-3"
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
                        </Section>
                    )}

                    {/* LLM Analysis Section */}
                    <Section
                        title="AI-POWERED SECURITY ANALYSIS"
                        icon={<IconSparkles className="h-4 w-4" />}
                        highlight
                    >
                        {llmAnalysis ? (
                            <div className="space-y-5">
                                {/* Provider Info */}
                                <div className="flex items-center gap-3 text-xs text-muted-foreground pb-3 border-b border-border">
                                    <span>Generated by</span>
                                    <Badge variant="outline" className="uppercase">{llmAnalysis.provider}</Badge>
                                    <Badge variant="secondary">{llmAnalysis.model}</Badge>
                                    <span className="ml-auto">{new Date(llmAnalysis.generated_at).toLocaleString()}</span>
                                </div>

                                {/* Executive Summary */}
                                <div>
                                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Executive Summary</h4>
                                    <p className="text-sm leading-relaxed">{llmAnalysis.analysis.executive_summary}</p>
                                </div>

                                {/* Threat Assessment */}
                                <div className="p-4 border border-border bg-muted/20">
                                    <div className="flex items-center justify-between mb-3">
                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Threat Assessment</h4>
                                        <Badge
                                            variant={llmAnalysis.analysis.threat_assessment.classification === 'CRITICAL' || llmAnalysis.analysis.threat_assessment.classification === 'MALICIOUS' ? 'destructive' : 'secondary'}
                                            className="text-xs"
                                        >
                                            {llmAnalysis.analysis.threat_assessment.classification}
                                        </Badge>
                                    </div>
                                    <p className="text-sm text-muted-foreground">{llmAnalysis.analysis.threat_assessment.reasoning}</p>
                                    <div className="mt-2 text-xs text-muted-foreground">
                                        Confidence: {(llmAnalysis.analysis.threat_assessment.confidence * 100).toFixed(0)}%
                                    </div>
                                </div>

                                {/* Attack Analysis */}
                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Attack Type</h4>
                                        <p className="text-sm">{llmAnalysis.analysis.attack_analysis.primary_attack_type}</p>
                                    </div>
                                    <div>
                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Kill Chain Phase</h4>
                                        <Badge variant="outline" className="text-xs">{llmAnalysis.analysis.attack_analysis.attack_chain_phase}</Badge>
                                    </div>
                                </div>

                                {/* MITRE Techniques */}
                                {llmAnalysis.analysis.attack_analysis.mitre_techniques.length > 0 && (
                                    <div>
                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">MITRE ATT&CK Techniques</h4>
                                        <div className="flex flex-wrap gap-2">
                                            {llmAnalysis.analysis.attack_analysis.mitre_techniques.map((tech, i) => (
                                                <Badge key={i} variant="secondary" className="text-xs font-mono">{tech}</Badge>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Attacker Intent */}
                                <div>
                                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Attacker Intent</h4>
                                    <p className="text-sm text-muted-foreground italic">{llmAnalysis.analysis.attack_analysis.attacker_intent}</p>
                                </div>

                                {/* Risk Indicators */}
                                {llmAnalysis.analysis.risk_indicators.length > 0 && (
                                    <div>
                                        <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Risk Indicators</h4>
                                        <ul className="space-y-1">
                                            {llmAnalysis.analysis.risk_indicators.map((indicator, i) => (
                                                <li key={i} className="flex items-start gap-2 text-sm">
                                                    <IconExclamationCircle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                                                    <span>{indicator}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}

                                {/* Recommendations */}
                                <div>
                                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Recommendations</h4>
                                    <ul className="space-y-1">
                                        {llmAnalysis.analysis.recommendations.map((rec, i) => (
                                            <li key={i} className="flex items-start gap-2 text-sm">
                                                <IconCheck className="h-4 w-4 text-green-500 shrink-0 mt-0.5" />
                                                <span>{rec}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>

                                {/* Forensic Notes */}
                                <div className="p-3 bg-zinc-950 border border-border">
                                    <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Forensic Notes</h4>
                                    <p className="text-xs font-mono text-zinc-400">{llmAnalysis.analysis.forensic_notes}</p>
                                </div>
                            </div>
                        ) : (
                            <div className="text-center py-6">
                                {llmError ? (
                                    <div className="text-sm text-red-500 mb-4">
                                        <IconAlertTriangle className="h-5 w-5 mx-auto mb-2" />
                                        {llmError}
                                    </div>
                                ) : (
                                    <p className="text-sm text-muted-foreground mb-4">
                                        Generate a comprehensive AI-powered security analysis of this attack using OpenAI or Gemini.
                                    </p>
                                )}
                                <button
                                    onClick={handleGenerateAnalysis}
                                    disabled={loadingLLM}
                                    className="inline-flex items-center gap-2 bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50"
                                >
                                    {loadingLLM ? (
                                        <>
                                            <IconLoader2 className="h-4 w-4 animate-spin" />
                                            Analyzing with AI...
                                        </>
                                    ) : (
                                        <>
                                            <IconSparkles className="h-4 w-4" />
                                            Generate AI Analysis
                                        </>
                                    )}
                                </button>
                            </div>
                        )}
                    </Section>
                </div>
            </div>

            <style jsx global>{`
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                @keyframes slideIn {
                    from { opacity: 0; transform: translateX(-50%) translateY(20px); }
                    to { opacity: 1; transform: translateX(-50%) translateY(0); }
                }
            `}</style>
        </>
    );
}

// Section component
interface SectionProps {
    title: string;
    icon: React.ReactNode;
    children: React.ReactNode;
    highlight?: boolean;
}

function Section({ title, icon, children, highlight }: SectionProps) {
    return (
        <div className={`${highlight ? 'border border-primary/30 bg-primary/5 p-5' : ''}`}>
            <div className="flex items-center gap-2 mb-3">
                <span className="text-primary">{icon}</span>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{title}</h3>
            </div>
            {children}
        </div>
    );
}

// Metadata item
interface MetadataItemProps {
    icon: React.ReactNode;
    label: string;
    value: string;
}

function MetadataItem({ icon, label, value }: MetadataItemProps) {
    return (
        <div className="p-3 bg-card border border-border">
            <div className="flex items-center gap-2 mb-1">
                <span className="text-muted-foreground">{icon}</span>
                <span className="text-xs text-muted-foreground">{label}</span>
            </div>
            <p className="text-sm font-medium text-foreground truncate" title={value}>{value}</p>
        </div>
    );
}

// Metric card
interface MetricCardProps {
    icon: React.ReactNode;
    label: string;
    value: string;
    color: string;
}

function MetricCard({ icon, label, value, color }: MetricCardProps) {
    return (
        <div className="border border-border bg-card p-4">
            <div className="flex items-center gap-2 mb-2">
                <div style={{ color }}>{icon}</div>
                <span className="text-xs text-muted-foreground">{label}</span>
            </div>
            <p className="text-xl font-bold" style={{ color }}>{value}</p>
        </div>
    );
}

export default AttackDetailModal;
