"use client";

import React, { useMemo } from "react";
import { motion } from "motion/react";
import {
    IconBrandGithub,
    IconBrandLinkedin,
    IconShieldCheck,
    IconDatabase,
    IconServer,
    IconBrain,
    IconChartBar,
    IconNetwork,
    IconLock,
    IconTerminal2,
    IconFileDatabase,
    IconCpu,
    IconFilter
} from "@tabler/icons-react";
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell,
    RadarChart,
    PolarGrid,
    PolarAngleAxis,
    PolarRadiusAxis,
    Radar,
    Legend
} from "recharts";

import { SparklesCore } from "@/components/ui/sparkles";
import { TextGenerateEffect } from "@/components/ui/text-generate-effect";
import { LayoutTextFlip } from "@/components/ui/layout-text-flip";
import { EncryptedText } from "@/components/ui/encrypted-text";
import { HoverBorderGradient } from "@/components/ui/hover-border-gradient";
import { PinContainer } from "@/components/ui/3d-pin";
import { CardSpotlight } from "@/components/ui/card-spotlight";
import { cn } from "@/lib/utils";
import {
    mlAlgorithms,
    datasets,
    services,
    architectureNodes,
    statistics,
    developerInfo,
    type MLAlgorithm,
    type Dataset,
    type ServiceConfig
} from "@/lib/dashboard-data";

// ============================================================================
// SECTION 0: HERO SECTION WITH SPARKLES
// ============================================================================
export function HeroSection() {
    return (
        <section className="relative w-full min-h-[60vh] flex flex-col items-center justify-center py-20 px-4">
            {/* Sparkles Effect */}
            <div className="w-full absolute inset-0 h-full overflow-hidden">
                <SparklesCore
                    id="hero-sparkles"
                    background="transparent"
                    minSize={0.4}
                    maxSize={1.2}
                    particleDensity={80}
                    className="w-full h-full"
                    particleColor="var(--sparkle-color)"
                />
            </div>

            {/* Main Title */}
            <div className="relative z-10 text-center px-4">
                <motion.h1
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="text-7xl md:text-9xl font-black tracking-tight"
                >
                    <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent inline-block">
                        NEXUS
                    </span>
                </motion.h1>

                {/* Sparkles under title - full width with gradient fade for organic spread */}
                <div className="w-full max-w-4xl h-32 relative mx-auto -mt-2 overflow-visible" style={{ maskImage: 'radial-gradient(ellipse 80% 100% at 50% 0%, black 30%, transparent 70%)', WebkitMaskImage: 'radial-gradient(ellipse 80% 100% at 50% 0%, black 30%, transparent 70%)' }}>
                    {/* Main glow line */}
                    <div className="absolute inset-x-0 top-0 bg-gradient-to-r from-transparent via-cyan-400 to-transparent h-[3px] w-full blur-md opacity-80" />
                    <div className="absolute inset-x-0 top-0 bg-gradient-to-r from-transparent via-cyan-300 to-transparent h-[2px] w-full" />
                    {/* Center accent glow */}
                    <div className="absolute left-1/4 right-1/4 top-0 bg-gradient-to-r from-transparent via-blue-400 to-transparent h-[6px] blur-md opacity-90" />
                    <div className="absolute left-1/4 right-1/4 top-0 bg-gradient-to-r from-transparent via-blue-300 to-transparent h-[2px]" />
                    {/* Extra bright center spot */}
                    <div className="absolute left-1/3 right-1/3 top-0 bg-cyan-300 h-[4px] blur-lg opacity-70" />
                    <SparklesCore
                        id="title-sparkles"
                        background="transparent"
                        minSize={0.5}
                        maxSize={2}
                        particleDensity={600}
                        className="w-full h-full"
                        particleColor="#22d3ee"
                    />
                </div>

                {/* Subtitle */}
                <div className="mt-8 mb-6">
                    <TextGenerateEffect
                        words="AI-Enhanced Honeypot Platform"
                        className="text-xl md:text-2xl text-neutral-600 dark:text-neutral-400"
                    />
                </div>

                {/* Dynamic Text */}
                <div className="flex items-center justify-center gap-3 text-lg md:text-2xl mt-6">
                    <LayoutTextFlip
                        text="Protecting with"
                        words={["SSH Honeypot", "FTP Honeypot", "MySQL Honeypot", "ML Detection", "AI Responses"]}
                        duration={2500}
                    />
                </div>

                {/* Stats Row */}
                <div className="flex flex-wrap justify-center gap-8 mt-12">
                    <StatBadge icon={<IconBrain className="w-5 h-5" />} value="6" label="ML Algorithms" />
                    <StatBadge icon={<IconServer className="w-5 h-5" />} value="3" label="Services" />
                    <StatBadge icon={<IconDatabase className="w-5 h-5" />} value="63+" label="Datasets" />
                    <StatBadge icon={<IconShieldCheck className="w-5 h-5" />} value="1.8GB+" label="Training Data" />
                </div>
            </div>
        </section>
    );
}

function StatBadge({ icon, value, label }: { icon: React.ReactNode; value: string; label: string }) {
    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="flex items-center gap-4 px-6 py-4 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm hover:shadow-md transition-shadow"
        >
            <span className="text-cyan-500">{icon}</span>
            <div className="text-left">
                <div className="text-xl font-bold text-neutral-900 dark:text-white">{value}</div>
                <div className="text-xs text-neutral-500 dark:text-neutral-400">{label}</div>
            </div>
        </motion.div>
    );
}

// ============================================================================
// SECTION 1: ARCHITECTURE DIAGRAM - ANIMATED FLOW VISUALIZATION
// ============================================================================
export function ArchitectureSection() {
    // Calculate dynamic training stats
    const archStats = useMemo(() => {
        let totalSamples = 0;
        const servicesSet = new Set<string>();

        mlAlgorithms.forEach(algo => {
            const services = ["ftp", "mysql", "ssh"] as const;
            services.forEach(service => {
                const metrics = algo.serviceMetrics?.[service];
                if (metrics?.status === "trained" && metrics.training_samples) {
                    servicesSet.add(service.toUpperCase());
                    // Count samples per service only once (use first algorithm's count per service)
                }
            });
        });

        // Get unique sample counts per service (from first algorithm)
        const ftpSamples = mlAlgorithms[0]?.serviceMetrics?.ftp?.training_samples || 0;
        const mysqlSamples = mlAlgorithms[0]?.serviceMetrics?.mysql?.training_samples || 0;
        const sshSamples = mlAlgorithms[0]?.serviceMetrics?.ssh?.training_samples || 0;
        totalSamples = ftpSamples + mysqlSamples + sshSamples;

        const formattedSamples = totalSamples >= 1000
            ? `${Math.round(totalSamples / 1000).toLocaleString()}K+`
            : `${totalSamples.toLocaleString()}+`;

        return {
            trainingSamples: formattedSamples,
            servicesCount: servicesSet.size
        };
    }, []);

    return (
        <section className="w-full py-20 px-4 overflow-hidden">
            <div className="max-w-7xl mx-auto">
                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <h2 className="text-4xl md:text-5xl font-bold mb-4">
                        <EncryptedText
                            text="System Architecture"
                            className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent"
                            revealDelayMs={30}
                        />
                    </h2>
                    <p className="text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
                        Enterprise-grade honeypot platform with AI-powered adaptive responses and ML-driven threat detection
                    </p>
                </motion.div>

                {/* Animated Architecture Flow Diagram */}
                <div className="relative">
                    {/* Main Architecture Container with Glow Effect */}
                    <div className="relative bg-gradient-to-br from-neutral-950 via-neutral-900 to-neutral-950 border border-neutral-800 rounded-2xl p-8 overflow-hidden">
                        {/* Background Grid Pattern */}
                        <div className="absolute inset-0 opacity-10">
                            <div className="absolute inset-0" style={{
                                backgroundImage: `radial-gradient(circle at 1px 1px, rgba(6, 182, 212, 0.3) 1px, transparent 0)`,
                                backgroundSize: '40px 40px'
                            }} />
                        </div>

                        {/* Animated Background Glow */}
                        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyan-500/5 rounded-full blur-3xl animate-pulse" />

                        {/* Architecture Flow */}
                        <div className="relative z-10">
                            {/* Top Row: Attackers -> Honeypots */}
                            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center mb-12">
                                {/* Attackers Section */}
                                <div className="lg:col-span-2">
                                    <motion.div
                                        initial={{ opacity: 0, x: -50 }}
                                        whileInView={{ opacity: 1, x: 0 }}
                                        viewport={{ once: true }}
                                        transition={{ duration: 0.6 }}
                                        className="relative"
                                    >
                                        <div className="text-center mb-4">
                                            <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">Threat Actors</span>
                                        </div>
                                        <div className="flex flex-col gap-3">
                                            {["Attacker 1", "Attacker 2", "Attacker N"].map((attacker, i) => (
                                                <motion.div
                                                    key={attacker}
                                                    initial={{ opacity: 0, y: 20 }}
                                                    whileInView={{ opacity: 1, y: 0 }}
                                                    viewport={{ once: true }}
                                                    transition={{ delay: i * 0.1 + 0.2 }}
                                                    className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg backdrop-blur-sm"
                                                >
                                                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                                                    <span className="text-xs text-red-300">{attacker}</span>
                                                </motion.div>
                                            ))}
                                        </div>
                                    </motion.div>
                                </div>

                                {/* Animated Connection Lines */}
                                <div className="lg:col-span-1 hidden lg:flex items-center justify-center">
                                    <AnimatedConnectionLine direction="right" color="red" />
                                </div>

                                {/* NEXUS Platform - Honeypots */}
                                <div className="lg:col-span-6">
                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.95 }}
                                        whileInView={{ opacity: 1, scale: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ duration: 0.6, delay: 0.3 }}
                                        className="relative"
                                    >
                                        {/* Platform Header */}
                                        <div className="flex items-center justify-center gap-2 mb-6">
                                            <IconShieldCheck className="w-6 h-6 text-cyan-400" />
                                            <span className="text-lg font-bold text-white">NEXUS Platform</span>
                                        </div>

                                        {/* Platform Container */}
                                        <div className="relative p-6 bg-gradient-to-br from-cyan-500/10 to-blue-500/5 border border-cyan-500/30 rounded-xl backdrop-blur-sm">
                                            {/* Glow Effect */}
                                            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-blue-500/5 rounded-xl blur-xl" />

                                            {/* Honeypot Services Row */}
                                            <div className="relative grid grid-cols-3 gap-4 mb-6">
                                                <HoneypotNode
                                                    icon={<IconTerminal2 className="w-6 h-6" />}
                                                    name="SSH"
                                                    port="22/8022"
                                                    color="cyan"
                                                    delay={0.4}
                                                    status="trained"
                                                />
                                                <HoneypotNode
                                                    icon={<IconDatabase className="w-6 h-6" />}
                                                    name="FTP"
                                                    port="21/2121"
                                                    color="purple"
                                                    delay={0.5}
                                                    status="active"
                                                />
                                                <HoneypotNode
                                                    icon={<IconServer className="w-6 h-6" />}
                                                    name="MySQL"
                                                    port="3306/3307"
                                                    color="emerald"
                                                    delay={0.6}
                                                    status="active"
                                                />
                                            </div>

                                            {/* Animated Data Flow Lines to AI Engine */}
                                            <div className="flex justify-center mb-4">
                                                <AnimatedDataFlow />
                                            </div>

                                            {/* AI/ML Engine */}
                                            <div className="grid grid-cols-3 gap-4">
                                                <EngineNode
                                                    icon={<IconCpu className="w-5 h-5" />}
                                                    name="ML Detector"
                                                    detail="6 Algorithms"
                                                    color="blue"
                                                    delay={0.7}
                                                />
                                                <EngineNode
                                                    icon={<IconBrain className="w-5 h-5" />}
                                                    name="LLM Response"
                                                    detail="GPT-4o, Gemini"
                                                    color="purple"
                                                    delay={0.8}
                                                />
                                                <EngineNode
                                                    icon={<IconNetwork className="w-5 h-5" />}
                                                    name="Embeddings"
                                                    detail="Similarity Search"
                                                    color="cyan"
                                                    delay={0.9}
                                                />
                                            </div>

                                            {/* Data Storage Layer */}
                                            <div className="mt-6 pt-4 border-t border-white/10">
                                                <div className="text-center mb-3">
                                                    <span className="text-xs text-neutral-400 uppercase tracking-wider">Data Layer</span>
                                                </div>
                                                <div className="grid grid-cols-3 gap-3">
                                                    <DataNode name="Virtual FS" icon={<IconFileDatabase className="w-4 h-4" />} />
                                                    <DataNode name="Virtual DB" icon={<IconDatabase className="w-4 h-4" />} />
                                                    <DataNode name="Session Logs" icon={<IconLock className="w-4 h-4" />} />
                                                </div>
                                            </div>
                                        </div>
                                    </motion.div>
                                </div>

                                {/* Animated Connection Lines */}
                                <div className="lg:col-span-1 hidden lg:flex items-center justify-center">
                                    <AnimatedConnectionLine direction="right" color="green" />
                                </div>

                                {/* Analysis Section */}
                                <div className="lg:col-span-2">
                                    <motion.div
                                        initial={{ opacity: 0, x: 50 }}
                                        whileInView={{ opacity: 1, x: 0 }}
                                        viewport={{ once: true }}
                                        transition={{ duration: 0.6, delay: 0.5 }}
                                        className="relative"
                                    >
                                        <div className="text-center mb-4">
                                            <span className="text-xs font-semibold text-green-400 uppercase tracking-wider">Analysis Output</span>
                                        </div>
                                        <div className="flex flex-col gap-3">
                                            <AnalysisNode
                                                icon={<IconChartBar className="w-5 h-5" />}
                                                name="REST API"
                                                detail="Real-time Data"
                                                delay={0.6}
                                            />
                                            <AnalysisNode
                                                icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M3 9h18M9 21V9" /></svg>}
                                                name="Web Dashboard"
                                                detail="SIEM Interface"
                                                delay={0.7}
                                            />
                                            <AnalysisNode
                                                icon={<IconFileDatabase className="w-5 h-5" />}
                                                name="Security Reports"
                                                detail="JSON, HTML, PDF"
                                                delay={0.8}
                                            />
                                        </div>
                                    </motion.div>
                                </div>
                            </div>

                            {/* Technical Details Legend */}
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true }}
                                transition={{ delay: 0.8 }}
                                className="mt-8 grid grid-cols-2 md:grid-cols-4 gap-4"
                            >
                                <TechStat label="Training Samples" value={archStats.trainingSamples} icon="📊" />
                                <TechStat label="ML Algorithms" value="6 Active" icon="🤖" />
                                <TechStat label="AI Providers" value="5 Integrated" icon="🧠" />
                                <TechStat label="Attack Detection" value="Real-time" icon="⚡" />
                            </motion.div>
                        </div>
                    </div>
                </div>

                {/* Detailed Flow Cards */}
                <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
                    <FlowCard
                        title="AI-Powered Responses"
                        items={["OpenAI GPT-4o", "Google Gemini", "AWS Bedrock", "Azure OpenAI", "Ollama (Local)"]}
                        icon={<IconBrain className="w-6 h-6" />}
                    />
                    <FlowCard
                        title="Real-time ML Detection"
                        items={["Isolation Forest", "One-Class SVM", "LOF", "HDBSCAN", "K-Means", "XGBoost"]}
                        icon={<IconCpu className="w-6 h-6" />}
                    />
                    <FlowCard
                        title="Forensic Capabilities"
                        items={["Chain of Custody", "Session Recording", "Attack Timeline", "Evidence Hashing", "Replay Capability"]}
                        icon={<IconLock className="w-6 h-6" />}
                    />
                </div>
            </div>
        </section>
    );
}

// Animated Data Flow Component
function AnimatedDataFlow() {
    return (
        <motion.div className="relative h-8 w-full flex items-center justify-center">
            {/* Flow Lines */}
            <div className="absolute inset-0 flex items-center justify-center">
                <motion.div
                    initial={{ scaleY: 0 }}
                    whileInView={{ scaleY: 1 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.5, delay: 0.6 }}
                    className="w-px h-full bg-gradient-to-b from-cyan-500/50 to-purple-500/50"
                />
            </div>
            {/* Animated Pulse */}
            <motion.div
                animate={{ y: [0, 20, 0] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                className="absolute w-2 h-2 bg-cyan-400 rounded-full shadow-lg shadow-cyan-400/50"
            />
        </motion.div>
    );
}

// Animated Connection Line
function AnimatedConnectionLine({ direction, color }: { direction: "right" | "down"; color: "red" | "green" | "cyan" }) {
    const colorClasses = {
        red: "from-red-500/50 to-orange-500/50",
        green: "from-blue-500/50 to-green-500/50",
        cyan: "from-cyan-500/50 to-blue-500/50"
    };

    const packetColors = {
        red: "bg-red-400 shadow-red-400/50",
        green: "bg-green-400 shadow-green-400/50",
        cyan: "bg-cyan-400 shadow-cyan-400/50"
    };

    return (
        <div className="relative w-full h-1 flex items-center">
            {/* Base Line */}
            <motion.div
                initial={{ scaleX: 0 }}
                whileInView={{ scaleX: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5 }}
                className={cn("w-full h-0.5 bg-gradient-to-r", colorClasses[color])}
            />
            {/* Animated Data Packet */}
            <motion.div
                animate={{ x: ["0%", "400%", "0%"] }}
                transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
                className={cn("absolute left-0 w-3 h-3 rounded-full shadow-lg", packetColors[color])}
            />
            {/* Arrow */}
            <div className={cn("absolute right-0 w-0 h-0 border-t-4 border-b-4 border-l-8 border-transparent",
                color === "red" ? "border-l-red-500/50" : color === "green" ? "border-l-green-500/50" : "border-l-cyan-500/50"
            )} />
        </div>
    );
}

// Honeypot Node Component
function HoneypotNode({
    icon,
    name,
    port,
    color,
    delay,
    status
}: {
    icon: React.ReactNode;
    name: string;
    port: string;
    color: "cyan" | "purple" | "emerald";
    delay: number;
    status: "active" | "trained" | "training";
}) {
    const colorClasses = {
        cyan: "from-cyan-500/20 to-cyan-600/10 border-cyan-500/40 text-cyan-400",
        purple: "from-purple-500/20 to-purple-600/10 border-purple-500/40 text-purple-400",
        emerald: "from-emerald-500/20 to-emerald-600/10 border-emerald-500/40 text-emerald-400"
    };

    const glowColors = {
        cyan: "shadow-cyan-500/20",
        purple: "shadow-purple-500/20",
        emerald: "shadow-emerald-500/20"
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay }}
            whileHover={{ scale: 1.05, y: -5 }}
            className={cn(
                "relative p-4 rounded-xl bg-gradient-to-br border backdrop-blur-sm transition-all duration-300 cursor-pointer",
                "shadow-lg hover:shadow-xl",
                colorClasses[color],
                glowColors[color]
            )}
        >
            {/* Pulse Effect */}
            <motion.div
                animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.2, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
                className={cn("absolute -inset-1 rounded-xl blur-xl",
                    color === "cyan" ? "bg-cyan-500/10" : color === "purple" ? "bg-purple-500/10" : "bg-emerald-500/10"
                )}
            />
            <div className="relative flex flex-col items-center text-center gap-2">
                <div className={cn("p-2 rounded-lg bg-black/30", colorClasses[color].split(" ").slice(-1)[0])}>
                    {icon}
                </div>
                <h4 className="font-bold text-white text-sm">{name} Honeypot</h4>
                <span className="text-xs text-neutral-400">Port: {port}</span>
                <div className="flex items-center gap-1.5">
                    <div className={cn("w-1.5 h-1.5 rounded-full animate-pulse",
                        status === "active" ? "bg-green-400" : status === "trained" ? "bg-cyan-400" : "bg-yellow-400"
                    )} />
                    <span className="text-[10px] text-neutral-500 uppercase">{status}</span>
                </div>
            </div>
        </motion.div>
    );
}

// Engine Node Component
function EngineNode({
    icon,
    name,
    detail,
    color,
    delay
}: {
    icon: React.ReactNode;
    name: string;
    detail: string;
    color: "blue" | "purple" | "cyan";
    delay: number;
}) {
    const colorClasses = {
        blue: "border-blue-500/30 text-blue-400",
        purple: "border-purple-500/30 text-purple-400",
        cyan: "border-cyan-500/30 text-cyan-400"
    };

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay }}
            className={cn("p-3 rounded-lg bg-black/30 border text-center", colorClasses[color])}
        >
            <div className="flex items-center justify-center gap-2 mb-1">
                {icon}
                <span className="text-xs font-semibold text-white">{name}</span>
            </div>
            <span className="text-[10px] text-neutral-500">{detail}</span>
        </motion.div>
    );
}

// Data Node Component
function DataNode({ name, icon }: { name: string; icon: React.ReactNode }) {
    return (
        <div className="flex items-center justify-center gap-2 px-3 py-2 bg-neutral-800/50 rounded-lg border border-neutral-700/50">
            <span className="text-cyan-400">{icon}</span>
            <span className="text-[10px] text-neutral-400">{name}</span>
        </div>
    );
}

// Analysis Node Component
function AnalysisNode({
    icon,
    name,
    detail,
    delay
}: {
    icon: React.ReactNode;
    name: string;
    detail: string;
    delay: number;
}) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay }}
            className="flex items-center gap-3 px-4 py-3 bg-green-500/10 border border-green-500/30 rounded-lg backdrop-blur-sm"
        >
            <div className="p-2 rounded-lg bg-green-500/20 text-green-400">
                {icon}
            </div>
            <div>
                <h5 className="text-sm font-semibold text-white">{name}</h5>
                <span className="text-[10px] text-neutral-400">{detail}</span>
            </div>
        </motion.div>
    );
}

// Tech Stat Component
function TechStat({ label, value, icon }: { label: string; value: string; icon: string }) {
    return (
        <div className="flex items-center gap-3 px-4 py-3 bg-white/5 rounded-lg border border-white/10">
            <span className="text-2xl">{icon}</span>
            <div>
                <p className="text-sm font-bold text-white">{value}</p>
                <p className="text-[10px] text-neutral-400">{label}</p>
            </div>
        </div>
    );
}

function FlowCard({ title, items, icon }: { title: string; items: string[]; icon: React.ReactNode }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm hover:shadow-md transition-shadow"
        >
            <div className="flex items-center gap-3 mb-4 text-cyan-500">
                {icon}
                <h4 className="font-semibold text-neutral-900 dark:text-white">{title}</h4>
            </div>
            <ul className="space-y-2">
                {items.map((item, i) => (
                    <li key={i} className="text-sm text-neutral-600 dark:text-neutral-400 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-cyan-500" />
                        {item}
                    </li>
                ))}
            </ul>
        </motion.div>
    );
}

// ============================================================================
// SECTION 1.5: COMMAND PROCESSING FLOW - 3-LAYER ARCHITECTURE
// ============================================================================
export function CommandProcessingSection() {
    return (
        <section id="command-processing" className="w-full py-20 px-4 overflow-hidden">
            <div className="max-w-7xl mx-auto">
                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <h2 className="text-4xl md:text-5xl font-bold mb-4">
                        <span className="bg-gradient-to-r from-purple-400 via-pink-500 to-red-500 bg-clip-text text-transparent">
                            Command Processing
                        </span>
                    </h2>
                    <p className="text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
                        3-layer intelligent command execution with deterministic processing, validation, and LLM fallback
                    </p>
                </motion.div>

                {/* Main Processing Flow Container */}
                <div className="relative bg-gradient-to-br from-neutral-950 via-neutral-900 to-neutral-950 border border-neutral-800 rounded-2xl p-8 overflow-hidden">
                    {/* Background Effects */}
                    <div className="absolute inset-0 opacity-10">
                        <div className="absolute inset-0" style={{
                            backgroundImage: `radial-gradient(circle at 1px 1px, rgba(168, 85, 247, 0.3) 1px, transparent 0)`,
                            backgroundSize: '40px 40px'
                        }} />
                    </div>
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-purple-500/5 rounded-full blur-3xl animate-pulse" />

                    <div className="relative z-10">
                        {/* Incoming Command */}
                        <motion.div
                            initial={{ opacity: 0, x: -50 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            viewport={{ once: true }}
                            className="flex justify-center mb-8"
                        >
                            <div className="inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/40 rounded-xl">
                                <motion.div
                                    animate={{ scale: [1, 1.2, 1] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                    className="w-3 h-3 bg-cyan-400 rounded-full shadow-lg shadow-cyan-400/50"
                                />
                                <span className="text-lg font-bold text-white">Incoming Command</span>
                                <code className="text-sm text-cyan-300 bg-black/30 px-2 py-1 rounded font-mono">ls -la /etc</code>
                            </div>
                        </motion.div>

                        {/* Animated Arrow Down */}
                        <div className="flex justify-center mb-8">
                            <AnimatedVerticalFlow color="cyan" />
                        </div>

                        {/* Three Layers */}
                        <div id="command-processing-layers" className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                            {/* Layer 1: Deterministic Execution */}
                            <ProcessingLayer
                                id="command-processing-layer1"
                                layerNumber={1}
                                title="Deterministic Execution"
                                color="cyan"
                                delay={0.2}
                                nodes={[
                                    { name: "Command Parser", detail: "Syntax Analysis", icon: "⚡" },
                                    { name: "Virtual Filesystem", detail: "Simulated FS/DB", icon: "📁" }
                                ]}
                                flowResult="success"
                                flowLabel="Success → Response"
                                flowColor="green"
                            />

                            {/* Layer 2: Validation & Error Handling */}
                            <ProcessingLayer
                                id="command-processing-layer2"
                                layerNumber={2}
                                title="Validation & Error Handling"
                                color="yellow"
                                delay={0.4}
                                nodes={[
                                    { name: "Syntax Validation", detail: "Command Structure", icon: "✓" },
                                    { name: "Injection Detection", detail: "Security Filter", icon: "🛡️" },
                                    { name: "Error Simulation", detail: "Realistic Errors", icon: "⚠️" }
                                ]}
                                flowResult="fallback"
                                flowLabel="Not Handled → Layer 2"
                                flowColor="yellow"
                            />

                            {/* Layer 3: LLM Fallback */}
                            <ProcessingLayer
                                id="command-processing-layer3"
                                layerNumber={3}
                                title="LLM Fallback"
                                color="purple"
                                delay={0.6}
                                nodes={[
                                    { name: "LLM Guard", detail: "Prompt Injection Filter", icon: "🔒" },
                                    { name: "LLM Response", detail: "GPT-4o / Gemini", icon: "🧠" },
                                    { name: "Output Cleaning", detail: "Response Sanitization", icon: "✨" }
                                ]}
                                flowResult="response"
                                flowLabel="Clean → LLM Response"
                                flowColor="purple"
                            />
                        </div>

                        {/* Final Response */}
                        <div className="flex justify-center mt-8">
                            <AnimatedVerticalFlow color="green" />
                        </div>

                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: 0.8 }}
                            className="flex justify-center mt-8"
                        >
                            <div className="inline-flex items-center gap-3 px-8 py-5 bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/40 rounded-xl">
                                <motion.div
                                    animate={{ scale: [1, 1.3, 1], opacity: [0.5, 1, 0.5] }}
                                    transition={{ duration: 1.5, repeat: Infinity }}
                                    className="w-4 h-4 bg-green-400 rounded-full shadow-lg shadow-green-400/50"
                                />
                                <span className="text-xl font-bold text-white">Response</span>
                                <span className="text-sm text-green-300">Delivered to Attacker</span>
                            </div>
                        </motion.div>

                        {/* Flow Statistics */}
                        <motion.div
                            id="command-processing-stats"
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: 1 }}
                            className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-4"
                        >
                            <ProcessingStat label="Deterministic Hit Rate" value="~70%" icon="⚡" color="cyan" />
                            <ProcessingStat label="Validation Pass Rate" value="~25%" icon="✓" color="yellow" />
                            <ProcessingStat label="LLM Fallback" value="~5%" icon="🧠" color="purple" />
                            <ProcessingStat label="Avg Response Time" value="<50ms" icon="⏱️" color="green" />
                        </motion.div>
                    </div>
                </div>

                {/* Detailed Layer Cards */}
                <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
                    <LayerDetailCard
                        title="Layer 1: Deterministic"
                        description="Fast, predictable command execution using pre-programmed responses and virtual filesystem operations."
                        features={["Command pattern matching", "Virtual filesystem operations", "Pre-built response templates", "Zero latency execution"]}
                        color="cyan"
                    />
                    <LayerDetailCard
                        title="Layer 2: Validation"
                        description="Security validation layer that detects injection attempts and generates realistic error responses."
                        features={["SQL/Command injection detection", "Syntax validation", "Error message simulation", "Attack pattern logging"]}
                        color="yellow"
                    />
                    <LayerDetailCard
                        title="Layer 3: LLM Fallback"
                        description="Intelligent AI-powered response generation for unhandled commands with prompt injection protection."
                        features={["LLM Guard protection", "GPT-4o / Gemini integration", "Context-aware responses", "Output sanitization"]}
                        color="purple"
                    />
                </div>
            </div>
        </section>
    );
}

// Processing Layer Component
function ProcessingLayer({
    id,
    layerNumber,
    title,
    color,
    delay,
    nodes,
    flowResult,
    flowLabel,
    flowColor
}: {
    id?: string;
    layerNumber: number;
    title: string;
    color: "cyan" | "yellow" | "purple";
    delay: number;
    nodes: { name: string; detail: string; icon: string }[];
    flowResult: "success" | "fallback" | "response";
    flowLabel: string;
    flowColor: "green" | "yellow" | "purple";
}) {
    const colorClasses = {
        cyan: "from-cyan-500/20 to-cyan-600/10 border-cyan-500/40",
        yellow: "from-yellow-500/20 to-orange-500/10 border-yellow-500/40",
        purple: "from-purple-500/20 to-pink-500/10 border-purple-500/40"
    };

    const flowColorClasses = {
        green: "text-green-400 border-green-500/30 bg-green-500/10",
        yellow: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
        purple: "text-purple-400 border-purple-500/30 bg-purple-500/10"
    };

    const headerColors = {
        cyan: "text-cyan-400",
        yellow: "text-yellow-400",
        purple: "text-purple-400"
    };

    return (
        <motion.div
            id={id}
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay }}
            className={cn(
                "relative p-6 rounded-xl bg-gradient-to-br border backdrop-blur-sm",
                colorClasses[color]
            )}
        >
            {/* Layer Header */}
            <div className="flex items-center gap-3 mb-6">
                <div className={cn(
                    "w-10 h-10 rounded-lg flex items-center justify-center text-lg font-bold",
                    color === "cyan" ? "bg-cyan-500/20 text-cyan-400" :
                        color === "yellow" ? "bg-yellow-500/20 text-yellow-400" :
                            "bg-purple-500/20 text-purple-400"
                )}>
                    {layerNumber}
                </div>
                <div>
                    <h3 className={cn("font-bold text-white text-sm", headerColors[color])}>{title}</h3>
                    <span className="text-xs text-neutral-500">Layer {layerNumber}</span>
                </div>
            </div>

            {/* Processing Nodes */}
            <div className="space-y-3 mb-6">
                {nodes.map((node, i) => (
                    <motion.div
                        key={node.name}
                        initial={{ opacity: 0, x: -20 }}
                        whileInView={{ opacity: 1, x: 0 }}
                        viewport={{ once: true }}
                        transition={{ delay: delay + (i * 0.1) }}
                        className="flex items-center gap-3 p-3 bg-black/30 rounded-lg border border-white/5"
                    >
                        <span className="text-xl">{node.icon}</span>
                        <div>
                            <p className="text-sm font-semibold text-white">{node.name}</p>
                            <p className="text-xs text-neutral-500">{node.detail}</p>
                        </div>
                    </motion.div>
                ))}
            </div>

            {/* Flow Result Indicator */}
            <motion.div
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                transition={{ delay: delay + 0.3 }}
                className={cn(
                    "flex items-center gap-2 px-3 py-2 rounded-lg border text-xs",
                    flowColorClasses[flowColor]
                )}
            >
                <motion.div
                    animate={{ x: [0, 5, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                >
                    →
                </motion.div>
                <span>{flowLabel}</span>
            </motion.div>
        </motion.div>
    );
}

// Animated Vertical Flow
function AnimatedVerticalFlow({ color }: { color: "cyan" | "green" | "purple" }) {
    const colorClasses = {
        cyan: "from-cyan-500/50 to-cyan-500/0",
        green: "from-green-500/50 to-green-500/0",
        purple: "from-purple-500/50 to-purple-500/0"
    };

    const packetColors = {
        cyan: "bg-cyan-400 shadow-cyan-400/50",
        green: "bg-green-400 shadow-green-400/50",
        purple: "bg-purple-400 shadow-purple-400/50"
    };

    return (
        <div className="relative h-12 w-1 flex flex-col items-center">
            <motion.div
                initial={{ scaleY: 0 }}
                whileInView={{ scaleY: 1 }}
                viewport={{ once: true }}
                className={cn("w-0.5 h-full bg-gradient-to-b", colorClasses[color])}
            />
            <motion.div
                animate={{ y: [0, 40, 0] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                className={cn("absolute top-0 w-2 h-2 rounded-full shadow-lg", packetColors[color])}
            />
            <div className={cn(
                "absolute bottom-0 w-0 h-0 border-l-4 border-r-4 border-t-8 border-transparent",
                color === "cyan" ? "border-t-cyan-500/50" :
                    color === "green" ? "border-t-green-500/50" :
                        "border-t-purple-500/50"
            )} />
        </div>
    );
}

// Processing Stat Component
function ProcessingStat({ label, value, icon, color }: { label: string; value: string; icon: string; color: "cyan" | "yellow" | "purple" | "green" }) {
    const colorClasses = {
        cyan: "border-cyan-500/30 bg-cyan-500/5",
        yellow: "border-yellow-500/30 bg-yellow-500/5",
        purple: "border-purple-500/30 bg-purple-500/5",
        green: "border-green-500/30 bg-green-500/5"
    };

    const textColors = {
        cyan: "text-cyan-400",
        yellow: "text-yellow-400",
        purple: "text-purple-400",
        green: "text-green-400"
    };

    return (
        <div className={cn("flex items-center gap-3 px-4 py-3 rounded-lg border", colorClasses[color])}>
            <span className="text-2xl">{icon}</span>
            <div>
                <p className={cn("text-sm font-bold", textColors[color])}>{value}</p>
                <p className="text-[10px] text-neutral-500">{label}</p>
            </div>
        </div>
    );
}

// Layer Detail Card Component
function LayerDetailCard({
    title,
    description,
    features,
    color
}: {
    title: string;
    description: string;
    features: string[];
    color: "cyan" | "yellow" | "purple";
}) {
    const borderColors = {
        cyan: "hover:border-cyan-500/50",
        yellow: "hover:border-yellow-500/50",
        purple: "hover:border-purple-500/50"
    };

    const iconColors = {
        cyan: "text-cyan-500",
        yellow: "text-yellow-500",
        purple: "text-purple-500"
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className={cn(
                "p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm hover:shadow-md transition-all",
                borderColors[color]
            )}
        >
            <h4 className={cn("font-semibold text-neutral-900 dark:text-white mb-2", iconColors[color])}>{title}</h4>
            <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-4">{description}</p>
            <ul className="space-y-2">
                {features.map((feature, i) => (
                    <li key={i} className="text-sm text-neutral-500 dark:text-neutral-400 flex items-center gap-2">
                        <span className={cn("w-1.5 h-1.5",
                            color === "cyan" ? "bg-cyan-500" :
                                color === "yellow" ? "bg-yellow-500" :
                                    "bg-purple-500"
                        )} />
                        {feature}
                    </li>
                ))}
            </ul>
        </motion.div>
    );
}

// ============================================================================
// SECTION 2: ML ALGORITHMS
// ============================================================================
export function MLSection() {
    // Dynamically calculate stats from data
    const mlStats = useMemo(() => {
        // Calculate total training samples across all services
        let totalTrainingSamples = 0;
        let servicesTrainedSet = new Set<string>();
        let highestAccuracy = 0;
        let highestAccuracyModel = "";
        let highestAccuracyService = "";

        mlAlgorithms.forEach(algo => {
            // Check each service
            const services = ["ftp", "mysql", "ssh"] as const;
            services.forEach(service => {
                const metrics = algo.serviceMetrics?.[service];
                if (metrics?.status === "trained") {
                    servicesTrainedSet.add(service.toUpperCase());

                    // Add training samples (only count once per service per algorithm)
                    if (metrics.training_samples) {
                        totalTrainingSamples += metrics.training_samples;
                    }

                    // Check for highest accuracy
                    const accuracyStr = metrics.accuracy;
                    if (accuracyStr && typeof accuracyStr === "string" && accuracyStr !== "Pending") {
                        const accuracyNum = parseFloat(accuracyStr.replace("%", ""));
                        if (accuracyNum > highestAccuracy) {
                            highestAccuracy = accuracyNum;
                            highestAccuracyModel = algo.name.split(" ")[0];
                            highestAccuracyService = service.toUpperCase();
                        }
                    }
                }
            });
        });

        // Format training samples (remove duplicates by dividing by algos that use same data)
        const uniqueTrainingSamples = Math.round(totalTrainingSamples / mlAlgorithms.length);
        const formattedSamples = uniqueTrainingSamples >= 1000
            ? `${(uniqueTrainingSamples / 1000).toFixed(1)}K+`
            : `${uniqueTrainingSamples}+`;

        return {
            totalAlgorithms: mlAlgorithms.length,
            highestAccuracy: `${highestAccuracy.toFixed(1)}%`,
            highestAccuracyLabel: `${highestAccuracyService} ${highestAccuracyModel}`,
            trainingSamples: formattedSamples,
            servicesTrainedCount: servicesTrainedSet.size,
            servicesTrainedLabel: Array.from(servicesTrainedSet).join(" • ")
        };
    }, []);

    // Chart data
    const accuracyData = mlAlgorithms.map(algo => ({
        name: algo.name.split(" ")[0],
        accuracy: algo.accuracy && algo.accuracy !== "N/A" ? parseFloat(String(algo.accuracy).replace(/[^0-9.]/g, "")) : 0,
        fill: algo.type === "Anomaly Detection" ? "#06b6d4" : algo.type === "Clustering" ? "#8b5cf6" : "#10b981"
    }));

    const typeDistribution = [
        { name: "Anomaly Detection", value: 3, color: "#06b6d4" },
        { name: "Clustering", value: 2, color: "#8b5cf6" },
        { name: "Supervised", value: 1, color: "#10b981" }
    ];

    const radarData = mlAlgorithms.map(algo => ({
        algorithm: algo.name.split(" ")[0],
        accuracy: algo.accuracy && algo.accuracy !== "N/A" ? parseFloat(String(algo.accuracy).replace(/[^0-9.]/g, "")) : 0,
        fullMark: 100
    }));

    return (
        <section className="w-full py-20 px-4">
            <div className="max-w-7xl mx-auto">
                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <h2 className="text-4xl md:text-5xl font-bold mb-4">
                        <span className="bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">
                            Machine Learning
                        </span>
                    </h2>
                    <p className="text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
                        6 advanced ML algorithms for comprehensive threat detection and classification
                    </p>
                </motion.div>

                {/* ML Algorithm Cards with 3D Pin Effect */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
                    {mlAlgorithms.map((algo, index) => (
                        <MLAlgorithmCard key={algo.id} algorithm={algo} index={index} />
                    ))}
                </div>

                {/* Visualizations */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-16">
                    {/* Accuracy Bar Chart - Best Model Performance */}
                    <div className="p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                        <h3 className="text-lg font-semibold mb-2 text-neutral-900 dark:text-white">Algorithm Accuracy</h3>
                        <p className="text-xs text-neutral-500 mb-4">Best Model: {mlStats.highestAccuracyLabel} ({mlStats.highestAccuracy})</p>
                        <ResponsiveContainer width="100%" height={250}>
                            <BarChart data={accuracyData} layout="vertical">
                                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                <XAxis type="number" domain={[0, 100]} stroke="#9ca3af" />
                                <YAxis dataKey="name" type="category" width={80} stroke="#9ca3af" fontSize={12} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151", borderRadius: "8px" }}
                                    labelStyle={{ color: "#fff" }}
                                    formatter={(value: number) => [`${value.toFixed(1)}%`, "Accuracy"]}
                                />
                                <Bar dataKey="accuracy" radius={[0, 4, 4, 0]}>
                                    {accuracyData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.fill} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Algorithm Type Distribution */}
                    <div className="p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                        <h3 className="text-lg font-semibold mb-4 text-neutral-900 dark:text-white">Algorithm Types</h3>
                        <ResponsiveContainer width="100%" height={250}>
                            <PieChart>
                                <Pie
                                    data={typeDistribution}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {typeDistribution.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151", borderRadius: "8px" }}
                                />
                                <Legend />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Radar Chart */}
                    <div className="p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                        <h3 className="text-lg font-semibold mb-4 text-neutral-900 dark:text-white">Performance Radar</h3>
                        <ResponsiveContainer width="100%" height={250}>
                            <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                                <PolarGrid stroke="#374151" />
                                <PolarAngleAxis dataKey="algorithm" stroke="#9ca3af" fontSize={10} />
                                <PolarRadiusAxis angle={90} domain={[0, 100]} stroke="#9ca3af" />
                                <Radar name="Accuracy" dataKey="accuracy" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.5} />
                            </RadarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* ML Stats Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-12">
                    <StatsCard title="Total Algorithms" value={String(mlStats.totalAlgorithms)} subtitle="Active Models" icon={<IconCpu />} />
                    <StatsCard title="Highest Accuracy" value={mlStats.highestAccuracy} subtitle={mlStats.highestAccuracyLabel} icon={<IconChartBar />} />
                    <StatsCard title="Training Samples" value={mlStats.trainingSamples} subtitle={mlStats.servicesTrainedLabel} icon={<IconFileDatabase />} />
                    <StatsCard title="Services Trained" value={String(mlStats.servicesTrainedCount)} subtitle={mlStats.servicesTrainedLabel} icon={<IconServer />} />
                </div>
            </div>
        </section>
    );
}

function MLAlgorithmCard({ algorithm, index }: { algorithm: MLAlgorithm; index: number }) {
    const typeColors: Record<string, string> = {
        "Anomaly Detection": "text-cyan-400",
        "Clustering": "text-purple-400",
        "Supervised Learning": "text-green-400"
    };

    // Get display title based on algorithm type
    const getDisplayTitle = (): string => {
        if (algorithm.type === "Clustering") {
            const score = algorithm.silhouette_score;
            return `Silhouette: ${typeof score === "number" ? score.toFixed(3) : "N/A"}`;
        }
        if (algorithm.type === "Supervised Learning") {
            return String(algorithm.accuracy ?? "N/A");
        }
        return String(algorithm.accuracy ?? "N/A");
    };

    // Render metrics based on algorithm type
    const renderMetrics = () => {
        if (algorithm.type === "Clustering") {
            // Get silhouette scores for display
            const ftpSilhouette = algorithm.serviceMetrics?.ftp?.silhouette_score;
            const mysqlSilhouette = algorithm.serviceMetrics?.mysql?.silhouette_score;
            const sshSilhouette = algorithm.serviceMetrics?.ssh?.silhouette_score;

            return (
                <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                        <span className="text-slate-500">Max Clusters:</span>
                        <span className="text-purple-400 font-semibold">{algorithm.clusters ?? "N/A"}</span>
                    </div>
                    <div className="pt-2 border-t border-white/5 space-y-1">
                        <div className="flex justify-between">
                            <span className="text-slate-500">FTP:</span>
                            <span className="text-green-400">
                                {algorithm.serviceMetrics?.ftp?.clusters ?? "—"} <span className="text-slate-500">|</span> {typeof ftpSilhouette === "number" ? ftpSilhouette.toFixed(2) : "—"}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-slate-500">MySQL:</span>
                            <span className="text-emerald-400">
                                {algorithm.serviceMetrics?.mysql?.clusters ?? "—"} <span className="text-slate-500">|</span> {typeof mysqlSilhouette === "number" ? mysqlSilhouette.toFixed(2) : "—"}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-slate-500">SSH:</span>
                            <span className="text-yellow-400">
                                {algorithm.serviceMetrics?.ssh?.clusters ?? 0} <span className="text-slate-500">|</span> {typeof sshSilhouette === "number" ? sshSilhouette.toFixed(2) : "—"}
                            </span>
                        </div>
                    </div>
                    <div className="text-[13px] text-slate-400 text-right font-medium">clusters <span className="text-cyan-500/70">|</span> silhouette</div>
                </div>
            );
        }

        if (algorithm.type === "Supervised Learning") {
            return (
                <div className="space-y-2 text-xs">
                    <div className="flex justify-between">
                        <span className="text-slate-500">Best Accuracy:</span>
                        <span className="text-green-400 font-semibold">{algorithm.accuracy ?? "N/A"}</span>
                    </div>
                    <div className="pt-2 border-t border-white/5 space-y-1">
                        <div className="flex justify-between">
                            <span className="text-slate-500">FTP:</span>
                            <span className="text-green-400">{algorithm.serviceMetrics?.ftp?.accuracy ?? "—"}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-slate-500">MySQL:</span>
                            <span className="text-emerald-400">{algorithm.serviceMetrics?.mysql?.accuracy ?? "—"}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-slate-500">SSH:</span>
                            <span className="text-yellow-400">{algorithm.serviceMetrics?.ssh?.accuracy ?? "Pending"}</span>
                        </div>
                    </div>
                </div>
            );
        }

        // Anomaly Detection
        return (
            <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                    <span className="text-slate-500">Best Accuracy:</span>
                    <span className="text-cyan-400 font-semibold">{algorithm.accuracy ?? "N/A"}</span>
                </div>
                <div className="pt-2 border-t border-white/5 space-y-1">
                    <div className="flex justify-between">
                        <span className="text-slate-500">FTP:</span>
                        <span className="text-green-400">{algorithm.serviceMetrics?.ftp?.accuracy ?? "—"}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-500">MySQL:</span>
                        <span className="text-emerald-400">{algorithm.serviceMetrics?.mysql?.accuracy ?? "—"}</span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-500">SSH:</span>
                        <span className="text-yellow-400">{algorithm.serviceMetrics?.ssh?.accuracy ?? "Pending"}</span>
                    </div>
                </div>
            </div>
        );
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: index * 0.1 }}
            className="h-[320px] w-full"
        >
            <PinContainer title={getDisplayTitle()} href="#">
                <div className="flex flex-col p-4 tracking-tight text-slate-100/50 w-[280px] h-[220px]">
                    <h3 className="max-w-xs font-bold text-base text-slate-100">
                        {algorithm.name}
                    </h3>
                    <div className={cn("text-xs font-medium mt-1", typeColors[algorithm.type])}>
                        {algorithm.type}
                    </div>
                    <p className="text-sm text-slate-400 mt-3 leading-relaxed line-clamp-2">
                        {algorithm.description}
                    </p>
                    <div className="mt-auto pt-4 border-t border-white/10">
                        {renderMetrics()}
                    </div>
                </div>
            </PinContainer>
        </motion.div>
    );
}

function StatsCard({ title, value, subtitle, icon }: { title: string; value: string; subtitle: string; icon: React.ReactNode }) {
    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            className="p-5 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm hover:shadow-md transition-shadow"
        >
            <div className="flex items-start justify-between">
                <div>
                    <p className="text-xs text-neutral-500 dark:text-neutral-400">{title}</p>
                    <p className="text-2xl font-bold text-neutral-900 dark:text-white mt-1">{value}</p>
                    <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">{subtitle}</p>
                </div>
                <span className="text-cyan-500">{icon}</span>
            </div>
        </motion.div>
    );
}

// ============================================================================
// SECTION 3: DATASETS
// ============================================================================
export function DatasetsSection() {
    const [activeCategory, setActiveCategory] = React.useState<string>("All");

    const categories = useMemo(() => {
        const cats = ["All", ...new Set(datasets.map(d => d.category))];
        return cats;
    }, []);

    const filteredDatasets = useMemo(() => {
        if (activeCategory === "All") return datasets;
        return datasets.filter(d => d.category === activeCategory);
    }, [activeCategory]);

    // Dataset size distribution
    const categoryStats = useMemo(() => {
        const stats: Record<string, number> = {};
        datasets.forEach(d => {
            const size = parseFloat(d.size.replace(/[^0-9.]/g, ""));
            stats[d.category] = (stats[d.category] || 0) + size;
        });
        return Object.entries(stats).map(([name, value]) => ({
            name: name.split(" ")[0],
            size: Math.round(value * 10) / 10,
            color: getCategoryColor(name)
        }));
    }, []);

    return (
        <section className="w-full py-20 px-4">
            <div className="max-w-7xl mx-auto">
                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-12"
                >
                    <h2 className="text-4xl md:text-5xl font-bold mb-4">
                        <span className="bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                            Datasets
                        </span>
                    </h2>
                    <p className="text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
                        Over 1.8GB of real honeypot data, network traffic, and labeled training datasets
                    </p>
                </motion.div>

                {/* Category Filter - Premium Card Container */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="mb-12 p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-lg"
                >
                    {/* Filter Header */}
                    <div className="flex items-center justify-between mb-4 pb-4 border-b border-neutral-100 dark:border-neutral-800">
                        <div className="flex items-center gap-2">
                            <IconFilter className="w-5 h-5 text-cyan-500" />
                            <span className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">Filter by Category</span>
                        </div>
                        <span className="text-xs text-neutral-500 dark:text-neutral-500">
                            {categories.length} categories available
                        </span>
                    </div>

                    {/* All Button + Category Groups */}
                    <div className="space-y-4">
                        {/* Primary "All" Button */}
                        <div className="flex items-center gap-3">
                            <button
                                onClick={() => setActiveCategory("All")}
                                className={cn(
                                    "px-6 py-2.5 text-sm font-semibold transition-all duration-200 border-2",
                                    activeCategory === "All"
                                        ? "bg-gradient-to-r from-cyan-500 to-blue-500 text-white border-transparent shadow-lg shadow-cyan-500/30"
                                        : "bg-neutral-50 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border-neutral-200 dark:border-neutral-600 hover:border-cyan-500 hover:text-cyan-500"
                                )}
                            >
                                All Categories
                            </button>
                            <div className="h-6 w-px bg-neutral-200 dark:bg-neutral-700" />
                            <span className="text-xs text-neutral-400 dark:text-neutral-500">or select specific:</span>
                        </div>

                        {/* Category Grid - Organized in Rows */}
                        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
                            {categories.filter(cat => cat !== "All").map(cat => (
                                <button
                                    key={cat}
                                    onClick={() => setActiveCategory(cat)}
                                    className={cn(
                                        "px-4 py-2 text-xs font-medium transition-all duration-200 text-center",
                                        activeCategory === cat
                                            ? "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500 shadow-sm"
                                            : "bg-neutral-50 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400 border border-neutral-200 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-750 hover:border-neutral-300 dark:hover:border-neutral-600"
                                    )}
                                >
                                    {cat}
                                </button>
                            ))}
                        </div>
                    </div>
                </motion.div>

                {/* Dataset Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-16">
                    {filteredDatasets.slice(0, 12).map((dataset, index) => (
                        <DatasetCard key={dataset.id} dataset={dataset} index={index} />
                    ))}
                </div>

                {/* Dataset Statistics */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-16">
                    {/* Size by Category */}
                    <div className="p-6 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 shadow-sm">
                        <h3 className="text-lg font-semibold mb-4 text-neutral-900 dark:text-white">Data Size by Category (MB)</h3>
                        <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={categoryStats}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                <XAxis dataKey="name" stroke="#9ca3af" fontSize={10} angle={-45} textAnchor="end" height={80} />
                                <YAxis stroke="#9ca3af" />
                                <Tooltip
                                    contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151", borderRadius: "8px" }}
                                    labelStyle={{ color: "#fff" }}
                                />
                                <Bar dataKey="size" radius={[4, 4, 0, 0]}>
                                    {categoryStats.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Dataset Summary */}
                    <div className="grid grid-cols-2 gap-4">
                        <StatsCard title="Total Files" value="63" subtitle="Dataset Files" icon={<IconDatabase />} />
                        <StatsCard title="Total Size" value="1.8GB+" subtitle="Training Data" icon={<IconFileDatabase />} />
                        <StatsCard title="Categories" value="10" subtitle="Data Types" icon={<IconNetwork />} />
                        <StatsCard title="CICIDS2017" value="8" subtitle="Attack Scenarios" icon={<IconShieldCheck />} />
                    </div>
                </div>
            </div>
        </section>
    );
}

function DatasetCard({ dataset, index }: { dataset: Dataset; index: number }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: index * 0.05 }}
            className="p-5 bg-white dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-700 hover:border-cyan-500 shadow-sm hover:shadow-md transition-all"
        >
            <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                    <IconDatabase className="w-5 h-5 text-cyan-500" />
                    <span className="text-xs px-2 py-1 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 font-medium">
                        {dataset.format}
                    </span>
                </div>
                <span className="text-sm font-medium text-neutral-600 dark:text-neutral-400">{dataset.size}</span>
            </div>
            <h4 className="font-semibold text-neutral-900 dark:text-white mb-2 text-sm truncate" title={dataset.name}>
                {dataset.name}
            </h4>
            <p className="text-xs text-neutral-500 dark:text-neutral-400 line-clamp-2">
                {dataset.description}
            </p>
            <div className="mt-3 pt-3 border-t border-neutral-100 dark:border-neutral-800">
                <span className="text-xs text-neutral-500 dark:text-neutral-500">{dataset.category}</span>
            </div>
        </motion.div>
    );
}

function getCategoryColor(category: string): string {
    const colors: Record<string, string> = {
        "CICIDS2017": "#06b6d4",
        "Cowrie Honeypot": "#8b5cf6",
        "SSH Logs": "#10b981",
        "Authentication": "#f59e0b",
        "Vulnerability": "#ef4444",
        "ML Training": "#ec4899",
        "Network Traffic": "#6366f1",
        "Command Logs": "#14b8a6",
        "Session Data": "#f97316",
        "TTY Logs": "#84cc16"
    };
    return colors[category] || "#6b7280";
}

// ============================================================================
// SECTION 4: SERVICES
// ============================================================================
export function ServicesSection() {
    return (
        <section className="w-full py-20 px-4">
            <div className="max-w-7xl mx-auto">
                {/* Section Header */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-center mb-16"
                >
                    <h2 className="text-4xl md:text-5xl font-bold mb-4">
                        <span className="bg-gradient-to-r from-green-400 to-emerald-500 bg-clip-text text-transparent">
                            Service Emulators
                        </span>
                    </h2>
                    <p className="text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
                        Production-ready honeypot services with full AI + ML integration
                    </p>
                </motion.div>

                {/* Service Cards */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    {services.map((service, index) => (
                        <ServiceCard key={service.id} service={service} index={index} />
                    ))}
                </div>
            </div>
        </section>
    );
}

function ServiceCard({ service, index }: { service: ServiceConfig; index: number }) {
    const serviceIcons: Record<string, React.ReactNode> = {
        ssh: <IconTerminal2 className="w-8 h-8" />,
        ftp: <IconDatabase className="w-8 h-8" />,
        mysql: <IconServer className="w-8 h-8" />
    };

    const serviceColors: Record<string, string> = {
        ssh: "#06b6d4",
        ftp: "#8b5cf6",
        mysql: "#10b981"
    };

    const serviceColorClasses: Record<string, string> = {
        ssh: "text-cyan-500 bg-cyan-500/10 dark:bg-cyan-500/20",
        ftp: "text-purple-500 bg-purple-500/10 dark:bg-purple-500/20",
        mysql: "text-emerald-500 bg-emerald-500/10 dark:bg-emerald-500/20"
    };

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: index * 0.1 }}
        >
            <CardSpotlight className="h-full" color={serviceColors[service.id]}>
                <div className="relative z-20">
                    {/* Header */}
                    <div className="flex items-center gap-4 mb-4">
                        <div className={cn("p-3", serviceColorClasses[service.id])}>
                            {serviceIcons[service.id]}
                        </div>
                        <div>
                            <h3 className="text-xl font-bold text-white">{service.name}</h3>
                            <div className="flex items-center gap-2 mt-1">
                                <span className="text-xs px-2 py-0.5 bg-green-500/20 text-green-400 font-medium">
                                    {service.status}
                                </span>
                            </div>
                        </div>
                    </div>

                    {/* Port & Protocol */}
                    <div className="flex gap-4 mb-4 py-3 border-y border-white/10">
                        <div>
                            <span className="text-xs text-neutral-400">Port</span>
                            <p className="text-lg font-mono text-cyan-400">{service.port}</p>
                        </div>
                        <div>
                            <span className="text-xs text-neutral-400">Protocol</span>
                            <p className="text-sm text-neutral-300 truncate max-w-[150px]">{service.protocol}</p>
                        </div>
                        <div>
                            <span className="text-xs text-neutral-400">Accounts</span>
                            <p className="text-lg font-mono text-cyan-400">{service.userAccounts}</p>
                        </div>
                    </div>

                    {/* Description */}
                    <p className="text-sm text-neutral-400 mb-4 line-clamp-3">
                        {service.description}
                    </p>

                    {/* Features */}
                    <div className="mb-4">
                        <h4 className="text-xs font-semibold text-neutral-300 mb-2">Key Features</h4>
                        <div className="flex flex-wrap gap-1">
                            {service.features.slice(0, 5).map((feature, i) => (
                                <span
                                    key={i}
                                    className="text-xs px-2 py-1 bg-white/5 text-neutral-400"
                                >
                                    {feature.split(" ").slice(0, 3).join(" ")}
                                </span>
                            ))}
                        </div>
                    </div>

                    {/* AI Models */}
                    <div>
                        <h4 className="text-xs font-semibold text-neutral-300 mb-2">AI Providers</h4>
                        <div className="flex flex-wrap gap-1">
                            {service.aiModels.slice(0, 3).map((model, i) => (
                                <span
                                    key={i}
                                    className="text-xs px-2 py-1 bg-purple-500/10 text-purple-400"
                                >
                                    {model.split(" ")[0]}
                                </span>
                            ))}
                        </div>
                    </div>
                </div>
            </CardSpotlight>
        </motion.div>
    );
}

// ============================================================================
// SECTION 5: FOOTER
// ============================================================================
export function FooterSection() {
    return (
        <footer className="w-full py-12 px-4 mt-20 border-t border-neutral-200/10 dark:border-white/10">
            <div className="max-w-7xl mx-auto">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
                    {/* Brand */}
                    <div>
                        <h3 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent mb-3">
                            NEXUS
                        </h3>
                        <p className="text-sm text-neutral-500 dark:text-neutral-400">
                            AI-Enhanced Honeypot Platform for cybersecurity professionals and researchers.
                        </p>
                    </div>

                    {/* Links */}
                    <div>
                        <h4 className="font-semibold text-neutral-900 dark:text-white mb-3">Quick Links</h4>
                        <ul className="space-y-2 text-sm text-neutral-500 dark:text-neutral-400">
                            <li><a href="#architecture" className="hover:text-cyan-400 transition-colors">Architecture</a></li>
                            <li><a href="#ml" className="hover:text-cyan-400 transition-colors">ML Algorithms</a></li>
                            <li><a href="#datasets" className="hover:text-cyan-400 transition-colors">Datasets</a></li>
                            <li><a href="#services" className="hover:text-cyan-400 transition-colors">Services</a></li>
                        </ul>
                    </div>

                    {/* Developer */}
                    <div>
                        <h4 className="font-semibold text-neutral-900 dark:text-white mb-3">Developer</h4>
                        <p className="text-sm text-neutral-500 dark:text-neutral-400 mb-3">
                            {developerInfo.name}
                        </p>
                        <div className="flex gap-3">
                            <a
                                href={developerInfo.github}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="p-2.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 hover:border-neutral-600 text-white transition-all duration-200 hover:scale-110"
                            >
                                <IconBrandGithub className="w-5 h-5" />
                            </a>
                            <a
                                href={developerInfo.linkedin}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="p-2.5 rounded-lg bg-[#0A66C2] hover:bg-[#004182] border border-[#0A66C2] text-white transition-all duration-200 hover:scale-110"
                            >
                                <IconBrandLinkedin className="w-5 h-5" />
                            </a>
                        </div>
                    </div>
                </div>

                {/* Bottom */}
                <div className="pt-8 border-t border-neutral-200/10 dark:border-white/10 flex flex-col md:flex-row justify-between items-center gap-4">
                    <p className="text-sm text-neutral-500 dark:text-neutral-400">
                        © {new Date().getFullYear()} NEXUS. All rights reserved.
                    </p>
                    <div className="flex gap-4 text-sm text-neutral-500 dark:text-neutral-400">
                        <a href="/privacy" className="hover:text-cyan-400 transition-colors">Privacy Policy</a>
                        <a href="/terms" className="hover:text-cyan-400 transition-colors">Terms of Service</a>
                    </div>
                </div>
            </div>
        </footer>
    );
}
