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
    IconCpu
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
        <section className="relative w-full min-h-[60vh] flex flex-col items-center justify-center overflow-hidden py-20">
            {/* Sparkles Effect */}
            <div className="w-full absolute inset-0 h-full">
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
            <div className="relative z-10 text-center">
                <motion.h1
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8 }}
                    className="text-7xl md:text-9xl font-black tracking-tighter mb-4"
                >
                    <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
                        NEXUS
                    </span>
                </motion.h1>

                {/* Sparkles under title */}
                <div className="w-[300px] md:w-[500px] h-20 relative mx-auto">
                    <div className="absolute inset-x-10 top-0 bg-gradient-to-r from-transparent via-cyan-500 to-transparent h-[2px] w-3/4 blur-sm" />
                    <div className="absolute inset-x-10 top-0 bg-gradient-to-r from-transparent via-cyan-500 to-transparent h-px w-3/4" />
                    <div className="absolute inset-x-32 top-0 bg-gradient-to-r from-transparent via-blue-500 to-transparent h-[5px] w-1/4 blur-sm" />
                    <div className="absolute inset-x-32 top-0 bg-gradient-to-r from-transparent via-blue-500 to-transparent h-px w-1/4" />
                    <SparklesCore
                        id="title-sparkles"
                        background="transparent"
                        minSize={0.4}
                        maxSize={1}
                        particleDensity={1200}
                        className="w-full h-full"
                        particleColor="#06b6d4"
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
            className="flex items-center gap-3 px-5 py-3 rounded-full bg-white/10 dark:bg-black/20 backdrop-blur-sm border border-neutral-200/20 dark:border-white/10"
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
// SECTION 1: ARCHITECTURE DIAGRAM
// ============================================================================
export function ArchitectureSection() {
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

                {/* Architecture Diagram */}
                <div className="relative">
                    <div className="grid grid-cols-1 md:grid-cols-7 gap-4 items-center">
                        {/* Attackers */}
                        <ArchitectureNode
                            icon={<IconTerminal2 className="w-8 h-8" />}
                            title="Attackers"
                            description="External threat actors"
                            color="red"
                            delay={0}
                        />

                        {/* Arrow */}
                        <ArrowConnector />

                        {/* Service Layer */}
                        <ArchitectureNode
                            icon={<IconServer className="w-8 h-8" />}
                            title="Service Emulators"
                            description="SSH • FTP • MySQL"
                            color="blue"
                            delay={0.1}
                        />

                        {/* Arrow */}
                        <ArrowConnector />

                        {/* AI/ML Layer */}
                        <div className="flex flex-col gap-4">
                            <ArchitectureNode
                                icon={<IconBrain className="w-8 h-8" />}
                                title="AI Layer"
                                description="LLM Responses"
                                color="purple"
                                delay={0.2}
                                small
                            />
                            <ArchitectureNode
                                icon={<IconCpu className="w-8 h-8" />}
                                title="ML Detection"
                                description="6 Algorithms"
                                color="cyan"
                                delay={0.25}
                                small
                            />
                        </div>

                        {/* Arrow */}
                        <ArrowConnector />

                        {/* Output */}
                        <ArchitectureNode
                            icon={<IconChartBar className="w-8 h-8" />}
                            title="Analysis & Reports"
                            description="Forensics • Alerts"
                            color="green"
                            delay={0.3}
                        />
                    </div>

                    {/* Detailed Flow Description */}
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
            </div>
        </section>
    );
}

function ArchitectureNode({
    icon,
    title,
    description,
    color,
    delay,
    small = false
}: {
    icon: React.ReactNode;
    title: string;
    description: string;
    color: string;
    delay: number;
    small?: boolean;
}) {
    const colorClasses: Record<string, string> = {
        red: "from-red-500/20 to-red-600/10 border-red-500/30 text-red-500",
        blue: "from-blue-500/20 to-blue-600/10 border-blue-500/30 text-blue-500",
        purple: "from-purple-500/20 to-purple-600/10 border-purple-500/30 text-purple-500",
        cyan: "from-cyan-500/20 to-cyan-600/10 border-cyan-500/30 text-cyan-500",
        green: "from-green-500/20 to-green-600/10 border-green-500/30 text-green-500"
    };

    return (
        <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ delay, duration: 0.5 }}
            className={cn(
                "relative p-4 rounded-xl bg-gradient-to-br border backdrop-blur-sm",
                colorClasses[color],
                small ? "py-3" : "py-6"
            )}
        >
            <div className={cn("flex flex-col items-center text-center gap-2", colorClasses[color].split(" ").pop())}>
                {icon}
                <h3 className={cn("font-semibold text-neutral-900 dark:text-white", small ? "text-sm" : "text-base")}>{title}</h3>
                <p className={cn("text-neutral-500 dark:text-neutral-400", small ? "text-xs" : "text-sm")}>{description}</p>
            </div>
        </motion.div>
    );
}

function ArrowConnector() {
    return (
        <div className="hidden md:flex items-center justify-center">
            <motion.div
                initial={{ scaleX: 0 }}
                whileInView={{ scaleX: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5 }}
                className="w-full h-0.5 bg-gradient-to-r from-cyan-500/50 to-blue-500/50"
            />
            <div className="w-2 h-2 rotate-45 border-r-2 border-t-2 border-cyan-500/50 -ml-1" />
        </div>
    );
}

function FlowCard({ title, items, icon }: { title: string; items: string[]; icon: React.ReactNode }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="p-6 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10 backdrop-blur-sm"
        >
            <div className="flex items-center gap-3 mb-4 text-cyan-500">
                {icon}
                <h4 className="font-semibold text-neutral-900 dark:text-white">{title}</h4>
            </div>
            <ul className="space-y-2">
                {items.map((item, i) => (
                    <li key={i} className="text-sm text-neutral-600 dark:text-neutral-400 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-500/50" />
                        {item}
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
    // Chart data
    const accuracyData = mlAlgorithms.map(algo => ({
        name: algo.name.split(" ")[0],
        accuracy: parseFloat(algo.accuracy.replace("%", "")),
        fill: algo.type === "Anomaly Detection" ? "#06b6d4" : algo.type === "Clustering" ? "#8b5cf6" : "#10b981"
    }));

    const typeDistribution = [
        { name: "Anomaly Detection", value: 3, color: "#06b6d4" },
        { name: "Clustering", value: 2, color: "#8b5cf6" },
        { name: "Supervised", value: 1, color: "#10b981" }
    ];

    const radarData = mlAlgorithms.map(algo => ({
        algorithm: algo.name.split(" ")[0],
        accuracy: parseFloat(algo.accuracy.replace("%", "")),
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
                    {/* Accuracy Bar Chart */}
                    <div className="p-6 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10">
                        <h3 className="text-lg font-semibold mb-4 text-neutral-900 dark:text-white">Algorithm Accuracy</h3>
                        <ResponsiveContainer width="100%" height={250}>
                            <BarChart data={accuracyData} layout="vertical">
                                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                <XAxis type="number" domain={[80, 100]} stroke="#9ca3af" />
                                <YAxis dataKey="name" type="category" width={80} stroke="#9ca3af" fontSize={12} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: "#1f2937", border: "1px solid #374151", borderRadius: "8px" }}
                                    labelStyle={{ color: "#fff" }}
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
                    <div className="p-6 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10">
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
                    <div className="p-6 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10">
                        <h3 className="text-lg font-semibold mb-4 text-neutral-900 dark:text-white">Performance Radar</h3>
                        <ResponsiveContainer width="100%" height={250}>
                            <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                                <PolarGrid stroke="#374151" />
                                <PolarAngleAxis dataKey="algorithm" stroke="#9ca3af" fontSize={10} />
                                <PolarRadiusAxis angle={90} domain={[80, 100]} stroke="#9ca3af" />
                                <Radar name="Accuracy" dataKey="accuracy" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.5} />
                            </RadarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* ML Stats Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-12">
                    <StatsCard title="Total Algorithms" value="6" subtitle="Active Models" icon={<IconCpu />} />
                    <StatsCard title="Highest Accuracy" value="96.1%" subtitle="XGBoost" icon={<IconChartBar />} />
                    <StatsCard title="Model Files" value="9" subtitle="Trained Models" icon={<IconFileDatabase />} />
                    <StatsCard title="Services Covered" value="3" subtitle="SSH • FTP • MySQL" icon={<IconServer />} />
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

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: index * 0.1 }}
            className="h-[320px] w-full"
        >
            <PinContainer title={algorithm.accuracy} href="#">
                <div className="flex flex-col p-4 tracking-tight text-slate-100/50 w-[280px] h-[220px]">
                    <h3 className="max-w-xs font-bold text-base text-slate-100">
                        {algorithm.name}
                    </h3>
                    <div className={cn("text-xs font-medium mt-1", typeColors[algorithm.type])}>
                        {algorithm.type}
                    </div>
                    <p className="text-sm text-slate-400 mt-3 leading-relaxed">
                        {algorithm.description}
                    </p>
                    <div className="mt-auto pt-4 border-t border-white/10">
                        <div className="grid grid-cols-2 gap-2 text-xs">
                            <div>
                                <span className="text-slate-500">Accuracy:</span>
                                <span className="ml-2 text-cyan-400 font-semibold">{algorithm.accuracy}</span>
                            </div>
                            <div>
                                <span className="text-slate-500">Precision:</span>
                                <span className="ml-2 text-slate-400">{algorithm.precision}</span>
                            </div>
                            <div>
                                <span className="text-slate-500">Recall:</span>
                                <span className="ml-2 text-slate-400">{algorithm.recall}</span>
                            </div>
                            <div>
                                <span className="text-slate-500">F1:</span>
                                <span className="ml-2 text-slate-400">{algorithm.f1Score}</span>
                            </div>
                        </div>
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
            className="p-5 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10"
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

                {/* Category Filter */}
                <div className="flex flex-wrap justify-center gap-2 mb-12">
                    {categories.map(cat => (
                        <HoverBorderGradient
                            key={cat}
                            as="button"
                            onClick={() => setActiveCategory(cat)}
                            className={cn(
                                "text-sm transition-colors",
                                activeCategory === cat
                                    ? "bg-cyan-500/20"
                                    : "bg-transparent hover:bg-white/5"
                            )}
                        >
                            {cat}
                        </HoverBorderGradient>
                    ))}
                </div>

                {/* Dataset Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-16">
                    {filteredDatasets.slice(0, 12).map((dataset, index) => (
                        <DatasetCard key={dataset.id} dataset={dataset} index={index} />
                    ))}
                </div>

                {/* Dataset Statistics */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-16">
                    {/* Size by Category */}
                    <div className="p-6 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10">
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
            className="p-5 rounded-xl bg-white/5 dark:bg-black/20 border border-neutral-200/20 dark:border-white/10 hover:border-cyan-500/30 transition-colors"
        >
            <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                    <IconDatabase className="w-5 h-5 text-cyan-500" />
                    <span className="text-xs px-2 py-1 rounded-full bg-cyan-500/10 text-cyan-400">
                        {dataset.format}
                    </span>
                </div>
                <span className="text-sm font-medium text-neutral-400">{dataset.size}</span>
            </div>
            <h4 className="font-semibold text-neutral-900 dark:text-white mb-2 text-sm truncate" title={dataset.name}>
                {dataset.name}
            </h4>
            <p className="text-xs text-neutral-500 dark:text-neutral-400 line-clamp-2">
                {dataset.description}
            </p>
            <div className="mt-3 pt-3 border-t border-white/5">
                <span className="text-xs text-neutral-500">{dataset.category}</span>
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
                        <div
                            className="p-3 rounded-lg"
                            style={{ backgroundColor: `${serviceColors[service.id]}20` }}
                        >
                            {serviceIcons[service.id]}
                        </div>
                        <div>
                            <h3 className="text-xl font-bold text-white">{service.name}</h3>
                            <div className="flex items-center gap-2 mt-1">
                                <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400">
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
                                    className="text-xs px-2 py-1 rounded-full bg-white/5 text-neutral-400"
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
                                    className="text-xs px-2 py-1 rounded-full bg-purple-500/10 text-purple-400"
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
                                className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-neutral-400 hover:text-white transition-colors"
                            >
                                <IconBrandGithub className="w-5 h-5" />
                            </a>
                            <a
                                href={developerInfo.linkedin}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-neutral-400 hover:text-white transition-colors"
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
