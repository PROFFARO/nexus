"use client";

import { motion } from "framer-motion";
import { LucideIcon, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

export interface StatCardProps {
    title: string;
    value: string | number;
    change?: {
        value: number;
        trend: "up" | "down" | "neutral";
    };
    icon?: LucideIcon;
    iconColor?: string;
    suffix?: string;
    sparkline?: number[];
}

export function StatCard({
    title,
    value,
    change,
    icon: Icon,
    iconColor = "text-[var(--primary)]",
    suffix,
    sparkline,
}: StatCardProps) {
    const getTrendIcon = () => {
        if (!change) return null;
        const TrendIcon =
            change.trend === "up"
                ? TrendingUp
                : change.trend === "down"
                    ? TrendingDown
                    : Minus;
        return TrendIcon;
    };

    const getTrendColor = () => {
        if (!change) return "";
        if (change.trend === "up") return "text-emerald-400";
        if (change.trend === "down") return "text-red-400";
        return "text-[var(--muted-foreground)]";
    };

    const TrendIcon = getTrendIcon();

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card glass-card-hover stat-card p-5"
        >
            <div className="flex items-start justify-between">
                <div className="space-y-1">
                    <p className="text-sm font-medium text-[var(--muted-foreground)]">
                        {title}
                    </p>
                    <div className="flex items-baseline gap-2">
                        <h3 className="text-2xl font-bold tracking-tight">
                            {value}
                            {suffix && (
                                <span className="ml-1 text-base font-normal text-[var(--muted-foreground)]">
                                    {suffix}
                                </span>
                            )}
                        </h3>
                    </div>
                    {change && TrendIcon && (
                        <div className={cn("flex items-center gap-1 text-sm", getTrendColor())}>
                            <TrendIcon className="h-4 w-4" />
                            <span className="font-medium">
                                {change.value > 0 ? "+" : ""}
                                {change.value}%
                            </span>
                            <span className="text-[var(--muted-foreground)]">vs last 24h</span>
                        </div>
                    )}
                </div>

                {Icon && (
                    <div
                        className={cn(
                            "flex h-11 w-11 items-center justify-center rounded-xl bg-white/5",
                            iconColor
                        )}
                    >
                        <Icon className="h-5 w-5" />
                    </div>
                )}
            </div>

            {/* Mini Sparkline */}
            {sparkline && sparkline.length > 0 && (
                <div className="mt-4 flex h-8 items-end gap-0.5">
                    {sparkline.map((value, i) => {
                        const max = Math.max(...sparkline);
                        const height = max > 0 ? (value / max) * 100 : 0;
                        return (
                            <div
                                key={i}
                                className="flex-1 rounded-t-sm bg-[var(--primary)]/30 transition-all hover:bg-[var(--primary)]/50"
                                style={{ height: `${Math.max(height, 8)}%` }}
                            />
                        );
                    })}
                </div>
            )}
        </motion.div>
    );
}

export interface StatsGridProps {
    children: React.ReactNode;
    className?: string;
}

export function StatsGrid({ children, className }: StatsGridProps) {
    return (
        <div className={cn("grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4", className)}>
            {children}
        </div>
    );
}
