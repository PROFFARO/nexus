"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface ServiceBadgeProps {
    service: "ssh" | "ftp" | "mysql";
    size?: "sm" | "md";
}

export function ServiceBadge({ service, size = "sm" }: ServiceBadgeProps) {
    return (
        <span
            className={cn(
                "service-badge",
                `service-${service}`,
                size === "md" && "px-3 py-1 text-xs"
            )}
        >
            {service.toUpperCase()}
        </span>
    );
}

interface RiskBadgeProps {
    level: "low" | "medium" | "high" | "critical";
    animated?: boolean;
}

export function RiskBadge({ level, animated = false }: RiskBadgeProps) {
    return (
        <span
            className={cn(
                "risk-badge",
                `risk-${level}`,
                animated && level === "critical" && "alert-critical-pulse"
            )}
        >
            {level}
        </span>
    );
}

interface CardProps {
    children: React.ReactNode;
    className?: string;
    hover?: boolean;
    animate?: boolean;
}

export function Card({
    children,
    className,
    hover = true,
    animate = true,
}: CardProps) {
    const Wrapper = animate ? motion.div : "div";
    const animationProps = animate
        ? {
            initial: { opacity: 0, y: 20 },
            animate: { opacity: 1, y: 0 },
        }
        : {};

    return (
        <Wrapper
            {...animationProps}
            className={cn(
                "glass-card p-5",
                hover && "glass-card-hover",
                className
            )}
        >
            {children}
        </Wrapper>
    );
}

interface CardHeaderProps {
    title: string;
    subtitle?: string;
    action?: React.ReactNode;
}

export function CardHeader({ title, subtitle, action }: CardHeaderProps) {
    return (
        <div className="mb-4 flex items-start justify-between">
            <div>
                <h3 className="font-semibold">{title}</h3>
                {subtitle && (
                    <p className="text-sm text-[var(--muted-foreground)]">{subtitle}</p>
                )}
            </div>
            {action}
        </div>
    );
}

interface ProgressBarProps {
    value: number;
    max?: number;
    color?: "primary" | "success" | "warning" | "danger";
    showLabel?: boolean;
    size?: "sm" | "md";
}

export function ProgressBar({
    value,
    max = 100,
    color = "primary",
    showLabel = false,
    size = "md",
}: ProgressBarProps) {
    const percentage = Math.min(Math.max((value / max) * 100, 0), 100);

    const colors = {
        primary: "bg-[var(--primary)]",
        success: "bg-emerald-500",
        warning: "bg-amber-500",
        danger: "bg-red-500",
    };

    return (
        <div className="flex items-center gap-3">
            <div
                className={cn(
                    "flex-1 overflow-hidden rounded-full bg-white/10",
                    size === "sm" ? "h-1.5" : "h-2"
                )}
            >
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${percentage}%` }}
                    transition={{ duration: 0.5, ease: "easeOut" }}
                    className={cn("h-full rounded-full", colors[color])}
                />
            </div>
            {showLabel && (
                <span className="w-12 text-right text-sm font-medium text-[var(--muted-foreground)]">
                    {Math.round(percentage)}%
                </span>
            )}
        </div>
    );
}

interface LiveIndicatorProps {
    active?: boolean;
    label?: string;
}

export function LiveIndicator({ active = true, label = "Live" }: LiveIndicatorProps) {
    return (
        <div className="flex items-center gap-2">
            <div className="relative">
                <div
                    className={cn(
                        "h-2 w-2 rounded-full",
                        active ? "bg-emerald-500" : "bg-red-500"
                    )}
                />
                {active && (
                    <div className="absolute inset-0 h-2 w-2 animate-ping rounded-full bg-emerald-500 opacity-75" />
                )}
            </div>
            <span className="text-xs font-medium text-[var(--muted-foreground)]">
                {label}
            </span>
        </div>
    );
}

interface EmptyStateProps {
    icon?: React.ReactNode;
    title: string;
    description?: string;
    action?: React.ReactNode;
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
    return (
        <div className="flex flex-col items-center justify-center py-12 text-center">
            {icon && (
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-white/5 text-[var(--muted-foreground)]">
                    {icon}
                </div>
            )}
            <h3 className="mb-1 font-semibold">{title}</h3>
            {description && (
                <p className="mb-4 max-w-sm text-sm text-[var(--muted-foreground)]">
                    {description}
                </p>
            )}
            {action}
        </div>
    );
}
