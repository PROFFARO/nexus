"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import {
    LayoutDashboard,
    Shield,
    Terminal,
    Database,
    Activity,
    FileText,
    Settings,
    Globe,
    Brain,
    ChevronLeft,
    ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";

interface NavItem {
    label: string;
    href: string;
    icon: React.ElementType;
    badge?: string | number;
}

const mainNavItems: NavItem[] = [
    { label: "Dashboard", href: "/", icon: LayoutDashboard },
    { label: "Attack Map", href: "/attacks", icon: Globe },
    { label: "Sessions", href: "/sessions", icon: Activity },
    { label: "ML Insights", href: "/ml", icon: Brain },
];

const serviceNavItems: NavItem[] = [
    { label: "SSH Monitor", href: "/services/ssh", icon: Terminal },
    { label: "FTP Monitor", href: "/services/ftp", icon: Database },
    { label: "MySQL Monitor", href: "/services/mysql", icon: Database },
];

const systemNavItems: NavItem[] = [
    { label: "Reports", href: "/reports", icon: FileText },
    { label: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
    const pathname = usePathname();
    const [collapsed, setCollapsed] = useState(false);

    const NavLink = ({ item }: { item: NavItem }) => {
        const isActive = pathname === item.href;
        const Icon = item.icon;

        return (
            <Link
                href={item.href}
                className={cn(
                    "sidebar-link group relative",
                    isActive && "active"
                )}
            >
                {isActive && (
                    <motion.div
                        layoutId="activeNav"
                        className="absolute inset-0 rounded-lg bg-[var(--primary-muted)]"
                        transition={{ type: "spring", duration: 0.4 }}
                    />
                )}
                <Icon className="relative z-10 h-5 w-5 shrink-0" />
                {!collapsed && (
                    <span className="relative z-10 truncate">{item.label}</span>
                )}
                {!collapsed && item.badge && (
                    <span className="relative z-10 ml-auto rounded-full bg-[var(--primary)] px-2 py-0.5 text-xs font-semibold text-[var(--primary-foreground)]">
                        {item.badge}
                    </span>
                )}
            </Link>
        );
    };

    const NavSection = ({
        title,
        items,
    }: {
        title: string;
        items: NavItem[];
    }) => (
        <div className="space-y-1">
            {!collapsed && (
                <h4 className="mb-2 px-3 text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                    {title}
                </h4>
            )}
            {items.map((item) => (
                <NavLink key={item.href} item={item} />
            ))}
        </div>
    );

    return (
        <motion.aside
            initial={false}
            animate={{ width: collapsed ? 72 : 256 }}
            transition={{ duration: 0.2, ease: "easeInOut" }}
            className="fixed left-0 top-0 z-40 flex h-screen flex-col border-r border-[var(--sidebar-border)] bg-[var(--sidebar-bg)]"
        >
            {/* Logo Header */}
            <div className="flex h-16 items-center justify-between border-b border-[var(--sidebar-border)] px-4">
                <Link href="/" className="flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-[var(--primary)] to-[var(--accent)]">
                        <Shield className="h-5 w-5 text-white" />
                    </div>
                    {!collapsed && (
                        <motion.span
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="text-lg font-bold tracking-tight"
                        >
                            NEXUS
                        </motion.span>
                    )}
                </Link>
                <button
                    onClick={() => setCollapsed(!collapsed)}
                    className="rounded-lg p-1.5 text-[var(--muted-foreground)] transition-colors hover:bg-white/5 hover:text-[var(--foreground)]"
                >
                    {collapsed ? (
                        <ChevronRight className="h-4 w-4" />
                    ) : (
                        <ChevronLeft className="h-4 w-4" />
                    )}
                </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 space-y-6 overflow-y-auto p-3">
                <NavSection title="Overview" items={mainNavItems} />
                <NavSection title="Services" items={serviceNavItems} />
                <NavSection title="System" items={systemNavItems} />
            </nav>

            {/* Status Footer */}
            <div className="border-t border-[var(--sidebar-border)] p-3">
                <div
                    className={cn(
                        "flex items-center gap-3 rounded-lg bg-emerald-500/10 p-3",
                        collapsed && "justify-center"
                    )}
                >
                    <div className="relative">
                        <div className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
                        <div className="absolute inset-0 h-2.5 w-2.5 animate-ping rounded-full bg-emerald-500 opacity-75" />
                    </div>
                    {!collapsed && (
                        <div className="text-xs">
                            <p className="font-semibold text-emerald-400">System Online</p>
                            <p className="text-[var(--muted-foreground)]">3 services active</p>
                        </div>
                    )}
                </div>
            </div>
        </motion.aside>
    );
}
