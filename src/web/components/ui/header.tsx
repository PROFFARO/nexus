"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { UserButton } from "@clerk/nextjs";
import {
    Search,
    Bell,
    Settings,
    Calendar,
    RefreshCw,
    AlertTriangle,
    Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "@/components/theme-toggle";

interface Notification {
    id: string;
    type: "alert" | "info" | "success";
    title: string;
    message: string;
    time: string;
    read: boolean;
}

const mockNotifications: Notification[] = [
    {
        id: "1",
        type: "alert",
        title: "Critical Attack Detected",
        message: "SQL injection attempt from 192.168.1.45",
        time: "2 min ago",
        read: false,
    },
    {
        id: "2",
        type: "alert",
        title: "Brute Force Attack",
        message: "Multiple SSH login failures from 10.0.0.23",
        time: "15 min ago",
        read: false,
    },
    {
        id: "3",
        type: "success",
        title: "ML Model Updated",
        message: "SSH anomaly detector retrained successfully",
        time: "1 hour ago",
        read: true,
    },
];

export function Header() {
    const [searchOpen, setSearchOpen] = useState(false);
    const [notificationsOpen, setNotificationsOpen] = useState(false);
    const [lastRefresh] = useState(new Date());

    const unreadCount = mockNotifications.filter((n) => !n.read).length;

    return (
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[var(--border)] bg-[var(--background)]/80 px-6 backdrop-blur-xl transition-all duration-300">
            {/* Left section - Breadcrumb / Page Title */}
            <div className="flex items-center gap-4">
                <div>
                    <h1 className="text-lg font-semibold">Security Dashboard</h1>
                    <p className="text-xs text-[var(--muted-foreground)]">
                        Real-time threat monitoring
                    </p>
                </div>
            </div>

            {/* Center section - Search */}
            <div className="flex flex-1 justify-center px-8">
                <motion.div
                    initial={false}
                    animate={{ width: searchOpen ? 480 : 320 }}
                    className="relative"
                >
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--muted-foreground)]" />
                    <input
                        type="text"
                        placeholder="Search sessions, IPs, commands..."
                        onFocus={() => setSearchOpen(true)}
                        onBlur={() => setSearchOpen(false)}
                        className="h-10 w-full rounded-xl border border-[var(--input-border)] bg-[var(--input)] pl-10 pr-4 text-sm outline-none transition-all placeholder:text-[var(--muted-foreground)] focus:border-[var(--primary)] focus:ring-2 focus:ring-[var(--ring)]"
                    />
                    <kbd className="absolute right-3 top-1/2 hidden -translate-y-1/2 rounded bg-[var(--card)] border border-[var(--border)] px-1.5 py-0.5 text-xs text-[var(--muted-foreground)] sm:block shadow-sm">
                        ⌘K
                    </kbd>
                </motion.div>
            </div>

            {/* Right section - Actions */}
            <div className="flex items-center gap-2">
                {/* Date Range */}
                <button className="btn-secondary flex items-center gap-2">
                    <Calendar className="h-4 w-4" />
                    <span className="hidden text-sm md:inline">Last 24 hours</span>
                </button>

                {/* Refresh */}
                <button className="rounded-lg p-2 text-[var(--muted-foreground)] transition-colors hover:bg-white/5 hover:text-[var(--foreground)]">
                    <RefreshCw className="h-5 w-5" />
                </button>

                {/* Notifications */}
                <div className="relative">
                    <button
                        onClick={() => setNotificationsOpen(!notificationsOpen)}
                        className="relative rounded-lg p-2 text-[var(--muted-foreground)] transition-colors hover:bg-white/5 hover:text-[var(--foreground)]"
                    >
                        <Bell className="h-5 w-5" />
                        {unreadCount > 0 && (
                            <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
                                {unreadCount}
                            </span>
                        )}
                    </button>

                    <AnimatePresence>
                        {notificationsOpen && (
                            <>
                                <div
                                    className="fixed inset-0 z-40"
                                    onClick={() => setNotificationsOpen(false)}
                                />
                                <motion.div
                                    initial={{ opacity: 0, y: 8, scale: 0.96 }}
                                    animate={{ opacity: 1, y: 0, scale: 1 }}
                                    exit={{ opacity: 0, y: 8, scale: 0.96 }}
                                    transition={{ duration: 0.15 }}
                                    className="absolute right-0 top-full z-50 mt-2 w-80 rounded-xl border border-[var(--glass-border)] bg-[var(--card)] p-2 shadow-2xl"
                                >
                                    <div className="mb-2 flex items-center justify-between px-2 pt-1">
                                        <h3 className="font-semibold">Notifications</h3>
                                        <button className="text-xs text-[var(--primary)] hover:underline">
                                            Mark all read
                                        </button>
                                    </div>
                                    <div className="max-h-80 space-y-1 overflow-y-auto">
                                        {mockNotifications.map((notification) => (
                                            <div
                                                key={notification.id}
                                                className={cn(
                                                    "flex gap-3 rounded-lg p-3 transition-colors hover:bg-white/5",
                                                    !notification.read && "bg-white/[0.02]"
                                                )}
                                            >
                                                <div
                                                    className={cn(
                                                        "mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg",
                                                        notification.type === "alert" &&
                                                        "bg-red-500/15 text-red-400",
                                                        notification.type === "success" &&
                                                        "bg-emerald-500/15 text-emerald-400",
                                                        notification.type === "info" &&
                                                        "bg-blue-500/15 text-blue-400"
                                                    )}
                                                >
                                                    {notification.type === "alert" && (
                                                        <AlertTriangle className="h-4 w-4" />
                                                    )}
                                                    {notification.type === "success" && (
                                                        <Check className="h-4 w-4" />
                                                    )}
                                                </div>
                                                <div className="flex-1 overflow-hidden">
                                                    <p className="truncate text-sm font-medium">
                                                        {notification.title}
                                                    </p>
                                                    <p className="truncate text-xs text-[var(--muted-foreground)]">
                                                        {notification.message}
                                                    </p>
                                                    <p className="mt-1 text-xs text-[var(--muted)]">
                                                        {notification.time}
                                                    </p>
                                                </div>
                                                {!notification.read && (
                                                    <div className="h-2 w-2 shrink-0 rounded-full bg-[var(--primary)]" />
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                </motion.div>
                            </>
                        )}
                    </AnimatePresence>
                </div>

                {/* Theme Toggle */}
                <ThemeToggle />

                {/* Settings */}
                <button className="rounded-lg p-2 text-[var(--muted-foreground)] transition-colors hover:bg-[var(--muted)] hover:text-[var(--foreground)]">
                    <Settings className="h-5 w-5" />
                </button>

                {/* User Avatar (Clerk) */}
                <div className="ml-2">
                    <UserButton
                        appearance={{
                            elements: {
                                avatarBox: "h-9 w-9",
                            },
                        }}
                    />
                </div>
            </div>
        </header>
    );
}
