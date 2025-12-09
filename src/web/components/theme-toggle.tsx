"use client";

import { useTheme } from "next-themes";
import { useEffect, useState } from "react";
import { Moon, Sun, Monitor } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";

export function ThemeToggle() {
    const { theme, setTheme, resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
    }, []);

    if (!mounted) {
        return (
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--secondary)]">
                <div className="h-4 w-4 animate-pulse rounded bg-[var(--muted)]" />
            </div>
        );
    }

    return (
        <motion.button
            onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className={cn(
                "relative flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--border)] bg-[var(--secondary)] transition-colors hover:bg-[var(--secondary-hover)]"
            )}
            title={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} mode`}
        >
            <AnimatePresence mode="wait" initial={false}>
                {resolvedTheme === "dark" ? (
                    <motion.div
                        key="moon"
                        initial={{ opacity: 0, rotate: -90 }}
                        animate={{ opacity: 1, rotate: 0 }}
                        exit={{ opacity: 0, rotate: 90 }}
                        transition={{ duration: 0.15 }}
                    >
                        <Moon className="h-4 w-4 text-[var(--foreground)]" />
                    </motion.div>
                ) : (
                    <motion.div
                        key="sun"
                        initial={{ opacity: 0, rotate: 90 }}
                        animate={{ opacity: 1, rotate: 0 }}
                        exit={{ opacity: 0, rotate: -90 }}
                        transition={{ duration: 0.15 }}
                    >
                        <Sun className="h-4 w-4 text-[var(--foreground)]" />
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.button>
    );
}

export function ThemeDropdown() {
    const { theme, setTheme, resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);
    const [open, setOpen] = useState(false);

    useEffect(() => {
        setMounted(true);
    }, []);

    if (!mounted) return null;

    const themes = [
        { value: "light", label: "Light", icon: Sun },
        { value: "dark", label: "Dark", icon: Moon },
        { value: "system", label: "System", icon: Monitor },
    ];

    return (
        <div className="relative">
            <motion.button
                onClick={() => setOpen(!open)}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="flex items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--secondary)] px-3 py-2 text-sm font-medium text-[var(--foreground)] transition-colors hover:bg-[var(--secondary-hover)]"
            >
                {resolvedTheme === "dark" ? (
                    <Moon className="h-4 w-4" />
                ) : (
                    <Sun className="h-4 w-4" />
                )}
                <span className="capitalize">{theme}</span>
            </motion.button>

            <AnimatePresence>
                {open && (
                    <>
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-40"
                            onClick={() => setOpen(false)}
                        />
                        <motion.div
                            initial={{ opacity: 0, y: -10 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -10 }}
                            className="absolute right-0 top-full z-50 mt-2 w-36 rounded-lg border border-[var(--border)] bg-[var(--card)] p-1 shadow-lg"
                        >
                            {themes.map((t) => (
                                <button
                                    key={t.value}
                                    onClick={() => {
                                        setTheme(t.value);
                                        setOpen(false);
                                    }}
                                    className={cn(
                                        "flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                                        theme === t.value
                                            ? "bg-[var(--primary-muted)] text-[var(--primary)]"
                                            : "text-[var(--foreground)] hover:bg-[var(--muted)]"
                                    )}
                                >
                                    <t.icon className="h-4 w-4" />
                                    {t.label}
                                </button>
                            ))}
                        </motion.div>
                    </>
                )}
            </AnimatePresence>
        </div>
    );
}
