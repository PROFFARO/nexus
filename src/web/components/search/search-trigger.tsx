"use client";

import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { Kbd, KbdGroup } from "@/components/ui/kbd";

interface SearchTriggerProps {
    onClick: () => void;
    className?: string;
    variant?: "default" | "compact" | "icon";
}

export function SearchTrigger({
    onClick,
    className,
    variant = "default",
}: SearchTriggerProps) {
    // Use state for Mac detection to avoid hydration mismatch
    const [shortcutKey, setShortcutKey] = useState("Ctrl");

    useEffect(() => {
        // Only detect Mac on client side after hydration
        const isMac = /Mac|iPod|iPhone|iPad/.test(navigator.platform);
        setShortcutKey(isMac ? "⌘" : "Ctrl");
    }, []);

    if (variant === "icon") {
        return (
            <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={onClick}
                className={cn(
                    "flex items-center justify-center h-10 w-10 rounded-xl",
                    "bg-muted/50 hover:bg-muted text-muted-foreground hover:text-foreground",
                    "border border-border/50 hover:border-border",
                    "transition-colors duration-200",
                    "focus:outline-none focus:ring-2 focus:ring-primary/20",
                    className
                )}
                aria-label="Open search"
            >
                <Search className="h-4 w-4" />
            </motion.button>
        );
    }

    if (variant === "compact") {
        return (
            <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={onClick}
                className={cn(
                    "flex items-center gap-2 h-9 px-3 rounded-lg",
                    "bg-muted/50 hover:bg-muted text-muted-foreground hover:text-foreground",
                    "border border-border/50 hover:border-border",
                    "transition-all duration-200",
                    "focus:outline-none focus:ring-2 focus:ring-primary/20",
                    className
                )}
                aria-label="Open search"
            >
                <Search className="h-3.5 w-3.5" />
                <span className="text-sm">Search</span>
                <KbdGroup className="ml-1">
                    <Kbd className="text-[10px] px-1">{shortcutKey}</Kbd>
                    <Kbd className="text-[10px] px-1">K</Kbd>
                </KbdGroup>
            </motion.button>
        );
    }

    // Default variant - full width search bar style
    return (
        <motion.button
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
            onClick={onClick}
            className={cn(
                "group relative flex items-center gap-3 w-full max-w-md h-11 px-4 rounded-xl",
                "bg-muted/30 hover:bg-muted/50",
                "border border-border/50 hover:border-border",
                "text-muted-foreground hover:text-foreground",
                "transition-all duration-200",
                "focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/30",
                "cursor-text",
                className
            )}
            aria-label="Open search"
        >
            {/* Search Icon */}
            <Search className="h-4 w-4 shrink-0 transition-transform group-hover:scale-110" />

            {/* Placeholder Text */}
            <span className="flex-1 text-left text-sm">
                Search pages, settings, actions...
            </span>

            {/* Keyboard Shortcut */}
            <KbdGroup className="shrink-0 opacity-70 group-hover:opacity-100 transition-opacity">
                <Kbd className="text-[10px] px-1.5 py-0.5">{shortcutKey}</Kbd>
                <Kbd className="text-[10px] px-1.5 py-0.5">K</Kbd>
            </KbdGroup>

            {/* Hover Glow Effect */}
            <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-primary/5 via-transparent to-primary/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
        </motion.button>
    );
}
