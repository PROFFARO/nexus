"use client";
import React, { useState, useEffect } from "react";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import {
    IconSettings,
    IconTerminal2,
    IconShieldLock,
    IconLayoutDashboard,
    IconBrain,
    IconMessages,
    IconSun,
    IconMoon,
    IconFileText,
    IconLock,
    IconSearch
} from "@tabler/icons-react";
import { motion } from "framer-motion";
import Image from "next/image";
import { cn } from "@/lib/utils";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { CommandSearch } from "@/components/search";
import { SearchProvider, useSearch } from "@/hooks/use-search";

// Inner component that uses the search context
function DashboardLayoutInner({
    children,
}: {
    children: React.ReactNode;
}) {
    const [open, setOpen] = useState(false);
    const pathname = usePathname();
    const { setTheme, resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);
    const { open: openSearch } = useSearch();

    useEffect(() => {
        setMounted(true);
    }, []);

    const links = [
        {
            label: "Dashboard",
            href: "/",
            icon: (
                <IconLayoutDashboard className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Live Attacks",
            href: "/attacks",
            icon: (
                <IconTerminal2 className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Real Time ML Analysis",
            href: "/ml-analysis",
            icon: (
                <IconBrain className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Live Conversations",
            href: "/conversations",
            icon: (
                <IconMessages className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Sessions",
            href: "/sessions",
            icon: (
                <IconShieldLock className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Settings",
            href: "/settings",
            icon: (
                <IconSettings className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Terms of Service",
            href: "/terms",
            icon: (
                <IconFileText className="h-5 w-5 flex-shrink-0" />
            ),
        },
        {
            label: "Privacy Policy",
            href: "/privacy",
            icon: (
                <IconLock className="h-5 w-5 flex-shrink-0" />
            ),
        },
    ];

    return (
        <div
            className={cn(
                "rounded-md flex flex-col md:flex-row bg-gray-100 dark:bg-neutral-900 w-full flex-1 mx-auto border border-neutral-200 dark:border-neutral-700 overflow-hidden relative z-20",
                "h-screen"
            )}
        >
            <Sidebar open={open} setOpen={setOpen}>
                <SidebarBody className="justify-between gap-10 bg-white/95 dark:bg-neutral-950/95 backdrop-blur-xl border-r border-neutral-200/50 dark:border-white/10 py-4 px-3 z-50 isolate">
                    <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
                        {/* Logo Section */}
                        <div className="flex items-center gap-2 px-1 py-1 overflow-hidden">
                            <div className="h-8 w-8 relative flex-shrink-0">
                                <Image src="/assets/nexus_logo.svg" alt="NEXUS" fill className="object-contain" />
                            </div>
                            <motion.span
                                animate={{
                                    display: open ? "inline-block" : "none",
                                    opacity: open ? 1 : 0,
                                }}
                                className="font-bold text-xl bg-clip-text text-transparent bg-gradient-to-r from-neutral-800 to-neutral-600 dark:from-white dark:to-neutral-400 whitespace-pre"
                            >
                                NEXUS
                            </motion.span>
                        </div>

                        {/* Search Button */}
                        <button
                            onClick={(e) => {
                                e.preventDefault();
                                openSearch();
                            }}
                            className="mt-6 w-full flex items-center justify-start gap-2 py-2 px-2 cursor-pointer group text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-white/5 rounded transition-all duration-200"
                        >
                            <IconSearch className="h-5 w-5 flex-shrink-0 group-hover:text-primary transition-colors" />
                            <motion.span
                                animate={{
                                    display: open ? "inline-block" : "none",
                                    opacity: open ? 1 : 0,
                                }}
                                className="text-sm group-hover:translate-x-1 transition duration-150 whitespace-pre inline-block"
                            >
                                Search
                            </motion.span>
                            <motion.div
                                animate={{
                                    display: open ? "flex" : "none",
                                    opacity: open ? 1 : 0,
                                }}
                                className="ml-auto flex items-center gap-0.5"
                            >
                                <kbd className="px-1.5 py-0.5 text-[10px] font-medium bg-neutral-200 dark:bg-neutral-800 rounded text-neutral-500 dark:text-neutral-400">
                                    Ctrl
                                </kbd>
                                <kbd className="px-1.5 py-0.5 text-[10px] font-medium bg-neutral-200 dark:bg-neutral-800 rounded text-neutral-500 dark:text-neutral-400">
                                    K
                                </kbd>
                            </motion.div>
                        </button>

                        <div className="mt-4 flex flex-col gap-2">
                            {links.map((link, idx) => {
                                const isActive = pathname === link.href;
                                return (
                                    <SidebarLink
                                        key={idx}
                                        link={link}
                                        className={cn(
                                            "transition-all duration-200 rounded px-2",
                                            isActive
                                                ? "bg-orange-500/10 text-orange-600 dark:text-orange-400 font-medium"
                                                : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-white/5"
                                        )}
                                    />
                                );
                            })}

                            <div
                                onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
                                className="cursor-pointer group mt-auto"
                            >
                                <SidebarLink
                                    link={{
                                        label: mounted ? (resolvedTheme === "dark" ? "Light Mode" : "Dark Mode") : "Theme",
                                        href: "#",
                                        icon: mounted && resolvedTheme === "dark" ? (
                                            <IconSun className="h-5 w-5 flex-shrink-0 group-hover:text-orange-500 transition-colors" />
                                        ) : (
                                            <IconMoon className="h-5 w-5 flex-shrink-0 group-hover:text-blue-500 transition-colors" />
                                        )
                                    }}
                                    className="text-neutral-600 dark:text-neutral-400 group-hover:bg-neutral-100 dark:group-hover:bg-white/5 rounded px-2"
                                />
                            </div>
                        </div>
                    </div>
                </SidebarBody>
            </Sidebar>

            {/* Main Content */}
            <main className="flex-1 overflow-auto bg-[var(--background)] p-4 md:p-8 transition-all duration-300">
                <div className="max-w-7xl mx-auto h-full w-full">
                    {children}
                </div>
            </main>

            {/* Global Command Search */}
            <CommandSearch />
        </div>
    );
}

// Wrapper component that provides the SearchProvider
export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <SearchProvider>
            <DashboardLayoutInner>{children}</DashboardLayoutInner>
        </SearchProvider>
    );
}