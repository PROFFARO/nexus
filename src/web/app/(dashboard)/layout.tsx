"use client";
import React, { useState } from "react";
import { Sidebar, SidebarBody, SidebarLink } from "@/components/ui/sidebar";
import {
    IconSettings,
    IconUserBolt,
    IconTerminal2,
    IconShieldLock,
    IconLayoutDashboard,
    IconLogout,
    IconBrain,
    IconMessages,
} from "@tabler/icons-react";
import { motion } from "framer-motion";
import Image from "next/image";
import { cn } from "@/lib/utils";
import { UserButton, useClerk, useUser } from "@clerk/nextjs";
import { usePathname, useRouter } from "next/navigation";

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const [open, setOpen] = useState(false);
    const { signOut } = useClerk();
    const { user } = useUser();
    const pathname = usePathname();
    const router = useRouter();

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
            label: "Logs",
            href: "/logs",
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
    ];

    return (
        <div
            className={cn(
                "rounded-md flex flex-col md:flex-row bg-gray-100 dark:bg-neutral-900 w-full flex-1 mx-auto border border-neutral-200 dark:border-neutral-700 overflow-hidden",
                "h-screen"
            )}
        >
            <Sidebar open={open} setOpen={setOpen}>
                <SidebarBody className="justify-between gap-10 bg-white/50 dark:bg-neutral-900/50 backdrop-blur-xl border-r border-neutral-200/50 dark:border-white/5 py-4 px-3">
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

                        <div className="mt-10 flex flex-col gap-2">
                            {links.map((link, idx) => {
                                const isActive = pathname === link.href;
                                return (
                                    <SidebarLink
                                        key={idx}
                                        link={link}
                                        className={cn(
                                            "transition-all duration-200 rounded-xl px-2",
                                            isActive
                                                ? "bg-orange-500/10 text-orange-600 dark:text-orange-400 font-medium"
                                                : "text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-white/5"
                                        )}
                                    />
                                );
                            })}

                            <div
                                onClick={() => signOut({ redirectUrl: '/sign-in' })}
                                className="cursor-pointer group mt-auto"
                            >
                                <SidebarLink
                                    link={{
                                        label: "Logout",
                                        href: "#",
                                        icon: <IconLogout className="h-5 w-5 flex-shrink-0 group-hover:text-red-500 transition-colors" />
                                    }}
                                    className="text-neutral-600 dark:text-neutral-400 group-hover:bg-red-500/10 group-hover:text-red-500 rounded-xl px-2"
                                />
                            </div>
                        </div>
                    </div>

                    {/* User Profile */}
                    <div className="border-t border-neutral-200/50 dark:border-white/5 pt-4">
                        <div
                            className={cn(
                                "flex items-center gap-3 px-1 rounded-xl p-2 transition-colors",
                                "hover:bg-neutral-100 dark:hover:bg-white/5"
                            )}
                        >
                            <div onClick={(e) => e.stopPropagation()} className="flex items-center justify-center">
                                <UserButton afterSignOutUrl="/sign-in" appearance={{
                                    elements: {
                                        avatarBox: "h-8 w-8 ring-2 ring-white/20"
                                    }
                                }} />
                            </div>
                            <motion.div
                                animate={{
                                    display: open ? "flex" : "none",
                                    opacity: open ? 1 : 0,
                                }}
                                className="flex flex-col overflow-hidden items-start text-left"
                            >
                                <span className="text-sm font-semibold text-neutral-800 dark:text-neutral-200 truncate max-w-[150px]">
                                    {user?.fullName || "User"}
                                </span>
                                <span className="text-xs text-neutral-500 dark:text-neutral-400 truncate max-w-[150px]">
                                    {user?.primaryEmailAddress?.emailAddress}
                                </span>
                            </motion.div>
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
        </div>
    );
}
