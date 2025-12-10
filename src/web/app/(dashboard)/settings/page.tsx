"use client";

import { useState } from "react";
import { useUser, useClerk } from "@clerk/nextjs";
import { useTheme } from "next-themes";
import { motion } from "framer-motion";
import {
    IconUser,
    IconMoon,
    IconSun,
    IconBell,
    IconShield,
    IconPalette,
    IconDeviceFloppy,
    IconCheck,
} from "@tabler/icons-react";

export default function SettingsPage() {
    const { user } = useUser();
    const { openUserProfile } = useClerk();
    const { theme, setTheme, resolvedTheme } = useTheme();
    const [notifications, setNotifications] = useState({
        email: true,
        push: false,
        attacks: true,
        weekly: true,
    });
    const [saved, setSaved] = useState(false);

    const handleSave = () => {
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
    };

    return (
        <div className="max-w-4xl mx-auto space-y-8">
            {/* Page Header */}
            <div>
                <h1 className="text-2xl font-bold">Settings</h1>
                <p className="text-muted-foreground mt-1">
                    Manage your account preferences and application settings
                </p>
            </div>

            {/* Profile Section */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-border bg-card p-6"
            >
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 rounded-lg bg-primary/10">
                        <IconUser className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                        <h2 className="text-lg font-semibold">Profile</h2>
                        <p className="text-sm text-muted-foreground">Manage your personal information</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                        <div>
                            <p className="font-medium">{user?.fullName || "User"}</p>
                            <p className="text-sm text-muted-foreground">{user?.primaryEmailAddress?.emailAddress}</p>
                        </div>
                        <button
                            onClick={() => openUserProfile()}
                            className="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                        >
                            Edit Profile
                        </button>
                    </div>
                </div>
            </motion.div>

            {/* Appearance Section */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="rounded-xl border border-border bg-card p-6"
            >
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 rounded-lg bg-purple-500/10">
                        <IconPalette className="h-5 w-5 text-purple-500" />
                    </div>
                    <div>
                        <h2 className="text-lg font-semibold">Appearance</h2>
                        <p className="text-sm text-muted-foreground">Customize how NEXUS looks</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                        <div className="flex items-center gap-3">
                            {resolvedTheme === "dark" ? (
                                <IconMoon className="h-5 w-5 text-blue-400" />
                            ) : (
                                <IconSun className="h-5 w-5 text-orange-400" />
                            )}
                            <div>
                                <p className="font-medium">Theme</p>
                                <p className="text-sm text-muted-foreground">
                                    Currently using {resolvedTheme} mode
                                </p>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={() => setTheme("light")}
                                className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${theme === "light"
                                        ? "bg-primary text-primary-foreground border-primary"
                                        : "border-border hover:bg-muted"
                                    }`}
                            >
                                Light
                            </button>
                            <button
                                onClick={() => setTheme("dark")}
                                className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${theme === "dark"
                                        ? "bg-primary text-primary-foreground border-primary"
                                        : "border-border hover:bg-muted"
                                    }`}
                            >
                                Dark
                            </button>
                            <button
                                onClick={() => setTheme("system")}
                                className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${theme === "system"
                                        ? "bg-primary text-primary-foreground border-primary"
                                        : "border-border hover:bg-muted"
                                    }`}
                            >
                                System
                            </button>
                        </div>
                    </div>
                </div>
            </motion.div>

            {/* Notifications Section */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="rounded-xl border border-border bg-card p-6"
            >
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 rounded-lg bg-amber-500/10">
                        <IconBell className="h-5 w-5 text-amber-500" />
                    </div>
                    <div>
                        <h2 className="text-lg font-semibold">Notifications</h2>
                        <p className="text-sm text-muted-foreground">Configure how you receive alerts</p>
                    </div>
                </div>

                <div className="space-y-3">
                    {[
                        { key: "email", label: "Email Notifications", desc: "Receive updates via email" },
                        { key: "push", label: "Push Notifications", desc: "Browser push notifications" },
                        { key: "attacks", label: "Attack Alerts", desc: "Immediate alerts for critical attacks" },
                        { key: "weekly", label: "Weekly Digest", desc: "Weekly summary of honeypot activity" },
                    ].map((item) => (
                        <div
                            key={item.key}
                            className="flex items-center justify-between p-4 rounded-lg bg-muted/50"
                        >
                            <div>
                                <p className="font-medium">{item.label}</p>
                                <p className="text-sm text-muted-foreground">{item.desc}</p>
                            </div>
                            <button
                                onClick={() =>
                                    setNotifications((prev) => ({
                                        ...prev,
                                        [item.key]: !prev[item.key as keyof typeof notifications],
                                    }))
                                }
                                className={`relative w-11 h-6 rounded-full transition-colors ${notifications[item.key as keyof typeof notifications]
                                        ? "bg-primary"
                                        : "bg-muted-foreground/30"
                                    }`}
                            >
                                <span
                                    className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${notifications[item.key as keyof typeof notifications]
                                            ? "translate-x-5"
                                            : "translate-x-0"
                                        }`}
                                />
                            </button>
                        </div>
                    ))}
                </div>
            </motion.div>

            {/* Security Section */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="rounded-xl border border-border bg-card p-6"
            >
                <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 rounded-lg bg-red-500/10">
                        <IconShield className="h-5 w-5 text-red-500" />
                    </div>
                    <div>
                        <h2 className="text-lg font-semibold">Security</h2>
                        <p className="text-sm text-muted-foreground">Manage your security preferences</p>
                    </div>
                </div>

                <div className="space-y-3">
                    <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                        <div>
                            <p className="font-medium">Two-Factor Authentication</p>
                            <p className="text-sm text-muted-foreground">Add an extra layer of security</p>
                        </div>
                        <button
                            onClick={() => openUserProfile()}
                            className="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                        >
                            Configure
                        </button>
                    </div>
                    <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                        <div>
                            <p className="font-medium">Active Sessions</p>
                            <p className="text-sm text-muted-foreground">Manage your active sessions</p>
                        </div>
                        <button
                            onClick={() => openUserProfile()}
                            className="px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
                        >
                            View
                        </button>
                    </div>
                </div>
            </motion.div>

            {/* Save Button */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="flex justify-end"
            >
                <button
                    onClick={handleSave}
                    className="flex items-center gap-2 px-6 py-2.5 bg-primary text-primary-foreground font-medium rounded-lg hover:bg-primary/90 transition-colors"
                >
                    {saved ? (
                        <>
                            <IconCheck className="h-5 w-5" />
                            Saved
                        </>
                    ) : (
                        <>
                            <IconDeviceFloppy className="h-5 w-5" />
                            Save Changes
                        </>
                    )}
                </button>
            </motion.div>
        </div>
    );
}
