"use client";

import { Sidebar } from "@/components/ui/sidebar";
import { Header } from "@/components/ui/header";
import { motion } from "framer-motion";
import { useState, useEffect } from "react";

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

    // Listen for sidebar state changes
    useEffect(() => {
        const handleResize = () => {
            if (window.innerWidth < 1024) {
                setSidebarCollapsed(true);
            }
        };

        handleResize();
        window.addEventListener("resize", handleResize);
        return () => window.removeEventListener("resize", handleResize);
    }, []);

    return (
        <div className="min-h-screen bg-[var(--background)]">
            <Sidebar />

            <motion.div
                initial={false}
                animate={{ marginLeft: sidebarCollapsed ? 72 : 256 }}
                transition={{ duration: 0.2, ease: "easeInOut" }}
                className="flex min-h-screen flex-col"
                style={{ marginLeft: 256 }} // Default, will be animated
            >
                <Header />

                <main className="flex-1 p-6">
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.3 }}
                    >
                        {children}
                    </motion.div>
                </main>
            </motion.div>
        </div>
    );
}
