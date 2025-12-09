"use client";

import { useEffect } from "react";
import { useClerk } from "@clerk/nextjs";
import { Loader2 } from "lucide-react";
import { motion } from "framer-motion";

export default function SSOCallback() {
    const { handleRedirectCallback } = useClerk();

    useEffect(() => {
        handleRedirectCallback({});
    }, [handleRedirectCallback]);

    return (
        <div className="flex min-h-screen items-center justify-center bg-[var(--background)]">
            <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex flex-col items-center justify-center text-center p-8 rounded-2xl bg-[var(--card)] border border-[var(--border)] shadow-xl"
            >
                <div className="relative">
                    <div className="h-16 w-16 rounded-full bg-[var(--primary)] opacity-10 blur-xl animate-pulse" />
                    <Loader2 className="absolute inset-0 m-auto h-8 w-8 animate-spin text-[var(--primary)]" />
                </div>

                <h2 className="mt-6 text-xl font-semibold text-[var(--foreground)]">
                    Verifying Identity
                </h2>
                <p className="mt-2 text-sm text-[var(--muted-foreground)]">
                    Securely connecting your account...
                </p>
            </motion.div>
        </div>
    );
}
