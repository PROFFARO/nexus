"use client";

import { ClerkProvider } from "@clerk/nextjs";
import { dark } from "@clerk/themes";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";

export function ClerkWrapper({ children }: { children: React.ReactNode }) {
    const { resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
    }, []);

    return (
        <ClerkProvider
            appearance={{
                baseTheme: mounted && resolvedTheme === "dark" ? dark : undefined,
                variables: {
                    colorPrimary: '#0d9488',
                    colorBackground: mounted && resolvedTheme === "dark" ? "#18181b" : "#ffffff",
                    colorInputBackground: mounted && resolvedTheme === "dark" ? "#27272a" : "#ffffff",
                    colorInputText: mounted && resolvedTheme === "dark" ? "#fafafa" : "#18181b",
                },
                elements: {
                    card: "shadow-xl border-border/50",
                    rootBox: "font-sans",
                }
            }}
        >
            {children}
        </ClerkProvider>
    );
}
