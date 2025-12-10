"use client";

import { useEffect } from "react";

export default function DashboardPage() {
    // Sync user with MongoDB on first access
    useEffect(() => {
        fetch("/api/auth/sync")
            .then((res) => res.json())
            .then((data) => {
                if (data.success) {
                    console.log("[User Sync] Synced:", data.user.email, "Role:", data.user.role);
                } else if (data.error) {
                    console.error("[User Sync Error]", data.error);
                }
            })
            .catch((err) => console.error("[User Sync] Error:", err));
    }, []);

    return (
        <div className="h-full w-full">
            {/* Dashboard content will be added here */}
        </div>
    );
}
