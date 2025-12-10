"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Sidebar } from "@/components/ui/sidebar";
import { Header } from "@/components/ui/header";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
    Terminal,
    Database,
    Shield,
    AlertTriangle,
    Bell,
    Ban,
    CheckCircle,
    Settings,
    Save,
} from "lucide-react";
import { cn } from "@/lib/utils";

// Mock security settings - will be replaced with real API data
const mockSecuritySettings = {
    ssh: {
        alertThresholds: { criticalScore: 90, highScore: 70, mediumScore: 50 },
        autoBlockEnabled: true,
        blockDuration: 60,
        maxFailedAttempts: 5,
        blacklistedIPs: ["192.168.1.100", "10.0.0.50"],
        whitelistedIPs: ["192.168.1.1"],
        customRules: [
            { name: "Block rm -rf", pattern: "rm -rf", action: "block", severity: "critical" },
            { name: "Alert passwd access", pattern: "/etc/passwd", action: "alert", severity: "high" },
        ],
    },
    ftp: {
        alertThresholds: { criticalScore: 85, highScore: 65, mediumScore: 45 },
        autoBlockEnabled: true,
        blockDuration: 30,
        maxFailedAttempts: 3,
        blacklistedIPs: [],
        whitelistedIPs: [],
        customRules: [
            { name: "Block exe uploads", pattern: "\\.exe$", action: "block", severity: "critical" },
        ],
    },
    mysql: {
        alertThresholds: { criticalScore: 90, highScore: 75, mediumScore: 55 },
        autoBlockEnabled: true,
        blockDuration: 120,
        maxFailedAttempts: 3,
        blacklistedIPs: [],
        whitelistedIPs: [],
        customRules: [
            { name: "Block DROP TABLE", pattern: "DROP TABLE", action: "block", severity: "critical" },
            { name: "Alert UNION SELECT", pattern: "UNION.*SELECT", action: "alert", severity: "high" },
        ],
    },
};

type Protocol = "ssh" | "ftp" | "mysql";

const protocolIcons = {
    ssh: Terminal,
    ftp: Database,
    mysql: Database,
};

const protocolColors = {
    ssh: "text-cyan-400",
    ftp: "text-purple-400",
    mysql: "text-amber-400",
};

export default function SecuritySettingsPage() {
    const [activeProtocol, setActiveProtocol] = useState<Protocol>("ssh");
    const [settings, setSettings] = useState(mockSecuritySettings);
    const [hasChanges, setHasChanges] = useState(false);

    const currentSettings = settings[activeProtocol];
    const ProtocolIcon = protocolIcons[activeProtocol];

    const handleThresholdChange = (
        level: "criticalScore" | "highScore" | "mediumScore",
        value: number
    ) => {
        setSettings({
            ...settings,
            [activeProtocol]: {
                ...currentSettings,
                alertThresholds: {
                    ...currentSettings.alertThresholds,
                    [level]: value,
                },
            },
        });
        setHasChanges(true);
    };

    return (
        <div className="min-h-screen bg-background" suppressHydrationWarning>
            <div className="gradient-bg" />
            <Sidebar>{null}</Sidebar>

            <div className="flex min-h-screen flex-col" style={{ marginLeft: 256 }}>
                <Header />{null}

                <main className="flex-1 p-6">
                    <div className="space-y-6">
                        {/* Page Header */}
                        <div className="flex items-center justify-between">
                            <div>
                                <h1 className="text-2xl font-bold">Protocol Security Settings</h1>
                                <p className="text-sm text-muted-foreground">
                                    Configure security rules and thresholds for each protocol
                                </p>
                            </div>
                            <Button
                                disabled={!hasChanges}
                                className="flex items-center gap-2"
                            >
                                <Save className="h-4 w-4" />
                                Save Changes
                            </Button>
                        </div>

                        {/* Protocol Tabs */}
                        <Tabs
                            value={activeProtocol}
                            onValueChange={(v) => setActiveProtocol(v as Protocol)}
                        >
                            <TabsList className="grid w-full grid-cols-3">
                                <TabsTrigger
                                    value="ssh"
                                    className="flex items-center gap-2 data-[state=active]:text-cyan-400"
                                >
                                    <Terminal className="h-4 w-4" />
                                    SSH
                                </TabsTrigger>
                                <TabsTrigger
                                    value="ftp"
                                    className="flex items-center gap-2 data-[state=active]:text-purple-400"
                                >
                                    <Database className="h-4 w-4" />
                                    FTP
                                </TabsTrigger>
                                <TabsTrigger
                                    value="mysql"
                                    className="flex items-center gap-2 data-[state=active]:text-amber-400"
                                >
                                    <Database className="h-4 w-4" />
                                    MySQL
                                </TabsTrigger>
                            </TabsList>

                            <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
                                {/* Alert Thresholds */}
                                <Card className="border-border/50 bg-card/80">
                                    <CardHeader>
                                        <CardTitle className="flex items-center gap-2">
                                            <AlertTriangle className={cn("h-5 w-5", protocolColors[activeProtocol])} />
                                            Alert Thresholds
                                        </CardTitle>
                                        <CardDescription>
                                            ML anomaly score thresholds for alert severity
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent className="space-y-6">
                                        {/* Critical Threshold */}
                                        <div className="space-y-2">
                                            <div className="flex items-center justify-between">
                                                <span className="text-sm font-medium text-red-400">
                                                    Critical Threshold
                                                </span>
                                                <span className="text-sm font-bold">
                                                    {currentSettings.alertThresholds.criticalScore}
                                                </span>
                                            </div>
                                            <Progress
                                                value={currentSettings.alertThresholds.criticalScore}
                                                className="h-2 [&>div]:bg-red-500"
                                            />
                                            <Input
                                                type="range"
                                                min="50"
                                                max="100"
                                                value={currentSettings.alertThresholds.criticalScore}
                                                onChange={(e) =>
                                                    handleThresholdChange("criticalScore", parseInt(e.target.value))
                                                }
                                                className="h-2"
                                            />
                                        </div>

                                        {/* High Threshold */}
                                        <div className="space-y-2">
                                            <div className="flex items-center justify-between">
                                                <span className="text-sm font-medium text-orange-400">
                                                    High Threshold
                                                </span>
                                                <span className="text-sm font-bold">
                                                    {currentSettings.alertThresholds.highScore}
                                                </span>
                                            </div>
                                            <Progress
                                                value={currentSettings.alertThresholds.highScore}
                                                className="h-2 [&>div]:bg-orange-500"
                                            />
                                            <Input
                                                type="range"
                                                min="30"
                                                max="90"
                                                value={currentSettings.alertThresholds.highScore}
                                                onChange={(e) =>
                                                    handleThresholdChange("highScore", parseInt(e.target.value))
                                                }
                                                className="h-2"
                                            />
                                        </div>

                                        {/* Medium Threshold */}
                                        <div className="space-y-2">
                                            <div className="flex items-center justify-between">
                                                <span className="text-sm font-medium text-amber-400">
                                                    Medium Threshold
                                                </span>
                                                <span className="text-sm font-bold">
                                                    {currentSettings.alertThresholds.mediumScore}
                                                </span>
                                            </div>
                                            <Progress
                                                value={currentSettings.alertThresholds.mediumScore}
                                                className="h-2 [&>div]:bg-amber-500"
                                            />
                                            <Input
                                                type="range"
                                                min="10"
                                                max="70"
                                                value={currentSettings.alertThresholds.mediumScore}
                                                onChange={(e) =>
                                                    handleThresholdChange("mediumScore", parseInt(e.target.value))
                                                }
                                                className="h-2"
                                            />
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* Auto-Block Settings */}
                                <Card className="border-border/50 bg-card/80">
                                    <CardHeader>
                                        <CardTitle className="flex items-center gap-2">
                                            <Ban className={cn("h-5 w-5", protocolColors[activeProtocol])} />
                                            Auto-Block Settings
                                        </CardTitle>
                                        <CardDescription>
                                            Automatic IP blocking configuration
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent className="space-y-4">
                                        <div className="flex items-center justify-between rounded-lg border border-border p-4">
                                            <div>
                                                <p className="font-medium">Auto-Block Enabled</p>
                                                <p className="text-sm text-muted-foreground">
                                                    Automatically block IPs after suspicious activity
                                                </p>
                                            </div>
                                            <div
                                                className={cn(
                                                    "flex h-6 w-11 cursor-pointer items-center rounded-full px-1 transition-colors",
                                                    currentSettings.autoBlockEnabled
                                                        ? "bg-emerald-500"
                                                        : "bg-muted"
                                                )}
                                                onClick={() => {
                                                    setSettings({
                                                        ...settings,
                                                        [activeProtocol]: {
                                                            ...currentSettings,
                                                            autoBlockEnabled: !currentSettings.autoBlockEnabled,
                                                        },
                                                    });
                                                    setHasChanges(true);
                                                }}
                                            >
                                                <div
                                                    className={cn(
                                                        "h-4 w-4 rounded-full bg-white transition-transform",
                                                        currentSettings.autoBlockEnabled && "translate-x-5"
                                                    )}
                                                />
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="space-y-2">
                                                <label className="text-sm font-medium">
                                                    Block Duration (minutes)
                                                </label>
                                                <Input
                                                    type="number"
                                                    value={currentSettings.blockDuration}
                                                    onChange={(e) => {
                                                        setSettings({
                                                            ...settings,
                                                            [activeProtocol]: {
                                                                ...currentSettings,
                                                                blockDuration: parseInt(e.target.value) || 0,
                                                            },
                                                        });
                                                        setHasChanges(true);
                                                    }}
                                                />
                                            </div>
                                            <div className="space-y-2">
                                                <label className="text-sm font-medium">
                                                    Max Failed Attempts
                                                </label>
                                                <Input
                                                    type="number"
                                                    value={currentSettings.maxFailedAttempts}
                                                    onChange={(e) => {
                                                        setSettings({
                                                            ...settings,
                                                            [activeProtocol]: {
                                                                ...currentSettings,
                                                                maxFailedAttempts: parseInt(e.target.value) || 0,
                                                            },
                                                        });
                                                        setHasChanges(true);
                                                    }}
                                                />
                                            </div>
                                        </div>

                                        {/* IP Lists Summary */}
                                        <div className="grid grid-cols-2 gap-4 pt-2">
                                            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3">
                                                <p className="text-sm font-medium text-red-400">
                                                    Blacklisted IPs
                                                </p>
                                                <p className="text-2xl font-bold">
                                                    {currentSettings.blacklistedIPs.length}
                                                </p>
                                            </div>
                                            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3">
                                                <p className="text-sm font-medium text-emerald-400">
                                                    Whitelisted IPs
                                                </p>
                                                <p className="text-2xl font-bold">
                                                    {currentSettings.whitelistedIPs.length}
                                                </p>
                                            </div>
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* Custom Rules */}
                                <Card className="border-border/50 bg-card/80 lg:col-span-2">
                                    <CardHeader>
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <CardTitle className="flex items-center gap-2">
                                                    <Shield className={cn("h-5 w-5", protocolColors[activeProtocol])} />
                                                    Custom Security Rules
                                                </CardTitle>
                                                <CardDescription>
                                                    Pattern-based detection rules for {activeProtocol.toUpperCase()}
                                                </CardDescription>
                                            </div>
                                            <Button variant="outline" size="sm">
                                                Add Rule
                                            </Button>
                                        </div>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="space-y-2">
                                            {currentSettings.customRules.map((rule, index) => (
                                                <motion.div
                                                    key={index}
                                                    initial={{ opacity: 0 }}
                                                    animate={{ opacity: 1 }}
                                                    className="flex items-center justify-between rounded-lg border border-border p-4"
                                                >
                                                    <div className="flex-1">
                                                        <div className="flex items-center gap-2">
                                                            <span className="font-medium">{rule.name}</span>
                                                            <Badge
                                                                variant="outline"
                                                                className={cn(
                                                                    rule.severity === "critical" &&
                                                                    "bg-red-500/15 text-red-400 border-red-500/30",
                                                                    rule.severity === "high" &&
                                                                    "bg-orange-500/15 text-orange-400 border-orange-500/30",
                                                                    rule.severity === "medium" &&
                                                                    "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                                                )}
                                                            >
                                                                {rule.severity.toUpperCase()}
                                                            </Badge>
                                                            <Badge variant="outline">
                                                                {rule.action.toUpperCase()}
                                                            </Badge>
                                                        </div>
                                                        <p className="mt-1 font-mono text-sm text-muted-foreground">
                                                            Pattern: {rule.pattern}
                                                        </p>
                                                    </div>
                                                    <Button variant="ghost" size="sm">
                                                        Edit
                                                    </Button>
                                                </motion.div>
                                            ))}
                                            {currentSettings.customRules.length === 0 && (
                                                <div className="py-8 text-center text-muted-foreground">
                                                    No custom rules configured for {activeProtocol.toUpperCase()}
                                                </div>
                                            )}
                                        </div>
                                    </CardContent>
                                </Card>
                            </div>
                        </Tabs>
                    </div>
                </main>
            </div>
        </div>
    );
}
