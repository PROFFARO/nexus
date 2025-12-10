"use client";

import { useState, useEffect } from "react";
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
    Users,
    Shield,
    Search,
    MoreVertical,
    UserPlus,
    CheckCircle,
    XCircle,
    Mail,
    Terminal,
    Database,
} from "lucide-react";
import { cn } from "@/lib/utils";

// Mock users data - will be replaced with real API data
const mockUsers = [
    {
        id: "1",
        email: "admin@nexus.io",
        firstName: "System",
        lastName: "Admin",
        role: "admin" as const,
        isActive: true,
        lastLoginAt: "2024-12-10T01:00:00Z",
        permissions: {
            ssh: { view: true, configure: true, export: true },
            ftp: { view: true, configure: true, export: true },
            mysql: { view: true, configure: true, export: true },
        },
    },
    {
        id: "2",
        email: "analyst@nexus.io",
        firstName: "Security",
        lastName: "Analyst",
        role: "analyst" as const,
        isActive: true,
        lastLoginAt: "2024-12-09T18:30:00Z",
        permissions: {
            ssh: { view: true, configure: true, export: true },
            ftp: { view: true, configure: true, export: true },
            mysql: { view: true, configure: true, export: true },
        },
    },
    {
        id: "3",
        email: "viewer@nexus.io",
        firstName: "Read",
        lastName: "Only",
        role: "viewer" as const,
        isActive: true,
        lastLoginAt: "2024-12-08T12:00:00Z",
        permissions: {
            ssh: { view: true, configure: false, export: false },
            ftp: { view: true, configure: false, export: false },
            mysql: { view: true, configure: false, export: false },
        },
    },
    {
        id: "4",
        email: "inactive@nexus.io",
        firstName: "Disabled",
        lastName: "User",
        role: "viewer" as const,
        isActive: false,
        lastLoginAt: null,
        permissions: {
            ssh: { view: true, configure: false, export: false },
            ftp: { view: true, configure: false, export: false },
            mysql: { view: true, configure: false, export: false },
        },
    },
];

type UserRole = "admin" | "analyst" | "viewer";

function getRoleBadgeClass(role: UserRole) {
    const styles = {
        admin: "bg-red-500/15 text-red-400 border-red-500/30",
        analyst: "bg-amber-500/15 text-amber-400 border-amber-500/30",
        viewer: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    };
    return styles[role];
}

export default function AdminUsersPage() {
    const [searchQuery, setSearchQuery] = useState("");
    const [activeTab, setActiveTab] = useState("all");

    const filteredUsers = mockUsers.filter((user) => {
        const matchesSearch =
            user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
            `${user.firstName} ${user.lastName}`
                .toLowerCase()
                .includes(searchQuery.toLowerCase());

        if (activeTab === "all") return matchesSearch;
        if (activeTab === "active") return matchesSearch && user.isActive;
        if (activeTab === "inactive") return matchesSearch && !user.isActive;
        return matchesSearch && user.role === activeTab;
    });

    return (
        <div className="min-h-screen bg-background" suppressHydrationWarning>
            <div className="gradient-bg" />
            <Sidebar>{null}</Sidebar>

            <div className="flex min-h-screen flex-col" style={{ marginLeft: 256 }}>
                <Header />

                <main className="flex-1 p-6">
                    <div className="space-y-6">
                        {/* Page Header */}
                        <div className="flex items-center justify-between">
                            <div>
                                <h1 className="text-2xl font-bold">User Management</h1>
                                <p className="text-sm text-muted-foreground">
                                    Manage user access and permissions
                                </p>
                            </div>
                            <Button className="flex items-center gap-2">
                                <UserPlus className="h-4 w-4" />
                                Invite User
                            </Button>
                        </div>

                        {/* Stats Cards */}
                        <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
                            <Card className="border-border/50 bg-card/80">
                                <CardContent className="p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/15 text-blue-400">
                                            <Users className="h-5 w-5" />
                                        </div>
                                        <div>
                                            <p className="text-2xl font-bold">{mockUsers.length}</p>
                                            <p className="text-xs text-muted-foreground">
                                                Total Users
                                            </p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                            <Card className="border-border/50 bg-card/80">
                                <CardContent className="p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/15 text-red-400">
                                            <Shield className="h-5 w-5" />
                                        </div>
                                        <div>
                                            <p className="text-2xl font-bold">
                                                {mockUsers.filter((u) => u.role === "admin").length}
                                            </p>
                                            <p className="text-xs text-muted-foreground">Admins</p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                            <Card className="border-border/50 bg-card/80">
                                <CardContent className="p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400">
                                            <CheckCircle className="h-5 w-5" />
                                        </div>
                                        <div>
                                            <p className="text-2xl font-bold">
                                                {mockUsers.filter((u) => u.isActive).length}
                                            </p>
                                            <p className="text-xs text-muted-foreground">Active</p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                            <Card className="border-border/50 bg-card/80">
                                <CardContent className="p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gray-500/15 text-gray-400">
                                            <XCircle className="h-5 w-5" />
                                        </div>
                                        <div>
                                            <p className="text-2xl font-bold">
                                                {mockUsers.filter((u) => !u.isActive).length}
                                            </p>
                                            <p className="text-xs text-muted-foreground">Inactive</p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        </div>

                        {/* Users Table */}
                        <Card className="border-border/50 bg-card/80">
                            <CardHeader>
                                <div className="flex items-center justify-between">
                                    <div>
                                        <CardTitle>Users</CardTitle>
                                        <CardDescription>
                                            All registered users and their permissions
                                        </CardDescription>
                                    </div>
                                    <div className="relative w-64">
                                        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                        <Input
                                            placeholder="Search users..."
                                            value={searchQuery}
                                            onChange={(e) => setSearchQuery(e.target.value)}
                                            className="pl-10"
                                        />
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent>
                                <Tabs value={activeTab} onValueChange={setActiveTab}>
                                    <TabsList className="mb-4">
                                        <TabsTrigger value="all">All</TabsTrigger>
                                        <TabsTrigger value="active">Active</TabsTrigger>
                                        <TabsTrigger value="inactive">Inactive</TabsTrigger>
                                        <TabsTrigger value="admin">Admins</TabsTrigger>
                                        <TabsTrigger value="analyst">Analysts</TabsTrigger>
                                    </TabsList>

                                    <ScrollArea className="h-[400px]">
                                        <div className="space-y-2">
                                            {filteredUsers.map((user, index) => (
                                                <motion.div
                                                    key={user.id}
                                                    initial={{ opacity: 0, y: 10 }}
                                                    animate={{ opacity: 1, y: 0 }}
                                                    transition={{ delay: index * 0.05 }}
                                                    className={cn(
                                                        "group flex items-center gap-4 rounded-lg border border-transparent p-4 transition-all hover:border-border hover:bg-muted/50",
                                                        !user.isActive && "opacity-60"
                                                    )}
                                                >
                                                    {/* Avatar */}
                                                    <div
                                                        className={cn(
                                                            "flex h-10 w-10 items-center justify-center rounded-full text-sm font-semibold",
                                                            user.isActive
                                                                ? "bg-primary text-primary-foreground"
                                                                : "bg-muted text-muted-foreground"
                                                        )}
                                                    >
                                                        {user.firstName[0]}
                                                        {user.lastName[0]}
                                                    </div>

                                                    {/* User Info */}
                                                    <div className="flex-1">
                                                        <div className="flex items-center gap-2">
                                                            <span className="font-medium">
                                                                {user.firstName} {user.lastName}
                                                            </span>
                                                            <Badge
                                                                variant="outline"
                                                                className={getRoleBadgeClass(user.role)}
                                                            >
                                                                {user.role.toUpperCase()}
                                                            </Badge>
                                                            {!user.isActive && (
                                                                <Badge variant="outline" className="bg-muted">
                                                                    INACTIVE
                                                                </Badge>
                                                            )}
                                                        </div>
                                                        <div className="flex items-center gap-3 text-sm text-muted-foreground">
                                                            <span className="flex items-center gap-1">
                                                                <Mail className="h-3 w-3" />
                                                                {user.email}
                                                            </span>
                                                            {user.lastLoginAt && (
                                                                <span>
                                                                    Last login:{" "}
                                                                    {new Date(user.lastLoginAt).toLocaleDateString()}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>

                                                    {/* Permissions Icons */}
                                                    <div className="flex items-center gap-2">
                                                        <div
                                                            className={cn(
                                                                "flex h-7 w-7 items-center justify-center rounded",
                                                                user.permissions.ssh.configure
                                                                    ? "bg-cyan-500/15 text-cyan-400"
                                                                    : "bg-muted text-muted-foreground"
                                                            )}
                                                            title="SSH"
                                                        >
                                                            <Terminal className="h-4 w-4" />
                                                        </div>
                                                        <div
                                                            className={cn(
                                                                "flex h-7 w-7 items-center justify-center rounded",
                                                                user.permissions.ftp.configure
                                                                    ? "bg-purple-500/15 text-purple-400"
                                                                    : "bg-muted text-muted-foreground"
                                                            )}
                                                            title="FTP"
                                                        >
                                                            <Database className="h-4 w-4" />
                                                        </div>
                                                        <div
                                                            className={cn(
                                                                "flex h-7 w-7 items-center justify-center rounded",
                                                                user.permissions.mysql.configure
                                                                    ? "bg-amber-500/15 text-amber-400"
                                                                    : "bg-muted text-muted-foreground"
                                                            )}
                                                            title="MySQL"
                                                        >
                                                            <Database className="h-4 w-4" />
                                                        </div>
                                                    </div>

                                                    {/* Actions Menu */}
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild>
                                                            <Button
                                                                variant="ghost"
                                                                size="icon"
                                                                className="opacity-0 group-hover:opacity-100"
                                                            >
                                                                <MoreVertical className="h-4 w-4" />
                                                            </Button>
                                                        </DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end">
                                                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                                                            <DropdownMenuSeparator />
                                                            <DropdownMenuItem>Edit Permissions</DropdownMenuItem>
                                                            <DropdownMenuItem>Change Role</DropdownMenuItem>
                                                            <DropdownMenuItem>View Activity</DropdownMenuItem>
                                                            <DropdownMenuSeparator />
                                                            {user.isActive ? (
                                                                <DropdownMenuItem className="text-red-400">
                                                                    Deactivate User
                                                                </DropdownMenuItem>
                                                            ) : (
                                                                <DropdownMenuItem className="text-emerald-400">
                                                                    Activate User
                                                                </DropdownMenuItem>
                                                            )}
                                                        </DropdownMenuContent>
                                                    </DropdownMenu>
                                                </motion.div>
                                            ))}
                                        </div>
                                    </ScrollArea>
                                </Tabs>
                            </CardContent>
                        </Card>
                    </div>
                </main>
            </div>
        </div>
    );
}
