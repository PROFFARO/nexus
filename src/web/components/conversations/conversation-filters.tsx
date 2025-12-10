"use client";

import { ConversationFilters, defaultFilters } from "@/types/conversation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator,
    DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import {
    Filter,
    Terminal,
    FolderOpen,
    Database,
    Network,
    Clock,
    ShieldAlert,
    Search,
    SortAsc,
    SortDesc,
    X,
    RotateCcw,
    Zap,
    AlertTriangle,
    Info,
    CheckCircle
} from "lucide-react";

interface ConversationFiltersProps {
    filters: ConversationFilters;
    onFiltersChange: (filters: ConversationFilters) => void;
    totalCount: number;
    filteredCount: number;
}

const protocolOptions = [
    { value: 'all', label: 'All Protocols', icon: Network },
    { value: 'ssh', label: 'SSH', icon: Terminal },
    { value: 'ftp', label: 'FTP', icon: FolderOpen },
    { value: 'mysql', label: 'MySQL', icon: Database },
] as const;

const severityOptions = [
    { value: 'all', label: 'All Levels', icon: Info, color: '' },
    { value: 'critical', label: 'Critical', icon: ShieldAlert, color: 'text-rose-500' },
    { value: 'high', label: 'High', icon: AlertTriangle, color: 'text-orange-500' },
    { value: 'medium', label: 'Medium', icon: Zap, color: 'text-amber-500' },
    { value: 'low', label: 'Low', icon: CheckCircle, color: 'text-yellow-500' },
    { value: 'info', label: 'Info Only', icon: Info, color: 'text-blue-500' },
] as const;

const timeRangeOptions = [
    { value: 'all', label: 'All Time' },
    { value: '1h', label: 'Last Hour' },
    { value: '24h', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
] as const;

const sortOptions = [
    { value: 'newest', label: 'Newest First', icon: SortDesc },
    { value: 'oldest', label: 'Oldest First', icon: SortAsc },
    { value: 'mostActive', label: 'Most Active', icon: Zap },
    { value: 'highestThreat', label: 'Highest Threat', icon: ShieldAlert },
] as const;

export function ConversationFiltersBar({ filters, onFiltersChange, totalCount, filteredCount }: ConversationFiltersProps) {
    const activeFilterCount = [
        filters.protocol !== 'all',
        filters.severity !== 'all',
        filters.timeRange !== 'all',
        filters.showActiveOnly,
        filters.ipFilter !== '',
        filters.usernameFilter !== '',
        filters.searchQuery !== '',
    ].filter(Boolean).length;

    const hasActiveFilters = activeFilterCount > 0;

    const updateFilter = <K extends keyof ConversationFilters>(key: K, value: ConversationFilters[K]) => {
        onFiltersChange({ ...filters, [key]: value });
    };

    const resetFilters = () => {
        onFiltersChange(defaultFilters);
    };

    const currentProtocol = protocolOptions.find(p => p.value === filters.protocol);
    const currentSeverity = severityOptions.find(s => s.value === filters.severity);
    const currentTimeRange = timeRangeOptions.find(t => t.value === filters.timeRange);
    const currentSort = sortOptions.find(s => s.value === filters.sortBy);

    return (
        <div className="flex flex-col gap-3 p-4 bg-card/50 backdrop-blur-xl border-b border-white/10 dark:border-white/5">
            {/* Top Row - Search and Quick Filters */}
            <div className="flex items-center gap-2 flex-wrap">
                {/* Search Input */}
                <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search conversations..."
                        value={filters.searchQuery}
                        onChange={(e) => updateFilter('searchQuery', e.target.value)}
                        className="pl-9 h-9 bg-muted/30 rounded-none border-white/10 focus:border-primary/50"
                    />
                    {filters.searchQuery && (
                        <button
                            onClick={() => updateFilter('searchQuery', '')}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        >
                            <X className="h-3.5 w-3.5" />
                        </button>
                    )}
                </div>

                {/* Protocol Filter */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn(
                                "h-9 gap-1.5 rounded-none border-dashed",
                                filters.protocol !== 'all' && "border-solid border-primary/50 bg-primary/10"
                            )}
                        >
                            {currentProtocol && <currentProtocol.icon className="h-3.5 w-3.5" />}
                            <span className="hidden sm:inline">{currentProtocol?.label}</span>
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="w-[160px] bg-card/95 backdrop-blur-xl border-white/10 rounded-none">
                        <DropdownMenuLabel className="text-xs text-muted-foreground">Protocol</DropdownMenuLabel>
                        {protocolOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('protocol', option.value)}
                                className={cn(
                                    "rounded-none cursor-pointer gap-2",
                                    filters.protocol === option.value && "bg-primary/20"
                                )}
                            >
                                <option.icon className="h-3.5 w-3.5" />
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Severity Filter */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn(
                                "h-9 gap-1.5 rounded-none border-dashed",
                                filters.severity !== 'all' && "border-solid border-primary/50 bg-primary/10"
                            )}
                        >
                            {currentSeverity && <currentSeverity.icon className={cn("h-3.5 w-3.5", currentSeverity.color)} />}
                            <span className="hidden sm:inline">{currentSeverity?.label}</span>
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="w-[160px] bg-card/95 backdrop-blur-xl border-white/10 rounded-none">
                        <DropdownMenuLabel className="text-xs text-muted-foreground">Severity</DropdownMenuLabel>
                        {severityOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('severity', option.value)}
                                className={cn(
                                    "rounded-none cursor-pointer gap-2",
                                    filters.severity === option.value && "bg-primary/20"
                                )}
                            >
                                <option.icon className={cn("h-3.5 w-3.5", option.color)} />
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Time Range Filter */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn(
                                "h-9 gap-1.5 rounded-none border-dashed",
                                filters.timeRange !== 'all' && "border-solid border-primary/50 bg-primary/10"
                            )}
                        >
                            <Clock className="h-3.5 w-3.5" />
                            <span className="hidden sm:inline">{currentTimeRange?.label}</span>
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="w-[160px] bg-card/95 backdrop-blur-xl border-white/10 rounded-none">
                        <DropdownMenuLabel className="text-xs text-muted-foreground">Time Range</DropdownMenuLabel>
                        {timeRangeOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('timeRange', option.value)}
                                className={cn(
                                    "rounded-none cursor-pointer",
                                    filters.timeRange === option.value && "bg-primary/20"
                                )}
                            >
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Sort */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm" className="h-9 gap-1.5 rounded-none border-dashed">
                            {currentSort && <currentSort.icon className="h-3.5 w-3.5" />}
                            <span className="hidden sm:inline">{currentSort?.label}</span>
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-[160px] bg-card/95 backdrop-blur-xl border-white/10 rounded-none">
                        <DropdownMenuLabel className="text-xs text-muted-foreground">Sort By</DropdownMenuLabel>
                        {sortOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('sortBy', option.value)}
                                className={cn(
                                    "rounded-none cursor-pointer gap-2",
                                    filters.sortBy === option.value && "bg-primary/20"
                                )}
                            >
                                <option.icon className="h-3.5 w-3.5" />
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Active Only Toggle */}
                <Button
                    variant={filters.showActiveOnly ? "default" : "outline"}
                    size="sm"
                    onClick={() => updateFilter('showActiveOnly', !filters.showActiveOnly)}
                    className={cn(
                        "h-9 rounded-none",
                        filters.showActiveOnly ? "bg-emerald-600 hover:bg-emerald-700" : "border-dashed"
                    )}
                >
                    <span className="relative flex h-2 w-2 mr-1.5">
                        {filters.showActiveOnly && (
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-white opacity-75"></span>
                        )}
                        <span className={cn(
                            "relative inline-flex rounded-full h-2 w-2",
                            filters.showActiveOnly ? "bg-white" : "bg-emerald-500"
                        )}></span>
                    </span>
                    <span className="hidden sm:inline">Active</span>
                </Button>

                {/* Reset Filters */}
                {hasActiveFilters && (
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={resetFilters}
                        className="h-9 gap-1.5 rounded-none text-muted-foreground hover:text-foreground"
                    >
                        <RotateCcw className="h-3.5 w-3.5" />
                        <span className="hidden sm:inline">Reset</span>
                    </Button>
                )}
            </div>

            {/* Bottom Row - IP/Username Filters & Status */}
            <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                    {/* IP Filter */}
                    <div className="relative">
                        <Input
                            placeholder="Filter IP..."
                            value={filters.ipFilter}
                            onChange={(e) => updateFilter('ipFilter', e.target.value)}
                            className="h-8 w-32 text-xs bg-muted/30 rounded-none border-white/10 focus:border-primary/50 font-mono"
                        />
                    </div>

                    {/* Username Filter */}
                    <div className="relative">
                        <Input
                            placeholder="Filter user..."
                            value={filters.usernameFilter}
                            onChange={(e) => updateFilter('usernameFilter', e.target.value)}
                            className="h-8 w-28 text-xs bg-muted/30 rounded-none border-white/10 focus:border-primary/50"
                        />
                    </div>
                </div>

                {/* Filter Status */}
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    {hasActiveFilters && (
                        <Badge variant="outline" className="rounded-none px-1.5 py-0 h-5 bg-primary/10 border-primary/30">
                            <Filter className="h-2.5 w-2.5 mr-1" />
                            {activeFilterCount} active
                        </Badge>
                    )}
                    <span>
                        Showing <span className="font-semibold text-foreground">{filteredCount}</span> of {totalCount}
                    </span>
                </div>
            </div>
        </div>
    );
}
