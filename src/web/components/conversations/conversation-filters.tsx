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
    CheckCircle,
    ChevronDown
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
        <div className="flex-shrink-0 flex flex-col gap-2 p-3 bg-gradient-to-r from-card/50 to-card/30 border-b border-border/50">
            {/* Top Row */}
            <div className="flex items-center gap-2 flex-wrap">
                {/* Search */}
                <div className="relative flex-1 min-w-[200px]">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                        placeholder="Search conversations..."
                        value={filters.searchQuery}
                        onChange={(e) => updateFilter('searchQuery', e.target.value)}
                        className="pl-10 h-9 bg-muted/30 rounded-none border-border/50 focus:border-primary/50"
                    />
                    {filters.searchQuery && (
                        <button
                            onClick={() => updateFilter('searchQuery', '')}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5"
                        >
                            <X className="h-4 w-4" />
                        </button>
                    )}
                </div>

                {/* Protocol */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn("h-9 gap-2 rounded-none border-border/50 px-3", filters.protocol !== 'all' && "border-primary/50 bg-primary/10")}
                        >
                            {currentProtocol && <currentProtocol.icon className="h-4 w-4" />}
                            <span>{currentProtocol?.label}</span>
                            <ChevronDown className="h-3 w-3 opacity-50" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="w-[160px] bg-card/95 backdrop-blur-xl border-border/50 rounded-none p-1">
                        <DropdownMenuLabel className="text-xs text-muted-foreground px-2">Protocol</DropdownMenuLabel>
                        {protocolOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('protocol', option.value)}
                                className={cn("rounded-none cursor-pointer gap-2 px-3 py-2", filters.protocol === option.value && "bg-primary/15")}
                            >
                                <option.icon className="h-4 w-4" />
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Severity */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn("h-9 gap-2 rounded-none border-border/50 px-3", filters.severity !== 'all' && "border-primary/50 bg-primary/10")}
                        >
                            {currentSeverity && <currentSeverity.icon className={cn("h-4 w-4", currentSeverity.color)} />}
                            <span>{currentSeverity?.label}</span>
                            <ChevronDown className="h-3 w-3 opacity-50" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="w-[160px] bg-card/95 backdrop-blur-xl border-border/50 rounded-none p-1">
                        <DropdownMenuLabel className="text-xs text-muted-foreground px-2">Severity</DropdownMenuLabel>
                        {severityOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('severity', option.value)}
                                className={cn("rounded-none cursor-pointer gap-2 px-3 py-2", filters.severity === option.value && "bg-primary/15")}
                            >
                                <option.icon className={cn("h-4 w-4", option.color)} />
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Time Range */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button
                            variant="outline"
                            size="sm"
                            className={cn("h-9 gap-2 rounded-none border-border/50 px-3", filters.timeRange !== 'all' && "border-primary/50 bg-primary/10")}
                        >
                            <Clock className="h-4 w-4" />
                            <span>{currentTimeRange?.label}</span>
                            <ChevronDown className="h-3 w-3 opacity-50" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="w-[160px] bg-card/95 backdrop-blur-xl border-border/50 rounded-none p-1">
                        <DropdownMenuLabel className="text-xs text-muted-foreground px-2">Time Range</DropdownMenuLabel>
                        {timeRangeOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('timeRange', option.value)}
                                className={cn("rounded-none cursor-pointer px-3 py-2", filters.timeRange === option.value && "bg-primary/15")}
                            >
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Sort */}
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm" className="h-9 gap-2 rounded-none border-border/50 px-3">
                            {currentSort && <currentSort.icon className="h-4 w-4" />}
                            <span>{currentSort?.label}</span>
                            <ChevronDown className="h-3 w-3 opacity-50" />
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-[160px] bg-card/95 backdrop-blur-xl border-border/50 rounded-none p-1">
                        <DropdownMenuLabel className="text-xs text-muted-foreground px-2">Sort By</DropdownMenuLabel>
                        {sortOptions.map((option) => (
                            <DropdownMenuItem
                                key={option.value}
                                onClick={() => updateFilter('sortBy', option.value)}
                                className={cn("rounded-none cursor-pointer gap-2 px-3 py-2", filters.sortBy === option.value && "bg-primary/15")}
                            >
                                <option.icon className="h-4 w-4" />
                                {option.label}
                            </DropdownMenuItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>

                {/* Active Only */}
                <Button
                    variant={filters.showActiveOnly ? "default" : "outline"}
                    size="sm"
                    onClick={() => updateFilter('showActiveOnly', !filters.showActiveOnly)}
                    className={cn(
                        "h-9 rounded-none px-3",
                        filters.showActiveOnly ? "bg-emerald-600 hover:bg-emerald-700" : "border-border/50"
                    )}
                >
                    <span className={cn("w-2 h-2 mr-2", filters.showActiveOnly ? "bg-white" : "bg-emerald-500")} />
                    Active
                </Button>

                {/* Reset */}
                {hasActiveFilters && (
                    <Button variant="ghost" size="sm" onClick={resetFilters} className="h-9 gap-2 rounded-none text-muted-foreground hover:text-foreground">
                        <RotateCcw className="h-4 w-4" />
                        Reset
                    </Button>
                )}
            </div>

            {/* Bottom Row */}
            <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                    <Input
                        placeholder="Filter IP..."
                        value={filters.ipFilter}
                        onChange={(e) => updateFilter('ipFilter', e.target.value)}
                        className="h-8 w-32 text-sm bg-muted/30 rounded-none border-border/50 font-mono"
                    />
                    <Input
                        placeholder="Filter user..."
                        value={filters.usernameFilter}
                        onChange={(e) => updateFilter('usernameFilter', e.target.value)}
                        className="h-8 w-28 text-sm bg-muted/30 rounded-none border-border/50"
                    />
                </div>
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                    {hasActiveFilters && (
                        <Badge className="rounded-none px-2 py-1 bg-primary/10 text-primary border-primary/20 font-semibold">
                            <Filter className="h-3 w-3 mr-1" />
                            {activeFilterCount} active
                        </Badge>
                    )}
                    <span>
                        Showing <span className="font-bold text-foreground">{filteredCount}</span> of {totalCount}
                    </span>
                </div>
            </div>
        </div>
    );
}
