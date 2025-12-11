"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
    ArrowRight,
    Clock,
    Sparkles,
    LayoutDashboard,
    Terminal,
    Brain,
    MessageSquare,
    Shield,
    Settings,
    FileText,
    Lock,
    CornerDownLeft,
    Command,
    Zap,
    Network,
    Database,
    Server,
    HardDrive,
    Palette,
    RefreshCw,
    Activity,
    Users,
    type LucideIcon,
} from "lucide-react";
import {
    CommandDialog,
    CommandInput,
    CommandList,
    CommandEmpty,
    CommandGroup,
    CommandItem,
    CommandSeparator,
} from "@/components/ui/command";
import { Kbd } from "@/components/ui/kbd";
import { cn } from "@/lib/utils";
import { useSearch } from "@/hooks/use-search";
import { SearchResult, SearchCategory } from "@/types/search";
import { categoryConfig, searchRegistry } from "@/lib/search-registry";

// Icon mapping for all result types
const iconMap: Record<string, LucideIcon> = {
    "page-dashboard": LayoutDashboard,
    "page-attacks": Terminal,
    "page-ml-analysis": Brain,
    "page-conversations": MessageSquare,
    "page-sessions": Shield,
    "page-settings": Settings,
    "page-terms": FileText,
    "page-privacy": Lock,
    "section-hero": Sparkles,
    "section-architecture": Network,
    "section-ml": Brain,
    "section-datasets": Database,
    "section-services": Server,
    "setting-ssh": Terminal,
    "setting-ftp": HardDrive,
    "setting-mysql": Database,
    "setting-smb": Network,
    "action-toggle-theme": Palette,
    "action-refresh": RefreshCw,
    "action-view-attacks": Zap,
    "action-view-ml": Activity,
    "action-view-sessions": Users,
};

// Category icons
const categoryIcons: Record<SearchCategory, LucideIcon> = {
    page: LayoutDashboard,
    section: Sparkles,
    setting: Settings,
    action: Zap,
};

interface CommandSearchProps {
    className?: string;
}

export function CommandSearch({ className }: CommandSearchProps) {
    const router = useRouter();
    const {
        isOpen,
        query,
        results,
        recentSearches,
        close,
        setQuery,
        selectResult,
    } = useSearch();

    const hasQuery = query.trim().length > 0;
    const hasResults = results.length > 0;

    // Get icon for a result
    const getIcon = (result: SearchResult): LucideIcon => {
        return iconMap[result.id] || categoryIcons[result.category] || Command;
    };

    // Group results by category
    const groupedResults = React.useMemo(() => {
        const groups = new Map<SearchCategory, SearchResult[]>();
        for (const result of results) {
            const existing = groups.get(result.category) || [];
            existing.push(result);
            groups.set(result.category, existing);
        }
        return groups;
    }, [results]);

    // Get suggested items for quick navigation
    const suggestedItems = React.useMemo(() => {
        return searchRegistry.filter(item => item.category === "page").slice(0, 6);
    }, []);

    return (
        <CommandDialog
            open={isOpen}
            onOpenChange={(open) => !open && close()}
            title="Search NEXUS"
            description="Search pages, settings, and actions"
            showCloseButton={false}
            className={cn(
                "max-w-2xl overflow-hidden rounded-2xl",
                "border border-neutral-200 dark:border-neutral-800",
                "bg-white dark:bg-neutral-950",
                "shadow-2xl",
                className
            )}
        >
            {/* Search Input - CommandInput already has search icon, just style the container */}
            <div className="border-b border-neutral-200 dark:border-neutral-800">
                <CommandInput
                    placeholder="Search pages, sections, settings..."
                    value={query}
                    onValueChange={setQuery}
                    className="h-14 text-base border-0 focus:ring-0 bg-transparent text-neutral-900 dark:text-white placeholder:text-neutral-500 dark:placeholder:text-neutral-400"
                />
            </div>

            {/* Results List */}
            <CommandList className="max-h-[420px] overflow-y-auto p-2">
                {/* No Results State */}
                {hasQuery && !hasResults && (
                    <CommandEmpty className="py-16">
                        <div className="flex flex-col items-center gap-4">
                            <div className="p-4 rounded-full bg-neutral-100 dark:bg-neutral-800">
                                <Command className="h-8 w-8 text-neutral-400 dark:text-neutral-500" />
                            </div>
                            <div className="text-center">
                                <p className="font-semibold text-neutral-900 dark:text-white">
                                    No results for "{query}"
                                </p>
                                <p className="text-sm text-neutral-500 dark:text-neutral-400 mt-1">
                                    Try different keywords or browse quick navigation below
                                </p>
                            </div>
                        </div>
                    </CommandEmpty>
                )}

                {/* Search Results */}
                {hasQuery && hasResults && (
                    <>
                        {Array.from(groupedResults.entries()).map(([category, items]) => {
                            const config = categoryConfig[category];
                            const CategoryIcon = categoryIcons[category];

                            return (
                                <CommandGroup
                                    key={category}
                                    heading={
                                        <div className="flex items-center gap-2 px-2 py-1.5">
                                            <CategoryIcon className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
                                            <span className="text-xs font-semibold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                                                {config?.label || category}
                                            </span>
                                            <span className="text-xs text-neutral-400 dark:text-neutral-500">
                                                ({items.length})
                                            </span>
                                        </div>
                                    }
                                    className="px-1"
                                >
                                    {items.map((result) => {
                                        const Icon = getIcon(result);

                                        return (
                                            <CommandItem
                                                key={result.id}
                                                value={`${result.title} ${result.description} ${result.keywords.join(" ")}`}
                                                onSelect={() => selectResult(result)}
                                                className={cn(
                                                    "flex items-center gap-3 px-3 py-3 rounded-xl cursor-pointer",
                                                    "transition-all duration-150",
                                                    "aria-selected:bg-primary/10 dark:aria-selected:bg-primary/20",
                                                    "hover:bg-neutral-100 dark:hover:bg-neutral-800/50",
                                                    "data-[selected=true]:bg-primary/10 dark:data-[selected=true]:bg-primary/20"
                                                )}
                                            >
                                                <div className={cn(
                                                    "flex items-center justify-center h-10 w-10 rounded-xl shrink-0",
                                                    "bg-neutral-100 dark:bg-neutral-800",
                                                    "group-aria-selected:bg-primary group-aria-selected:text-white",
                                                    "transition-colors"
                                                )}>
                                                    <Icon className="h-5 w-5 text-neutral-600 dark:text-neutral-300" />
                                                </div>

                                                <div className="flex-1 min-w-0">
                                                    <div className="font-medium text-sm text-neutral-900 dark:text-white truncate">
                                                        {result.title}
                                                    </div>
                                                    <div className="text-xs text-neutral-500 dark:text-neutral-400 truncate mt-0.5">
                                                        {result.description}
                                                    </div>
                                                </div>

                                                {result.section && (
                                                    <span className="text-[10px] px-2 py-1 rounded-md bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400 shrink-0 font-medium">
                                                        {result.section}
                                                    </span>
                                                )}

                                                {result.shortcut && (
                                                    <div className="flex items-center gap-1 shrink-0">
                                                        {result.shortcut.map((key, i) => (
                                                            <Kbd key={i} className="text-[10px] px-1.5 py-0.5">
                                                                {key}
                                                            </Kbd>
                                                        ))}
                                                    </div>
                                                )}

                                                <ArrowRight className="h-4 w-4 text-neutral-400 dark:text-neutral-500 shrink-0 opacity-0 group-aria-selected:opacity-100 transition-opacity" />
                                            </CommandItem>
                                        );
                                    })}
                                </CommandGroup>
                            );
                        })}
                    </>
                )}

                {/* Suggestions when no query */}
                {!hasQuery && (
                    <>
                        {/* Recent Searches */}
                        {recentSearches.length > 0 && (
                            <>
                                <CommandGroup
                                    heading={
                                        <div className="flex items-center gap-2 px-2 py-1.5">
                                            <Clock className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
                                            <span className="text-xs font-semibold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                                                Recent
                                            </span>
                                        </div>
                                    }
                                    className="px-1"
                                >
                                    {recentSearches.map((recentSearch, index) => (
                                        <CommandItem
                                            key={`recent-${index}`}
                                            value={`recent-${recentSearch}`}
                                            onSelect={() => setQuery(recentSearch)}
                                            className="flex items-center gap-3 px-3 py-2.5 rounded-xl cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800/50"
                                        >
                                            <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-neutral-100 dark:bg-neutral-800">
                                                <Clock className="h-4 w-4 text-neutral-500 dark:text-neutral-400" />
                                            </div>
                                            <span className="text-sm text-neutral-700 dark:text-neutral-200">{recentSearch}</span>
                                            <ArrowRight className="h-3.5 w-3.5 ml-auto text-neutral-400 dark:text-neutral-500" />
                                        </CommandItem>
                                    ))}
                                </CommandGroup>
                                <CommandSeparator className="my-2 bg-neutral-200 dark:bg-neutral-800" />
                            </>
                        )}

                        {/* Quick Navigation */}
                        <CommandGroup
                            heading={
                                <div className="flex items-center gap-2 px-2 py-1.5">
                                    <Sparkles className="h-3.5 w-3.5 text-neutral-500 dark:text-neutral-400" />
                                    <span className="text-xs font-semibold text-neutral-500 dark:text-neutral-400 uppercase tracking-wider">
                                        Quick Navigation
                                    </span>
                                </div>
                            }
                            className="px-1"
                        >
                            {suggestedItems.map((item) => {
                                const Icon = iconMap[item.id] || LayoutDashboard;
                                return (
                                    <CommandItem
                                        key={item.id}
                                        value={item.id}
                                        onSelect={() => {
                                            close();
                                            router.push(item.href);
                                        }}
                                        className="flex items-center gap-3 px-3 py-3 rounded-xl cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800/50"
                                    >
                                        <div className="flex items-center justify-center h-10 w-10 rounded-xl bg-neutral-100 dark:bg-neutral-800">
                                            <Icon className="h-5 w-5 text-neutral-600 dark:text-neutral-300" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="font-medium text-sm text-neutral-900 dark:text-white">
                                                {item.title}
                                            </div>
                                            <div className="text-xs text-neutral-500 dark:text-neutral-400 truncate mt-0.5">
                                                {item.description}
                                            </div>
                                        </div>
                                        <ArrowRight className="h-4 w-4 text-neutral-400 dark:text-neutral-500" />
                                    </CommandItem>
                                );
                            })}
                        </CommandGroup>
                    </>
                )}
            </CommandList>

            {/* Footer with keyboard hints */}
            <div className="flex items-center justify-between gap-4 border-t border-neutral-200 dark:border-neutral-800 px-4 py-3 bg-neutral-50 dark:bg-neutral-900/50">
                <div className="flex items-center gap-5 text-xs text-neutral-500 dark:text-neutral-400">
                    <div className="flex items-center gap-1.5">
                        <Kbd className="text-[10px] px-1.5 py-0.5 bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700">↑</Kbd>
                        <Kbd className="text-[10px] px-1.5 py-0.5 bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700">↓</Kbd>
                        <span className="text-neutral-600 dark:text-neutral-400">Navigate</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <Kbd className="text-[10px] px-2 py-0.5 bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700">↵</Kbd>
                        <span className="text-neutral-600 dark:text-neutral-400">Select</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <Kbd className="text-[10px] px-1.5 py-0.5 bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700">ESC</Kbd>
                        <span className="text-neutral-600 dark:text-neutral-400">Close</span>
                    </div>
                </div>
                <div className="text-xs font-medium text-neutral-400 dark:text-neutral-500">
                    NEXUS Search
                </div>
            </div>
        </CommandDialog>
    );
}
