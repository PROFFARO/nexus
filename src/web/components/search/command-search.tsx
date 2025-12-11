"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
    Search,
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
import { categoryConfig } from "@/lib/search-registry";

// Category icons mapping for consistency
const categoryIcons: Record<SearchCategory, React.ComponentType<{ className?: string }>> = {
    page: LayoutDashboard,
    section: Sparkles,
    setting: Settings,
    action: Terminal,
};

// Result item icon mapping
const resultIcons: Record<string, React.ComponentType<{ className?: string }>> = {
    "page-dashboard": LayoutDashboard,
    "page-attacks": Terminal,
    "page-ml-analysis": Brain,
    "page-conversations": MessageSquare,
    "page-sessions": Shield,
    "page-settings": Settings,
    "page-terms": FileText,
    "page-privacy": Lock,
};

interface CommandSearchProps {
    className?: string;
}

export function CommandSearch({ className }: CommandSearchProps) {
    const router = useRouter();
    const {
        isOpen,
        query,
        groupedResults,
        flatResults,
        selectedIndex,
        recentSearches,
        suggestedItems,
        close,
        setQuery,
        setSelectedIndex,
        selectResult,
        moveSelection,
        confirmSelection,
    } = useSearch();

    const hasQuery = query.trim().length > 0;
    const hasResults = flatResults.length > 0;

    // Handle keyboard navigation within command
    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "ArrowDown") {
            e.preventDefault();
            moveSelection("down");
        } else if (e.key === "ArrowUp") {
            e.preventDefault();
            moveSelection("up");
        } else if (e.key === "Enter" && hasResults) {
            e.preventDefault();
            confirmSelection();
        }
    };

    // Get icon for result
    const getResultIcon = (result: SearchResult) => {
        const Icon = result.icon || resultIcons[result.id] || categoryIcons[result.category];
        return Icon;
    };

    return (
        <CommandDialog
            open={isOpen}
            onOpenChange={(open) => !open && close()}
            title="Search"
            description="Search pages, settings, and actions"
            showCloseButton={false}
            className={cn(
                "max-w-2xl overflow-hidden rounded-2xl border border-border/50 bg-background/95 backdrop-blur-xl shadow-2xl",
                className
            )}
        >
            {/* Search Input */}
            <div
                className="flex items-center gap-3 border-b border-border/50 px-4"
                onKeyDown={handleKeyDown}
            >
                <Search className="h-5 w-5 text-muted-foreground shrink-0" />
                <CommandInput
                    placeholder="Search pages, sections, settings..."
                    value={query}
                    onValueChange={setQuery}
                    className="h-14 text-base placeholder:text-muted-foreground/60 border-0 focus:ring-0"
                />
                <div className="flex items-center gap-1.5 shrink-0">
                    <Kbd className="text-[10px] px-1.5">ESC</Kbd>
                </div>
            </div>

            {/* Results */}
            <CommandList className="max-h-[400px] overflow-y-auto p-2">
                {/* Empty State */}
                {hasQuery && !hasResults && (
                    <CommandEmpty className="py-12">
                        <div className="flex flex-col items-center gap-3 text-muted-foreground">
                            <div className="p-4 rounded-full bg-muted/50">
                                <Search className="h-6 w-6" />
                            </div>
                            <div className="text-center">
                                <p className="font-medium">No results found</p>
                                <p className="text-sm text-muted-foreground/70">
                                    Try searching for pages, settings, or actions
                                </p>
                            </div>
                        </div>
                    </CommandEmpty>
                )}

                {/* Search Results */}
                {hasQuery && hasResults && (
                    <>
                        {Array.from(groupedResults.entries()).map(([category, items], groupIndex) => {
                            const config = categoryConfig[category as SearchCategory];
                            const CategoryIcon = categoryIcons[category as SearchCategory];

                            return (
                                <CommandGroup
                                    key={category}
                                    heading={
                                        <div className="flex items-center gap-2 px-1 py-1">
                                            <CategoryIcon className="h-3.5 w-3.5 text-muted-foreground" />
                                            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                                                {config?.label || category}
                                            </span>
                                        </div>
                                    }
                                    className="px-1"
                                >
                                    {items.map((result, itemIndex) => {
                                        const globalIndex = flatResults.findIndex((r) => r.id === result.id);
                                        const isSelected = globalIndex === selectedIndex;
                                        const Icon = getResultIcon(result);

                                        return (
                                            <CommandItem
                                                key={result.id}
                                                value={result.id}
                                                onSelect={() => selectResult(result)}
                                                onMouseEnter={() => setSelectedIndex(globalIndex)}
                                                className={cn(
                                                    "flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-all duration-150",
                                                    "hover:bg-accent/50 data-[selected=true]:bg-accent",
                                                    isSelected && "bg-accent ring-1 ring-primary/20"
                                                )}
                                            >
                                                <motion.div
                                                    initial={false}
                                                    animate={{
                                                        scale: isSelected ? 1.05 : 1,
                                                        rotate: isSelected ? 3 : 0,
                                                    }}
                                                    transition={{ duration: 0.15 }}
                                                    className={cn(
                                                        "flex items-center justify-center h-9 w-9 rounded-lg shrink-0 transition-colors",
                                                        isSelected
                                                            ? "bg-primary text-primary-foreground"
                                                            : "bg-muted/80 text-muted-foreground"
                                                    )}
                                                >
                                                    <Icon className="h-4 w-4" />
                                                </motion.div>

                                                <div className="flex-1 min-w-0">
                                                    <div className="font-medium text-sm truncate">
                                                        {result.title}
                                                    </div>
                                                    <div className="text-xs text-muted-foreground truncate">
                                                        {result.description}
                                                    </div>
                                                </div>

                                                {result.section && (
                                                    <span className="text-[10px] px-2 py-0.5 rounded bg-muted text-muted-foreground shrink-0">
                                                        {result.section}
                                                    </span>
                                                )}

                                                {result.shortcut && (
                                                    <div className="flex items-center gap-1 shrink-0">
                                                        {result.shortcut.map((key, i) => (
                                                            <Kbd key={i} className="text-[10px] px-1">
                                                                {key}
                                                            </Kbd>
                                                        ))}
                                                    </div>
                                                )}

                                                <AnimatePresence>
                                                    {isSelected && (
                                                        <motion.div
                                                            initial={{ opacity: 0, x: -4 }}
                                                            animate={{ opacity: 1, x: 0 }}
                                                            exit={{ opacity: 0, x: 4 }}
                                                            className="shrink-0"
                                                        >
                                                            <CornerDownLeft className="h-3.5 w-3.5 text-primary" />
                                                        </motion.div>
                                                    )}
                                                </AnimatePresence>
                                            </CommandItem>
                                        );
                                    })}
                                </CommandGroup>
                            );
                        })}
                    </>
                )}

                {/* Suggestions (when no query) */}
                {!hasQuery && (
                    <>
                        {/* Recent Searches */}
                        {recentSearches.length > 0 && (
                            <CommandGroup
                                heading={
                                    <div className="flex items-center gap-2 px-1 py-1">
                                        <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                                        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                                            Recent
                                        </span>
                                    </div>
                                }
                                className="px-1"
                            >
                                {recentSearches.map((search, index) => (
                                    <CommandItem
                                        key={`recent-${index}`}
                                        value={`recent-${search}`}
                                        onSelect={() => setQuery(search)}
                                        className="flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer hover:bg-accent/50"
                                    >
                                        <div className="flex items-center justify-center h-8 w-8 rounded-lg bg-muted/50">
                                            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                                        </div>
                                        <span className="text-sm">{search}</span>
                                        <ArrowRight className="h-3 w-3 ml-auto text-muted-foreground" />
                                    </CommandItem>
                                ))}
                            </CommandGroup>
                        )}

                        <CommandSeparator className="my-2" />

                        {/* Suggested Pages */}
                        <CommandGroup
                            heading={
                                <div className="flex items-center gap-2 px-1 py-1">
                                    <Sparkles className="h-3.5 w-3.5 text-muted-foreground" />
                                    <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                                        Quick Navigation
                                    </span>
                                </div>
                            }
                            className="px-1"
                        >
                            {suggestedItems.map((item, index) => {
                                const Icon = item.icon || LayoutDashboard;
                                return (
                                    <CommandItem
                                        key={item.id}
                                        value={item.id}
                                        onSelect={() => {
                                            close();
                                            router.push(item.href);
                                        }}
                                        className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-accent/50"
                                    >
                                        <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-muted/80">
                                            <Icon className="h-4 w-4 text-muted-foreground" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="font-medium text-sm">{item.title}</div>
                                            <div className="text-xs text-muted-foreground truncate">
                                                {item.description}
                                            </div>
                                        </div>
                                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
                                    </CommandItem>
                                );
                            })}
                        </CommandGroup>
                    </>
                )}
            </CommandList>

            {/* Footer */}
            <div className="flex items-center justify-between gap-4 border-t border-border/50 px-4 py-2.5 bg-muted/30">
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <div className="flex items-center gap-1.5">
                        <Kbd className="text-[10px] px-1">↑</Kbd>
                        <Kbd className="text-[10px] px-1">↓</Kbd>
                        <span>Navigate</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <Kbd className="text-[10px] px-1.5">↵</Kbd>
                        <span>Select</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <Kbd className="text-[10px] px-1">ESC</Kbd>
                        <span>Close</span>
                    </div>
                </div>
                <div className="text-xs text-muted-foreground/60">
                    NEXUS Search
                </div>
            </div>
        </CommandDialog>
    );
}
