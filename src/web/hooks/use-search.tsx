"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { SearchResult } from "@/types/search";
import {
    search,
    getRecentSearches,
    addRecentSearch,
} from "@/lib/search-engine";
import { searchRegistry } from "@/lib/search-registry";

interface SearchContextValue {
    isOpen: boolean;
    query: string;
    results: SearchResult[];
    groupedResults: Map<string, SearchResult[]>;
    flatResults: SearchResult[];
    selectedIndex: number;
    recentSearches: string[];
    suggestedItems: typeof searchRegistry;
    open: () => void;
    close: () => void;
    toggle: () => void;
    setQuery: (query: string) => void;
    setSelectedIndex: (index: number) => void;
    selectResult: (result: SearchResult) => void;
    moveSelection: (direction: "up" | "down") => void;
    confirmSelection: () => void;
}

const SearchContext = createContext<SearchContextValue | null>(null);

export function SearchProvider({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const { setTheme, resolvedTheme } = useTheme();

    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState("");
    const [results, setResults] = useState<SearchResult[]>([]);
    const [selectedIndex, setSelectedIndex] = useState(0);
    const [recentSearches, setRecentSearches] = useState<string[]>([]);

    useEffect(() => {
        setRecentSearches(getRecentSearches());
    }, []);

    useEffect(() => {
        if (!query.trim()) {
            setResults([]);
            setSelectedIndex(0);
            return;
        }

        const timer = setTimeout(() => {
            const searchResults = search(query, 12);
            setResults(searchResults);
            setSelectedIndex(0);
        }, 150);

        return () => clearTimeout(timer);
    }, [query]);

    const groupedResults = useMemo(() => {
        const groups = new Map<string, SearchResult[]>();
        for (const result of results) {
            const existing = groups.get(result.category) || [];
            existing.push(result);
            groups.set(result.category, existing);
        }
        return groups;
    }, [results]);

    const flatResults = useMemo(() => {
        return Array.from(groupedResults.values()).flat();
    }, [groupedResults]);

    const open = useCallback(() => {
        setIsOpen(true);
        setQuery("");
        setResults([]);
        setSelectedIndex(0);
        setRecentSearches(getRecentSearches());
    }, []);

    const close = useCallback(() => {
        setIsOpen(false);
        setQuery("");
    }, []);

    const toggle = useCallback(() => {
        if (isOpen) {
            close();
        } else {
            open();
        }
    }, [isOpen, open, close]);

    const executeAction = useCallback((item: SearchResult) => {
        if (item.id === "action-toggle-theme") {
            setTheme(resolvedTheme === "dark" ? "light" : "dark");
            close();
            return;
        }

        if (item.id === "action-refresh") {
            window.location.reload();
            close();
            return;
        }

        if (item.href && !item.href.startsWith("#")) {
            addRecentSearch(item.title);
            setRecentSearches(getRecentSearches());
            close();
            router.push(item.href);
        }
    }, [router, close, setTheme, resolvedTheme]);

    const selectResult = useCallback((result: SearchResult) => {
        executeAction(result);
    }, [executeAction]);

    const moveSelection = useCallback((direction: "up" | "down") => {
        const maxIndex = flatResults.length - 1;
        if (maxIndex < 0) return;

        setSelectedIndex((prev) => {
            if (direction === "up") {
                return prev <= 0 ? maxIndex : prev - 1;
            } else {
                return prev >= maxIndex ? 0 : prev + 1;
            }
        });
    }, [flatResults.length]);

    const confirmSelection = useCallback(() => {
        if (flatResults[selectedIndex]) {
            selectResult(flatResults[selectedIndex]);
        }
    }, [flatResults, selectedIndex, selectResult]);

    // FIX APPLIED HERE: Using single quotes for 'k' to potentially resolve a parsing issue
    const handleGlobalKeyDown = useCallback((e: KeyboardEvent) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            toggle();
        }
    }, [toggle]);

    useEffect(() => {
        document.addEventListener("keydown", handleGlobalKeyDown);
        return () => document.removeEventListener("keydown", handleGlobalKeyDown);
    }, [handleGlobalKeyDown]);

    const suggestedItems = useMemo(() => {
        return searchRegistry
            .filter((item) => item.category === "page")
            .slice(0, 6);
    }, []);

    const value: SearchContextValue = {
        isOpen,
        query,
        results,
        groupedResults,
        flatResults,
        selectedIndex,
        recentSearches,
        suggestedItems,
        open,
        close,
        toggle,
        setQuery,
        setSelectedIndex,
        selectResult,
        moveSelection,
        confirmSelection,
    };

    return (
        <SearchContext.Provider value={value}>
            {children}
        </SearchContext.Provider>
    );
}

export function useSearch() {
    const context = useContext(SearchContext);
    if (!context) {
        throw new Error("useSearch must be used within a SearchProvider");
    }
    return context;
}