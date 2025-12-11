import { LucideIcon } from "lucide-react";

export type SearchCategory = "page" | "section" | "setting" | "action";

export interface SearchableItem {
    id: string;
    title: string;
    description: string;
    category: SearchCategory;
    href: string;
    icon?: LucideIcon;
    keywords: string[];
    section?: string;
    shortcut?: string[];
}

export interface SearchResult extends SearchableItem {
    score: number;
    matches?: {
        key: string;
        value: string;
        indices: [number, number][];
    }[];
}

export interface SearchState {
    isOpen: boolean;
    query: string;
    results: SearchResult[];
    selectedIndex: number;
    recentSearches: string[];
}
