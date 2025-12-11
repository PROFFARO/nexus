'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import {
    IconChevronDown,
    IconShield,
    IconBrain,
    IconAlertTriangle,
    IconSparkles,
    IconSearch,
    IconFileText,
    IconSettings,
} from '@tabler/icons-react';

const ICON_MAP: Record<string, React.ReactNode> = {
    'shield': <IconShield className="h-4 w-4" />,
    'brain': <IconBrain className="h-4 w-4" />,
    'alert-triangle': <IconAlertTriangle className="h-4 w-4" />,
    'sparkles': <IconSparkles className="h-4 w-4" />,
    'search': <IconSearch className="h-4 w-4" />,
    'file-text': <IconFileText className="h-4 w-4" />,
    'settings': <IconSettings className="h-4 w-4" />,
};

interface SettingsSectionProps {
    title: string;
    description?: string;
    icon?: string;
    defaultOpen?: boolean;
    children: React.ReactNode;
    badge?: string | number;
}

export function SettingsSection({
    title,
    description,
    icon = 'settings',
    defaultOpen = true,
    children,
    badge,
}: SettingsSectionProps) {
    const [isOpen, setIsOpen] = useState(defaultOpen);

    return (
        <div className="rounded-lg border border-border/50 bg-card/30 overflow-hidden">
            <button
                type="button"
                onClick={() => setIsOpen(!isOpen)}
                className={cn(
                    'w-full flex items-center justify-between gap-3 px-4 py-3',
                    'hover:bg-muted/50 transition-colors',
                    'focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset'
                )}
            >
                <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-md bg-primary/10 text-primary">
                        {ICON_MAP[icon] || ICON_MAP['settings']}
                    </div>
                    <div className="text-left">
                        <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-foreground">
                                {title}
                            </span>
                            {badge !== undefined && (
                                <span className="px-1.5 py-0.5 text-[10px] font-medium rounded-full bg-primary/10 text-primary">
                                    {badge}
                                </span>
                            )}
                        </div>
                        {description && (
                            <span className="text-xs text-muted-foreground">
                                {description}
                            </span>
                        )}
                    </div>
                </div>
                <motion.div
                    animate={{ rotate: isOpen ? 180 : 0 }}
                    transition={{ duration: 0.2 }}
                >
                    <IconChevronDown className="h-4 w-4 text-muted-foreground" />
                </motion.div>
            </button>

            <AnimatePresence initial={false}>
                {isOpen && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2, ease: 'easeInOut' }}
                        className="overflow-hidden"
                    >
                        <div className="px-4 pb-4 pt-1 border-t border-border/30">
                            <div className="divide-y divide-border/30">
                                {children}
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

export default SettingsSection;
