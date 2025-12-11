'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface SettingsToggleProps {
    checked: boolean;
    onChange: (checked: boolean) => void;
    label: string;
    description?: string;
    disabled?: boolean;
    size?: 'sm' | 'md' | 'lg';
}

export function SettingsToggle({
    checked,
    onChange,
    label,
    description,
    disabled = false,
    size = 'md',
}: SettingsToggleProps) {
    const sizes = {
        sm: { track: 'w-8 h-4', thumb: 'w-3 h-3', translate: 'translate-x-4' },
        md: { track: 'w-11 h-6', thumb: 'w-5 h-5', translate: 'translate-x-5' },
        lg: { track: 'w-14 h-7', thumb: 'w-6 h-6', translate: 'translate-x-7' },
    };

    const sizeConfig = sizes[size];

    return (
        <div className="flex items-start justify-between gap-4 py-3">
            <div className="flex-1 min-w-0">
                <label className="text-sm font-medium text-foreground cursor-pointer">
                    {label}
                </label>
                {description && (
                    <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                        {description}
                    </p>
                )}
            </div>
            <button
                type="button"
                role="switch"
                aria-checked={checked}
                disabled={disabled}
                onClick={() => !disabled && onChange(!checked)}
                className={cn(
                    'relative inline-flex shrink-0 cursor-pointer rounded-full border-2 border-transparent',
                    'transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2',
                    'focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
                    sizeConfig.track,
                    checked
                        ? 'bg-primary'
                        : 'bg-muted-foreground/30 dark:bg-muted-foreground/20',
                    disabled && 'opacity-50 cursor-not-allowed'
                )}
            >
                <motion.span
                    layout
                    transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                    className={cn(
                        'pointer-events-none inline-block rounded-full bg-white shadow-lg ring-0',
                        sizeConfig.thumb,
                        checked ? sizeConfig.translate : 'translate-x-0'
                    )}
                />
            </button>
        </div>
    );
}

export default SettingsToggle;
