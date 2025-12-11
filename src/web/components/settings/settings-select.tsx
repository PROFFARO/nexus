'use client';

import { cn } from '@/lib/utils';
import { IconChevronDown } from '@tabler/icons-react';

interface SettingsSelectProps {
    value: string;
    onChange: (value: string) => void;
    label: string;
    description?: string;
    options: string[];
    disabled?: boolean;
}

export function SettingsSelect({
    value,
    onChange,
    label,
    description,
    options,
    disabled = false,
}: SettingsSelectProps) {
    return (
        <div className="py-3">
            <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                    <label className="text-sm font-medium text-foreground">
                        {label}
                    </label>
                    {description && (
                        <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                            {description}
                        </p>
                    )}
                </div>
                <div className="relative">
                    <select
                        value={value}
                        onChange={(e) => onChange(e.target.value)}
                        disabled={disabled}
                        className={cn(
                            'appearance-none w-32 px-3 py-1.5 pr-8 text-sm rounded-md border',
                            'bg-background text-foreground cursor-pointer',
                            'border-input hover:border-muted-foreground/50',
                            'focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1',
                            'transition-colors',
                            disabled && 'opacity-50 cursor-not-allowed'
                        )}
                    >
                        {options.map((option) => (
                            <option key={option} value={option}>
                                {option.charAt(0).toUpperCase() + option.slice(1)}
                            </option>
                        ))}
                    </select>
                    <IconChevronDown
                        className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none"
                    />
                </div>
            </div>
        </div>
    );
}

export default SettingsSelect;
