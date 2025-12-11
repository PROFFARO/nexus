'use client';

import { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';

interface SettingsInputProps {
    value: number | string;
    onChange: (value: number | string) => void;
    label: string;
    description?: string;
    type?: 'text' | 'number';
    min?: number;
    max?: number;
    step?: number;
    disabled?: boolean;
    error?: string;
    suffix?: string;
}

export function SettingsInput({
    value,
    onChange,
    label,
    description,
    type = 'text',
    min,
    max,
    step = 1,
    disabled = false,
    error,
    suffix,
}: SettingsInputProps) {
    const [localValue, setLocalValue] = useState(String(value));
    const [localError, setLocalError] = useState<string | null>(null);

    useEffect(() => {
        setLocalValue(String(value));
    }, [value]);

    const validate = (val: string): boolean => {
        if (type === 'number') {
            const num = parseFloat(val);
            if (isNaN(num)) {
                setLocalError('Must be a valid number');
                return false;
            }
            if (min !== undefined && num < min) {
                setLocalError(`Must be at least ${min}`);
                return false;
            }
            if (max !== undefined && num > max) {
                setLocalError(`Must be at most ${max}`);
                return false;
            }
        }
        setLocalError(null);
        return true;
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const val = e.target.value;
        setLocalValue(val);

        if (validate(val)) {
            if (type === 'number') {
                onChange(parseFloat(val) || 0);
            } else {
                onChange(val);
            }
        }
    };

    const handleBlur = () => {
        validate(localValue);
    };

    const displayError = error || localError;

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
                <div className="flex items-center gap-2">
                    <input
                        type={type}
                        value={localValue}
                        onChange={handleChange}
                        onBlur={handleBlur}
                        min={min}
                        max={max}
                        step={step}
                        disabled={disabled}
                        className={cn(
                            'w-24 px-3 py-1.5 text-sm rounded-md border transition-colors',
                            'bg-background text-foreground',
                            'focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1',
                            displayError
                                ? 'border-destructive focus:ring-destructive'
                                : 'border-input hover:border-muted-foreground/50',
                            disabled && 'opacity-50 cursor-not-allowed'
                        )}
                    />
                    {suffix && (
                        <span className="text-xs text-muted-foreground">{suffix}</span>
                    )}
                </div>
            </div>
            {displayError && (
                <p className="text-xs text-destructive mt-1 text-right">
                    {displayError}
                </p>
            )}
        </div>
    );
}

export default SettingsInput;
