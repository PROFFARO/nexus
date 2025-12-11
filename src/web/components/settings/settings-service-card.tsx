'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import {
    IconTerminal2,
    IconFolder,
    IconDatabase,
    IconCircleCheck,
    IconCircleX,
    IconLoader2,
} from '@tabler/icons-react';
import { ServiceConfig, ServiceName, ConfigParameter } from '@/types/settings';
import { SettingsSection } from './settings-section';
import { SettingsToggle } from './settings-toggle';
import { SettingsInput } from './settings-input';
import { SettingsSelect } from './settings-select';

const SERVICE_ICONS: Record<ServiceName, React.ReactNode> = {
    ssh: <IconTerminal2 className="h-6 w-6" />,
    ftp: <IconFolder className="h-6 w-6" />,
    mysql: <IconDatabase className="h-6 w-6" />,
};

const SERVICE_COLORS: Record<ServiceName, string> = {
    ssh: '#22c55e',
    ftp: '#3b82f6',
    mysql: '#f59e0b',
};

interface SettingsServiceCardProps {
    config: ServiceConfig;
    onParameterChange: (section: string, key: string, value: string | number | boolean) => void;
    pendingChanges: Map<string, string | number | boolean>;
    disabled?: boolean;
}

function StatusIndicator({ status }: { status: ServiceConfig['status'] }) {
    if (status === 'running') {
        return (
            <div className="flex items-center gap-1.5 text-xs text-emerald-500">
                <IconCircleCheck className="h-3.5 w-3.5" />
                <span>Running</span>
            </div>
        );
    }
    if (status === 'stopped') {
        return (
            <div className="flex items-center gap-1.5 text-xs text-red-500">
                <IconCircleX className="h-3.5 w-3.5" />
                <span>Stopped</span>
            </div>
        );
    }
    if (status === 'configured' || status === 'unknown') {
        return (
            <div className="flex items-center gap-1.5 text-xs text-blue-500">
                <IconCircleCheck className="h-3.5 w-3.5" />
                <span>Configured</span>
            </div>
        );
    }
    return null;
}

function ParameterControl({
    param,
    onChange,
    pendingValue,
}: {
    param: ConfigParameter;
    onChange: (value: string | number | boolean) => void;
    pendingValue?: string | number | boolean;
}) {
    const currentValue = pendingValue !== undefined ? pendingValue : param.value;

    switch (param.type) {
        case 'boolean':
            return (
                <SettingsToggle
                    checked={currentValue as boolean}
                    onChange={onChange}
                    label={param.label}
                    description={param.description}
                />
            );
        case 'number':
            return (
                <SettingsInput
                    type="number"
                    value={currentValue as number}
                    onChange={(val) => onChange(val as number)}
                    label={param.label}
                    description={param.description}
                    min={param.min}
                    max={param.max}
                    step={param.step}
                />
            );
        case 'select':
            return (
                <SettingsSelect
                    value={currentValue as string}
                    onChange={onChange}
                    label={param.label}
                    description={param.description}
                    options={param.options || []}
                />
            );
        default:
            return (
                <SettingsInput
                    type="text"
                    value={currentValue as string}
                    onChange={(val) => onChange(val as string)}
                    label={param.label}
                    description={param.description}
                />
            );
    }
}

export function SettingsServiceCard({
    config,
    onParameterChange,
    pendingChanges,
    disabled = false,
}: SettingsServiceCardProps) {
    const serviceColor = SERVICE_COLORS[config.service];
    const changesCount = Array.from(pendingChanges.keys()).filter(k =>
        k.startsWith(`${config.service}.`)
    ).length;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={cn(
                'relative overflow-hidden rounded-xl border border-border/50',
                'bg-gradient-to-br from-card to-card/80',
                'shadow-sm hover:shadow-md transition-shadow duration-300'
            )}
        >
            {/* Top gradient accent */}
            <div
                className="absolute top-0 left-0 right-0 h-1"
                style={{ background: `linear-gradient(90deg, ${serviceColor}, ${serviceColor}80)` }}
            />

            {/* Header */}
            <div className="flex items-center justify-between gap-4 p-5 border-b border-border/30">
                <div className="flex items-center gap-4">
                    <div
                        className="p-3 rounded-xl"
                        style={{
                            backgroundColor: `${serviceColor}15`,
                            color: serviceColor,
                        }}
                    >
                        {SERVICE_ICONS[config.service]}
                    </div>
                    <div>
                        <h3 className="text-lg font-semibold text-foreground">
                            {config.displayName}
                        </h3>
                        <StatusIndicator status={config.status} />
                    </div>
                </div>
                {changesCount > 0 && (
                    <span className="px-2 py-1 text-xs font-medium rounded-full bg-amber-500/10 text-amber-600 dark:text-amber-400">
                        {changesCount} unsaved
                    </span>
                )}
            </div>

            {/* Sections */}
            <div className="p-4 space-y-3">
                {config.sections.map((section) => (
                    <SettingsSection
                        key={section.name}
                        title={section.label}
                        description={section.description}
                        icon={section.icon}
                        defaultOpen={section.name === 'security' || section.name === 'ml'}
                        badge={section.parameters.length}
                    >
                        {section.parameters.map((param) => {
                            const changeKey = `${config.service}.${section.name}.${param.key}`;
                            return (
                                <ParameterControl
                                    key={param.key}
                                    param={param}
                                    onChange={(value) => onParameterChange(section.name, param.key, value)}
                                    pendingValue={pendingChanges.get(changeKey)}
                                />
                            );
                        })}
                    </SettingsSection>
                ))}
            </div>

            {/* Disabled overlay */}
            {disabled && (
                <div className="absolute inset-0 bg-background/50 backdrop-blur-sm flex items-center justify-center">
                    <IconLoader2 className="h-8 w-8 animate-spin text-primary" />
                </div>
            )}
        </motion.div>
    );
}

export default SettingsServiceCard;
