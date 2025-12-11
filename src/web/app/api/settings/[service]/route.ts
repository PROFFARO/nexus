/**
 * Individual Service Settings API Route
 * GET: Read single service configuration
 * PUT: Update service configuration with backup
 */

import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs/promises';
import path from 'path';
import {
    ServiceConfig,
    ServiceName,
    ConfigSection,
    ConfigParameter,
    UpdateSettingsRequest,
    UpdateSettingsResponse,
    PARAMETER_METADATA,
    SECTION_METADATA,
    SERVICE_METADATA,
} from '@/types/settings';

const SERVICE_EMULATORS_DIR = path.resolve(process.cwd(), '../service_emulators');

const CONFIG_PATHS: Record<ServiceName, string> = {
    ssh: path.join(SERVICE_EMULATORS_DIR, 'SSH', 'config.ini'),
    ftp: path.join(SERVICE_EMULATORS_DIR, 'FTP', 'config.ini'),
    mysql: path.join(SERVICE_EMULATORS_DIR, 'MySQL', 'config.ini'),
};

const INCLUDED_SECTIONS = ['security', 'ml', 'attack_detection', 'ai_features', 'forensics', 'logging'];

/**
 * Parse INI file content into sections and key-value pairs
 */
function parseIniContent(content: string): Record<string, Record<string, string>> {
    const result: Record<string, Record<string, string>> = {};
    let currentSection = '';

    const lines = content.split('\n');

    for (const line of lines) {
        const trimmed = line.trim();

        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) {
            continue;
        }

        const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
        if (sectionMatch) {
            currentSection = sectionMatch[1].toLowerCase();
            if (!result[currentSection]) {
                result[currentSection] = {};
            }
            continue;
        }

        const kvMatch = trimmed.match(/^([^=]+)=(.*)$/);
        if (kvMatch && currentSection) {
            const key = kvMatch[1].trim();
            const value = kvMatch[2].trim();
            result[currentSection][key] = value;
        }
    }

    return result;
}

/**
 * Convert value to string for INI file
 */
function valueToString(value: string | number | boolean): string {
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    return String(value);
}

/**
 * Update INI content with new values while preserving structure and comments
 */
function updateIniContent(
    originalContent: string,
    updates: { section: string; key: string; value: string | number | boolean }[]
): string {
    const lines = originalContent.split('\n');
    const result: string[] = [];
    let currentSection = '';

    // Create a map for quick lookup
    const updateMap = new Map<string, string>();
    for (const update of updates) {
        const normalizedSection = update.section.toLowerCase();
        updateMap.set(`${normalizedSection}.${update.key}`, valueToString(update.value));
    }

    for (const line of lines) {
        const trimmed = line.trim();

        // Section header
        const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
        if (sectionMatch) {
            currentSection = sectionMatch[1].toLowerCase();
            result.push(line);
            continue;
        }

        // Key-value pair
        const kvMatch = trimmed.match(/^([^=]+)=(.*)$/);
        if (kvMatch && currentSection) {
            const key = kvMatch[1].trim();
            const mapKey = `${currentSection}.${key}`;

            if (updateMap.has(mapKey)) {
                // Preserve indentation
                const indent = line.match(/^(\s*)/)?.[1] || '';
                result.push(`${indent}${key} = ${updateMap.get(mapKey)}`);
                continue;
            }
        }

        // Keep original line (comments, empty lines, unchanged values)
        result.push(line);
    }

    return result.join('\n');
}

/**
 * Convert string value to appropriate type based on metadata
 */
function parseValue(key: string, value: string): string | number | boolean {
    const meta = PARAMETER_METADATA[key];

    if (!meta) {
        if (value.toLowerCase() === 'true') return true;
        if (value.toLowerCase() === 'false') return false;
        const num = parseFloat(value);
        if (!isNaN(num)) return num;
        return value;
    }

    switch (meta.type) {
        case 'boolean':
            return value.toLowerCase() === 'true';
        case 'number':
            return parseFloat(value) || 0;
        default:
            return value;
    }
}

/**
 * Build ConfigParameter from key/value
 */
function buildConfigParameter(sectionName: string, key: string, value: string): ConfigParameter {
    const meta = PARAMETER_METADATA[key];
    const parsedValue = parseValue(key, value);

    return {
        key,
        value: parsedValue,
        section: sectionName,
        type: meta?.type || (typeof parsedValue === 'boolean' ? 'boolean' : typeof parsedValue === 'number' ? 'number' : 'string'),
        label: meta?.label || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        description: meta?.description || `Configure ${key.replace(/_/g, ' ')}`,
        options: meta?.options,
        min: meta?.min,
        max: meta?.max,
        step: meta?.step,
    };
}

/**
 * Build ServiceConfig from parsed INI data
 */
function buildServiceConfig(
    service: ServiceName,
    parsedIni: Record<string, Record<string, string>>,
    configPath: string,
    lastModified?: string
): ServiceConfig {
    const sections: ConfigSection[] = [];

    for (const sectionName of INCLUDED_SECTIONS) {
        const sectionData = parsedIni[sectionName];
        if (!sectionData) continue;

        const sectionMeta = SECTION_METADATA[sectionName];
        const parameters: ConfigParameter[] = [];

        for (const [key, value] of Object.entries(sectionData)) {
            parameters.push(buildConfigParameter(sectionName, key, value));
        }

        if (parameters.length > 0) {
            sections.push({
                name: sectionName,
                label: sectionMeta?.label || sectionName,
                description: sectionMeta?.description || '',
                icon: sectionMeta?.icon || 'settings',
                parameters,
            });
        }
    }

    const serviceMeta = SERVICE_METADATA[service];

    return {
        service,
        displayName: serviceMeta?.displayName || service.toUpperCase(),
        status: 'configured',
        configPath,
        lastModified,
        sections,
    };
}

/**
 * Validate service name
 */
function isValidService(service: string): service is ServiceName {
    return ['ssh', 'ftp', 'mysql'].includes(service);
}

/**
 * Validate update request
 */
function validateUpdates(updates: UpdateSettingsRequest['updates']): { valid: boolean; error?: string } {
    for (const update of updates) {
        const meta = PARAMETER_METADATA[update.key];

        if (meta?.type === 'number' && typeof update.value === 'number') {
            if (meta.min !== undefined && update.value < meta.min) {
                return { valid: false, error: `${meta.label}: Value must be at least ${meta.min}` };
            }
            if (meta.max !== undefined && update.value > meta.max) {
                return { valid: false, error: `${meta.label}: Value must be at most ${meta.max}` };
            }
        }

        if (meta?.type === 'select' && meta.options) {
            if (!meta.options.includes(String(update.value))) {
                return { valid: false, error: `${meta.label}: Invalid option "${update.value}"` };
            }
        }
    }

    return { valid: true };
}

// GET: Read single service configuration
export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ service: string }> }
) {
    try {
        const { service } = await params;

        if (!isValidService(service)) {
            return NextResponse.json(
                { error: `Invalid service: ${service}. Must be ssh, ftp, or mysql` },
                { status: 400 }
            );
        }

        const configPath = CONFIG_PATHS[service];

        try {
            const content = await fs.readFile(configPath, 'utf-8');
            const stat = await fs.stat(configPath);
            const parsedIni = parseIniContent(content);

            const config = buildServiceConfig(
                service,
                parsedIni,
                configPath,
                stat.mtime.toISOString()
            );

            return NextResponse.json(config, {
                headers: {
                    'Cache-Control': 'no-store, no-cache, must-revalidate',
                },
            });
        } catch {
            return NextResponse.json(
                { error: `Config file not found for ${service}` },
                { status: 404 }
            );
        }
    } catch (error) {
        console.error('Settings GET error:', error);
        return NextResponse.json(
            { error: 'Failed to fetch settings', details: String(error) },
            { status: 500 }
        );
    }
}

// PUT: Update service configuration
export async function PUT(
    request: NextRequest,
    { params }: { params: Promise<{ service: string }> }
) {
    try {
        const { service } = await params;

        if (!isValidService(service)) {
            return NextResponse.json(
                { error: `Invalid service: ${service}. Must be ssh, ftp, or mysql` },
                { status: 400 }
            );
        }

        const configPath = CONFIG_PATHS[service];
        const body: UpdateSettingsRequest = await request.json();

        // Validate updates
        const validation = validateUpdates(body.updates);
        if (!validation.valid) {
            return NextResponse.json(
                { success: false, message: validation.error } as UpdateSettingsResponse,
                { status: 400 }
            );
        }

        // Read original content
        let originalContent: string;
        try {
            originalContent = await fs.readFile(configPath, 'utf-8');
        } catch {
            return NextResponse.json(
                { success: false, message: `Config file not found for ${service}` } as UpdateSettingsResponse,
                { status: 404 }
            );
        }

        // Create backup
        const backupPath = configPath + '.bak';
        await fs.writeFile(backupPath, originalContent, 'utf-8');

        // Update content
        const updatedContent = updateIniContent(originalContent, body.updates);

        // Write updated content
        await fs.writeFile(configPath, updatedContent, 'utf-8');

        // Read back the updated config
        const newContent = await fs.readFile(configPath, 'utf-8');
        const stat = await fs.stat(configPath);
        const parsedIni = parseIniContent(newContent);

        const updatedConfig = buildServiceConfig(
            service,
            parsedIni,
            configPath,
            stat.mtime.toISOString()
        );

        const response: UpdateSettingsResponse = {
            success: true,
            message: `Settings updated successfully for ${service}`,
            backupPath,
            updatedConfig,
        };

        return NextResponse.json(response);
    } catch (error) {
        console.error('Settings PUT error:', error);
        return NextResponse.json(
            { success: false, message: 'Failed to update settings', details: String(error) } as UpdateSettingsResponse,
            { status: 500 }
        );
    }
}
