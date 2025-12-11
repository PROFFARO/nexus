/**
 * Settings API Route - GET all service configurations
 * Reads config.ini files from service emulator directories
 */

import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs/promises';
import path from 'path';
import {
    ServiceConfig,
    ServiceName,
    ConfigSection,
    ConfigParameter,
    AllSettingsResponse,
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

// Sections to include (security-related only)
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

        // Skip empty lines and comments
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) {
            continue;
        }

        // Section header
        const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
        if (sectionMatch) {
            currentSection = sectionMatch[1].toLowerCase();
            if (!result[currentSection]) {
                result[currentSection] = {};
            }
            continue;
        }

        // Key-value pair
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
 * Convert string value to appropriate type based on metadata
 */
function parseValue(key: string, value: string): string | number | boolean {
    const meta = PARAMETER_METADATA[key];

    if (!meta) {
        // Try to infer type from value
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
        case 'select':
        case 'string':
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
        status: 'configured', // Config file was successfully read
        configPath,
        lastModified,
        sections,
    };
}

/**
 * Read and parse a service config file
 */
async function readServiceConfig(service: ServiceName): Promise<ServiceConfig | null> {
    const configPath = CONFIG_PATHS[service];

    try {
        const content = await fs.readFile(configPath, 'utf-8');
        const stat = await fs.stat(configPath);
        const parsedIni = parseIniContent(content);

        return buildServiceConfig(
            service,
            parsedIni,
            configPath,
            stat.mtime.toISOString()
        );
    } catch (error) {
        console.error(`Error reading config for ${service}:`, error);
        return null;
    }
}

export async function GET(request: NextRequest) {
    try {
        const services: ServiceConfig[] = [];

        // Read all service configs in parallel
        const results = await Promise.all([
            readServiceConfig('ssh'),
            readServiceConfig('ftp'),
            readServiceConfig('mysql'),
        ]);

        for (const config of results) {
            if (config) {
                services.push(config);
            }
        }

        const response: AllSettingsResponse = {
            services,
            timestamp: new Date().toISOString(),
        };

        return NextResponse.json(response, {
            headers: {
                'Cache-Control': 'no-store, no-cache, must-revalidate',
            },
        });
    } catch (error) {
        console.error('Settings API error:', error);
        return NextResponse.json(
            { error: 'Failed to fetch settings', details: String(error) },
            { status: 500 }
        );
    }
}
