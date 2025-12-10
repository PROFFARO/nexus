/**
 * Next.js API Route for Active Services
 */

import { NextResponse } from 'next/server';
import fs from 'fs/promises';
import path from 'path';

const SERVICE_EMULATORS_DIR = path.resolve(process.cwd(), '../service_emulators');

const SESSION_DIRS: Record<string, string> = {
    ssh: path.join(SERVICE_EMULATORS_DIR, 'SSH', 'sessions'),
    ftp: path.join(SERVICE_EMULATORS_DIR, 'FTP', 'sessions'),
    mysql: path.join(SERVICE_EMULATORS_DIR, 'MySQL', 'sessions'),
};

const CONFIG_FILES: Record<string, string> = {
    ssh: path.join(SERVICE_EMULATORS_DIR, 'SSH', 'config.ini'),
    ftp: path.join(SERVICE_EMULATORS_DIR, 'FTP', 'config.ini'),
    mysql: path.join(SERVICE_EMULATORS_DIR, 'MySQL', 'config.ini'),
};

async function getLLMConfig(service: string) {
    try {
        const configPath = CONFIG_FILES[service];
        const content = await fs.readFile(configPath, 'utf-8');

        // Simple INI parsing
        const lines = content.split('\n');
        let inLLM = false;
        const config: Record<string, string> = {
            llm_provider: 'gemini',
            model_name: 'gemini-2.5-flash',
        };

        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed === '[llm]') {
                inLLM = true;
                continue;
            }
            if (trimmed.startsWith('[') && trimmed !== '[llm]') {
                inLLM = false;
                continue;
            }
            if (inLLM && !trimmed.startsWith('#') && !trimmed.startsWith(';') && trimmed.includes('=')) {
                const [key, ...valueParts] = trimmed.split('=');
                const value = valueParts.join('=').trim();
                if (key.trim() === 'llm_provider') config.llm_provider = value;
                if (key.trim() === 'model_name') config.model_name = value;
            }
        }

        return config;
    } catch (err) {
        return { llm_provider: 'gemini', model_name: 'gemini-2.5-flash' };
    }
}

export async function GET() {
    try {
        const activeServices: any[] = [];

        for (const [service, sessionDir] of Object.entries(SESSION_DIRS)) {
            try {
                const items = await fs.readdir(sessionDir);
                const sessionCount = items.filter(item =>
                    !item.startsWith('_') && !item.endsWith('_states')
                ).length;

                if (sessionCount > 0) {
                    const config = await getLLMConfig(service);
                    activeServices.push({
                        service,
                        session_count: sessionCount,
                        config,
                    });
                }
            } catch (err) {
                // Directory doesn't exist
            }
        }

        return NextResponse.json(activeServices);
    } catch (error) {
        console.error('Active services error:', error);
        return NextResponse.json([], { status: 500 });
    }
}
