import { LogEntry } from './api';

// Message types in a conversation
export type MessageType = 'command' | 'response' | 'system' | 'auth' | 'session_summary';
export type MessageSender = 'attacker' | 'honeypot';

// Individual chat message
export interface ConversationMessage {
    id: string;
    timestamp: string;
    type: MessageType;
    sender: MessageSender;
    content: string;
    command?: string;        // Original command for command type
    response?: string;       // Response text for response type
    protocol?: string;       // SSH, FTP, MySQL
    username?: string;
    isTyping?: boolean;      // For typing indicator
    // Attack metadata
    attack_types?: string[];
    severity?: string;
    threat_score?: number;
    // Original log entry for details
    raw?: LogEntry;
}

// Grouped session data
export interface ConversationSession {
    id: string;              // session_id
    src_ip: string;
    src_port?: string | number;
    protocol: 'ssh' | 'ftp' | 'mysql' | 'unknown';
    username?: string;
    startTime: string;
    lastActivity: string;
    messages: ConversationMessage[];
    messageCount: number;
    isActive: boolean;
    // Aggregated threat data
    hasThreats: boolean;
    maxSeverity?: string;
    attackTypes: string[];
}

// Filter options for conversations
export interface ConversationFilters {
    protocol: 'all' | 'ssh' | 'ftp' | 'mysql';
    severity: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
    timeRange: 'all' | '1h' | '24h' | '7d' | 'custom';
    customStartDate?: Date;
    customEndDate?: Date;
    searchQuery: string;
    ipFilter: string;
    usernameFilter: string;
    showActiveOnly: boolean;
    sortBy: 'newest' | 'oldest' | 'mostActive' | 'highestThreat';
}

// Default filter values
export const defaultFilters: ConversationFilters = {
    protocol: 'all',
    severity: 'all',
    timeRange: 'all',
    searchQuery: '',
    ipFilter: '',
    usernameFilter: '',
    showActiveOnly: false,
    sortBy: 'newest'
};

// Utility function to determine message type from log entry
export function getMessageTypeFromLog(log: LogEntry): MessageType {
    // Flatten structured_data if present (MySQL logs)
    let flatLog = log;
    if ((log as any).structured_data && typeof (log as any).structured_data === 'object') {
        flatLog = { ...log, ...(log as any).structured_data };
    }

    const message = flatLog.message?.toLowerCase() || '';
    const event = (flatLog as any).event?.toLowerCase() || '';

    // MySQL specific events
    if (event === 'query_request') return 'command';
    if (event === 'query_response' || event === 'llm_interaction') return 'response';

    if (message.includes('session summary') || message.includes('ftp session summary')) {
        return 'session_summary';
    }
    if (message.includes('authentication') || message.includes('login')) {
        return 'auth';
    }
    if (message === 'user input' || message.includes('command') || flatLog.command || (flatLog as any).query) {
        return 'command';
    }
    if (message.includes('response') || (flatLog as any).response || (flatLog as any).summary) {
        return 'response';
    }
    return 'system';
}

// Utility function to determine sender from log entry
export function getSenderFromLog(log: LogEntry): MessageSender {
    // Flatten structured_data if present (MySQL logs)
    let flatLog = log;
    if ((log as any).structured_data && typeof (log as any).structured_data === 'object') {
        flatLog = { ...log, ...(log as any).structured_data };
    }

    const message = flatLog.message?.toLowerCase() || '';
    const event = (flatLog as any).event?.toLowerCase() || '';

    // MySQL specific events
    if (event === 'query_request') return 'attacker';
    if (event === 'query_response' || event === 'llm_interaction') return 'honeypot';

    // Commands from attacker
    if (message === 'user input' || flatLog.command || ((flatLog as any).query && !(flatLog as any).response && !(flatLog as any).summary)) {
        return 'attacker';
    }
    // Everything else is from the honeypot
    return 'honeypot';
}

// Extract display content from log entry
export function getMessageContent(log: LogEntry): string {
    // Flatten structured_data if present (MySQL logs)
    let flatLog = log;
    if ((log as any).structured_data && typeof (log as any).structured_data === 'object') {
        flatLog = { ...log, ...(log as any).structured_data };
    }

    const event = (flatLog as any).event?.toLowerCase() || '';

    // MySQL specific content extraction
    if (event === 'query_request' && (flatLog as any).query) return (flatLog as any).query;
    if (event === 'llm_interaction' && (flatLog as any).response) {
        const resp = (flatLog as any).response;
        if (Array.isArray(resp)) {
            try {
                return resp.map((row: any[]) => Array.isArray(row) ? row.join(', ') : String(row)).join('\n');
            } catch {
                return JSON.stringify(resp);
            }
        }
        return resp;
    }
    if (event === 'query_response') {
        // Check for actual response data first
        const resp = (flatLog as any).response;
        if (resp) {
            if (Array.isArray(resp)) {
                try {
                    return resp.map((row: any[]) => Array.isArray(row) ? row.join(', ') : String(row)).join('\n');
                } catch {
                    return JSON.stringify(resp);
                }
            }
            return resp;
        }
        // Fall back to summary
        if ((flatLog as any).summary) return `Result: ${(flatLog as any).summary} (${(flatLog as any).duration_ms}ms)`;
        if ((flatLog as any).error) return `Error: ${(flatLog as any).error}`;
    }

    // First check for command/query
    if (flatLog.command) return flatLog.command;
    if ((flatLog as any).query && !(flatLog as any).response && !(flatLog as any).summary) return (flatLog as any).query;

    // Check for response
    if ((flatLog as any).response) {
        const resp = (flatLog as any).response;
        if (Array.isArray(resp)) {
            try {
                return resp.map((row: any[]) => Array.isArray(row) ? row.join(', ') : String(row)).join('\n');
            } catch {
                return JSON.stringify(resp);
            }
        }
        return resp;
    }

    // Check for details (base64 encoded sometimes)
    if (flatLog.details) {
        try {
            return atob(flatLog.details);
        } catch {
            return flatLog.details;
        }
    }

    // Fall back to message
    return flatLog.message || '';
}

// Check if log entry is conversation-relevant
export function isConversationRelevant(log: LogEntry): boolean {
    // Flatten structured_data if present (MySQL logs)
    let flatLog = log;
    if ((log as any).structured_data && typeof (log as any).structured_data === 'object') {
        flatLog = { ...log, ...(log as any).structured_data };
    }
    
    const message = flatLog.message?.toLowerCase() || '';
    const event = (flatLog as any).event?.toLowerCase() || '';

    // Include MySQL specific events
    if (['query_request', 'query_response', 'llm_interaction'].includes(event)) {
        return true;
    }

    // Include these message types
    const relevantPatterns = [
        'user input',
        'command',
        'response',
        'authentication',
        'login',
        'session',
        'connection received',
        'data received',
        'query'
    ];

    // Check if message matches any pattern
    if (relevantPatterns.some(pattern => message.includes(pattern))) {
        return true;
    }

    // Include if has command or response
    if (flatLog.command || (flatLog as any).response || (flatLog as any).query) {
        return true;
    }

    return false;
}
