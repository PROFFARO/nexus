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
    const message = log.message?.toLowerCase() || '';

    if (message.includes('session summary') || message.includes('ftp session summary')) {
        return 'session_summary';
    }
    if (message.includes('authentication') || message.includes('login')) {
        return 'auth';
    }
    if (message === 'user input' || message.includes('command') || log.command) {
        return 'command';
    }
    if (message.includes('response') || log.response) {
        return 'response';
    }
    return 'system';
}

// Utility function to determine sender from log entry
export function getSenderFromLog(log: LogEntry): MessageSender {
    const message = log.message?.toLowerCase() || '';

    // Commands from attacker
    if (message === 'user input' || log.command) {
        return 'attacker';
    }
    // Everything else is from the honeypot
    return 'honeypot';
}

// Extract display content from log entry
export function getMessageContent(log: LogEntry): string {
    // First check for command
    if (log.command) return log.command;

    // Check for response
    if (log.response) return log.response;

    // Check for details (base64 encoded sometimes)
    if (log.details) {
        try {
            return atob(log.details);
        } catch {
            return log.details;
        }
    }

    // Fall back to message
    return log.message || '';
}

// Check if log entry is conversation-relevant
export function isConversationRelevant(log: LogEntry): boolean {
    const message = log.message?.toLowerCase() || '';

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
    if (log.command || log.response) {
        return true;
    }

    return false;
}
