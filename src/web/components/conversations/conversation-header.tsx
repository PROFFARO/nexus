"use client";

import { useState, useEffect } from "react";
import { ConversationSession, ConversationMessage } from "@/types/conversation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator,
    DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import {
    Terminal,
    FolderOpen,
    Database,
    Network,
    Clock,
    MessageSquare,
    Download,
    Flag,
    MoreVertical,
    User,
    FileJson,
    FileText,
    Copy,
    Check,
    AlertTriangle,
    ExternalLink,
    FolderPlus,
    Square,
    CheckSquare
} from "lucide-react";
import { toast } from "sonner";

interface ConversationHeaderProps {
    session: ConversationSession | null;
}

const COLLECTIONS_KEY = 'honeypot_session_collections';
const FALSE_POSITIVES_KEY = 'honeypot_false_positives';

function getProtocolIcon(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return <Terminal className="h-4 w-4" />;
        case 'ftp': return <FolderOpen className="h-4 w-4" />;
        case 'mysql': return <Database className="h-4 w-4" />;
        default: return <Network className="h-4 w-4" />;
    }
}

function getProtocolStyle(protocol: string) {
    switch (protocol?.toLowerCase()) {
        case 'ssh': return 'bg-sky-500/20 border-sky-500/30 text-sky-600 dark:text-sky-400';
        case 'ftp': return 'bg-violet-500/20 border-violet-500/30 text-violet-600 dark:text-violet-400';
        case 'mysql': return 'bg-amber-500/20 border-amber-500/30 text-amber-600 dark:text-amber-400';
        default: return 'bg-gray-500/20 border-gray-500/30 text-gray-600 dark:text-gray-400';
    }
}

function getSeverityStyle(severity?: string) {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
        case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
        case 'medium': return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
        case 'low': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
        default: return '';
    }
}

function formatDuration(startTime: string): string {
    const start = new Date(startTime).getTime();
    const now = Date.now();
    const diff = now - start;
    const hours = Math.floor(diff / 3600000);
    const minutes = Math.floor((diff % 3600000) / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

function exportToJSON(session: ConversationSession): void {
    const exportData = {
        session_info: {
            id: session.id, ip: session.src_ip, port: session.src_port, protocol: session.protocol,
            username: session.username, start_time: session.startTime, last_activity: session.lastActivity,
            is_active: session.isActive, message_count: session.messageCount, has_threats: session.hasThreats,
            max_severity: session.maxSeverity, attack_types: session.attackTypes
        },
        messages: session.messages.map(msg => ({
            id: msg.id, timestamp: msg.timestamp, type: msg.type, sender: msg.sender,
            content: msg.content, command: msg.command, attack_types: msg.attack_types, severity: msg.severity
        })),
        exported_at: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `session_${session.src_ip.replace(/\./g, '-')}_${session.protocol}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function exportToTXT(session: ConversationSession): void {
    let content = `HONEYPOT SESSION TRANSCRIPT\n${'='.repeat(40)}\n\n`;
    content += `Session: ${session.id}\nIP: ${session.src_ip}:${session.src_port || 'N/A'}\n`;
    content += `Protocol: ${session.protocol.toUpperCase()}\nUser: ${session.username || 'N/A'}\n`;
    content += `Start: ${new Date(session.startTime).toLocaleString()}\nMessages: ${session.messageCount}\n`;
    if (session.hasThreats) content += `Threats: ${session.maxSeverity} - ${session.attackTypes.join(', ')}\n`;
    content += `\n${'='.repeat(40)}\nTRANSCRIPT\n${'='.repeat(40)}\n\n`;
    session.messages.forEach(msg => {
        const time = new Date(msg.timestamp).toLocaleTimeString();
        const sender = msg.sender === 'attacker' ? 'ATTACKER' : 'HONEYPOT';
        content += `[${time}] ${sender}: ${msg.content || msg.command || ''}\n`;
    });
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `session_${session.src_ip.replace(/\./g, '-')}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function copySessionSummary(session: ConversationSession): void {
    const summary = `Session: ${session.src_ip} (${session.protocol.toUpperCase()})\nUser: ${session.username || 'N/A'}\nMessages: ${session.messageCount}\nThreats: ${session.hasThreats ? session.maxSeverity : 'None'}`;
    navigator.clipboard.writeText(summary);
}

function viewInNewTab(session: ConversationSession): void {
    const protocolColors: Record<string, { primary: string; secondary: string; gradient: string }> = {
        ssh: { primary: '#0ea5e9', secondary: '#38bdf8', gradient: 'linear-gradient(135deg, #0ea5e9, #06b6d4)' },
        ftp: { primary: '#8b5cf6', secondary: '#a78bfa', gradient: 'linear-gradient(135deg, #8b5cf6, #7c3aed)' },
        mysql: { primary: '#f59e0b', secondary: '#fbbf24', gradient: 'linear-gradient(135deg, #f59e0b, #eab308)' },
    };
    const colors = protocolColors[session.protocol.toLowerCase()] || protocolColors.ssh;

    const attackCount = session.messages.filter(m => m.attack_types && m.attack_types.length > 0).length;
    const commandCount = session.messages.filter(m => m.sender === 'attacker').length;
    const responseCount = session.messages.filter(m => m.sender === 'honeypot').length;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${session.src_ip} - ${session.protocol.toUpperCase()} Session | Nexus Honeypot</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0b;
            --bg-secondary: #111113;
            --bg-tertiary: #1a1a1d;
            --bg-card: #16161a;
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --border-color: #27272a;
            --border-subtle: #1f1f23;
            --accent: ${colors.primary};
            --accent-secondary: ${colors.secondary};
            --accent-gradient: ${colors.gradient};
            --attacker-bg: rgba(239, 68, 68, 0.08);
            --attacker-border: rgba(239, 68, 68, 0.25);
            --attacker-text: #fca5a5;
            --honeypot-bg: rgba(16, 185, 129, 0.08);
            --honeypot-border: rgba(16, 185, 129, 0.25);
            --honeypot-text: #6ee7b7;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.4);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.5);
        }
        
        [data-theme="light"] {
            --bg-primary: #fafafa;
            --bg-secondary: #f4f4f5;
            --bg-tertiary: #e4e4e7;
            --bg-card: #ffffff;
            --text-primary: #09090b;
            --text-secondary: #52525b;
            --text-muted: #71717a;
            --border-color: #e4e4e7;
            --border-subtle: #f4f4f5;
            --attacker-bg: rgba(239, 68, 68, 0.06);
            --attacker-border: rgba(239, 68, 68, 0.2);
            --attacker-text: #dc2626;
            --honeypot-bg: rgba(16, 185, 129, 0.06);
            --honeypot-border: rgba(16, 185, 129, 0.2);
            --honeypot-text: #059669;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.15);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        html { scroll-behavior: smooth; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            transition: background 0.3s ease, color 0.3s ease;
        }
        
        /* Header */
        .header {
            position: sticky;
            top: 0;
            z-index: 100;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
        }
        
        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }
        
        .session-info {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .protocol-badge {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 48px;
            height: 48px;
            background: var(--accent-gradient);
            color: white;
            font-weight: 700;
            font-size: 14px;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            box-shadow: var(--shadow-md);
        }
        
        .session-details h1 {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .port { color: var(--text-muted); font-weight: 500; }
        
        .session-meta {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-top: 6px;
            font-size: 13px;
            color: var(--text-secondary);
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .meta-item svg { opacity: 0.6; }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid;
        }
        
        .status-active {
            background: rgba(16, 185, 129, 0.1);
            border-color: rgba(16, 185, 129, 0.3);
            color: #10b981;
        }
        
        .status-closed {
            background: var(--bg-tertiary);
            border-color: var(--border-color);
            color: var(--text-muted);
        }
        
        .header-actions {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 10px 16px;
            font-size: 13px;
            font-weight: 500;
            border: 1px solid var(--border-color);
            background: var(--bg-card);
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .btn:hover {
            background: var(--bg-tertiary);
            border-color: var(--accent);
        }
        
        .btn-icon {
            width: 40px;
            height: 40px;
            padding: 0;
        }
        
        .btn-primary {
            background: var(--accent-gradient);
            border: none;
            color: white;
        }
        
        .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        
        /* Stats Bar */
        .stats-bar {
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
        }
        
        .stats-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 16px 24px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
        }
        
        .stat-card {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-subtle);
            transition: all 0.2s ease;
        }
        
        .stat-card:hover {
            border-color: var(--accent);
            transform: translateY(-2px);
        }
        
        .stat-icon {
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--bg-tertiary);
        }
        
        .stat-info { flex: 1; }
        
        .stat-value {
            font-size: 20px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-primary);
        }
        
        .stat-label {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 2px;
        }
        
        /* Messages Container */
        .messages-container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 32px 24px;
        }
        
        .date-header {
            text-align: center;
            margin-bottom: 24px;
        }
        
        .date-badge {
            display: inline-block;
            padding: 8px 20px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        /* Message Styles */
        .message {
            display: flex;
            margin-bottom: 16px;
            animation: fadeInUp 0.3s ease;
        }
        
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message.attacker { justify-content: flex-start; }
        .message.honeypot { justify-content: flex-end; }
        
        .message-wrapper {
            display: flex;
            align-items: flex-end;
            gap: 12px;
            max-width: 70%;
        }
        
        .message.honeypot .message-wrapper { flex-direction: row-reverse; }
        
        .avatar {
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            border: 2px solid;
        }
        
        .avatar.attacker {
            background: var(--attacker-bg);
            border-color: var(--attacker-border);
            color: var(--attacker-text);
        }
        
        .avatar.honeypot {
            background: var(--honeypot-bg);
            border-color: var(--honeypot-border);
            color: var(--honeypot-text);
        }
        
        .bubble {
            padding: 14px 18px;
            position: relative;
        }
        
        .bubble.attacker {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
        }
        
        .bubble.honeypot {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(6, 182, 212, 0.15));
            border: 1px solid var(--honeypot-border);
        }
        
        .command {
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .command-prompt {
            color: var(--success);
            font-weight: 700;
            margin-right: 8px;
        }
        
        .response-text {
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
        }
        
        .message-footer {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid var(--border-subtle);
        }
        
        .timestamp {
            font-size: 11px;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 4px;
        }
        
        .copy-btn {
            opacity: 0;
            transition: opacity 0.2s ease;
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
        }
        
        .message-wrapper:hover .copy-btn { opacity: 1; }
        .copy-btn:hover { color: var(--accent); }
        .copy-btn.copied { color: var(--success); }
        
        /* Attack Indicators */
        .attack-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 8px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            margin-right: 6px;
            margin-top: 8px;
        }
        
        .attack-badge.critical { background: rgba(239, 68, 68, 0.2); color: #f87171; }
        .attack-badge.high { background: rgba(249, 115, 22, 0.2); color: #fb923c; }
        .attack-badge.medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
        .attack-badge.type { background: rgba(236, 72, 153, 0.2); color: #f472b6; }
        
        /* Theme Toggle */
        .theme-toggle {
            position: relative;
            width: 56px;
            height: 30px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .theme-toggle::before {
            content: '';
            position: absolute;
            top: 3px;
            left: 3px;
            width: 22px;
            height: 22px;
            background: var(--accent-gradient);
            transition: transform 0.3s ease;
        }
        
        [data-theme="light"] .theme-toggle::before { transform: translateX(26px); }
        
        .theme-icons {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 6px;
            height: 100%;
        }
        
        .theme-icons svg { width: 14px; height: 14px; }
        
        /* Scroll to Top */
        .scroll-top {
            position: fixed;
            bottom: 24px;
            right: 24px;
            width: 48px;
            height: 48px;
            background: var(--accent-gradient);
            border: none;
            color: white;
            cursor: pointer;
            display: none;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-lg);
            transition: all 0.3s ease;
            z-index: 100;
        }
        
        .scroll-top:hover { transform: translateY(-3px); }
        .scroll-top.visible { display: flex; }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 32px 24px;
            border-top: 1px solid var(--border-color);
            background: var(--bg-secondary);
        }
        
        .footer-text {
            font-size: 13px;
            color: var(--text-muted);
        }
        
        .footer-brand {
            color: var(--accent);
            font-weight: 600;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header-content { flex-direction: column; align-items: flex-start; }
            .message-wrapper { max-width: 90%; }
            .stats-content { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="session-info">
                <div class="protocol-badge">${session.protocol.toUpperCase().slice(0, 3)}</div>
                <div class="session-details">
                    <h1>
                        ${session.src_ip}
                        <span class="port">:${session.src_port || 'N/A'}</span>
                        <span class="status-badge ${session.isActive ? 'status-active' : 'status-closed'}">
                            <span style="width:6px;height:6px;background:currentColor;border-radius:50%;"></span>
                            ${session.isActive ? 'ACTIVE' : 'CLOSED'}
                        </span>
                    </h1>
                    <div class="session-meta">
                        <div class="meta-item">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg>
                            ${new Date(session.startTime).toLocaleString()}
                        </div>
                        <div class="meta-item">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20,21v-2a4,4,0,0,0-4-4H8a4,4,0,0,0-4,4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            ${session.username || 'Anonymous'}
                        </div>
                    </div>
                </div>
            </div>
            <div class="header-actions">
                <button class="btn btn-icon" onclick="window.print()" title="Print">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6,9 6,2 18,2 18,9"/><path d="M6,18H4a2,2,0,0,1-2-2V9a2,2,0,0,1,2-2H20a2,2,0,0,1,2,2v7a2,2,0,0,1-2,2H18"/><rect x="6" y="14" width="12" height="8"/></svg>
                </button>
                <div class="theme-toggle" onclick="toggleTheme()" title="Toggle Theme">
                    <div class="theme-icons">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21,12.79A9,9,0,1,1,11.21,3,7,7,0,0,0,21,12.79Z"/></svg>
                    </div>
                </div>
            </div>
        </div>
    </header>
    
    <section class="stats-bar">
        <div class="stats-content">
            <div class="stat-card">
                <div class="stat-icon" style="color:${colors.primary}">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21,15a2,2,0,0,1-2,2H7l-4,4V5a2,2,0,0,1,2-2H19a2,2,0,0,1,2,2Z"/></svg>
                </div>
                <div class="stat-info">
                    <div class="stat-value">${session.messageCount}</div>
                    <div class="stat-label">Total Messages</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="color:#ef4444">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20,21v-2a4,4,0,0,0-4-4H8a4,4,0,0,0-4,4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </div>
                <div class="stat-info">
                    <div class="stat-value">${commandCount}</div>
                    <div class="stat-label">Attacker Commands</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="color:#10b981">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7,11V7a5,5,0,0,1,10,0v4"/></svg>
                </div>
                <div class="stat-info">
                    <div class="stat-value">${responseCount}</div>
                    <div class="stat-label">Honeypot Responses</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="color:#f59e0b">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29,3.86,1.82,18a2,2,0,0,0,1.71,3H20.47a2,2,0,0,0,1.71-3L13.71,3.86A2,2,0,0,0,10.29,3.86Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <div class="stat-info">
                    <div class="stat-value">${attackCount}</div>
                    <div class="stat-label">Attack Detected</div>
                </div>
            </div>
        </div>
    </section>
    
    <main class="messages-container">
        <div class="date-header">
            <div class="date-badge">${new Date(session.startTime).toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</div>
        </div>
        
        ${generateMessagesHtml(session.messages)}
    </main>
    
    <footer class="footer">
        <p class="footer-text">Session transcript exported from <span class="footer-brand">Nexus Honeypot</span> • ${new Date().toLocaleString()}</p>
    </footer>
    
    <button class="scroll-top" id="scrollTop" onclick="scrollToTop()">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18,15 12,9 6,15"/></svg>
    </button>
    
    <script>
        // Theme
        function toggleTheme() {
            const html = document.documentElement;
            const current = html.getAttribute('data-theme');
            const next = current === 'light' ? 'dark' : 'light';
            html.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
        }
        
        // Init theme
        (function() {
            const saved = localStorage.getItem('theme');
            const prefer = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', saved || prefer);
        })();
        
        // Copy
        function copyText(btn, text) {
            navigator.clipboard.writeText(text);
            btn.classList.add('copied');
            setTimeout(() => btn.classList.remove('copied'), 2000);
        }
        
        // Scroll to top
        function scrollToTop() { window.scrollTo({ top: 0, behavior: 'smooth' }); }
        
        window.addEventListener('scroll', function() {
            const btn = document.getElementById('scrollTop');
            if (window.scrollY > 300) {
                btn.classList.add('visible');
            } else {
                btn.classList.remove('visible');
            }
        });
    </script>
</body>
</html>`;
    const blob = new Blob([html], { type: 'text/html' });
    window.open(URL.createObjectURL(blob), '_blank');
}

// Helper function to generate messages HTML for popup
function generateMessagesHtml(messages: ConversationMessage[]): string {
    return messages.map((m, i) => {
        const isAttacker = m.sender === 'attacker';
        const content = (m.content || m.command || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const safeContent = content.replace(/'/g, "\\'").replace(/"/g, '&quot;');

        let attackIndicators = '';
        if (m.attack_types && m.attack_types.length > 0) {
            const badges = m.attack_types.slice(0, 3).map((t: string) => `<span class="attack-badge type">${t}</span>`).join('');
            const severityBadge = m.severity ? `<span class="attack-badge ${m.severity.toLowerCase()}">${m.severity.toUpperCase()}</span>` : '';
            attackIndicators = `<div style="margin-top:8px">${badges}${severityBadge}</div>`;
        }

        const avatarSvg = isAttacker
            ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20,21v-2a4,4,0,0,0-4-4H8a4,4,0,0,0-4,4v2"/><circle cx="12" cy="7" r="4"/></svg>'
            : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7,11V7a5,5,0,0,1,10,0v4"/></svg>';

        const contentHtml = (m.type === 'command' || m.command)
            ? `<div class="command"><span class="command-prompt">$</span>${content}</div>`
            : `<div class="response-text">${content}</div>`;

        const timestamp = new Date(m.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

        return `
            <div class="message ${isAttacker ? 'attacker' : 'honeypot'}" style="animation-delay:${i * 0.05}s">
                <div class="message-wrapper">
                    <div class="avatar ${isAttacker ? 'attacker' : 'honeypot'}">${avatarSvg}</div>
                    <div class="bubble ${isAttacker ? 'attacker' : 'honeypot'}">
                        ${contentHtml}
                        ${attackIndicators}
                        <div class="message-footer">
                            <span class="timestamp">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg>
                                ${timestamp}
                            </span>
                            <button class="copy-btn" onclick="copyText(this, '${safeContent}')">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5,15H4a2,2,0,0,1-2-2V4A2,2,0,0,1,4,2H13a2,2,0,0,1,2,2V5"/></svg>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Toggle false positive
function toggleFalsePositive(session: ConversationSession, isCurrentlyReported: boolean): boolean {
    const data = localStorage.getItem(FALSE_POSITIVES_KEY);
    let reports: any[] = data ? JSON.parse(data) : [];

    if (isCurrentlyReported) {
        // Remove from reports
        reports = reports.filter(r => r.session_id !== session.id);
        localStorage.setItem(FALSE_POSITIVES_KEY, JSON.stringify(reports));
        return false;
    } else {
        // Add to reports
        reports.push({ session_id: session.id, ip: session.src_ip, protocol: session.protocol, reported_at: new Date().toISOString() });
        localStorage.setItem(FALSE_POSITIVES_KEY, JSON.stringify(reports));
        return true;
    }
}

// Toggle collection
function toggleCollection(session: ConversationSession, isCurrentlySaved: boolean): boolean {
    const data = localStorage.getItem(COLLECTIONS_KEY);
    let collections: any[] = data ? JSON.parse(data) : [];

    if (isCurrentlySaved) {
        // Remove from collection
        collections = collections.filter(c => c.session_id !== session.id);
        localStorage.setItem(COLLECTIONS_KEY, JSON.stringify(collections));
        return false;
    } else {
        // Add to collection
        collections.push({ session_id: session.id, ip: session.src_ip, protocol: session.protocol, added_at: new Date().toISOString() });
        localStorage.setItem(COLLECTIONS_KEY, JSON.stringify(collections));
        return true;
    }
}

export function ConversationHeader({ session }: ConversationHeaderProps) {
    const [isFlagged, setIsFlagged] = useState(false);
    const [copied, setCopied] = useState(false);
    const [isInCollection, setIsInCollection] = useState(false);
    const [isReported, setIsReported] = useState(false);

    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        if (typeof window === 'undefined' || !session) return;
        const collections = JSON.parse(localStorage.getItem(COLLECTIONS_KEY) || '[]');
        const reports = JSON.parse(localStorage.getItem(FALSE_POSITIVES_KEY) || '[]');
        setIsInCollection(collections.some((c: any) => c.session_id === session.id));
        setIsReported(reports.some((r: any) => r.session_id === session.id));
        setIsFlagged(false); // Reset flag on session change
    }, [session?.id]);

    if (!session) {
        return (
            <div className="flex-shrink-0 h-14 flex items-center justify-center border-b border-border/50 bg-card/30">
                <p className="text-sm text-muted-foreground">Select a session to view details</p>
            </div>
        );
    }

    const handleToggleFalsePositive = () => {
        const newState = toggleFalsePositive(session, isReported);
        setIsReported(newState);
        toast.success(newState ? "Marked as False Positive" : "Removed False Positive");
    };

    const handleToggleCollection = () => {
        const newState = toggleCollection(session, isInCollection);
        setIsInCollection(newState);
        toast.success(newState ? "Added to Collection" : "Removed from Collection");
    };

    return (
        <div className="flex-shrink-0 flex items-center justify-between gap-4 px-4 py-2 border-b border-border/50 bg-card/50 min-h-[56px]">
            {/* Left: Session Info */}
            <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className={cn("flex-shrink-0 p-2 border", getProtocolStyle(session.protocol))}>
                    {getProtocolIcon(session.protocol)}
                </div>

                <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-base font-bold text-emerald-500 truncate">
                            {session.src_ip}
                        </span>
                        {session.src_port && (
                            <span className="text-xs text-muted-foreground font-mono">:{session.src_port}</span>
                        )}
                        <Badge className={cn(
                            "px-2 py-0.5 text-[10px] font-bold rounded-none",
                            session.isActive ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-muted text-muted-foreground"
                        )}>
                            {session.isActive ? "●ACTIVE" : "CLOSED"}
                        </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                        {session.username && (
                            <span className="flex items-center gap-1"><User className="h-3 w-3" />{session.username}</span>
                        )}
                        <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{formatDuration(session.startTime)}</span>
                        <span className="flex items-center gap-1"><MessageSquare className="h-3 w-3" />{session.messageCount}</span>
                    </div>
                </div>
            </div>

            {/* Middle: Threats */}
            {session.hasThreats && (
                <div className="flex items-center gap-1.5 flex-shrink-0 max-w-[300px] overflow-x-auto">
                    {session.maxSeverity && (
                        <Badge className={cn("px-2 py-0.5 text-[10px] font-bold uppercase rounded-none flex-shrink-0", getSeverityStyle(session.maxSeverity))}>
                            {session.maxSeverity}
                        </Badge>
                    )}
                    {session.attackTypes.slice(0, 2).map((type, i) => (
                        <Badge key={i} className="px-2 py-0.5 text-[10px] bg-rose-500/15 text-rose-400 border-rose-500/30 rounded-none flex-shrink-0 truncate max-w-[120px]">
                            {type}
                        </Badge>
                    ))}
                    {session.attackTypes.length > 2 && (
                        <Badge className="px-1.5 py-0.5 text-[10px] bg-muted text-muted-foreground rounded-none flex-shrink-0">
                            +{session.attackTypes.length - 2}
                        </Badge>
                    )}
                </div>
            )}

            {/* Right: Actions */}
            <div className="flex items-center gap-0.5 flex-shrink-0 pl-2 border-l border-border/50">
                {mounted ? (
                    <>
                        {/* Export */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-8 w-8 rounded-none">
                                    <Download className="h-4 w-4" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-[160px] bg-card border-border rounded-none">
                                <DropdownMenuItem onClick={() => { exportToJSON(session); toast.success("Exported JSON"); }} className="rounded-none gap-2 text-sm">
                                    <FileJson className="h-4 w-4 text-blue-500" /> JSON
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => { exportToTXT(session); toast.success("Exported TXT"); }} className="rounded-none gap-2 text-sm">
                                    <FileText className="h-4 w-4 text-emerald-500" /> TXT
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem onClick={() => { copySessionSummary(session); setCopied(true); setTimeout(() => setCopied(false), 2000); toast.success("Copied"); }} className="rounded-none gap-2 text-sm">
                                    {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />} Copy
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>

                        {/* Flag */}
                        <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => { setIsFlagged(!isFlagged); toast.success(isFlagged ? "Unflagged" : "Flagged for review"); }}
                            className={cn("h-8 w-8 rounded-none", isFlagged && "bg-amber-500/20 text-amber-500")}
                        >
                            <Flag className="h-4 w-4" />
                        </Button>

                        {/* More */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-8 w-8 rounded-none">
                                    <MoreVertical className="h-4 w-4" />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-[220px] bg-card border-border rounded-none p-1">
                                <DropdownMenuLabel className="text-xs text-muted-foreground">Session Actions</DropdownMenuLabel>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                    onClick={() => { viewInNewTab(session); toast.success("Opened in new tab"); }}
                                    className="rounded-none gap-3 text-sm py-2.5"
                                >
                                    <ExternalLink className="h-4 w-4 text-blue-500" />
                                    <span className="flex-1">Open in New Tab</span>
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                    onClick={handleToggleFalsePositive}
                                    className="rounded-none gap-3 text-sm py-2.5"
                                >
                                    {isReported ? <CheckSquare className="h-4 w-4 text-emerald-500" /> : <Square className="h-4 w-4 text-muted-foreground" />}
                                    <span className="flex-1">False Positive</span>
                                    {isReported && <Badge className="text-[9px] px-1.5 py-0 bg-emerald-500/20 text-emerald-500 border-emerald-500/30 rounded-none">ON</Badge>}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                    onClick={handleToggleCollection}
                                    className="rounded-none gap-3 text-sm py-2.5"
                                >
                                    {isInCollection ? <CheckSquare className="h-4 w-4 text-emerald-500" /> : <Square className="h-4 w-4 text-muted-foreground" />}
                                    <span className="flex-1">Save to Collection</span>
                                    {isInCollection && <Badge className="text-[9px] px-1.5 py-0 bg-emerald-500/20 text-emerald-500 border-emerald-500/30 rounded-none">ON</Badge>}
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </>
                ) : (
                    <div className="flex items-center gap-0.5 opacity-0">
                        {/* Placeholder while mounting to avoid layout shift */}
                        <div className="h-8 w-8" />
                        <div className="h-8 w-8" />
                        <div className="h-8 w-8" />
                    </div>
                )}
            </div>
        </div>
    );
}
