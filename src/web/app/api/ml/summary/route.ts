/**
 * Real LLM-Powered Summary Generation API Route
 * Calls external LLM providers (OpenAI, Gemini, etc.) to generate detailed attack analysis
 */

import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';
import { GoogleGenerativeAI } from '@google/generative-ai';

// Types
interface SummaryRequest {
    command: string;
    timestamp: string;
    service: string;
    session_id?: string;
    attack_types?: string[];
    severity?: string;
    ml_anomaly_score?: number;
    ml_risk_level?: string;
    ml_confidence?: number;
    ml_reason?: string;
    indicators?: string[];
    pattern_matches?: Array<{ type: string; pattern: string; severity: string }>;
    vulnerabilities?: Array<{ vulnerability_id: string; vuln_name: string; description?: string; severity: string; cvss_score?: number }>;
    src_ip?: string;
    username?: string;
}

interface LLMConfig {
    provider: string;
    model: string;
    temperature: number;
}

// Get LLM configuration from environment
function getLLMConfig(): LLMConfig {
    const provider = process.env.LLM_PROVIDER || 'gemini';
    const model = provider === 'openai'
        ? (process.env.OPENAI_MODEL || 'gpt-4o-mini')
        : (process.env.GEMINI_MODEL || 'gemini-2.5-flash');
    const temperature = parseFloat(process.env.LLM_TEMPERATURE || '0.3');

    return { provider, model, temperature };
}

// Build the analysis prompt
function buildPrompt(data: SummaryRequest): string {
    const attackTypesStr = data.attack_types?.join(', ') || 'None detected';
    const indicatorsStr = data.indicators?.slice(0, 10).join(', ') || 'None';
    const patternsStr = data.pattern_matches?.map(p => `${p.type}: ${p.pattern}`).join('; ') || 'None';
    const vulnsStr = data.vulnerabilities?.map(v => `${v.vuln_name} (${v.vulnerability_id || 'N/A'})`).join(', ') || 'None';

    return `You are a senior cybersecurity analyst specializing in honeypot analysis and intrusion detection. Analyze the following command execution captured by a ${data.service?.toUpperCase() || 'UNKNOWN'} honeypot and provide a comprehensive security assessment.

## CAPTURED DATA
- **Command**: \`${data.command}\`
- **Timestamp**: ${data.timestamp}
- **Service Protocol**: ${data.service?.toUpperCase() || 'N/A'}
- **Source IP**: ${data.src_ip || 'Unknown'}
- **Username**: ${data.username || 'N/A'}
- **Session ID**: ${data.session_id || 'N/A'}

## ML ANALYSIS RESULTS
- **Anomaly Score**: ${((data.ml_anomaly_score || 0) * 100).toFixed(1)}%
- **Risk Level**: ${data.ml_risk_level?.toUpperCase() || 'UNKNOWN'}
- **Confidence**: ${((data.ml_confidence || 0) * 100).toFixed(1)}%
- **ML Classification Reason**: ${data.ml_reason || 'N/A'}

## DETECTED THREATS
- **Attack Types**: ${attackTypesStr}
- **Severity**: ${data.severity?.toUpperCase() || 'UNKNOWN'}
- **Indicators**: ${indicatorsStr}
- **Pattern Matches**: ${patternsStr}
- **Vulnerabilities**: ${vulnsStr}

## REQUIRED OUTPUT FORMAT
Provide your analysis in the following structured JSON format (ONLY return valid JSON, no markdown):

{
    "executive_summary": "A 2-3 sentence high-level summary of what this command represents and its potential impact.",
    "threat_assessment": {
        "classification": "BENIGN | SUSPICIOUS | MALICIOUS | CRITICAL",
        "confidence": 0.0-1.0,
        "reasoning": "Detailed explanation of why you classified this command this way."
    },
    "attack_analysis": {
        "primary_attack_type": "The main attack category if any",
        "attack_chain_phase": "Reconnaissance | Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Exfiltration | Impact",
        "mitre_techniques": ["T1xxx - Technique Name"],
        "attacker_intent": "What the attacker is likely trying to achieve"
    },
    "risk_indicators": [
        "Specific risk indicator 1",
        "Specific risk indicator 2"
    ],
    "recommendations": [
        "Actionable recommendation 1",
        "Actionable recommendation 2"
    ],
    "forensic_notes": "Technical details useful for incident response and forensic analysis."
}`;
}

// Call OpenAI API
async function callOpenAI(prompt: string, config: LLMConfig): Promise<string> {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) throw new Error('OPENAI_API_KEY not configured');

    const openai = new OpenAI({ apiKey });

    const response = await openai.chat.completions.create({
        model: config.model,
        messages: [
            {
                role: 'system',
                content: 'You are a cybersecurity expert. Respond ONLY with valid JSON, no markdown formatting.'
            },
            { role: 'user', content: prompt }
        ],
        temperature: config.temperature,
        max_tokens: 2000,
        response_format: { type: 'json_object' }
    });

    return response.choices[0]?.message?.content || '';
}

// Call Gemini API
async function callGemini(prompt: string, config: LLMConfig): Promise<string> {
    const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error('GOOGLE_API_KEY or GEMINI_API_KEY not configured');

    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
        model: config.model,
        generationConfig: {
            temperature: config.temperature,
            maxOutputTokens: 2000,
        }
    });

    const result = await model.generateContent(prompt);
    const response = result.response;
    return response.text();
}

// Parse LLM response
function parseResponse(response: string): any {
    // Try to extract JSON from the response
    let cleaned = response.trim();

    // Remove markdown code blocks if present
    if (cleaned.startsWith('```json')) {
        cleaned = cleaned.slice(7);
    } else if (cleaned.startsWith('```')) {
        cleaned = cleaned.slice(3);
    }
    if (cleaned.endsWith('```')) {
        cleaned = cleaned.slice(0, -3);
    }
    cleaned = cleaned.trim();

    try {
        return JSON.parse(cleaned);
    } catch (e) {
        console.error('Failed to parse LLM response:', e);
        return null;
    }
}

// Generate fallback summary when LLM fails
function generateFallback(data: SummaryRequest): any {
    const anomalyScore = data.ml_anomaly_score || 0;
    const riskLevel = data.ml_risk_level || 'unknown';
    const attackTypes = data.attack_types || [];

    let classification = 'BENIGN';
    if (anomalyScore > 0.8 || riskLevel === 'critical') classification = 'CRITICAL';
    else if (anomalyScore > 0.6 || riskLevel === 'high') classification = 'MALICIOUS';
    else if (anomalyScore > 0.4 || riskLevel === 'medium') classification = 'SUSPICIOUS';

    return {
        executive_summary: `${data.service?.toUpperCase()} honeypot captured command "${data.command.slice(0, 50)}..." with ${(anomalyScore * 100).toFixed(1)}% anomaly score. ${attackTypes.length > 0 ? `Detected attack types: ${attackTypes.join(', ')}.` : 'No specific attack patterns matched.'}`,
        threat_assessment: {
            classification,
            confidence: data.ml_confidence || 0.75,
            reasoning: data.ml_reason || `Based on ML analysis with ${riskLevel} risk level and ${(anomalyScore * 100).toFixed(1)}% anomaly score.`
        },
        attack_analysis: {
            primary_attack_type: attackTypes[0] || 'Unknown',
            attack_chain_phase: attackTypes.includes('reconnaissance') ? 'Reconnaissance' : 'Execution',
            mitre_techniques: [],
            attacker_intent: `Potential ${attackTypes[0] || 'malicious'} activity detected on ${data.service?.toUpperCase()} service.`
        },
        risk_indicators: data.indicators || [],
        recommendations: [
            'Review session logs for additional context',
            'Check for related activity from the same source IP',
            riskLevel === 'high' || riskLevel === 'critical' ? 'Consider blocking source IP' : 'Continue monitoring'
        ],
        forensic_notes: `Command captured at ${data.timestamp}. Session: ${data.session_id || 'N/A'}. ${data.pattern_matches?.length || 0} pattern matches detected.`,
        _fallback: true
    };
}

export async function POST(request: NextRequest) {
    try {
        const data: SummaryRequest = await request.json();

        if (!data.command) {
            return NextResponse.json(
                { error: 'Command is required' },
                { status: 400 }
            );
        }

        const config = getLLMConfig();
        const prompt = buildPrompt(data);

        let response: string | null = null;
        let usedProvider = config.provider;
        let usedModel = config.model;

        // Try primary provider
        try {
            if (config.provider === 'openai') {
                response = await callOpenAI(prompt, config);
            } else if (config.provider === 'gemini') {
                response = await callGemini(prompt, config);
            }
        } catch (primaryError) {
            console.error(`Primary LLM (${config.provider}) failed:`, primaryError);

            // Try fallback to other provider
            try {
                if (config.provider === 'openai' && (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY)) {
                    usedProvider = 'gemini';
                    usedModel = 'gemini-2.5-flash';
                    response = await callGemini(prompt, { ...config, model: usedModel });
                } else if (config.provider === 'gemini' && process.env.OPENAI_API_KEY) {
                    usedProvider = 'openai';
                    usedModel = 'gpt-4o-mini';
                    response = await callOpenAI(prompt, { ...config, model: usedModel });
                }
            } catch (fallbackError) {
                console.error('Fallback LLM also failed:', fallbackError);
            }
        }

        // Parse the response or use fallback
        let parsedSummary;
        if (response) {
            parsedSummary = parseResponse(response);
        }

        if (!parsedSummary) {
            parsedSummary = generateFallback(data);
            usedProvider = 'rule-based';
            usedModel = 'fallback';
        }

        return NextResponse.json({
            success: true,
            provider: usedProvider,
            model: usedModel,
            generated_at: new Date().toISOString(),
            command: data.command,
            session_id: data.session_id,
            service: data.service,
            analysis: parsedSummary
        }, {
            headers: {
                'Cache-Control': 'no-store, no-cache, must-revalidate',
            }
        });

    } catch (error) {
        console.error('Summary generation error:', error);
        return NextResponse.json(
            { error: 'Failed to generate summary', details: String(error) },
            { status: 500 }
        );
    }
}
