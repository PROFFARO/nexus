/**
 * Settings Types for Service Configuration Management
 */

// Service types
export type ServiceName = 'ssh' | 'ftp' | 'mysql';
export type ServiceStatus = 'running' | 'stopped' | 'configured' | 'unknown';

// Parameter types
export type ConfigParamType = 'boolean' | 'number' | 'string' | 'select';

// Individual config parameter
export interface ConfigParameter {
    key: string;
    value: string | number | boolean;
    type: ConfigParamType;
    label: string;
    description: string;
    section: string;
    options?: string[];      // For select type
    min?: number;            // For number type
    max?: number;            // For number type
    step?: number;           // For number type
}

// Config section with parameters
export interface ConfigSection {
    name: string;
    label: string;
    description: string;
    icon: string;
    parameters: ConfigParameter[];
}

// Complete service configuration
export interface ServiceConfig {
    service: ServiceName;
    displayName: string;
    status: ServiceStatus;
    configPath: string;
    lastModified?: string;
    sections: ConfigSection[];
}

// API response for all settings
export interface AllSettingsResponse {
    services: ServiceConfig[];
    timestamp: string;
}

// Update request for a service
export interface UpdateSettingsRequest {
    updates: {
        section: string;
        key: string;
        value: string | number | boolean;
    }[];
}

// Update response
export interface UpdateSettingsResponse {
    success: boolean;
    message: string;
    backupPath?: string;
    updatedConfig?: ServiceConfig;
}

// Parameter metadata with descriptions and constraints
export const PARAMETER_METADATA: Record<string, Omit<ConfigParameter, 'key' | 'value' | 'section'>> = {
    // Security Section
    'ip_reputation': {
        type: 'boolean',
        label: 'IP Reputation Checking',
        description: 'Enable IP reputation checking against known threat databases to identify malicious sources',
    },
    'rate_limiting': {
        type: 'boolean',
        label: 'Rate Limiting',
        description: 'Limit connection attempts per IP to prevent brute force and DoS attacks',
    },
    'max_connections_per_ip': {
        type: 'number',
        label: 'Max Connections per IP',
        description: 'Maximum simultaneous connections allowed from a single IP address',
        min: 1,
        max: 100,
    },
    'connection_timeout': {
        type: 'number',
        label: 'Connection Timeout',
        description: 'Time in seconds before an idle connection is terminated',
        min: 30,
        max: 3600,
    },
    'intrusion_detection': {
        type: 'boolean',
        label: 'Intrusion Detection',
        description: 'Enable real-time detection of intrusion attempts and suspicious patterns',
    },
    'automated_blocking': {
        type: 'boolean',
        label: 'Automated Blocking',
        description: 'Automatically block IPs that exhibit malicious behavior (use with caution)',
    },
    'ssl_simulation': {
        type: 'boolean',
        label: 'SSL/TLS Simulation',
        description: 'Simulate SSL/TLS connections for MySQL protocol',
    },

    // Machine Learning Section
    'enabled': {
        type: 'boolean',
        label: 'ML Detection Enabled',
        description: 'Enable machine learning-based threat detection for enhanced security analysis',
    },
    'anomaly_threshold': {
        type: 'number',
        label: 'Anomaly Threshold',
        description: 'Sensitivity threshold (0.0-1.0). Higher values = more sensitive detection',
        min: 0.0,
        max: 1.0,
        step: 0.05,
    },
    'max_inference_ms': {
        type: 'number',
        label: 'Max Inference Time (ms)',
        description: 'Maximum time allowed for ML model inference. Lower values improve response times',
        min: 1,
        max: 1000,
    },
    'fallback_on_error': {
        type: 'boolean',
        label: 'Fallback on Error',
        description: 'Continue processing with default behavior if ML inference fails',
    },
    'use_gpu': {
        type: 'boolean',
        label: 'Use GPU Acceleration',
        description: 'Use GPU for ML inference if available (requires CUDA)',
    },
    'cache_embeddings': {
        type: 'boolean',
        label: 'Cache Embeddings',
        description: 'Cache computed embeddings to improve performance for repeated patterns',
    },
    'batch_size': {
        type: 'number',
        label: 'Batch Size',
        description: 'Number of samples to process in each batch for ML inference',
        min: 1,
        max: 128,
    },
    'model_update_interval': {
        type: 'number',
        label: 'Model Update Interval (s)',
        description: 'How often to check for model updates in seconds',
        min: 60,
        max: 86400,
    },

    // Attack Detection Section
    'sensitivity_level': {
        type: 'select',
        label: 'Detection Sensitivity',
        description: 'Overall sensitivity level for attack detection algorithms',
        options: ['low', 'medium', 'high', 'critical'],
    },
    'threat_scoring': {
        type: 'boolean',
        label: 'Threat Scoring',
        description: 'Calculate and assign threat scores to detected activities',
    },
    'alert_threshold': {
        type: 'number',
        label: 'Alert Threshold',
        description: 'Minimum threat score (0-100) required to trigger an alert',
        min: 0,
        max: 100,
    },
    'geolocation_analysis': {
        type: 'boolean',
        label: 'Geolocation Analysis',
        description: 'Analyze source IP geolocation for threat intelligence',
    },
    'reputation_filtering': {
        type: 'boolean',
        label: 'Reputation Filtering',
        description: 'Filter connections based on IP reputation scores',
    },
    'sql_injection_detection': {
        type: 'boolean',
        label: 'SQL Injection Detection',
        description: 'Detect and flag SQL injection attempts in queries',
    },
    'privilege_escalation_detection': {
        type: 'boolean',
        label: 'Privilege Escalation Detection',
        description: 'Detect attempts to escalate user privileges',
    },
    'data_exfiltration_detection': {
        type: 'boolean',
        label: 'Data Exfiltration Detection',
        description: 'Detect potential data exfiltration attempts',
    },

    // AI Features Section
    'dynamic_responses': {
        type: 'boolean',
        label: 'Dynamic Responses',
        description: 'Generate dynamic responses based on attacker behavior patterns',
    },
    'attack_pattern_recognition': {
        type: 'boolean',
        label: 'Pattern Recognition',
        description: 'Identify and classify attack patterns using AI',
    },
    'vulnerability_detection': {
        type: 'boolean',
        label: 'Vulnerability Detection',
        description: 'Detect attempts to exploit known vulnerabilities',
    },
    'real_time_analysis': {
        type: 'boolean',
        label: 'Real-Time Analysis',
        description: 'Perform real-time behavioral analysis during sessions',
    },
    'ai_attack_summaries': {
        type: 'boolean',
        label: 'AI Attack Summaries',
        description: 'Generate AI-powered summaries of attack sessions',
    },
    'adaptive_banners': {
        type: 'boolean',
        label: 'Adaptive Banners',
        description: 'Dynamically adjust server banners based on attacker profile',
    },
    'deception_techniques': {
        type: 'boolean',
        label: 'Deception Techniques',
        description: 'Use deception techniques to mislead and engage attackers',
    },
    'query_result_manipulation': {
        type: 'boolean',
        label: 'Query Result Manipulation',
        description: 'Manipulate query results to provide fake data to attackers',
    },

    // Forensics Section
    'file_monitoring': {
        type: 'boolean',
        label: 'File Monitoring',
        description: 'Monitor and log all file upload/download operations',
    },
    'query_logging': {
        type: 'boolean',
        label: 'Query Logging',
        description: 'Log all SQL queries for analysis',
    },
    'save_uploads': {
        type: 'boolean',
        label: 'Save Uploads',
        description: 'Save all uploaded files for forensic analysis',
    },
    'save_downloads': {
        type: 'boolean',
        label: 'Save Downloads',
        description: 'Save all downloaded files for forensic analysis',
    },
    'save_queries': {
        type: 'boolean',
        label: 'Save Queries',
        description: 'Store all queries for later analysis',
    },
    'file_hash_analysis': {
        type: 'boolean',
        label: 'File Hash Analysis',
        description: 'Compute and log file hashes for integrity verification',
    },
    'query_hash_analysis': {
        type: 'boolean',
        label: 'Query Hash Analysis',
        description: 'Compute query hashes for deduplication and analysis',
    },
    'malware_detection': {
        type: 'boolean',
        label: 'Malware Detection',
        description: 'Scan uploaded files for malware signatures',
    },
    'forensic_reports': {
        type: 'boolean',
        label: 'Forensic Reports',
        description: 'Generate detailed forensic reports for each session',
    },
    'chain_of_custody': {
        type: 'boolean',
        label: 'Chain of Custody',
        description: 'Maintain chain of custody logging for evidence integrity',
    },
    'attack_correlation': {
        type: 'boolean',
        label: 'Attack Correlation',
        description: 'Correlate attacks across sessions to identify campaigns',
    },

    // Logging Section
    'log_level': {
        type: 'select',
        label: 'Log Level',
        description: 'Minimum severity level for log messages',
        options: ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    },
    'structured_logging': {
        type: 'boolean',
        label: 'Structured Logging',
        description: 'Use structured JSON format for log entries',
    },
    'real_time_streaming': {
        type: 'boolean',
        label: 'Real-Time Streaming',
        description: 'Enable real-time log streaming to dashboard',
    },
    'log_rotation_size': {
        type: 'number',
        label: 'Log Rotation Size (MB)',
        description: 'Maximum log file size before rotation',
        min: 10,
        max: 1000,
    },
    'log_backup_count': {
        type: 'number',
        label: 'Log Backup Count',
        description: 'Number of rotated log files to keep',
        min: 1,
        max: 100,
    },
    'log_compression': {
        type: 'boolean',
        label: 'Log Compression',
        description: 'Compress rotated log files to save disk space',
    },
};

// Section metadata
export const SECTION_METADATA: Record<string, { label: string; description: string; icon: string }> = {
    'security': {
        label: 'Security',
        description: 'Network security and access control settings',
        icon: 'shield',
    },
    'ml': {
        label: 'Machine Learning',
        description: 'ML-based threat detection configuration',
        icon: 'brain',
    },
    'attack_detection': {
        label: 'Attack Detection',
        description: 'Attack pattern detection and alerting',
        icon: 'alert-triangle',
    },
    'ai_features': {
        label: 'AI Features',
        description: 'Advanced AI-powered honeypot features',
        icon: 'sparkles',
    },
    'forensics': {
        label: 'Forensics',
        description: 'Evidence collection and analysis',
        icon: 'search',
    },
    'logging': {
        label: 'Logging',
        description: 'Log management and output configuration',
        icon: 'file-text',
    },
};

// Service display names and icons
export const SERVICE_METADATA: Record<ServiceName, { displayName: string; icon: string; color: string }> = {
    'ssh': {
        displayName: 'SSH Honeypot',
        icon: 'terminal',
        color: '#22c55e',
    },
    'ftp': {
        displayName: 'FTP Honeypot',
        icon: 'folder',
        color: '#3b82f6',
    },
    'mysql': {
        displayName: 'MySQL Honeypot',
        icon: 'database',
        color: '#f59e0b',
    },
};
