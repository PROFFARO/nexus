# NEXUS FTP Honeypot

AI-Enhanced FTP honeypot with comprehensive attack analysis and forensic capabilities.

## Overview

The NEXUS FTP honeypot simulates a realistic FTP server environment at NexusGames Studio, a game development company. It uses AI to provide dynamic responses and comprehensive forensic analysis of FTP-based attacks.

## Features

### AI-Enhanced Capabilities
- **Dynamic Response Generation**: Context-aware FTP responses based on attacker behavior
- **Attack Pattern Recognition**: Real-time identification of FTP attack techniques
- **Vulnerability Detection**: Automated FTP exploitation attempt analysis
- **Behavioral Analysis**: Sophisticated attacker profiling and intent analysis

### FTP Protocol Support
- **Standard FTP Commands**: USER, PASS, SYST, PWD, CWD, LIST, NLST, RETR, STOR, PASV, PORT, TYPE, QUIT
- **Authentication Simulation**: Realistic login process with multiple account types
- **File Transfer Simulation**: Upload/download operations with forensic logging
- **Directory Navigation**: Realistic directory structures and permissions
- **Data Connection Modes**: Both active and passive mode support

### Security & Forensics
- **Forensic Chain of Custody**: Complete evidence tracking and integrity verification
- **Session Recording**: Full FTP interaction logging with replay capability
- **File Monitoring**: Upload/download tracking with hash analysis
- **Attack Classification**: Real-time threat assessment and categorization

### Attack Detection
- **Directory Traversal**: Detection of path traversal attempts
- **FTP Bounce Attacks**: Identification of PORT command abuse
- **Brute Force Detection**: Authentication attack pattern recognition
- **Malicious Uploads**: Analysis of suspicious file uploads
- **Data Exfiltration**: Monitoring of sensitive file downloads

## Quick Start

### Installation

1. **Install Dependencies**:
   ```bash
   pip install langchain-openai langchain-google-genai python-dotenv matplotlib seaborn pandas
   ```

2. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Run FTP Honeypot**:
   ```bash
   python ftp_server.py
   ```

### Using the CLI

```bash
# Start FTP honeypot with default settings
python ../../cli/nexus_cli.py ftp

# Start with custom port and configuration
python ../../cli/nexus_cli.py ftp --port 2121 --config custom.ini

# Generate security report
python ../../cli/nexus_cli.py report ftp --output reports/

# View session logs
python ../../cli/nexus_cli.py logs ftp --conversation --decode
```

## Configuration

### Main Configuration (`config.ini`)
- **FTP Settings**: Port, banner, connection limits
- **LLM Configuration**: AI provider and model settings
- **Security Options**: Attack detection sensitivity
- **Logging**: Forensic and session logging options

### Environment Variables (`.env`)
- **API Keys**: OpenAI, Google Gemini, Azure, AWS credentials
- **Provider Settings**: Custom endpoints and configurations

### Attack Patterns (`attack_patterns.json`)
- **Reconnaissance**: Information gathering patterns
- **Directory Traversal**: Path traversal attack signatures
- **FTP Bounce**: PORT command abuse patterns
- **Brute Force**: Authentication attack patterns
- **Malicious Uploads**: Suspicious file upload patterns

### Vulnerability Signatures (`vulnerability_signatures.json`)
- **CVE Database**: Known FTP vulnerabilities
- **Exploit Patterns**: Attack technique signatures
- **Severity Scoring**: CVSS-based risk assessment

## Supported LLM Providers

- **OpenAI**: GPT-4, GPT-3.5-turbo
- **Google Gemini**: gemini-pro, gemini-2.5-flash-lite
- **Azure OpenAI**: Enterprise OpenAI models
- **AWS Bedrock**: Claude, Llama models
- **Ollama**: Local model deployment

## Data Collection & Analysis

### Session Data
- FTP command history and analysis
- Attack pattern detection results
- File transfer activities (uploads/downloads)
- Authentication attempts and patterns
- Behavioral analysis metrics

### Forensic Evidence
- Complete session recordings
- File transfer artifacts with hashes
- Network connection logs
- Attack timeline reconstruction
- Chain of custody documentation

### Reporting
- **Executive Summaries**: High-level threat overview
- **Technical Analysis**: Detailed attack breakdowns
- **IOCs**: Indicators of Compromise extraction
- **Visualizations**: Attack pattern charts and graphs
- **Recommendations**: Security improvement suggestions

## Attack Scenarios Detected

### Directory Traversal
- `../../../etc/passwd` attempts
- Windows path traversal (`..\..\..`)
- URL-encoded traversal sequences

### FTP Bounce Attacks
- PORT commands with third-party IPs
- Internal network scanning via FTP
- Protocol abuse for reconnaissance

### Brute Force Authentication
- Systematic password guessing
- Common credential combinations
- Account enumeration attempts

### Malicious File Operations
- Executable file uploads (.exe, .bat, .sh)
- Web shell deployment attempts
- Backdoor installation patterns

### Data Exfiltration
- Sensitive file downloads
- Database backup theft
- Configuration file access

## Security Considerations

⚠️ **Important Security Notes**:
- All sensitive files are excluded from version control
- API keys must be configured in `.env` files
- Session data contains sensitive attacker information
- Forensic logs may include personally identifiable information
- Deploy in isolated network environments for production use

## File Structure

```
FTP/
├── ftp_server.py              # Main FTP honeypot server
├── config.ini                 # Configuration file
├── .env                       # Environment variables
├── prompt.txt                 # AI system prompt
├── attack_patterns.json       # Attack detection patterns
├── vulnerability_signatures.json # Vulnerability database
├── report_generator.py        # Security report generator
├── generate_report.py         # Simple report script
├── test_ftp.py               # Basic functionality test
├── sessions/                  # Session data directory
│   └── ftp_session_*/        # Individual session folders
│       ├── session_summary.json
│       ├── forensic_chain.json
│       ├── downloads/
│       └── uploads/
└── reports/                   # Generated reports
    ├── ftp_honeypot_report_*.json
    ├── ftp_honeypot_report_*.html
    └── visualizations/
```

## Integration with NEXUS Platform

The FTP honeypot integrates seamlessly with the NEXUS platform:

- **Centralized CLI**: Managed via `nexus_cli.py`
- **Unified Logging**: Logs to centralized `logs/ftp_log.log`
- **Report Generation**: Consistent reporting format
- **Session Analysis**: Compatible with log viewer tools

## Development & Customization

### Adding New Attack Patterns
1. Edit `attack_patterns.json`
2. Add pattern regex and metadata
3. Restart honeypot to load new patterns

### Custom AI Responses
1. Modify `prompt.txt` for system behavior
2. Adjust LLM parameters in `config.ini`
3. Test with different AI providers

### Extending Forensics
1. Add new evidence types in `ForensicChainLogger`
2. Implement custom analysis in `report_generator.py`
3. Create visualization templates

## Troubleshooting

### Common Issues
- **Port binding errors**: Check if port 2121 is available
- **AI API failures**: Verify API keys in `.env` file
- **Session directory errors**: Ensure write permissions
- **Log file issues**: Check log directory permissions

### Debug Mode
```bash
# Enable debug logging
python ftp_server.py --log-level DEBUG

# Test basic connectivity
python test_ftp.py

# Validate configuration
python -c "from configparser import ConfigParser; c=ConfigParser(); c.read('config.ini'); print('Config OK')"
```

## Contributing

1. Follow existing code structure and patterns
2. Ensure all sensitive data is properly excluded from commits
3. Add comprehensive logging for new features
4. Include forensic chain integration for evidence collection
5. Test with multiple LLM providers when applicable
6. Update attack patterns and vulnerability signatures

## License

This project is for educational and research purposes. Ensure compliance with local laws and regulations when deploying honeypots.

## Support

For issues and questions:
- Check session logs for troubleshooting
- Review configuration files for proper setup
- Ensure API keys are correctly configured
- Verify network connectivity and port availability
- Test with the included `test_ftp.py` script