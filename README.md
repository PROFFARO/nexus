# NEXUS Development - AI-Enhanced Honeypot Platform

Advanced cybersecurity honeypot system with AI-powered adaptive responses and comprehensive threat intelligence.

## Overview

NEXUS is an intelligent honeypot platform that simulates realistic corporate environments to attract, analyze, and learn from cyber attackers. The system uses AI to provide dynamic responses and comprehensive forensic analysis.

## Service Emulators

### SSH Honeypot ✅ **ACTIVE**
- **Status**: Fully operational with AI integration
- **Features**:
  - AI-powered adaptive responses using multiple LLM providers
  - Real-time attack pattern recognition
  - Vulnerability exploitation detection
  - Forensic chain of custody logging
  - Session recording and analysis
  - File upload/download monitoring
  - Behavioral analysis and threat scoring
- **Location**: `src/service_emulators/SSH/`
- **Port**: 8022 (configurable)
- **AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama

### FTP Honeypot ✅ **ACTIVE**
- **Status**: Fully operational with AI integration and telnet support
- **Features**:
  - AI-powered adaptive FTP responses using multiple LLM providers
  - Real-time FTP attack pattern recognition and vulnerability detection
  - Directory traversal, bounce attack, and brute force detection
  - Forensic chain of custody logging with complete session recording
  - File transfer monitoring with hash analysis and malware detection
  - Telnet client compatibility with command aliases (ls/dir)
  - Proper FTP data connection handling for standard clients
  - Dynamic directory listing generation based on attack context
  - Multi-line AI response support for complex interactions
  - Standard FTP protocol compliance with consistent status codes
- **Location**: `src/service_emulators/FTP/`
- **Port**: 2121 (configurable)
- **AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama
- **Client Support**: Standard FTP clients, telnet, command-line tools

### HTTP/Web Honeypot 🚧 **PLANNED**
- **Status**: Directory structure created, implementation pending
- **Location**: `src/service_emulators/HTTP/`

### MySQL Database Honeypot 🚧 **PLANNED**
- **Status**: Directory structure created, implementation pending
- **Location**: `src/service_emulators/MySQL/`

### SMB File Share Honeypot 🚧 **PLANNED**
- **Status**: Directory structure created, implementation pending
- **Location**: `src/service_emulators/SMB/`

## Key Features

### AI-Enhanced Capabilities
- **Dynamic Response Generation**: Context-aware responses based on attacker behavior
- **Attack Pattern Recognition**: Real-time identification of attack techniques
- **Vulnerability Detection**: Automated exploitation attempt analysis
- **Behavioral Analysis**: Sophisticated attacker profiling and intent analysis

### Security & Forensics
- **Forensic Chain of Custody**: Complete evidence tracking and integrity verification
- **Session Recording**: Full interaction logging with replay capability
- **File Monitoring**: Upload/download tracking with hash analysis
- **Threat Intelligence**: Integrated attack signatures and vulnerability databases

### Corporate Environment Simulation
- **NexusGames Studio**: Realistic game development company environment
- **Authentic File Systems**: Dynamic generation of believable corporate structures
- **Network Topology**: Simulated enterprise infrastructure
- **User Accounts**: Comprehensive honeypot account management

## Quick Start

### SSH Honeypot Setup

1. **Install Dependencies**:
   ```bash
   pip install asyncssh langchain-openai langchain-google-genai python-dotenv matplotlib seaborn pandas
   ```

2. **Configure Environment**:
   ```bash
   cp src/service_emulators/SSH/.env.example src/service_emulators/SSH/.env
   # Edit .env with your API keys
   ```

3. **Run SSH Honeypot**:
   ```bash
   cd src/service_emulators/SSH
   python ssh_server.py
   ```

### FTP Honeypot Setup

1. **Install Dependencies**:
   ```bash
   pip install asyncssh langchain-openai langchain-google-genai python-dotenv matplotlib seaborn pandas
   ```

2. **Configure Environment**:
   ```bash
   cp src/service_emulators/FTP/.env.example src/service_emulators/FTP/.env
   # Edit .env with your API keys
   ```

3. **Run FTP Honeypot**:
   ```bash
   cd src/service_emulators/FTP
   python ftp_server.py
   ```

4. **Test with Telnet** (for testing):
   ```bash
   telnet localhost 2121
   # Commands: USER admin, PASS admin, ls, help, quit
   ```

### Using the Centralized CLI

```bash
# Start SSH honeypot
python src/cli/nexus_cli.py ssh --port 8022

# Start FTP honeypot
python src/cli/nexus_cli.py ftp --port 2121

# Test FTP honeypot with telnet
telnet localhost 2121

# Generate security reports
python src/cli/nexus_cli.py report ssh --output reports/
python src/cli/nexus_cli.py report ftp --output reports/

# View session logs
python src/cli/nexus_cli.py logs ssh --conversation --decode
python src/cli/nexus_cli.py logs ftp --conversation --decode

# List all services
python src/cli/nexus_cli.py list
```

## Configuration

### SSH Honeypot Configuration
- **Config File**: `src/service_emulators/SSH/config.ini`
- **Environment**: `src/service_emulators/SSH/.env`
- **Attack Patterns**: `src/service_emulators/SSH/attack_patterns.json`
- **Vulnerability Signatures**: `src/service_emulators/SSH/vulnerability_signatures.json`

### FTP Honeypot Configuration
- **Config File**: `src/service_emulators/FTP/config.ini`
- **Environment**: `src/service_emulators/FTP/.env`
- **Attack Patterns**: `src/service_emulators/FTP/attack_patterns.json`
- **Vulnerability Signatures**: `src/service_emulators/FTP/vulnerability_signatures.json`
- **User Accounts**: Configured in config.ini with 40+ honeypot accounts
- **Client Support**: Standard FTP clients, telnet, FileZilla, WinSCP

### Supported LLM Providers
- OpenAI (GPT-4, GPT-3.5)
- Google Gemini
- Azure OpenAI
- AWS Bedrock
- Ollama (Local models)

## Data Collection & Analysis

### Session Data
- Complete command history with AI analysis
- Real-time attack pattern detection results
- Vulnerability exploitation attempt logging
- File transfer activities with hash analysis
- Behavioral analysis and threat scoring metrics
- Multi-client session support (FTP clients, telnet)

### Forensic Evidence
- Complete session recordings with replay capability
- File upload/download artifacts with malware detection
- Network connection logs and data transfer analysis
- Attack timeline reconstruction with AI-powered summaries
- Chain of custody documentation with integrity verification
- Session metadata and client fingerprinting

## Security Considerations

⚠️ **Important Security Notes**:
- All sensitive files are excluded from version control
- SSH keys and certificates are auto-generated
- API keys must be configured in `.env` files
- Session data contains sensitive attacker information
- Forensic logs may include personally identifiable information
- FTP honeypot accepts file uploads - monitor disk usage
- Telnet support is for testing only - use proper FTP clients in production
- AI responses may reveal honeypot nature to sophisticated attackers

## Development Roadmap

### Phase 1: Core SSH Implementation ✅
- [x] Basic SSH honeypot functionality
- [x] AI integration with multiple providers
- [x] Attack pattern recognition
- [x] Forensic logging system
- [x] Session management and analysis

### Phase 2: FTP Implementation ✅
- [x] Complete FTP honeypot implementation with AI integration
- [x] AI-enhanced FTP protocol simulation with dynamic responses
- [x] Directory traversal and FTP bounce attack detection
- [x] File transfer forensic analysis with hash verification
- [x] Brute force authentication monitoring and logging
- [x] Telnet client compatibility and command alias support
- [x] Proper FTP data connection handling for standard clients
- [x] Multi-line AI response support and consistent status codes
- [x] Session recording with complete forensic chain of custody

### Phase 3: Additional Services 🚧
- [ ] HTTP/Web application honeypot
- [ ] MySQL database honeypot
- [ ] SMB file share honeypot

### Phase 3: Advanced Features 📋
- [ ] Real-time dashboard and visualization
- [ ] Machine learning-based threat prediction
- [ ] Automated response orchestration
- [ ] Integration with SIEM systems
- [ ] Multi-honeypot correlation analysis

## Contributing

1. Follow existing code structure and patterns
2. Ensure all sensitive data is properly excluded from commits
3. Add comprehensive logging for new features
4. Include forensic chain integration for evidence collection
5. Test with multiple LLM providers when applicable
6. Test with both standard FTP clients and telnet for compatibility
7. Ensure proper FTP protocol compliance and status code usage
8. Verify AI responses are consistent and realistic

## License

This project is for educational and research purposes. Ensure compliance with local laws and regulations when deploying honeypots.

## Support

For issues and questions:
- Check existing session logs for troubleshooting
- Review configuration files for proper setup
- Ensure API keys are correctly configured
- Verify network connectivity and port availability
- Test with telnet first: `telnet localhost 2121`
- Check FTP client compatibility and data connection settings
- Monitor AI response consistency and system prompt configuration