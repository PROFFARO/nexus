# 🕸️ NEXUS Development - AI-Enhanced Honeypot Platform

<div align="center">

![NEXUS Logo](https://img.shields.io/badge/NEXUS-AI%20Honeypot-blue?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python&logoColor=white)
![AI Powered](https://img.shields.io/badge/AI-Powered-orange?style=for-the-badge&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)

**A cybersecurity honeypot system with AI-powered adaptive responses and comprehensive threat intelligence**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🛡️ Security](#-security) • [🤝 Contributing](#-contributing)

</div>

---

## 🌟 Overview

nexus is an intelligent honeypot platform that simulates realistic corporate environments to attract, analyze, and learn from cyber attackers. The system uses AI technology to provide dynamic responses and comprehensive forensic analysis, making it one of the most adaptive honeypot solutions available.

### 🎯 Key Features

- **🤖 AI-Powered Responses**: Dynamic, context-aware responses using multiple LLM providers
- **🔍 Real-time Analysis**: Advanced attack pattern recognition and behavioral analysis
- **📊 Comprehensive Reporting**: Detailed security reports with visualizations
- **🔐 Forensic Chain**: Complete evidence tracking and integrity verification
- **🌐 Multi-Protocol**: SSH, FTP, HTTP/Web services with more planned
- **⚡ Easy Deployment**: Simple CLI interface and Docker support

---

## 🚀 Service Emulators

### ✅ SSH Honeypot - **FULLY OPERATIONAL**
<details>
<summary><strong>Click to expand SSH details</strong></summary>

**Status**: Production-ready with full AI integration

**Features**:
- 🤖 AI-powered adaptive responses using multiple LLM providers
- 🔍 Real-time attack pattern recognition and classification
- 🛡️ Vulnerability exploitation detection and analysis
- 📝 Forensic chain of custody logging with complete audit trail
- 🎥 Session recording and replay capability
- 📁 File upload/download monitoring with hash analysis
- 🧠 Behavioral analysis and sophisticated threat scoring
- 🎭 Corporate environment simulation (NexusGames Studio)

**Location**: `src/service_emulators/SSH/`  
**Default Port**: 8022 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama

</details>

### ✅ FTP Honeypot - **FULLY OPERATIONAL**
<details>
<summary><strong>Click to expand FTP details</strong></summary>

**Status**: Production-ready with full AI integration and telnet support

**Features**:
- 🤖 AI-powered adaptive FTP responses using multiple LLM providers
- 🔍 Real-time FTP attack pattern recognition and vulnerability detection
- 🛡️ Directory traversal, bounce attack, and brute force detection
- 📝 Forensic chain of custody logging with complete session recording
- 📁 File transfer monitoring with hash analysis and malware detection
- 💻 Telnet client compatibility with command aliases (ls/dir)
- 🌐 Proper FTP data connection handling for standard clients
- 📂 Dynamic directory listing generation based on attack context
- 💬 Multi-line AI response support for complex interactions
- 📋 Standard FTP protocol compliance with consistent status codes

**Location**: `src/service_emulators/FTP/`  
**Default Port**: 2121 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**Client Support**: Standard FTP clients, telnet, FileZilla, WinSCP, command-line tools

</details>

### ✅ HTTP/Web Honeypot - **FULLY OPERATIONAL**
<details>
<summary><strong>Click to expand HTTP details</strong></summary>

**Status**: Production-ready with full AI integration and dynamic content generation

**Features**:
- 🤖 AI-powered dynamic web content generation (no static templates)
- 🌐 Professional corporate website simulation (NexusGames Studio)
- 🔍 Real-time web attack detection (SQL injection, XSS, path traversal)
- 📝 Comprehensive HTTP request/response logging and analysis
- 📁 File upload monitoring with malware detection capabilities
- 🛡️ Advanced vulnerability exploitation detection and logging
- 🎭 Realistic game development company environment simulation
- 💻 Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)
- 🔐 SSL/HTTPS support with proper certificate handling
- 📊 Session management and user authentication simulation

**Location**: `src/service_emulators/HTTP/`  
**Default Port**: 8080 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**Protocol Support**: HTTP/1.1, HTTPS, WebSocket (planned)

</details>

### 🚧 MySQL Database Honeypot - **PLANNED**
**Status**: Directory structure created, implementation pending  
**Location**: `src/service_emulators/MySQL/`

### 🚧 SMB File Share Honeypot - **PLANNED**
**Status**: Directory structure created, implementation pending  
**Location**: `src/service_emulators/SMB/`

---

## 🛠️ Installation & Setup

### Prerequisites

- **Python 3.8+** (Python 3.9+ recommended)
- **Git** for cloning the repository
- **API Keys** for at least one LLM provider (OpenAI, Google Gemini, etc.)

### 1. Clone Repository

```bash
git clone https://github.com/PROFFARO/nexus-development.git
cd nexus-development
```

### 2. Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Or install with virtual environment (recommended)
python -m venv nexus-env
source nexus-env/bin/activate  # On Windows: nexus-env\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
# Copy environment template for each service
cp src/service_emulators/SSH/.env.example src/service_emulators/SSH/.env
cp src/service_emulators/FTP/.env.example src/service_emulators/FTP/.env
cp src/service_emulators/HTTP/.env.example src/service_emulators/HTTP/.env

# Edit .env files with your API keys
# Example for OpenAI:
# OPENAI_API_KEY=your_openai_api_key_here
```

---

## 🚀 Quick Start

### Using the Centralized CLI (Recommended)

The NEXUS CLI provides a unified interface for all honeypot services:

```bash
# List all available services
python src/cli/nexus_cli.py list

# Start SSH honeypot
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider openai

# Start FTP honeypot
python src/cli/nexus_cli.py ftp --port 2121 --llm-provider gemini

# Start HTTP honeypot
python src/cli/nexus_cli.py http --port 8080 --llm-provider ollama

# Generate security reports
python src/cli/nexus_cli.py report ssh --output reports/ --format both
python src/cli/nexus_cli.py report ftp --output reports/ --format html
python src/cli/nexus_cli.py report http --output reports/ --format json

# View session logs with conversation format
python src/cli/nexus_cli.py logs ssh --conversation --decode
python src/cli/nexus_cli.py logs ftp --conversation --save ftp_session.txt
python src/cli/nexus_cli.py logs http --filter attacks --format json
```

### Direct Service Execution

You can also run services directly:

<details>
<summary><strong>SSH Honeypot</strong></summary>

```bash
cd src/service_emulators/SSH
python ssh_server.py --port 8022 --llm-provider openai --model-name gpt-4o-mini
```

</details>

<details>
<summary><strong>FTP Honeypot</strong></summary>

```bash
cd src/service_emulators/FTP
python ftp_server.py --port 2121 --llm-provider gemini --model-name gemini-2.5-flash-lite

# Test with telnet (for quick testing)
telnet localhost 2121
# Commands: USER admin, PASS admin, ls, help, quit
```

</details>

<details>
<summary><strong>HTTP Honeypot</strong></summary>

```bash
cd src/service_emulators/HTTP
python http_server.py --port 8080 --llm-provider ollama --model-name llama3.2

# Test with curl or browser
curl http://localhost:8080/
curl -X POST http://localhost:8080/admin/login -d "username=admin&password=test"
```

</details>

---

## ⚙️ Configuration

### LLM Provider Configuration

NEXUS supports multiple AI providers. Configure in `.env` files for each specific services:

<details>
<summary><strong>OpenAI Configuration</strong></summary>

```bash
# .env file
OPENAI_API_KEY=your_openai_api_key_here

# config.ini
[llm]
llm_provider = openai
model_name = gpt-4o-mini
temperature = 0.2
```

</details>

<details>
<summary><strong>Google Gemini Configuration</strong></summary>

```bash
# .env file
GOOGLE_API_KEY=your_google_api_key_here

# config.ini
[llm]
llm_provider = gemini
model_name = gemini-2.5-flash-lite
temperature = 0.2
```

</details>

<details>
<summary><strong>Ollama (Local) Configuration</strong></summary>

```bash
# config.ini
[llm]
llm_provider = ollama
model_name = llama3.2
base_url = http://localhost:11434
temperature = 0.2
```

</details>

<details>
<summary><strong>Azure OpenAI Configuration</strong></summary>

```bash
# .env file
AZURE_OPENAI_API_KEY=your_azure_api_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=your-deployment-name
AZURE_OPENAI_API_VERSION=2024-02-01

# config.ini
[llm]
llm_provider = azure
model_name = gpt-4o
azure_deployment = your-deployment-name
azure_endpoint = https://your-resource.openai.azure.com/
azure_api_version = 2024-02-01
```

</details>

<details>
<summary><strong>AWS Bedrock Configuration</strong></summary>

```bash
# .env file
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=us-east-1

# config.ini
[llm]
llm_provider = AWS
model_name = anthropic.claude-3-5-sonnet-20240620-v1:0
aws_region = us-east-1
aws_credentials_profile = default
```

</details>

### Service-Specific Configuration

Each service has detailed configuration options in their respective `config.ini` files:

- **SSH**: `src/service_emulators/SSH/config.ini`
- **FTP**: `src/service_emulators/FTP/config.ini`
- **HTTP**: `src/service_emulators/HTTP/config.ini`

---

## 📊 Data Collection & Analysis

### Session Data Collection

nexus collects comprehensive data for security analysis:

- **Complete Command History**: Every command with AI analysis
- **Attack Pattern Detection**: Real-time classification of attack techniques
- **Vulnerability Exploitation**: Detailed logging of exploitation attempts
- **File Transfer Activities**: Hash analysis and malware detection
- **Behavioral Analysis**: Sophisticated attacker profiling and intent analysis
- **Network Forensics**: Complete connection logs and data transfer analysis

### Forensic Evidence Chain

- **Session Recordings**: Complete interaction logs with replay capability
- **File Artifacts**: Upload/download artifacts with integrity verification
- **Attack Timeline**: Chronological reconstruction of attack sequences
- **Chain of Custody**: Legal-grade evidence documentation
- **Integrity Verification**: Cryptographic hashing of all evidence

### Report Generation

Generate comprehensive security reports:

```bash
# Generate reports for all services
python src/cli/nexus_cli.py report ssh --output reports/ --format both
python src/cli/nexus_cli.py report ftp --output reports/ --format html
python src/cli/nexus_cli.py report http --output reports/ --format json

# Advanced filtering
python src/cli/nexus_cli.py report ssh --severity critical --period 7d
python src/cli/nexus_cli.py report ftp --sessions-dir custom/sessions
```

Reports include:
- **Executive Summary**: High-level attack statistics
- **Detailed Analysis**: Attack patterns, vulnerabilities, and IOCs
- **Visualizations**: Charts and graphs for trend analysis
- **Recommendations**: Actionable security improvements
- **Forensic Timeline**: Complete attack reconstruction

---

## 🔧 Advanced Usage

### Custom AI Prompts

Customize AI behavior with custom prompts:

```bash
# Use custom prompt file
python src/cli/nexus_cli.py ssh --prompt-file custom_prompt.txt

# Use inline prompt
python src/cli/nexus_cli.py ftp --prompt "You are a secure FTP server..."
```

### Multiple LLM Providers

Switch between providers easily:

```bash
# Use different providers for different services
python src/cli/nexus_cli.py ssh --llm-provider openai --model-name gpt-4o
python src/cli/nexus_cli.py ftp --llm-provider gemini --model-name gemini-2.5-flash-lite
python src/cli/nexus_cli.py http --llm-provider ollama --model-name llama3.2
```

### Custom User Accounts

Add honeypot accounts to attract attackers:

```bash
# Add multiple user accounts
python src/cli/nexus_cli.py ssh -u admin=admin123 -u root=password -u guest=guest
python src/cli/nexus_cli.py ftp -u webmaster=nexus2024 -u developer=devpass
```

### Log Analysis

Analyze session logs with advanced filtering:

```bash
# View full conversations
python src/cli/nexus_cli.py logs ssh --conversation --decode

# Filter by attack types
python src/cli/nexus_cli.py logs ftp --filter attacks --format json

# Save analysis to file
python src/cli/nexus_cli.py logs http --save analysis.txt --conversation
```

---

## 🛡️ Security Considerations

### ⚠️ Important Security Notes

- **Isolated Environment**: Deploy honeypots in isolated network segments
- **API Key Security**: Store API keys securely and rotate regularly
- **Data Privacy**: Session data may contain sensitive attacker information
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Resource Monitoring**: Monitor disk usage for file uploads and logs
- **Network Security**: Use proper firewall rules and access controls

### Best Practices

1. **Network Isolation**: Deploy in DMZ or isolated VLAN
2. **Regular Updates**: Keep dependencies and AI models updated
3. **Log Rotation**: Implement log rotation to manage disk space
4. **Backup Strategy**: Regular backups of session data and configurations
5. **Monitoring**: Set up alerts for high-severity attacks
6. **Legal Review**: Consult legal team before deployment

---

## 📖 Documentation

### File Structure

```
nexus-development/
├── src/
│   ├── cli/                    # Centralized CLI interface
│   │   └── nexus_cli.py       # Main CLI application
│   ├── logs/                   # Log analysis tools
│   │   └── log_viewer.py      # Session log viewer
│   └── service_emulators/      # Honeypot services
│       ├── SSH/               # SSH honeypot
│       ├── FTP/               # FTP honeypot
│       ├── HTTP/              # HTTP/Web honeypot
│       ├── MySQL/             # MySQL honeypot (planned)
│       └── SMB/               # SMB honeypot (planned)
├── requirements.txt           # Python dependencies
└── README.md                 # This file
```

### Configuration Files

- **`config.ini`**: Main configuration for each service
- **`.env`**: Environment variables (API keys, secrets)
- **`attack_patterns.json`**: Attack pattern definitions
- **`vulnerability_signatures.json`**: Vulnerability signatures

### Session Data Structure

```json
{
  "session_id": "unique_session_identifier",
  "start_time": "2024-01-15T10:30:00Z",
  "end_time": "2024-01-15T10:45:00Z",
  "client_info": {
    "ip": "192.168.1.100",
    "port": 54321,
    "user_agent": "OpenSSH_8.0"
  },
  "commands": [...],
  "attack_analysis": [...],
  "vulnerabilities": [...],
  "files_transferred": [...]
}
```

---

## 🚧 Development Roadmap

### Phase 1: Core Implementation ✅
- [x] SSH honeypot with AI integration
- [x] FTP honeypot with AI integration
- [x] HTTP/Web honeypot with AI integration
- [x] Centralized CLI interface
- [x] Comprehensive reporting system
- [x] Forensic chain of custody

### Phase 2: Advanced Features 🚧
- [ ] MySQL database honeypot
- [ ] SMB file share honeypot
- [ ] Real-time dashboard and visualization
- [ ] Machine learning-based threat prediction
- [ ] SIEM integration (Splunk, ELK Stack)
- [ ] Docker containerization

### Phase 3: Enterprise Features 📋
- [ ] Multi-honeypot correlation analysis
- [ ] Automated response orchestration
- [ ] Threat intelligence feeds integration
- [ ] Advanced behavioral analysis
- [ ] Cloud deployment templates
- [ ] Enterprise management console

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/PROFFARO/nexus-development.git
cd nexus-development
python -m venv dev-env
source dev-env/bin/activate  # On Windows: dev-env\Scripts\activate
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy
```

### Contribution Guidelines

1. **Code Style**: Follow PEP 8 and use Black for formatting
2. **Testing**: Add tests for new features
3. **Documentation**: Update README and docstrings
4. **Security**: Ensure sensitive data is properly excluded
5. **Logging**: Add comprehensive logging for new features
6. **AI Integration**: Test with multiple LLM providers

### Adding New Services

1. Create service directory under `src/service_emulators/`
2. Implement core honeypot functionality
3. Add AI integration using existing patterns
4. Create configuration files and templates
5. Add CLI integration
6. Implement report generation
7. Add comprehensive testing

---

## 📄 License

This project is for **educational and research purposes only**. Please ensure compliance with local laws and regulations when deploying honeypots.

### Disclaimer

- This software is provided "as is" without warranty
- Users are responsible for legal compliance in their jurisdiction
- Not intended for production security without proper review
- AI responses may reveal honeypot nature to sophisticated attackers

---

## 🆘 Support & Troubleshooting

### Common Issues

<details>
<summary><strong>API Key Issues</strong></summary>

```bash
# Check API key configuration
cat src/service_emulators/SSH/.env
cat src/service_emulators/FTP/.env
cat src/service_emulators/HTTP/.env

# Test API connectivity
python -c "import openai; print('OpenAI API key valid')"
```

</details>

<details>
<summary><strong>Port Conflicts</strong></summary>

```bash
# Check port availability
netstat -an | grep :8022  # SSH
netstat -an | grep :2121  # FTP
netstat -an | grep :8080  # HTTP

# Use different ports
python src/cli/nexus_cli.py ssh --port 2222
python src/cli/nexus_cli.py ftp --port 2122
python src/cli/nexus_cli.py http --port 8081
```

</details>

<details>
<summary><strong>Permission Issues</strong></summary>

```bash
# Check file permissions
ls -la src/service_emulators/SSH/
ls -la src/service_emulators/FTP/
ls -la src/service_emulators/HTTP/

# Fix permissions if needed
chmod +x src/cli/nexus_cli.py
chmod 600 src/service_emulators/*/server.key
```

</details>

### Getting Help

- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Join GitHub Discussions for questions
- **Documentation**: Check service-specific README files
- **Logs**: Enable debug logging for troubleshooting

### Testing Connectivity

```bash
# Test SSH honeypot
ssh admin@localhost -p 8022

# Test FTP honeypot
telnet localhost 2121
# Or use FTP client: ftp localhost 2121

# Test HTTP honeypot
curl http://localhost:8080/
# Or open in browser: http://localhost:8080
```

---

<div align="center">

**🕸️ NEXUS - Advanced AI-Enhanced Honeypot Platform**

*Protecting networks through intelligent deception*

[![GitHub Stars](https://img.shields.io/github/stars/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development)
[![GitHub Forks](https://img.shields.io/github/forks/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development)

</div>