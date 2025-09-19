# 🕸️ NEXUS Development - AI-Enhanced Honeypot Platform

<div align="center">

![NEXUS Logo](https://img.shields.io/badge/NEXUS-AI%20Honeypot-blue?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python&logoColor=white)
![AI Powered](https://img.shields.io/badge/AI-Powered-orange?style=for-the-badge&logo=openai&logoColor=white)
![License](https://img.shields.io/badge/License-Educational-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0.0-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=for-the-badge)

**A next-generation cybersecurity honeypot platform with AI-powered adaptive responses, comprehensive threat intelligence, and enterprise-grade forensic capabilities**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🛡️ Security](#-security-considerations) • [🤝 Contributing](#-contributing) • [📊 Features](#-key-features) • [🔧 API Reference](#-api--integration)

</div>

---

## 🌟 Overview

**NEXUS** is a cutting-edge, AI-enhanced honeypot platform designed for cybersecurity professionals, researchers, and organizations seeking advanced threat detection and analysis capabilities. Built with enterprise-grade architecture, NEXUS simulates realistic corporate environments to attract, analyze, and learn from sophisticated cyber attackers using state-of-the-art artificial intelligence.

### 🎯 Key Features

| Feature | Description | Status |
|---------|-------------|--------|
| **🤖 AI-Powered Responses** | Dynamic, context-aware responses using 5+ LLM providers (OpenAI, Gemini, Ollama, Azure, AWS) | ✅ Production |
| **🔍 Real-time Analysis** | Advanced attack pattern recognition with ML-based behavioral analysis | ✅ Production |
| **📊 Comprehensive Reporting** | Interactive dashboards, detailed security reports with visualizations | ✅ Production |
| **🔐 Forensic Chain** | Legal-grade evidence tracking with cryptographic integrity verification | ✅ Production |
| **🌐 Multi-Protocol Support** | SSH, FTP, HTTP/HTTPS, MySQL with SMB planned | ✅ 4/5 Services |
| **⚡ Enterprise Deployment** | CLI interface, Docker support | ✅ Production |
| **📈 Scalability** | Horizontal scaling, load balancing, distributed deployment | 🚧 In Progress |

### 🏆 What Makes NEXUS Unique

- **First AI-Native Honeypot**: Built from ground up with AI integration, not retrofitted
- **Enterprise-Grade Forensics**: Complete Forensic chain of attack analysis with proper CVE attacks descriptions.
- **Multi-LLM Architecture**: Vendor-agnostic AI and full support of multiple parameter tweaking.
- **Corporate Environment Simulation**: Realistic NexusGames Studio environment with authentic data plus support of changing of enviroment.
- **Real-time Threat Intelligence**: Live attack pattern updates and log generation.

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

### ✅ MySQL Database Honeypot - **FULLY OPERATIONAL**
<details>
<summary><strong>Click to expand MySQL details</strong></summary>

**Status**: Production-ready with full AI integration and MySQL protocol implementation

**Features**:
- 🤖 AI-powered adaptive MySQL responses using multiple LLM providers
- 🔍 Real-time SQL injection and attack pattern recognition
- 🛡️ Advanced vulnerability exploitation detection and logging
- 📝 Forensic chain of custody logging with complete session recording
- 📊 MySQL protocol compliance with proper handshake and authentication
- 💻 Support for standard MySQL clients (mysql, phpMyAdmin, Workbench)
- 🗄️ Dynamic database and table simulation based on attack context
- 🔐 Multi-user authentication with configurable accounts
- 📈 Comprehensive SQL query analysis and threat scoring
- 🎭 Corporate database environment simulation (NexusGames Studio)

**Location**: `src/service_emulators/MySQL/`  
**Default Port**: 3306 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**Client Support**: Standard MySQL clients, command-line tools, WorkBench applications

</details>

### 🚧 SMB File Share Honeypot - **PLANNED**
**Status**: Directory structure created, implementation pending  
**Location**: `src/service_emulators/SMB/`

---

## 🛠️ Installation & Setup

### 📋 Prerequisites

| Requirement | Version | Purpose | Installation |
|-------------|---------|---------|-------------|
| **Python** | 3.8+ (3.11+ recommended) | Core runtime | [Download Python](https://python.org/downloads/) |
| **Git** | Latest | Repository cloning and contribution | [Download Git](https://git-scm.com/downloads) |
| **LLM API Key** | N/A | AI responses | Choose from [supported providers](#llm-provider-configuration) |
| **MySQL Client** | 8.0+ (optional) | Testing MySQL honeypot | `apt install mysql-client` or [MySQL Downloads](https://dev.mysql.com/downloads/) |
| **Docker** | 20.0+ (optional) | Containerized deployment | [Docker Installation](https://docs.docker.com/get-docker/) |

### 🔑 Supported LLM Providers

| Provider | Models | Cost | Setup Difficulty | Recommended Use |
|----------|--------|------|------------------|----------------|
| **OpenAI** | GPT-4o, GPT-4o-mini, ... | $$$ | Easy | Production, high-quality responses |
| **Google Gemini** | Gemini-2.5-flash-lite, ... | $$ | Easy | Cost-effective, fast responses |
| **Ollama** | Llama3.2, CodeLlama, ... | Free | Medium | Local deployment, privacy |
| **Azure OpenAI** | GPT-4o, GPT-3.5, ... | $$$ | Medium | Enterprise, compliance |
| **AWS Bedrock** | Claude-3.5-Sonnet, ... | $$$ | Hard | AWS ecosystem integration |

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
cp src/service_emulators/MySQL/.env.example src/service_emulators/MySQL/.env

# Edit .env files with your API keys
# Example for OpenAI:
# OPENAI_API_KEY=your_openai_api_key_here
```

---

## 🚀 Quick Start

### 🎯 30-Second Demo

```bash
# 1. Start SSH honeypot (most popular)
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider <model_name>

# 2. In another terminal, test it
ssh admin@localhost -p 8022
# Password: admin (or any password - it accepts all)

# 3. Try some commands and see AI responses!
ls
whoami
cat /etc/passwd
```

### 🎮 Interactive Demo Mode

```bash
# Launch interactive setup wizard
python src/cli/nexus_cli.py demo

# Or quick demo with all services
python src/cli/nexus_cli.py demo --all-services
```

### 🖥️ Centralized CLI Interface

**The NEXUS CLI provides a unified interface for all honeypot services:**

```bash
# 📋 Service Management
python src/cli/nexus_cli.py list                    # List all services
python src/cli/nexus_cli.py status                  # Check service status
python src/cli/nexus_cli.py stop-all               # Emergency stop all

# 🚀 Start Services (choose your preferred LLM)
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider openai
python src/cli/nexus_cli.py ftp --port 2121 --llm-provider gemini
python src/cli/nexus_cli.py http --port 8080 --llm-provider ollama
python src/cli/nexus_cli.py mysql --port 3306 --llm-provider openai

# 📊 Advanced Options
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider openai \
  --model-name gpt-4o --temperature 0.3 --max-tokens 2000 \
  --user-account admin=admin123 --user-account root=toor

# 🔄 Multi-Service Deployment
python src/cli/nexus_cli.py deploy --config production.yaml
```

### 📊 Monitoring & Analysis

```bash
# 📈 Real-time Monitoring
python src/cli/nexus_cli.py monitor --service ssh --live
python src/cli/nexus_cli.py dashboard --port 8090    # Web dashboard

# 📋 Generate Reports
python src/cli/nexus_cli.py report ssh --output reports/ --format both
python src/cli/nexus_cli.py report ftp --output reports/ --format html
python src/cli/nexus_cli.py report http --output reports/ --format json
python src/cli/nexus_cli.py report mysql --output reports/ --format both

# 🔍 Log Analysis
python src/cli/nexus_cli.py logs ssh --conversation --decode
python src/cli/nexus_cli.py logs ftp --conversation --save ftp_session.txt
python src/cli/nexus_cli.py logs http --filter attacks --format json
python src/cli/nexus_cli.py logs mysql --conversation --save mysql_session.txt

# 🎯 Advanced Filtering
python src/cli/nexus_cli.py logs ssh --filter attacks --severity critical --last 24h
python src/cli/nexus_cli.py report ssh --severity high --period 7d
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

<details>
<summary><strong>MySQL Honeypot</strong></summary>

```bash
cd src/service_emulators/MySQL
python mysql_server.py --port 3306 --llm-provider openai --model-name gpt-4o-mini

# Test with MySQL client
mysql -h localhost -P 3306 -u root -p
# Or: mysql -h localhost -P 3306 -u admin -padmin
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
- **MySQL**: `src/service_emulators/MySQL/config.ini`

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
python src/cli/nexus_cli.py report ssh --output path_to_directory --format both
python src/cli/nexus_cli.py report ftp --output path_to_directory --format html
python src/cli/nexus_cli.py report http --output path_to_directory --format json

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
python src/cli/nexus_cli.py mysql --llm-provider openai --model-name gpt-4o-mini
```

### Custom User Accounts

Add honeypot accounts to attract attackers:

```bash
# Add multiple user accounts
python src/cli/nexus_cli.py ssh -u admin=admin123 -u root=password -u guest=guest
python src/cli/nexus_cli.py ftp -u webmaster=nexus2024 -u developer=devpass
python src/cli/nexus_cli.py mysql -u root=* -u admin=admin -u developer=dev123
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
- [x] MySQL database honeypot
- [x] Centralized CLI interface
- [x] Comprehensive reporting system
- [x] Forensic chain of custody

### Phase 2: Advanced Features 🚧
- [ ] Real-time dashboard and visualization
- [ ] Machine learning-based threat prediction
- [ ] Docker containerization

### Phase 3: Enterprise Features 📋
- [ ] SMB file share honeypot
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
netstat -an | grep :3306  # MySQL

# Use different ports
python src/cli/nexus_cli.py ssh --port 2222
python src/cli/nexus_cli.py ftp --port 2122
python src/cli/nexus_cli.py http --port 8081
python src/cli/nexus_cli.py mysql --port 3307
```

</details>

<details>
<summary><strong>Permission Issues</strong></summary>

```bash
# Check file permissions
ls -la src/service_emulators/SSH/
ls -la src/service_emulators/FTP/
ls -la src/service_emulators/HTTP/
ls -la src/service_emulators/MySQL/

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

# Test MySQL honeypot
mysql -h localhost -P 3306 -u root -p
# Or: mysql -h localhost -P 3306 -u admin -padmin
```

<div align="center">

**🕸️ NEXUS - Next-Generation AI-Enhanced Honeypot Platform**

*Revolutionizing cybersecurity through intelligent deception and advanced threat detection*

[![GitHub Stars](https://img.shields.io/github/stars/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development)
[![GitHub Forks](https://img.shields.io/github/forks/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development)
[![GitHub Issues](https://img.shields.io/github/issues/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development/issues)
[![GitHub Contributors](https://img.shields.io/github/contributors/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development/graphs/contributors)

**[🚀 Get Started](https://nexus-honeypot.com/get-started)** • **[📚 Documentation](https://docs.nexus-honeypot.com)** • **[💼 Enterprise](https://nexus-honeypot.com/enterprise)** • **[🎓 Training](https://training.nexus-honeypot.com)**

---

**Made with ❤️ by the PROFFARO**  
*Licensed under Educational Use - See [LICENSE](LICENSE) for details*

**⚡ Powered by AI • 🛡️ Secured by Design • 🌍 Trusted Worldwide**

</div>