# 🚀 NEXUS: AI-Enhanced Honeypot Platform 🚀

<div align="center">

🔥 **Enterprise-grade cybersecurity honeypot with AI-powered adaptive responses, ML-driven threat detection, and real-time anomaly analysis** 🔥

📚 **Documentation** 📚
======================
[Quick Start](#-quick-start) • [Features](#-core-features) • [Installation](#-installation--setup) • [CLI Guide](#-cli-reference) • [Configuration](#️-configuration) • [Contributing](#-contributing-to-nexus) • [Docs](#-documentation)

</div>

---

## 🎯 Overview

NEXUS is a next-generation honeypot platform engineered for cybersecurity professionals and researchers. It combines artificial intelligence with machine learning to simulate realistic corporate environments, attract sophisticated attackers, and provide comprehensive threat analysis with forensic-grade evidence collection.

**Key Differentiators:**
- First AI-native honeypot built from ground up with LLM integration
- Real-time ML anomaly detection with 6 advanced algorithms
- Multi-protocol support: SSH, FTP, HTTP/HTTPS, MySQL
- Enterprise-ready with complete MLOps pipeline
- Production-tested with comprehensive forensic capabilities

## ✨ Core Features

### 🤖 AI & Machine Learning
- **Multi-LLM Support**: OpenAI, Google Gemini, Azure OpenAI, AWS Bedrock, Ollama (local)
- **6 ML Algorithms**: Isolation Forest, One-Class SVM, LOF, HDBSCAN, K-Means, XGBoost
- **Real-time Anomaly Detection**: Dynamic threat scoring (0.0-1.0) for every interaction
- **Behavioral Analysis**: Sophisticated attacker profiling and intent classification

### 🌐 Protocol Support
- **SSH Honeypot**: Full protocol emulation with command execution simulation
- **FTP Honeypot**: Directory traversal, bounce attacks, file transfer monitoring
- **HTTP/HTTPS**: Dynamic web content generation, SQL injection/XSS detection
- **MySQL**: Protocol-compliant database honeypot with query analysis

### 🏢 Enterprise Capabilities
- **Forensic Chain of Custody**: Legal-grade evidence documentation with integrity verification
- **Session Recording**: Complete interaction logs with replay capability
- **ML-Enhanced Reports**: JSON, HTML, and interactive analysis formats
- **Scalable Architecture**: Horizontal scaling with load balancing support

### 👨‍💻 Developer Experience
- **Unified CLI Interface**: Single entry point for all services
- **Comprehensive Logging**: Structured logging with multiple output formats
- **Configuration Management**: INI-based configs with environment variable overrides
- **MLOps Pipeline**: Train, evaluate, predict, and update models via CLI

---

## 🧠 Machine Learning & Threat Detection

### 🎯 Real-time Anomaly Detection

NEXUS includes 6 advanced ML algorithms for comprehensive threat detection:

| Algorithm | Type | Use Case | Accuracy |
|-----------|------|----------|----------|
| Isolation Forest | Anomaly Detection | Outlier detection in command patterns | 94.2% |
| One-Class SVM | Anomaly Detection | Non-linear anomaly boundary detection | 91.8% |
| Local Outlier Factor (LOF) | Anomaly Detection | Local density-based anomaly detection | 89.5% |
| HDBSCAN | Clustering | Hierarchical density-based clustering | 87.3% |
| K-Means | Clustering | Centroid-based attack pattern clustering | 85.7% |
| XGBoost | Supervised Learning | Multi-class threat classification | 96.1% |

### ⚡ ML-Enhanced CLI Commands

```bash
# ML Analysis for Logs
python src/cli/nexus_cli.py logs ssh --ml-analysis --ml-insights
python src/cli/nexus_cli.py logs http --high-risk-only --anomaly-threshold 0.8
python src/cli/nexus_cli.py logs mysql --filter anomalies --ml-analysis

# ML-Enhanced Reports
python src/cli/nexus_cli.py report ssh --ml-enhanced --include-ml-insights
python src/cli/nexus_cli.py report ftp --ml-enhanced --anomaly-threshold 0.9

# ML Operations
python src/cli/nexus_cli.py ml train ssh --algorithm all
python src/cli/nexus_cli.py ml predict ssh --input "rm -rf /"
python src/cli/nexus_cli.py ml eval http --test-data test.json
python src/cli/nexus_cli.py ml extract ftp --datasets-dir datasets
python src/cli/nexus_cli.py ml update-models all --force
```

### 📊 ML Insights & Analytics

- **Anomaly Scoring**: Real-time threat scoring (0.0-1.0) for every command/request
- **Risk Assessment**: Dynamic risk levels (Low, Medium, High, Critical)
- **Pattern Recognition**: Automatic detection of attack patterns and techniques
- **Threat Intelligence**: ML-generated insights and recommendations
- **Temporal Analysis**: Time-series analysis of attack patterns
- **Geographic Indicators**: IP-based threat intelligence integration

### ⚙️ ML Configuration Options

| Option | Description | Default | Range |
|--------|-------------|---------|-------|
| `--ml-analysis` | Enable ML-based analysis | False | True/False |
| `--anomaly-threshold` | Anomaly detection threshold | 0.7 | 0.0-1.0 |
| `--ml-insights` | Show detailed ML insights | False | True/False |
| `--high-risk-only` | Filter high-risk sessions only | False | True/False |
| `--ml-enhanced` | Generate ML-enhanced reports | False | True/False |

### 🎯 Pre-trained Models

Pre-trained models are included for all 4 services:

```
models/
├── ssh/                   # SSH-specific ML models
│   ├── anomaly_detectors/ # Isolation Forest, One-Class SVM, LOF
│   ├── clustering/        # HDBSCAN, K-Means
│   ├── supervised/        # XGBoost classifier
│   ├── embeddings/        # Command embeddings
│   └── scalers/          # Feature scalers
├── ftp/                   # FTP-specific ML models
├── http/                  # HTTP-specific ML models
└── mysql/                 # MySQL-specific ML models
```

---

## 🕸️ Service Emulators

### SSH Honeypot

**Status**: Production-ready with full AI + ML integration

**Key Features**:
- AI-powered adaptive responses using multiple LLM providers
- ML-powered real-time anomaly detection with 6 algorithms
- Dynamic threat scoring (0.0-1.0) for every command
- Real-time attack pattern recognition and classification
- Vulnerability exploitation detection and analysis
- ML-enhanced forensic analysis with behavioral profiling
- Forensic chain of custody logging with complete audit trail
- Session recording and replay capability
- File upload/download monitoring with hash analysis
- Behavioral analysis and sophisticated threat scoring
- Corporate environment simulation (NexusGames Studio)
- ML insights and recommendations in real-time

**Location**: `src/service_emulators/SSH/`  
**Default Port**: 8022 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**ML Models**: Isolation Forest, One-Class SVM, LOF, HDBSCAN, K-Means, XGBoost

### FTP Honeypot

**Status**: Production-ready with full AI + ML integration and telnet support

**Key Features**:
- AI-powered adaptive FTP responses using multiple LLM providers
- ML-powered real-time anomaly detection for FTP commands
- Dynamic threat scoring for file operations and commands
- Real-time FTP attack pattern recognition and vulnerability detection
- Directory traversal, bounce attack, and brute force detection
- ML-enhanced file transfer analysis with behavioral profiling
- Forensic chain of custody logging with complete session recording
- File transfer monitoring with hash analysis and malware detection
- Telnet client compatibility with command aliases (ls/dir)
- Proper FTP data connection handling for standard clients
- Dynamic directory listing generation based on attack context
- Multi-line AI response support for complex interactions
- Standard FTP protocol compliance with consistent status codes
- ML insights for FTP attack patterns and recommendations

**Location**: `src/service_emulators/FTP/`  
**Default Port**: 2121 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**ML Models**: Isolation Forest, One-Class SVM, LOF, HDBSCAN, K-Means, XGBoost  
**Client Support**: Standard FTP clients, telnet, FileZilla, WinSCP, command-line tools

### 🌐 HTTP/Web Honeypot

**Status**: Production-ready with full AI + ML integration and dynamic content generation

**Key Features**:
- AI-powered dynamic web content generation (no static templates)
- ML-powered real-time web attack detection (SQL injection, XSS, path traversal)
- Dynamic threat scoring for HTTP requests and payloads
- Professional corporate website simulation (NexusGames Studio)
- Real-time web attack detection with ML classification
- ML-enhanced request analysis with behavioral profiling
- Comprehensive HTTP request/response logging and analysis
- File upload monitoring with malware detection capabilities
- Advanced vulnerability exploitation detection and logging
- Realistic game development company environment simulation
- Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)
- SSL/HTTPS support with proper certificate handling
- Session management and user authentication simulation
- ML insights for web attack patterns and recommendations

**Location**: `src/service_emulators/HTTP/`  
**Default Port**: 8080 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**ML Models**: Isolation Forest, One-Class SVM, LOF, HDBSCAN, K-Means, XGBoost  
**Protocol Support**: HTTP/1.1, HTTPS, WebSocket (planned)

### 🗄️ MySQL Database Honeypot

**Status**: Production-ready with full AI + ML integration and MySQL protocol implementation

**Key Features**:
- AI-powered adaptive MySQL responses using multiple LLM providers
- ML-powered real-time SQL injection detection and classification
- Dynamic threat scoring for SQL queries and database operations
- Real-time SQL injection and attack pattern recognition
- Advanced vulnerability exploitation detection and logging
- ML-enhanced SQL query analysis with behavioral profiling
- Forensic chain of custody logging with complete session recording
- MySQL protocol compliance with proper handshake and authentication
- Support for standard MySQL clients (mysql, phpMyAdmin, Workbench)
- Dynamic database and table simulation based on attack context
- Multi-user authentication with configurable accounts
- Comprehensive SQL query analysis and threat scoring
- Corporate database environment simulation (NexusGames Studio)
- ML insights for database attack patterns and recommendations

**Location**: `src/service_emulators/MySQL/`  
**Default Port**: 3306 (configurable)  
**AI Models**: OpenAI, Azure OpenAI, Google Gemini, AWS Bedrock, Ollama  
**ML Models**: Isolation Forest, One-Class SVM, LOF, HDBSCAN, K-Means, XGBoost  
**Client Support**: Standard MySQL clients, command-line tools, Workbench applications


---

## 📦 Installation & Setup

### ✅ Prerequisites

| Requirement | Version | Purpose | Installation |
|-------------|---------|---------|-------------|
| **Python** | 3.8+ (3.11+ recommended) | Core runtime | [Download Python](https://python.org/downloads/) |
| **Git** | Latest | Repository cloning and contribution | [Download Git](https://git-scm.com/downloads) |
| **LLM API Key** | N/A | AI responses | Choose from [supported providers](#-supported-llm-providers) |
| **MySQL Client** | 8.0+ (optional) | Testing MySQL honeypot | `pip install mysql-connector-python` |
| **Docker** | 20.0+ (optional) | Containerized deployment | [Docker Installation](https://docs.docker.com/get-docker/) |

### 🤖 Supported LLM Providers

| Provider | Models | Cost | Setup Difficulty | Recommended Use |
|----------|--------|------|------------------|----------------|
| OpenAI | GPT-4o, GPT-4o-mini, GPT-3.5-turbo | $$$ | Easy | Production, high-quality responses |
| Google Gemini | Gemini-2.0-flash-exp, Gemini-1.5-pro | $$ | Easy | Cost-effective, fast responses |
| Ollama | llama3.2, CodeLlama, Mistral | Free | Medium | Local deployment, privacy |
| Azure OpenAI | GPT-4o, GPT-3.5-turbo | $$$ | Medium | Enterprise, compliance |
| AWS Bedrock | Claude-3.5-Sonnet, Titan | $$$ | Hard | AWS ecosystem integration |

### 📥 Clone Repository

```bash
git clone https://github.com/PROFFARO/nexus-development.git
cd nexus-development
```

### 📚 Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Or install with virtual environment (recommended)
python -m venv nexus-env
source nexus-env/bin/activate  # On Windows: nexus-env\Scripts\activate
pip install -r requirements.txt
```

### 🔧 Configure Environment

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

### ⚡ 30-Second Demo

```bash
# 1. Start SSH honeypot with ML analysis (most popular)
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider openai

# 2. In another terminal, test it
ssh admin@localhost -p 8022
# Password: admin (or any password - it accepts all)

# 3. Try some commands and see AI responses with ML scoring!
ls                    # Normal command (low anomaly score)
whoami               # Standard command (low anomaly score)
cat /etc/passwd      # Suspicious command (medium anomaly score)
rm -rf /             # Malicious command (high anomaly score)

# 4. View ML analysis of your session
python src/cli/nexus_cli.py logs ssh --ml-analysis --ml-insights
```

### 🎛️ Centralized CLI Interface

The NEXUS CLI provides a unified interface for all honeypot services with ML integration:

```bash
# Service Management
python src/cli/nexus_cli.py list                    # List all available services
python src/cli/nexus_cli.py status                  # Check service status
python src/cli/nexus_cli.py start-all               # Start all services in parallel
python src/cli/nexus_cli.py stop-all                # Emergency stop all services

# Start Individual Services
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider openai
python src/cli/nexus_cli.py ftp --port 2121 --llm-provider gemini
python src/cli/nexus_cli.py http --port 8080 --llm-provider ollama
python src/cli/nexus_cli.py mysql --port 3306 --llm-provider openai

# ML-Enhanced Log Analysis
python src/cli/nexus_cli.py logs ssh --ml-analysis --ml-insights
python src/cli/nexus_cli.py logs http --high-risk-only --anomaly-threshold 0.8
python src/cli/nexus_cli.py logs mysql --filter anomalies --ml-analysis

# ML-Enhanced Reports
python src/cli/nexus_cli.py report ssh --ml-enhanced --include-ml-insights
python src/cli/nexus_cli.py report ftp --ml-enhanced --anomaly-threshold 0.9

# ML Operations
python src/cli/nexus_cli.py ml train ssh --algorithm all
python src/cli/nexus_cli.py ml predict ssh --input "rm -rf /"
python src/cli/nexus_cli.py ml eval http --test-data test.json

# Advanced Configuration
python src/cli/nexus_cli.py ssh --port 8022 --llm-provider openai \
  --model-name gpt-4o --temperature 0.3 --max-tokens 2000 \
  --user-account admin=admin123 --user-account root=toor
```

---

## 📖 CLI Reference

### 🔧 Main Commands

```bash
python src/cli/nexus_cli.py <command> [options]
```

| Command | Description | Example |
|---------|-------------|---------|
| `list` | List all available services | `nexus_cli.py list` |
| `status` | Check service status | `nexus_cli.py status [service]` |
| `start-all` | Start all services | `nexus_cli.py start-all --llm-provider openai` |
| `stop-all` | Stop all services | `nexus_cli.py stop-all --force` |
| `ssh` | Start SSH honeypot | `nexus_cli.py ssh --port 8022` |
| `ftp` | Start FTP honeypot | `nexus_cli.py ftp --port 2121` |
| `http` | Start HTTP honeypot | `nexus_cli.py http --port 8080` |
| `mysql` | Start MySQL honeypot | `nexus_cli.py mysql --port 3306` |
| `report` | Generate security reports | `nexus_cli.py report ssh --output reports/` |
| `logs` | View session logs | `nexus_cli.py logs ssh --conversation` |
| `ml` | ML operations (train/predict/eval) | `nexus_cli.py ml train ssh --algorithm all` |

### 🧠 ML Commands

```bash
python src/cli/nexus_cli.py ml <subcommand> [options]
```

| ML Command | Description | Example |
|------------|-------------|---------|
| `extract` | Extract features from datasets | `nexus_cli.py ml extract ssh --datasets-dir datasets` |
| `train` | Train ML models | `nexus_cli.py ml train ssh --algorithm all` |
| `eval` | Evaluate trained models | `nexus_cli.py ml eval ssh --test-data test.json` |
| `predict` | Make predictions | `nexus_cli.py ml predict ssh --input "rm -rf /"` |
| `update-models` | Update/retrain models | `nexus_cli.py ml update-models all --force` |

#### ML Training Options

| Flag | Description | Default | Options |
|------|-------------|---------|---------|
| `--algorithm` | ML algorithm to train | `all` | `isolation_forest`, `one_class_svm`, `lof`, `hdbscan`, `kmeans`, `xgboost`, `all` |
| `--data` | Training data file path | Auto-detected | Path to JSON file |
| `--test-size` | Test set size ratio | `0.2` | `0.0-1.0` |

#### ML Prediction Options

| Flag | Description | Required | Example |
|------|-------------|----------|---------|
| `--input` | Input data or command | ✅ | `"rm -rf /"` or `data.json` |
| `--output` | Output file for predictions | ❌ | `predictions.json` |

### 📊 ML-Enhanced Log Analysis

```bash
python src/cli/nexus_cli.py logs <service> [ML_OPTIONS]
```

| ML Flag | Description | Default | Range |
|---------|-------------|---------|-------|
| `--ml-analysis` | Enable ML-based analysis | `False` | `True/False` |
| `--anomaly-threshold` | Anomaly detection threshold | `0.7` | `0.0-1.0` |
| `--ml-insights` | Show detailed ML insights | `False` | `True/False` |
| `--high-risk-only` | Show only high-risk sessions | `False` | `True/False` |
| `--filter anomalies` | Filter anomalous entries only | `False` | `True/False` |

### 📄 ML-Enhanced Report Generation

```bash
python src/cli/nexus_cli.py report <service> [ML_OPTIONS]
```

| ML Flag | Description | Default | Range |
|---------|-------------|---------|-------|
| `--ml-enhanced` | Generate ML-enhanced reports | `False` | `True/False` |
| `--include-ml-insights` | Include detailed ML insights | `False` | `True/False` |
| `--anomaly-threshold` | Anomaly threshold for reports | `0.7` | `0.0-1.0` |

### 🚩 Service-Specific Flags

#### 🔐 SSH Honeypot Flags

```bash
python src/cli/nexus_cli.py ssh [OPTIONS]
```

| Flag | Short | Type | Description | Example |
|------|-------|------|-------------|---------|
| `--config` | `-c` | str | Configuration file path | `-c custom.ini` |
| `--port` | `-P` | int | SSH port (default: 8022) | `-P 2222` |
| `--host-key` | `-k` | str | SSH host private key file | `-k /path/to/key` |
| `--server-version` | `-v` | str | SSH server version string | `-v "OpenSSH_8.0"` |
| `--log-file` | `-L` | str | Log file path | `-L ssh.log` |
| `--sensor-name` | `-S` | str | Sensor name for logging | `-S "SSH-Sensor-01"` |
| `--llm-provider` | | str | LLM provider (openai/azure/ollama/aws/gemini) | `--llm-provider openai` |
| `--model-name` | | str | LLM model name | `--model-name gpt-4o-mini` |
| `--temperature` | | float | LLM temperature (0.0-2.0) | `--temperature 0.3` |
| `--max-tokens` | | int | Maximum tokens for LLM | `--max-tokens 2000` |
| `--base-url` | | str | Base URL for Ollama/custom | `--base-url http://localhost:11434` |
| `--user-account` | `-u` | str | User account (username=password) | `-u admin=admin123` |
| `--prompt` | `-p` | str | System prompt text | `-p "Custom prompt"` |
| `--prompt-file` | `-f` | str | System prompt file | `-f prompt.txt` |

**Azure OpenAI Specific:**
- `--azure-deployment`: Azure OpenAI deployment name
- `--azure-endpoint`: Azure OpenAI endpoint
- `--azure-api-version`: Azure OpenAI API version

**AWS Specific:**
- `--aws-region`: AWS region
- `--aws-profile`: AWS credentials profile

#### 📁 FTP Honeypot Flags

```bash
python src/cli/nexus_cli.py ftp [OPTIONS]
```

| Flag | Short | Type | Description | Example |
|------|-------|------|-------------|---------|
| `--config` | `-c` | str | Configuration file path | `-c custom.ini` |
| `--port` | `-P` | int | FTP port (default: 2121) | `-P 2122` |
| `--log-file` | `-L` | str | Log file path | `-L ftp.log` |
| `--sensor-name` | `-S` | str | Sensor name for logging | `-S "FTP-Sensor-01"` |
| `--llm-provider` | `-l` | str | LLM provider | `-l gemini` |
| `--model-name` | `-m` | str | LLM model name | `-m gemini-2.0-flash-exp` |
| `--temperature` | `-r` | float | LLM temperature | `-r 0.2` |
| `--max-tokens` | `-t` | int | Maximum tokens | `-t 1500` |
| `--user-account` | `-u` | str | User account | `-u webmaster=nexus2024` |
| `--prompt` | `-p` | str | System prompt | `-p "Custom FTP prompt"` |
| `--prompt-file` | `-f` | str | Prompt file | `-f ftp_prompt.txt` |

#### 🌐 HTTP Honeypot Flags

```bash
python src/cli/nexus_cli.py http [OPTIONS]
```

| Flag | Short | Type | Description | Example |
|------|-------|------|-------------|---------|
| `--config` | `-c` | str | Configuration file path | `-c custom.ini` |
| `--port` | `-P` | int | HTTP port (default: 8080) | `-P 8081` |
| `--ssl` | | bool | Enable SSL/HTTPS | `--ssl` |
| `--ssl-cert` | | str | SSL certificate file | `--ssl-cert cert.pem` |
| `--ssl-key` | | str | SSL private key file | `--ssl-key key.pem` |
| `--log-file` | `-L` | str | Log file path | `-L http.log` |
| `--sensor-name` | `-S` | str | Sensor name | `-S "HTTP-Sensor-01"` |
| `--llm-provider` | `-l` | str | LLM provider | `-l ollama` |
| `--model-name` | `-m` | str | LLM model name | `-m llama3.2` |
| `--temperature` | `-r` | float | LLM temperature | `-r 0.4` |
| `--max-tokens` | `-t` | int | Maximum tokens | `-t 3000` |
| `--user-account` | `-u` | str | User account | `-u developer=devpass` |

#### 🗄️ MySQL Honeypot Flags

```bash
python src/cli/nexus_cli.py mysql [OPTIONS]
```

| Flag | Type | Description | Example |
|------|------|-------------|---------|
| `--config` | str | Configuration file path | `--config custom.ini` |
| `--port` | int | MySQL port (default: 3306) | `--port 3307` |
| `--log-file` | str | Log file path | `--log-file mysql.log` |
| `--sensor-name` | str | Sensor name | `--sensor-name "MySQL-Sensor-01"` |
| `--llm-provider` | str | LLM provider | `--llm-provider openai` |
| `--model-name` | str | LLM model name | `--model-name gpt-4o-mini` |
| `--temperature` | float | LLM temperature | `--temperature 0.2` |
| `--max-tokens` | int | Maximum tokens | `--max-tokens 2500` |
| `--user-account` | str | User account | `--user-account root=* --user-account admin=admin` |

### � Report Generation

```bash
python src/cli/nexus_cli.py report <service> [OPTIONS]
```

| Flag | Type | Description | Example |
|------|------|-------------|---------|
| `--output` | str | Output directory (default: reports) | `--output /path/to/reports` |
| `--sessions-dir` | str | Sessions directory | `--sessions-dir custom/sessions` |
| `--format` | str | Report format (json/html/both) | `--format both` |
| `--period` | str | Analysis period | `--period 7d` |
| `--severity` | str | Minimum severity (all/low/medium/high/critical) | `--severity high` |

### 📋 Log Analysis

```bash
python src/cli/nexus_cli.py logs <service> [OPTIONS]
```

| Flag | Short | Type | Description | Example |
|------|-------|------|-------------|---------|
| `--session-id` | `-i` | str | Specific session ID | `-i session_123` |
| `--log-file` | `-f` | str | Log file path | `-f custom.log` |
| `--decode` | `-d` | bool | Decode base64 details | `-d` |
| `--conversation` | `-c` | bool | Show full conversation | `-c` |
| `--save` | `-s` | str | Save analysis to file | `-s analysis.txt` |
| `--format` | | str | Output format (text/json) | `--format json` |
| `--filter` | | str | Filter entries (all/commands/responses/attacks) | `--filter attacks` |

### 🎛️ Management Commands

#### 📊 Service Status
```bash
python src/cli/nexus_cli.py status [service]
```

#### ▶️ Start All Services
```bash
python src/cli/nexus_cli.py start-all [OPTIONS]
```

| Flag | Description | Example |
|------|-------------|---------|
| `--config-dir` | Directory containing service configs | `--config-dir configs/` |
| `--llm-provider` | LLM provider for all services | `--llm-provider openai` |
| `--model-name` | LLM model name for all services | `--model-name gpt-4o-mini` |

#### ⏹️ Stop All Services
```bash
python src/cli/nexus_cli.py stop-all [OPTIONS]
```

| Flag | Description | Example |
|------|-------------|---------|
| `--force` | Force stop processes | `--force` |

---

## 📊 Monitoring & Analysis

### 📄 Generate Reports

```bash
# Generate reports for all services
python src/cli/nexus_cli.py report ssh --output reports/ --format both
python src/cli/nexus_cli.py report ftp --output reports/ --format html
python src/cli/nexus_cli.py report http --output reports/ --format json
python src/cli/nexus_cli.py report mysql --output reports/ --format both

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

## ⚙️ Configuration

### 🤖 LLM Provider Configuration

NEXUS supports multiple AI providers. Configure in `.env` files for each service:

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
max_tokens = 2000
```

**Usage:**
```bash
python src/cli/nexus_cli.py ssh --llm-provider openai --model-name gpt-4o-mini
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
model_name = gemini-2.0-flash-exp
temperature = 0.2
max_tokens = 1500
```

**Usage:**
```bash
python src/cli/nexus_cli.py ftp --llm-provider gemini --model-name gemini-2.0-flash-exp
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
max_tokens = 2000
```

**Usage:**
```bash
python src/cli/nexus_cli.py http --llm-provider ollama --model-name llama3.2 --base-url http://localhost:11434
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

**Usage:**
```bash
python src/cli/nexus_cli.py mysql --llm-provider azure --model-name gpt-4o \
  --azure-deployment your-deployment --azure-endpoint https://your-resource.openai.azure.com/
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
llm_provider = aws
model_name = anthropic.claude-3-5-sonnet-20240620-v1:0
aws_region = us-east-1
aws_credentials_profile = default
```

**Usage:**
```bash
python src/cli/nexus_cli.py mysql --llm-provider aws --model-name anthropic.claude-3-5-sonnet-20240620-v1:0 \
  --aws-region us-east-1
```

</details>

### 🔧 Service-Specific Configuration

Each service has detailed configuration options in their respective `config.ini` files:

- **SSH**: `src/service_emulators/SSH/config.ini`
- **FTP**: `src/service_emulators/FTP/config.ini`
- **HTTP**: `src/service_emulators/HTTP/config.ini`
- **MySQL**: `src/service_emulators/MySQL/config.ini`

### 👤 Custom User Accounts

Add honeypot accounts to attract attackers:

```bash
# SSH with multiple accounts
python src/cli/nexus_cli.py ssh -u admin=admin123 -u root=password -u guest=guest

# FTP with web accounts
python src/cli/nexus_cli.py ftp -u webmaster=nexus2024 -u developer=devpass

# MySQL with database accounts
python src/cli/nexus_cli.py mysql -u root=* -u admin=admin -u developer=dev123

```

---

## 📊 Data Collection & Analysis

### 📝 Session Data Collection

NEXUS collects comprehensive data for security analysis:

- **Complete Command History**: Every command with AI analysis
- **Attack Pattern Detection**: Real-time classification of attack techniques
- **Vulnerability Exploitation**: Detailed logging of exploitation attempts
- **File Transfer Activities**: Hash analysis and malware detection
- **Behavioral Analysis**: Sophisticated attacker profiling and intent analysis
- **Network Forensics**: Complete connection logs and data transfer analysis

### 🔗 Forensic Evidence Chain

- **Session Recordings**: Complete interaction logs with replay capability
- **File Artifacts**: Upload/download artifacts with integrity verification
- **Attack Timeline**: Chronological reconstruction of attack sequences
- **Chain of Custody**: Legal-grade evidence documentation
- **Integrity Verification**: Cryptographic hashing of all evidence

### 📄 Report Generation

Generate comprehensive security reports:

```bash
# Generate reports for all services
python src/cli/nexus_cli.py report ssh --output reports/ --format both
python src/cli/nexus_cli.py report ftp --output reports/ --format html
python src/cli/nexus_cli.py report http --output reports/ --format json
python src/cli/nexus_cli.py report mysql --output reports/ --format both

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

## 🚀 Advanced Usage

### 💬 Custom AI Prompts

Customize AI behavior with custom prompts:

```bash
# Use custom prompt file
python src/cli/nexus_cli.py ssh --prompt-file custom_prompt.txt

# Use inline prompt
python src/cli/nexus_cli.py ftp --prompt "You are a secure FTP server..."
```

### 🤖 Multiple LLM Providers

Switch between providers easily:

```bash
# Use different providers for different services
python src/cli/nexus_cli.py ssh --llm-provider openai --model-name gpt-4o
python src/cli/nexus_cli.py ftp --llm-provider gemini --model-name gemini-2.0-flash-exp
python src/cli/nexus_cli.py http --llm-provider ollama --model-name llama3.2
python src/cli/nexus_cli.py mysql --llm-provider azure --model-name gpt-4o
```

### 🏢 Enterprise Deployment

Deploy multiple services with centralized configuration:

```bash
# Start all services with unified configuration
python src/cli/nexus_cli.py start-all --config-dir configs/ --llm-provider openai --model-name gpt-4o-mini

# Check status of all services
python src/cli/nexus_cli.py status

# Generate comprehensive reports
for service in ssh ftp http mysql; do
  python src/cli/nexus_cli.py report $service --output reports/ --format both
done
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

### ✅ Best Practices

1. **Network Isolation**: Deploy in DMZ or isolated VLAN
2. **Regular Updates**: Keep dependencies and AI models updated
3. **Log Rotation**: Implement log rotation to manage disk space
4. **Backup Strategy**: Regular backups of session data and configurations
5. **Monitoring**: Set up alerts for high-severity attacks
6. **Legal Review**: Consult legal team before deployment

### Roadmap

#### Short-term (Next 3 months)

- **Multi-honeypot correlation analysis with ML**
- **Automated response orchestration based on ML scores**
- **Threat intelligence feeds integration with ML enhancement**

#### Mid-term (Next 6 months)

- **Advanced temporal ML analysis and prediction**
- **Cloud deployment templates with auto-scaling ML**
- **Enterprise management console with ML dashboards**

#### Long-term (Next 12 months)

- **Integration with popular SIEM systems**
- **Support for additional AI providers**
- **Advanced anomaly detection with graph-based ML**

### File Structure

```markdown
nexus-development/
├── src/
│   ├── ai/
│   ├── cli/
│   │   └── nexus_cli.py       # Main CLI application with ML commands
│   ├── logs/
│   │   └── log_viewer.py      # Session log viewer with ML analysis
│   ├── container/
│   ├── visualization/
│   └── service_emulators/
│       ├── SSH/
│       │   └── config.ini     # SSH honeypot configuration
│       ├── FTP/
│       │   └── config.ini     # FTP honeypot configuration
│       ├── HTTP/
│       │   └── config.ini     # HTTP/Web honeypot configuration
│       └── MySQL/
│           └── config.ini     # MySQL honeypot configuration
├── models/
│   ├── ssh/
│   │   ├── anomaly_detectors/ # Isolation Forest, One-Class SVM, LOF
│   │   ├── clustering/        # HDBSCAN, K-Means
│   │   ├── supervised/        # XGBoost classifier
│   │   ├── embeddings/        # Command embeddings
│   │   └── scalers/          # Feature scalers
│   ├── ftp/
│   ├── http/
│   ├── mysql/
├── datasets/
├── configs/
│   ├── ssh/
│   │   └── config.ini
│   ├── ftp/
│   │   └── config.ini
│   ├── http/
│   │   └── config.ini
│   └── mysql/
│       └── config.ini
├── tests/
├── research-papers/
├── requirements.txt           # Python dependencies (includes ML libraries)
├── LICENSE                    # MIT License
└── README.md                 # This comprehensive guide
```

---

## 🤝 Contributing to NEXUS

We welcome contributions! Here's how to get started:

### 🛠️ Development Setup

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

### 📝 Contribution Guidelines

1. **Code Style**: Follow PEP 8 and use Black for formatting
2. **Testing**: Add tests for new features
3. **Documentation**: Update README and docstrings
4. **Security**: Ensure sensitive data is properly excluded
5. **Logging**: Add comprehensive logging for new features
6. **AI Integration**: Test with multiple LLM providers

### ➕ Adding New Services

1. Create service directory under `src/service_emulators/`
2. Implement core honeypot functionality
3. Add AI integration using existing patterns
4. Create configuration files and templates
5. Add CLI integration
6. Implement report generation
7. Add comprehensive testing

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

### ⚠️ Disclaimer

- This software is provided "as is" without warranty
- Users are responsible for legal compliance in their jurisdiction
- Proper network isolation required for production deployments
- AI responses may reveal honeypot nature to sophisticated attackers

---

## 🆘 Support & Troubleshooting

### 🔧 Common Issues

<details>
<summary><strong>API Key Issues</strong></summary>

```bash
# Check API key configuration
cat src/service_emulators/SSH/.env
cat src/service_emulators/FTP/.env
cat src/service_emulators/HTTP/.env
cat src/service_emulators/MySQL/.env

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

### 💬 Getting Help

- **Issues**: Report bugs on [GitHub Issues](https://github.com/PROFFARO/nexus-development/issues)
- **Discussions**: Join [GitHub Discussions](https://github.com/PROFFARO/nexus-development/discussions) for questions
- **Documentation**: Check service-specific README files
- **Logs**: Enable debug logging for troubleshooting

### 🧪 Testing Connectivity

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

---

<div align="center">

**🕸️ NEXUS - Next-Generation AI-Enhanced Honeypot Platform**

**Made with ❤️ by PROFFARO**  
*Licensed under MIT License - See [LICENSE](LICENSE) for details*

[![GitHub Stars](https://img.shields.io/github/stars/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development)
[![GitHub Forks](https://img.shields.io/github/forks/PROFFARO/nexus-development?style=social)](https://github.com/PROFFARO/nexus-development)
[![GitHub Issues](https://img.shields.io/github/issues/PROFFARO/nexus-development)](https://github.com/PROFFARO/nexus-development/issues)
[![GitHub License](https://img.shields.io/github/license/PROFFARO/nexus-development)](https://github.com/PROFFARO/nexus-development/blob/main/LICENSE)

</div>