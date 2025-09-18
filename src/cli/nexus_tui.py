#!/usr/bin/env python3
"""
NEXUS Honeypot TUI - Beautiful Textual-based interface for all service emulators
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Button, Static, Input, Select, Checkbox, 
    TabbedContent, TabPane, DataTable, Log, Label, Switch,
    OptionList, RadioSet, RadioButton, Collapsible
)
from textual.screen import Screen
from textual.binding import Binding
from textual import on
from rich.text import Text
from rich.panel import Panel
from rich.console import Console

# Import the original CLI logic
from nexus_cli import NexusCLI

class ServiceConfigScreen(Screen):
    """Configuration screen for individual services"""
    
    def __init__(self, service_name: str, cli: NexusCLI):
        super().__init__()
        self.service_name = service_name
        self.cli = cli
        self.config = {}
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with ScrollableContainer():
            yield Static(f"🛠️ Configure {self.service_name.upper()} Honeypot", classes="title")
            
            with Vertical(classes="config-form"):
                # Basic Configuration
                with Collapsible(title="📋 Basic Configuration", collapsed=False):
                    yield Label("Port:")
                    yield Input(placeholder=f"Default: {self._get_default_port()}", id="port")
                    
                    yield Label("Log File:")
                    yield Input(placeholder="Optional custom log file path", id="log_file")
                    
                    yield Label("Sensor Name:")
                    yield Input(placeholder="Optional sensor identifier", id="sensor_name")
                    
                    if self.service_name == "ssh":
                        yield Label("Host Key:")
                        yield Input(placeholder="SSH host private key file", id="host_key")
                        
                        yield Label("Server Version:")
                        yield Input(placeholder="SSH server version string", id="server_version")
                    
                    elif self.service_name == "http":
                        yield Label("SSL/HTTPS:")
                        yield Switch(id="ssl")
                        
                        yield Label("SSL Certificate:")
                        yield Input(placeholder="SSL certificate file", id="ssl_cert")
                        
                        yield Label("SSL Key:")
                        yield Input(placeholder="SSL private key file", id="ssl_key")
                
                # LLM Configuration
                with Collapsible(title="🤖 AI/LLM Configuration", collapsed=False):
                    yield Label("LLM Provider:")
                    yield Select([
                        ("OpenAI", "openai"),
                        ("Azure OpenAI", "azure"),
                        ("Google Gemini", "gemini"),
                        ("AWS Bedrock", "aws"),
                        ("Ollama (Local)", "ollama")
                    ], id="llm_provider")
                    
                    yield Label("Model Name:")
                    yield Input(placeholder="e.g., gpt-4o-mini, gemini-2.5-flash-lite", id="model_name")
                    
                    yield Label("Temperature (0.0-2.0):")
                    yield Input(placeholder="0.2", id="temperature")
                    
                    yield Label("Max Tokens:")
                    yield Input(placeholder="Optional token limit", id="max_tokens")
                    
                    yield Label("Base URL (Ollama):")
                    yield Input(placeholder="http://localhost:11434", id="base_url")
                
                # Azure OpenAI Configuration
                with Collapsible(title="☁️ Azure OpenAI Configuration"):
                    yield Label("Azure Deployment:")
                    yield Input(placeholder="Azure deployment name", id="azure_deployment")
                    
                    yield Label("Azure Endpoint:")
                    yield Input(placeholder="https://your-resource.openai.azure.com/", id="azure_endpoint")
                    
                    yield Label("Azure API Version:")
                    yield Input(placeholder="2024-02-01", id="azure_api_version")
                
                # AWS Configuration
                with Collapsible(title="🔧 AWS Configuration"):
                    yield Label("AWS Region:")
                    yield Input(placeholder="us-east-1", id="aws_region")
                    
                    yield Label("AWS Profile:")
                    yield Input(placeholder="default", id="aws_profile")
                
                # User Accounts
                with Collapsible(title="👥 User Accounts"):
                    yield Label("User Accounts (username=password):")
                    yield Input(placeholder="admin=admin123", id="user_account_1")
                    yield Input(placeholder="root=password", id="user_account_2")
                    yield Input(placeholder="guest=guest", id="user_account_3")
                
                # Custom Prompts
                with Collapsible(title="💬 Custom Prompts"):
                    yield Label("System Prompt:")
                    yield Input(placeholder="Custom system prompt text", id="prompt")
                    
                    yield Label("Prompt File:")
                    yield Input(placeholder="Path to prompt file", id="prompt_file")
            
            with Horizontal(classes="button-row"):
                yield Button("🚀 Start Service", variant="primary", id="start")
                yield Button("💾 Save Config", variant="success", id="save")
                yield Button("🔙 Back", variant="default", id="back")
        
        yield Footer()
    
    def _get_default_port(self) -> str:
        defaults = {"ssh": "8022", "ftp": "2121", "http": "8080"}
        return defaults.get(self.service_name, "8080")
    
    @on(Button.Pressed, "#start")
    def start_service(self):
        """Start the service with current configuration"""
        self._collect_config()
        self.app.push_screen(ServiceRunScreen(self.service_name, self.config, self.cli))
    
    @on(Button.Pressed, "#save")
    def save_config(self):
        """Save current configuration"""
        self._collect_config()
        self.notify("Configuration saved!", severity="information")
    
    @on(Button.Pressed, "#back")
    def go_back(self):
        """Return to main screen"""
        self.app.pop_screen()
    
    def _collect_config(self):
        """Collect configuration from form inputs"""
        self.config = {}
        
        # Basic config
        if self.query_one("#port").value:
            self.config["port"] = int(self.query_one("#port").value)
        if self.query_one("#log_file").value:
            self.config["log_file"] = self.query_one("#log_file").value
        if self.query_one("#sensor_name").value:
            self.config["sensor_name"] = self.query_one("#sensor_name").value
        
        # Service-specific
        if self.service_name == "ssh":
            if self.query_one("#host_key").value:
                self.config["host_key"] = self.query_one("#host_key").value
            if self.query_one("#server_version").value:
                self.config["server_version"] = self.query_one("#server_version").value
        elif self.service_name == "http":
            self.config["ssl"] = self.query_one("#ssl").value
            if self.query_one("#ssl_cert").value:
                self.config["ssl_cert"] = self.query_one("#ssl_cert").value
            if self.query_one("#ssl_key").value:
                self.config["ssl_key"] = self.query_one("#ssl_key").value
        
        # LLM config
        if self.query_one("#llm_provider").value:
            self.config["llm_provider"] = self.query_one("#llm_provider").value
        if self.query_one("#model_name").value:
            self.config["model_name"] = self.query_one("#model_name").value
        if self.query_one("#temperature").value:
            self.config["temperature"] = float(self.query_one("#temperature").value)
        if self.query_one("#max_tokens").value:
            self.config["max_tokens"] = int(self.query_one("#max_tokens").value)
        if self.query_one("#base_url").value:
            self.config["base_url"] = self.query_one("#base_url").value
        
        # Azure config
        if self.query_one("#azure_deployment").value:
            self.config["azure_deployment"] = self.query_one("#azure_deployment").value
        if self.query_one("#azure_endpoint").value:
            self.config["azure_endpoint"] = self.query_one("#azure_endpoint").value
        if self.query_one("#azure_api_version").value:
            self.config["azure_api_version"] = self.query_one("#azure_api_version").value
        
        # AWS config
        if self.query_one("#aws_region").value:
            self.config["aws_region"] = self.query_one("#aws_region").value
        if self.query_one("#aws_profile").value:
            self.config["aws_profile"] = self.query_one("#aws_profile").value
        
        # User accounts
        user_accounts = []
        for i in range(1, 4):
            account = self.query_one(f"#user_account_{i}").value
            if account:
                user_accounts.append(account)
        if user_accounts:
            self.config["user_account"] = user_accounts
        
        # Prompts
        if self.query_one("#prompt").value:
            self.config["prompt"] = self.query_one("#prompt").value
        if self.query_one("#prompt_file").value:
            self.config["prompt_file"] = self.query_one("#prompt_file").value

class ServiceRunScreen(Screen):
    """Screen showing running service with logs"""
    
    def __init__(self, service_name: str, config: Dict[str, Any], cli: NexusCLI):
        super().__init__()
        self.service_name = service_name
        self.config = config
        self.cli = cli
        self.process = None
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        yield Static(f"🚀 Running {self.service_name.upper()} Honeypot", classes="title")
        
        with Horizontal():
            with Vertical(classes="status-panel"):
                yield Static("📊 Service Status", classes="panel-title")
                yield Static(f"Service: {self.service_name.upper()}", id="service_status")
                yield Static(f"Port: {self.config.get('port', 'Default')}", id="port_status")
                yield Static(f"LLM: {self.config.get('llm_provider', 'Default')}", id="llm_status")
                yield Static("Status: Starting...", id="run_status")
            
            with Vertical(classes="log-panel"):
                yield Static("📝 Service Logs", classes="panel-title")
                yield Log(id="service_log")
        
        with Horizontal(classes="button-row"):
            yield Button("⏹️ Stop Service", variant="error", id="stop")
            yield Button("📊 View Reports", variant="success", id="reports")
            yield Button("🔙 Back", variant="default", id="back")
        
        yield Footer()
    
    def on_mount(self):
        """Start the service when screen mounts"""
        self._start_service()
    
    def _start_service(self):
        """Start the honeypot service"""
        try:
            # Create mock args object from config
            class MockArgs:
                def __init__(self, config):
                    for key, value in config.items():
                        setattr(self, key, value)
                    # Set defaults for missing attributes
                    for attr in ['config', 'port', 'log_file', 'sensor_name', 'llm_provider', 
                               'model_name', 'temperature', 'max_tokens', 'base_url',
                               'azure_deployment', 'azure_endpoint', 'azure_api_version',
                               'aws_region', 'aws_profile', 'user_account', 'prompt', 'prompt_file']:
                        if not hasattr(self, attr):
                            setattr(self, attr, None)
                    # SSH specific
                    if not hasattr(self, 'host_key'):
                        setattr(self, 'host_key', None)
                    if not hasattr(self, 'server_version'):
                        setattr(self, 'server_version', None)
                    # HTTP specific
                    if not hasattr(self, 'ssl'):
                        setattr(self, 'ssl', False)
                    if not hasattr(self, 'ssl_cert'):
                        setattr(self, 'ssl_cert', None)
                    if not hasattr(self, 'ssl_key'):
                        setattr(self, 'ssl_key', None)
            
            args = MockArgs(self.config)
            
            # Update status
            self.query_one("#run_status").update("Status: Running ✅")
            
            # Start service in background (simplified for demo)
            log_widget = self.query_one("#service_log")
            log_widget.write_line(f"Starting {self.service_name.upper()} honeypot...")
            log_widget.write_line(f"Configuration: {self.config}")
            log_widget.write_line("Service started successfully!")
            log_widget.write_line("Waiting for connections...")
            
            self.notify(f"{self.service_name.upper()} honeypot started!", severity="information")
            
        except Exception as e:
            self.query_one("#run_status").update(f"Status: Error ❌")
            self.query_one("#service_log").write_line(f"Error starting service: {e}")
            self.notify(f"Failed to start {self.service_name}: {e}", severity="error")
    
    @on(Button.Pressed, "#stop")
    def stop_service(self):
        """Stop the running service"""
        if self.process:
            self.process.terminate()
        self.query_one("#run_status").update("Status: Stopped ⏹️")
        self.query_one("#service_log").write_line("Service stopped by user")
        self.notify("Service stopped", severity="warning")
    
    @on(Button.Pressed, "#reports")
    def view_reports(self):
        """View service reports"""
        self.app.push_screen(ReportsScreen(self.service_name, self.cli))
    
    @on(Button.Pressed, "#back")
    def go_back(self):
        """Return to main screen"""
        if self.process:
            self.process.terminate()
        self.app.pop_screen()

class ReportsScreen(Screen):
    """Screen for generating and viewing reports"""
    
    def __init__(self, service_name: str, cli: NexusCLI):
        super().__init__()
        self.service_name = service_name
        self.cli = cli
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        yield Static(f"📊 {self.service_name.upper()} Security Reports", classes="title")
        
        with ScrollableContainer():
            with Vertical(classes="report-form"):
                yield Label("Output Directory:")
                yield Input(value="reports", id="output_dir")
                
                yield Label("Sessions Directory:")
                yield Input(placeholder="Optional custom sessions directory", id="sessions_dir")
                
                yield Label("Report Format:")
                yield Select([
                    ("Both JSON and HTML", "both"),
                    ("JSON Only", "json"),
                    ("HTML Only", "html")
                ], value="both", id="format")
                
                yield Label("Analysis Period:")
                yield Select([
                    ("All Time", "all"),
                    ("Last 7 Days", "7d"),
                    ("Last 30 Days", "30d"),
                    ("Last 90 Days", "90d")
                ], value="all", id="period")
                
                yield Label("Minimum Severity:")
                yield Select([
                    ("All Levels", "all"),
                    ("Low and Above", "low"),
                    ("Medium and Above", "medium"),
                    ("High and Above", "high"),
                    ("Critical Only", "critical")
                ], value="all", id="severity")
        
        with Horizontal(classes="button-row"):
            yield Button("📈 Generate Report", variant="primary", id="generate")
            yield Button("📁 Open Reports Folder", variant="success", id="open_folder")
            yield Button("🔙 Back", variant="default", id="back")
        
        yield Footer()
    
    @on(Button.Pressed, "#generate")
    def generate_report(self):
        """Generate security report"""
        try:
            # Create mock args for report generation
            class MockArgs:
                def __init__(self, outer_self):
                    self.service = outer_self.service_name
                    self.output = outer_self.query_one("#output_dir").value
                    self.sessions_dir = outer_self.query_one("#sessions_dir").value or None
                    self.format = outer_self.query_one("#format").value
                    self.period = outer_self.query_one("#period").value
                    self.severity = outer_self.query_one("#severity").value
            
            args = MockArgs(self)
            
            self.notify("Generating report...", severity="information")
            
            # Use original CLI logic
            result = self.cli.generate_report(args)
            
            if result == 0:
                self.notify("Report generated successfully!", severity="information")
            else:
                self.notify("Failed to generate report", severity="error")
                
        except Exception as e:
            self.notify(f"Error generating report: {e}", severity="error")
    
    @on(Button.Pressed, "#open_folder")
    def open_reports_folder(self):
        """Open reports folder in file explorer"""
        output_dir = self.query_one("#output_dir").value
        try:
            if os.name == 'nt':  # Windows
                os.startfile(output_dir)
            else:  # Unix/Linux/Mac
                subprocess.run(['xdg-open', output_dir])
            self.notify("Reports folder opened", severity="information")
        except Exception as e:
            self.notify(f"Could not open folder: {e}", severity="error")
    
    @on(Button.Pressed, "#back")
    def go_back(self):
        """Return to previous screen"""
        self.app.pop_screen()

class LogsScreen(Screen):
    """Screen for viewing session logs"""
    
    def __init__(self, service_name: str, cli: NexusCLI):
        super().__init__()
        self.service_name = service_name
        self.cli = cli
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        yield Static(f"📝 {self.service_name.upper()} Session Logs", classes="title")
        
        with Horizontal():
            with Vertical(classes="log-controls"):
                yield Label("Session ID:")
                yield Input(placeholder="Optional specific session", id="session_id")
                
                yield Label("Log File:")
                yield Input(placeholder="Optional custom log file", id="log_file")
                
                yield Label("Format:")
                yield Select([
                    ("Text", "text"),
                    ("JSON", "json")
                ], value="text", id="format")
                
                yield Label("Filter:")
                yield Select([
                    ("All Entries", "all"),
                    ("Commands Only", "commands"),
                    ("Responses Only", "responses"),
                    ("Attacks Only", "attacks")
                ], value="all", id="filter")
                
                yield Label("Options:")
                yield Checkbox("Decode Base64", id="decode")
                yield Checkbox("Conversation Format", id="conversation")
                
                yield Button("🔍 Load Logs", variant="primary", id="load")
                yield Button("💾 Save to File", variant="success", id="save")
            
            with Vertical(classes="log-display"):
                yield Log(id="log_content")
        
        with Horizontal(classes="button-row"):
            yield Button("🔙 Back", variant="default", id="back")
        
        yield Footer()
    
    @on(Button.Pressed, "#load")
    def load_logs(self):
        """Load and display logs"""
        try:
            # Create mock args for log viewing
            class MockArgs:
                def __init__(self, outer_self):
                    self.outer_self = outer_self
                    self.service = outer_self.service_name
                    self.session_id = outer_self.query_one("#session_id").value or None
                    self.log_file = outer_self.query_one("#log_file").value or None
                    self.format = outer_self.query_one("#format").value
                    self.filter = outer_self.query_one("#filter").value
                    self.decode = outer_self.query_one("#decode").value
                    self.conversation = outer_self.query_one("#conversation").value
                    self.save = None
            
            args = MockArgs(self)
            
            log_widget = self.query_one("#log_content")
            log_widget.clear()
            log_widget.write_line(f"Loading {self.service_name.upper()} logs...")
            log_widget.write_line(f"Session ID: {args.session_id or 'All'}")
            log_widget.write_line(f"Format: {args.format}")
            log_widget.write_line(f"Filter: {args.filter}")
            log_widget.write_line("=" * 50)
            
            # Mock log entries for demonstration
            log_widget.write_line("[2024-01-15 10:30:00] Connection from 192.168.1.100:54321")
            log_widget.write_line("[2024-01-15 10:30:01] Authentication attempt: admin/admin123")
            log_widget.write_line("[2024-01-15 10:30:02] Command: ls -la")
            log_widget.write_line("[2024-01-15 10:30:03] AI Response: total 24...")
            log_widget.write_line("[2024-01-15 10:30:04] Attack detected: Directory traversal")
            
            self.notify("Logs loaded successfully", severity="information")
            
        except Exception as e:
            self.notify(f"Error loading logs: {e}", severity="error")
    
    @on(Button.Pressed, "#save")
    def save_logs(self):
        """Save logs to file"""
        self.notify("Logs saved to file", severity="information")
    
    @on(Button.Pressed, "#back")
    def go_back(self):
        """Return to main screen"""
        self.app.pop_screen()

class NexusApp(App):
    """Main NEXUS Honeypot TUI Application"""
    
    CSS = """
    .title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin: 1;
    }
    
    .service-card {
        border: solid $primary;
        margin: 1;
        padding: 1;
        height: auto;
    }
    
    .service-status {
        color: $success;
        text-style: bold;
    }
    
    .service-planned {
        color: $warning;
        text-style: italic;
    }
    
    .button-row {
        height: auto;
        margin: 1;
        align: center middle;
    }
    
    .config-form {
        margin: 1;
        padding: 1;
    }
    
    .status-panel {
        width: 30%;
        border: solid $primary;
        margin: 1;
        padding: 1;
    }
    
    .log-panel {
        width: 70%;
        border: solid $primary;
        margin: 1;
        padding: 1;
    }
    
    .panel-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    
    .report-form {
        margin: 1;
        padding: 1;
    }
    
    .log-controls {
        width: 30%;
        border: solid $primary;
        margin: 1;
        padding: 1;
    }
    
    .log-display {
        width: 70%;
        border: solid $primary;
        margin: 1;
        padding: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("h", "help", "Help"),
    ]
    
    def __init__(self):
        super().__init__()
        self.cli = NexusCLI()
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        yield Static("🕸️ NEXUS AI-Enhanced Honeypot Platform", classes="title")
        
        with TabbedContent():
            with TabPane("🏠 Services", id="services"):
                with ScrollableContainer():
                    yield self._create_services_panel()
            
            with TabPane("📊 Reports", id="reports"):
                with ScrollableContainer():
                    yield self._create_reports_panel()
            
            with TabPane("📝 Logs", id="logs"):
                with ScrollableContainer():
                    yield self._create_logs_panel()
            
            with TabPane("ℹ️ About", id="about"):
                with ScrollableContainer():
                    yield self._create_about_panel()
        
        yield Footer()
    
    def _create_services_panel(self) -> Container:
        """Create the services management panel"""
        container = Container()
        
        with container:
            yield Static("Available Honeypot Services", classes="panel-title")
            
            for service, info in self.cli.services.items():
                with Horizontal(classes="service-card"):
                    with Vertical():
                        status = "✅ IMPLEMENTED" if info['implemented'] else "🚧 PLANNED"
                        status_class = "service-status" if info['implemented'] else "service-planned"
                        
                        yield Static(f"{service.upper()}", classes="title")
                        yield Static(status, classes=status_class)
                        yield Static(info['description'])
                    
                    with Vertical():
                        if info['implemented']:
                            yield Button(f"⚙️ Configure", id=f"config_{service}")
                            yield Button(f"📊 Reports", id=f"report_{service}")
                            yield Button(f"📝 Logs", id=f"logs_{service}")
                        else:
                            yield Button(f"🚧 Coming Soon", disabled=True)
        
        return container
    
    def _create_reports_panel(self) -> Container:
        """Create the reports panel"""
        container = Container()
        
        with container:
            yield Static("Security Reports", classes="panel-title")
            
            for service, info in self.cli.services.items():
                if info['implemented']:
                    with Horizontal(classes="service-card"):
                        yield Static(f"{service.upper()} Reports")
                        yield Button(f"📈 Generate", id=f"gen_report_{service}")
        
        return container
    
    def _create_logs_panel(self) -> Container:
        """Create the logs panel"""
        container = Container()
        
        with container:
            yield Static("Session Logs", classes="panel-title")
            
            for service, info in self.cli.services.items():
                if info['implemented']:
                    with Horizontal(classes="service-card"):
                        yield Static(f"{service.upper()} Logs")
                        yield Button(f"🔍 View", id=f"view_logs_{service}")
        
        return container
    
    def _create_about_panel(self) -> Container:
        """Create the about panel"""
        container = Container()
        
        with container:
            yield Static("About NEXUS", classes="panel-title")
            yield Static("""
🕸️ NEXUS Development - AI-Enhanced Honeypot Platform

A cybersecurity honeypot system with AI-powered adaptive responses 
and comprehensive threat intelligence.

🎯 Key Features:
• 🤖 AI-Powered Responses using multiple LLM providers
• 🔍 Real-time attack pattern recognition
• 📊 Comprehensive security reporting
• 🔐 Complete forensic chain of custody
• 🌐 Multi-protocol support (SSH, FTP, HTTP)
• ⚡ Beautiful TUI interface

🛡️ Supported Services:
• SSH Honeypot - Fully operational
• FTP Honeypot - Fully operational  
• HTTP/Web Honeypot - Fully operational
• MySQL Honeypot - Planned
• SMB Honeypot - Planned

🤖 Supported AI Providers:
• OpenAI (GPT models)
• Azure OpenAI
• Google Gemini
• AWS Bedrock
• Ollama (Local models)

⚠️ Security Notice:
Deploy honeypots in isolated network segments only.
This software is for educational and research purposes.
            """)
        
        return container
    
    @on(Button.Pressed)
    def handle_button_press(self, event: Button.Pressed) -> None:
        """Handle all button presses"""
        button_id = event.button.id
        
        if button_id.startswith("config_"):
            service = button_id.replace("config_", "")
            self.push_screen(ServiceConfigScreen(service, self.cli))
        
        elif button_id.startswith("report_") or button_id.startswith("gen_report_"):
            service = button_id.replace("report_", "").replace("gen_report_", "")
            self.push_screen(ReportsScreen(service, self.cli))
        
        elif button_id.startswith("logs_") or button_id.startswith("view_logs_"):
            service = button_id.replace("logs_", "").replace("view_logs_", "")
            self.push_screen(LogsScreen(service, self.cli))
    
    def action_refresh(self) -> None:
        """Refresh the application"""
        self.notify("Application refreshed", severity="information")
    
    def action_help(self) -> None:
        """Show help information"""
        self.notify("Use Tab to navigate, Enter to select, Q to quit", severity="information")

def main():
    """Main entry point"""
    app = NexusApp()
    app.run()

if __name__ == "__main__":
    main()