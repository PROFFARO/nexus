"""
NEXUS Honeypot CLI - Centralized command-line interface for all service emulators
"""

import argparse
import sys
import os
import subprocess
from pathlib import Path

class NexusCLI:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.services = {
            'ssh': {
                'path': self.base_dir / 'service_emulators' / 'SSH' / 'ssh_server.py',
                'implemented': True,
                'description': 'SSH honeypot with AI-powered responses'
            },
            'ftp': {
                'path': self.base_dir / 'service_emulators' / 'FTP' / 'ftp_server.py',
                'implemented': True,
                'description': 'FTP honeypot with AI-powered responses'
            },
            'http': {
                'path': self.base_dir / 'service_emulators' / 'HTTP' / 'http_server.py',
                'implemented': True,
                'description': 'HTTP/Web honeypot with AI-powered responses'
            },
            'mysql': {
                'path': self.base_dir / 'service_emulators' / 'MySQL' / 'mysql_server.py',
                'implemented': True,
                'description': 'MySQL database honeypot with AI-powered responses'
            }
        }

    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='NEXUS AI-Enhanced Honeypot Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='Use "nexus_cli.py <command> --help" for more information on a specific command.'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # List services command
        list_parser = subparsers.add_parser('list', help='List all available services')
        
        # Report generation command
        report_parser = subparsers.add_parser('report', help='Generate security reports')
        report_parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql'], 
                                 help='Service to generate report for')
        report_parser.add_argument('--output', '-o', default='reports', help='Output directory')
        report_parser.add_argument('--sessions-dir', '-s', help='Sessions directory (default: service-specific)')
        report_parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', 
                                 help='Report format')
        report_parser.add_argument('--period', help='Analysis period (e.g., 7d, 30d, all)')
        report_parser.add_argument('--severity', choices=['all', 'low', 'medium', 'high', 'critical'], 
                                 default='all', help='Minimum severity level')
        
        # ML Analysis options for reports
        report_parser.add_argument('--ml-enhanced', action='store_true',
                                 help='Generate ML-enhanced reports with anomaly detection')
        report_parser.add_argument('--include-ml-insights', action='store_true',
                                 help='Include detailed ML insights in reports')
        report_parser.add_argument('--anomaly-threshold', type=float, default=0.7,
                                 help='Anomaly detection threshold for reports (0.0-1.0, default: 0.7)')
        
        # Logs command for viewing session conversations
        logs_parser = subparsers.add_parser('logs', help='View and analyze session logs')
        logs_parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql'],
                               help='Service to view logs for')
        logs_parser.add_argument('--session-id', '-i', help='Specific session ID to view')
        logs_parser.add_argument('--log-file', '-f', help='Log file path (default: service-specific)')
        logs_parser.add_argument('--decode', '-d', action='store_true', 
                               help='Decode base64 encoded details')
        logs_parser.add_argument('--conversation', '-c', action='store_true',
                               help='Show full conversation format')
        logs_parser.add_argument('--save', '-s', help='Save analysis to file (absolute or relative path)')
        logs_parser.add_argument('--format', choices=['text', 'json'], default='text',
                               help='Output format (text or json)')
        logs_parser.add_argument('--filter', choices=['all', 'commands', 'responses', 'attacks', 'anomalies'],
                               default='all', help='Filter log entries')
        
        # ML Analysis options for logs
        logs_parser.add_argument('--ml-analysis', '--ml', action='store_true', 
                               help='Enable ML-based anomaly detection and analysis')
        logs_parser.add_argument('--anomaly-threshold', type=float, default=0.7,
                               help='Anomaly detection threshold (0.0-1.0, default: 0.7)')
        logs_parser.add_argument('--ml-insights', action='store_true',
                               help='Show detailed ML insights and statistics')
        logs_parser.add_argument('--high-risk-only', action='store_true',
                               help='Show only high-risk sessions (anomaly score > 0.9)')
        
        # SSH service parser
        ssh_parser = subparsers.add_parser('ssh', help='Start SSH honeypot')
        self._add_ssh_arguments(ssh_parser)
        # FTP service parser
        ftp_parser = subparsers.add_parser('ftp', help='Start FTP honeypot')
        self._add_ftp_arguments(ftp_parser)
        # HTTP service parser
        http_parser = subparsers.add_parser('http', help='Start HTTP honeypot')
        self._add_http_arguments(http_parser)
        # MySQL service parser
        mysql_parser = subparsers.add_parser('mysql', help='Start MySQL honeypot')
        self._add_mysql_arguments(mysql_parser)
        
        # ML commands
        ml_parser = subparsers.add_parser('ml', help='Machine Learning operations')
        ml_subparsers = ml_parser.add_subparsers(dest='ml_command', help='ML commands')
        
        # ML extract command
        extract_parser = ml_subparsers.add_parser('extract', help='Extract features from datasets')
        extract_parser.add_argument('service', choices=['ssh', 'http', 'ftp', 'mysql', 'all'],
                                  help='Service to extract features for')
        extract_parser.add_argument('--datasets-dir', default='datasets', help='Datasets directory')
        extract_parser.add_argument('--output', '-o', help='Output file path')
        
        # ML train command
        train_parser = ml_subparsers.add_parser('train', help='Train ML models')
        train_parser.add_argument('service', choices=['ssh', 'http', 'ftp', 'mysql', 'all'],
                                help='Service to train models for')
        train_parser.add_argument('--algorithm', choices=['isolation_forest', 'one_class_svm', 'lof', 'hdbscan', 'kmeans', 'xgboost', 'all'],
                                default='all', help='ML algorithm to train')
        train_parser.add_argument('--data', help='Training data file path')
        train_parser.add_argument('--test-size', type=float, default=0.2, help='Test set size (0.0-1.0)')
        
        # ML evaluate command
        eval_parser = ml_subparsers.add_parser('eval', help='Evaluate trained models')
        eval_parser.add_argument('service', choices=['ssh', 'http', 'ftp', 'mysql'],
                               help='Service to evaluate models for')
        eval_parser.add_argument('--test-data', help='Test data file path')
        eval_parser.add_argument('--model', help='Specific model to evaluate')
        
        # ML predict command
        predict_parser = ml_subparsers.add_parser('predict', help='Make predictions with trained models')
        predict_parser.add_argument('service', choices=['ssh', 'http', 'ftp', 'mysql'],
                                  help='Service to make predictions for')
        predict_parser.add_argument('--input', required=True, help='Input data file or single command/query')
        predict_parser.add_argument('--output', help='Output file for predictions')
        
        # ML update-models command
        update_parser = ml_subparsers.add_parser('update-models', help='Update/retrain models')
        update_parser.add_argument('service', choices=['ssh', 'http', 'ftp', 'mysql', 'all'],
                                 help='Service to update models for')
        update_parser.add_argument('--model-path', help='Path to new model files')
        update_parser.add_argument('--force', action='store_true', help='Force model update')
        
        # Management commands
        status_parser = subparsers.add_parser('status', help='Check service status')
        status_parser.add_argument('service', nargs='?', help='Specific service to check (optional)')
        
        stop_parser = subparsers.add_parser('stop-all', help='Stop all running services')
        stop_parser.add_argument('--force', action='store_true', help='Force stop processes')
        
        start_parser = subparsers.add_parser('start-all', help='Start all implemented services')
        start_parser.add_argument('--config-dir', help='Directory containing service configs')
        start_parser.add_argument('--llm-provider', choices=['openai', 'azure', 'ollama', 'aws', 'gemini'], help='LLM provider for all services')
        start_parser.add_argument('--model-name', help='LLM model name for all services')
        
        
        return parser

    def _add_ftp_arguments(self, parser):
        """Add FTP-specific arguments"""
        # Configuration
        parser.add_argument('-c', '--config', help='Configuration file path')
        parser.add_argument('-H', '--host', help='Host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)')
        parser.add_argument('-P', '--port', type=int, help='FTP port (default: 2121)')
        parser.add_argument('-L', '--log-file', help='Log file path')
        parser.add_argument('-S', '--sensor-name', help='Sensor name for logging')
        
        # LLM Configuration
        parser.add_argument('--llm-provider', choices=['openai', 'azure', 'ollama', 'aws', 'gemini'],
                          help='LLM provider')
        parser.add_argument('--model-name', help='LLM model name')
        parser.add_argument('--temperature', type=float, help='LLM temperature (0.0-2.0)')
        parser.add_argument('--max-tokens', type=int, help='Maximum tokens for LLM')
        parser.add_argument('--base-url', help='Base URL for Ollama/custom providers')
        
        # Azure OpenAI specific
        parser.add_argument('--azure-deployment', help='Azure OpenAI deployment name')
        parser.add_argument('--azure-endpoint', help='Azure OpenAI endpoint')
        parser.add_argument('--azure-api-version', help='Azure OpenAI API version')
        
        # AWS specific
        parser.add_argument('--aws-region', help='AWS region')
        parser.add_argument('--aws-profile', help='AWS credentials profile')
        
        # User accounts
        parser.add_argument('-u', '--user-account', action='append',
                          help='User account (username=password). Can be repeated')
        
        # Prompts
        parser.add_argument('-p', '--prompt', help='System prompt text')
        parser.add_argument('-f', '--prompt-file', help='System prompt file')

    def _add_http_arguments(self, parser):
        """Add HTTP-specific arguments"""
        # Configuration
        parser.add_argument('-c', '--config', help='Configuration file path')
        parser.add_argument('-H', '--host', help='Host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)')
        parser.add_argument('-P', '--port', type=int, help='HTTP port (default: 8080)')
        parser.add_argument('-L', '--log-file', help='Log file path')
        parser.add_argument('-S', '--sensor-name', help='Sensor name for logging')
        
        # SSL/HTTPS Configuration
        parser.add_argument('--ssl', action='store_true', help='Enable SSL/HTTPS')
        parser.add_argument('--ssl-cert', help='SSL certificate file')
        parser.add_argument('--ssl-key', help='SSL private key file')
        
        # LLM Configuration
        parser.add_argument('--llm-provider', choices=['openai', 'azure', 'ollama', 'aws', 'gemini'],
                          help='LLM provider')
        parser.add_argument('--model-name', help='LLM model name')
        parser.add_argument('--temperature', type=float, help='LLM temperature (0.0-2.0)')
        parser.add_argument('--max-tokens', type=int, help='Maximum tokens for LLM')
        parser.add_argument('--base-url', help='Base URL for Ollama/custom providers')
        
        # Azure OpenAI specific
        parser.add_argument('--azure-deployment', help='Azure OpenAI deployment name')
        parser.add_argument('--azure-endpoint', help='Azure OpenAI endpoint')
        parser.add_argument('--azure-api-version', help='Azure OpenAI API version')
        
        # AWS specific
        parser.add_argument('--aws-region', help='AWS region')
        parser.add_argument('--aws-profile', help='AWS credentials profile')
        
        # User accounts
        parser.add_argument('-u', '--user-account', action='append',
                          help='User account (username=password). Can be repeated')
        
        # Prompts
        parser.add_argument('-p', '--prompt', help='System prompt text')
        parser.add_argument('-f', '--prompt-file', help='System prompt file')

    def _add_ssh_arguments(self, parser):
        """Add SSH-specific arguments"""
        # Configuration
        parser.add_argument('-c', '--config', help='Configuration file path')
        parser.add_argument('-H', '--host', help='Host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)')
        parser.add_argument('-P', '--port', type=int, help='SSH port (default: 8022)')
        parser.add_argument('-k', '--host-key', help='SSH host private key file')
        parser.add_argument('-v', '--server-version', help='SSH server version string')
        parser.add_argument('-L', '--log-file', help='Log file path')
        parser.add_argument('-S', '--sensor-name', help='Sensor name for logging')
        
        # LLM Configuration
        parser.add_argument('--llm-provider', choices=['openai', 'azure', 'ollama', 'aws', 'gemini'],
                          help='LLM provider')
        parser.add_argument('--model-name', help='LLM model name')
        parser.add_argument('--temperature', type=float, help='LLM temperature (0.0-2.0)')
        parser.add_argument('--max-tokens', type=int, help='Maximum tokens for LLM')
        parser.add_argument('--base-url', help='Base URL for Ollama/custom providers')
        
        # Azure OpenAI specific
        parser.add_argument('--azure-deployment', help='Azure OpenAI deployment name')
        parser.add_argument('--azure-endpoint', help='Azure OpenAI endpoint')
        parser.add_argument('--azure-api-version', help='Azure OpenAI API version')
        
        # AWS specific
        parser.add_argument('--aws-region', help='AWS region')
        parser.add_argument('--aws-profile', help='AWS credentials profile')
        
        # User accounts
        parser.add_argument('-u', '--user-account', action='append',
                          help='User account (username=password). Can be repeated')
        
        # Prompts
        parser.add_argument('-p', '--prompt', help='System prompt text')
        parser.add_argument('-f', '--prompt-file', help='System prompt file')

    def _add_mysql_arguments(self, parser):
        """Add MySQL-specific arguments"""
        # Configuration
        parser.add_argument('-c', '--config', help='Configuration file path')
        parser.add_argument('-H', '--host', help='Host to bind to (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)')
        parser.add_argument('-P', '--port', type=int, help='MySQL port (default: 3306)')
        parser.add_argument('-L', '--log-file', help='Log file path')
        parser.add_argument('-S', '--sensor-name', help='Sensor name for logging')
        
        # LLM Configuration
        parser.add_argument('--llm-provider', choices=['openai', 'azure', 'ollama', 'aws', 'gemini'],
                          help='LLM provider')
        parser.add_argument('--model-name', help='LLM model name')
        parser.add_argument('--temperature', type=float, help='LLM temperature (0.0-2.0)')
        parser.add_argument('--max-tokens', type=int, help='Maximum tokens for LLM')
        parser.add_argument('--base-url', help='Base URL for Ollama/custom providers')
        
        # Azure OpenAI specific
        parser.add_argument('--azure-deployment', help='Azure OpenAI deployment name')
        parser.add_argument('--azure-endpoint', help='Azure OpenAI endpoint')
        parser.add_argument('--azure-api-version', help='Azure OpenAI API version')
        
        # AWS specific
        parser.add_argument('--aws-region', help='AWS region')
        parser.add_argument('--aws-profile', help='AWS credentials profile')
        
        # User accounts
        parser.add_argument('-u', '--user-account', action='append',
                          help='User account (username=password). Can be repeated')
        
        # Prompts
        parser.add_argument('-p', '--prompt', help='System prompt text')
        parser.add_argument('-f', '--prompt-file', help='System prompt file')

    def _build_ssh_command(self, args, ssh_script):
        """Build SSH command arguments"""
        cmd = [sys.executable, str(ssh_script)]
        
        arg_mappings = [
            (args.config, ['-c', args.config]),
            (args.host, ['-H', args.host]),
            (args.port, ['-P', str(args.port)]),
            (args.host_key, ['-k', args.host_key]),
            (args.server_version, ['-v', args.server_version]),
            (args.log_file, ['-L', args.log_file]),
            (args.sensor_name, ['-S', args.sensor_name]),
            (args.llm_provider, ['-l', args.llm_provider]),
            (args.model_name, ['-m', args.model_name]),
            (args.temperature is not None, ['-r', str(args.temperature)]),
            (args.max_tokens, ['-t', str(args.max_tokens)]),
            (args.prompt, ['-p', args.prompt]),
            (args.prompt_file, ['-f', args.prompt_file])
        ]
        
        for condition, extension in arg_mappings:
            if condition:
                cmd.extend(extension)
        
        if args.user_account:
            for account in args.user_account:
                cmd.extend(['-u', account])
        
        return cmd
    
    def _setup_environment(self, args):
        """Setup environment variables"""
        env = os.environ.copy()
        env_mappings = [
            (args.base_url, 'OLLAMA_BASE_URL'),
            (args.azure_deployment, 'AZURE_OPENAI_DEPLOYMENT'),
            (args.azure_endpoint, 'AZURE_OPENAI_ENDPOINT'),
            (args.azure_api_version, 'AZURE_OPENAI_API_VERSION'),
            (args.aws_region, 'AWS_DEFAULT_REGION'),
            (args.aws_profile, 'AWS_PROFILE')
        ]
        
        for value, key in env_mappings:
            if value:
                env[key] = value
        
        return env

    def run_ssh_service(self, args):
        """Run SSH honeypot with provided arguments"""
        if not self.services['ssh']['implemented']:
            print("Error: SSH service not implemented")
            return 1
            
        ssh_script = self.services['ssh']['path']
        if not ssh_script.exists():
            print(f"Error: SSH script not found at {ssh_script}")
            return 1
        
        cmd = self._build_ssh_command(args, ssh_script)
        env = self._setup_environment(args)
        ssh_dir = self.services['ssh']['path'].parent
        
        try:
            subprocess.run(cmd, cwd=ssh_dir, env=env)
        except KeyboardInterrupt:
            print("\nSSH honeypot stopped")
        except Exception as e:
            print(f"Error running SSH honeypot: {e}")
            return 1
        
        return 0

    def generate_report(self, args):
        """Generate security report for specific service"""
        service_info = self.services.get(args.service)
        if not service_info:
            print(f"Error: Unknown service {args.service}")
            return 1
            
        if not service_info['implemented']:
            print(f"Error: Report generation for {args.service} not implemented")
            print(f"Service {args.service.upper()} is planned but not yet available")
            return 1
        
        # Service-specific report generation
        if args.service == 'ssh':
            return self._generate_ssh_report(args)
        elif args.service == 'ftp':
            return self._generate_ftp_report(args)
        elif args.service == 'http':
            return self._generate_http_report(args)
        elif args.service == 'mysql':
            return self._generate_mysql_report(args)
        else:
            print(f"Error: Report generation not implemented for {args.service}")
            return 1
    
    def _generate_ssh_report(self, args):
        """Generate SSH-specific security report"""
        ssh_dir = self.services['ssh']['path'].parent
        sessions_dir = args.sessions_dir or str(ssh_dir / 'sessions')
        
        # Build command for SSH report generator with proper path handling
        import tempfile
        
        # Escape paths properly for Windows
        ssh_dir_escaped = str(ssh_dir).replace('\\', '\\\\')
        sessions_dir_escaped = sessions_dir.replace('\\', '\\\\')
        output_dir_escaped = args.output.replace('\\', '\\\\')
        
        script_content = f'''import sys
from pathlib import Path

# Add SSH directory to path
sys.path.insert(0, r"{ssh_dir_escaped}")

try:
    from report_generator import SSHHoneypotReportGenerator
    
    # Set logs directory to the main logs directory
    logs_dir = Path(r"{ssh_dir_escaped}").parent.parent / "logs"
    
    generator = SSHHoneypotReportGenerator(sessions_dir=r"{sessions_dir_escaped}", logs_dir=str(logs_dir))
    report_files = generator.generate_comprehensive_report(output_dir=r"{output_dir_escaped}", format_type="{args.format}")
    
    if "error" in report_files:
        print(f"Error: {{report_files['error']}}")
        sys.exit(1)
    
    print("SSH Security Report Generated Successfully!")
    if "{args.format}" in ["json", "both"]:
        print(f"JSON Report: {{report_files.get('json', 'Not generated')}}")
    if "{args.format}" in ["html", "both"]:
        print(f"HTML Report: {{report_files.get('html', 'Not generated')}}")
    
except Exception as e:
    print(f"Error: {{e}}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
        
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            temp_script = f.name
        
        cmd = [sys.executable, temp_script]
        
        try:
            print(f"[INFO] Generating SSH security report...")
            print(f"[INFO] Sessions directory: {sessions_dir}")
            print(f"[INFO] Output directory: {args.output}")
            print(f"[INFO] Format: {args.format}")
            
            result = subprocess.run(cmd, cwd=ssh_dir, capture_output=True, text=True, encoding='utf-8')
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            if result.returncode != 0:
                print(f"[ERROR] Report generation failed with exit code {result.returncode}")
                return 1
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_script)
            except:
                pass
        
        return 0

    def _generate_ftp_report(self, args):
        """Generate FTP-specific security report"""
        ftp_dir = self.services['ftp']['path'].parent
        sessions_dir = args.sessions_dir or str(ftp_dir / 'sessions')
        
        # Build command for FTP report generator with proper path handling
        import tempfile
        
        # Escape paths properly for Windows
        ftp_dir_escaped = str(ftp_dir).replace('\\', '\\\\')
        sessions_dir_escaped = sessions_dir.replace('\\', '\\\\')
        output_dir_escaped = args.output.replace('\\', '\\\\')
        
        script_content = f'''import sys
from pathlib import Path

# Add FTP directory to path
sys.path.insert(0, r"{ftp_dir_escaped}")

try:
    from report_generator import FTPHoneypotReportGenerator
    
    generator = FTPHoneypotReportGenerator(sessions_dir=r"{sessions_dir_escaped}")
    report_files = generator.generate_comprehensive_report(output_dir=r"{output_dir_escaped}", format_type="{args.format}")
    
    if "error" in report_files:
        print(f"[ERROR] {{report_files['error']}}")
        sys.exit(1)
    
    print("[SUCCESS] FTP Security Report Generated Successfully!")
    if "{args.format}" in ["json", "both"]:
        print(f"[INFO] JSON Report: {{report_files.get('json', 'Not generated')}}")
    if "{args.format}" in ["html", "both"]:
        print(f"[INFO] HTML Report: {{report_files.get('html', 'Not generated')}}")
    
except Exception as e:
    print(f"[ERROR] {{e}}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
        
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            temp_script = f.name
        
        cmd = [sys.executable, temp_script]
        
        try:
            print(f"[INFO] Generating FTP security report...")
            print(f"[INFO] Sessions directory: {sessions_dir}")
            print(f"[INFO] Output directory: {args.output}")
            print(f"[INFO] Format: {args.format}")
            
            result = subprocess.run(cmd, cwd=ftp_dir, capture_output=True, text=True, encoding='utf-8')
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            if result.returncode != 0:
                print(f"[ERROR] Report generation failed with exit code {result.returncode}")
                return 1
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_script)
            except:
                pass
        
        return 0
    
    def _generate_http_report(self, args):
        """Generate HTTP-specific security report"""
        http_dir = self.services['http']['path'].parent
        sessions_dir = args.sessions_dir or str(http_dir / 'sessions')
        
        # Build command for HTTP report generator with proper path handling
        import tempfile
        
        # Escape paths properly for Windows
        http_dir_escaped = str(http_dir).replace('\\', '\\\\')
        sessions_dir_escaped = sessions_dir.replace('\\', '\\\\')
        output_dir_escaped = args.output.replace('\\', '\\\\')
        
        script_content = f'''import sys
from pathlib import Path

# Add HTTP directory to path
sys.path.insert(0, r"{http_dir_escaped}")

try:
    from report_generator import HTTPHoneypotReportGenerator
    
    generator = HTTPHoneypotReportGenerator(sessions_dir=r"{sessions_dir_escaped}")
    report_files = generator.generate_comprehensive_report(output_dir=r"{output_dir_escaped}", format_type="{args.format}")
    
    if "error" in report_files:
        print(f"[ERROR] {{report_files['error']}}")
        sys.exit(1)
    
    print("[SUCCESS] HTTP Security Report Generated Successfully!")
    if "{args.format}" in ["json", "both"]:
        print(f"[INFO] JSON Report: {{report_files.get('json', 'Not generated')}}")
    if "{args.format}" in ["html", "both"]:
        print(f"[INFO] HTML Report: {{report_files.get('html', 'Not generated')}}")
    
except Exception as e:
    print(f"[ERROR] {{e}}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
        
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            temp_script = f.name
        
        cmd = [sys.executable, temp_script]
        
        try:
            print(f"[INFO] Generating HTTP security report...")
            print(f"[INFO] Sessions directory: {sessions_dir}")
            print(f"[INFO] Output directory: {args.output}")
            print(f"[INFO] Format: {args.format}")
            
            result = subprocess.run(cmd, cwd=http_dir, capture_output=True, text=True, encoding='utf-8')
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            if result.returncode != 0:
                print(f"[ERROR] Report generation failed with exit code {result.returncode}")
                return 1
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_script)
            except:
                pass
        
        return 0
    
    def _generate_mysql_report(self, args):
        """Generate MySQL-specific security report"""
        mysql_dir = self.services['mysql']['path'].parent
        sessions_dir = args.sessions_dir or str(mysql_dir / 'sessions')
        
        # Use Python script execution instead of inline code to avoid path escaping issues
        # Escape paths properly for Windows
        mysql_dir_escaped = str(mysql_dir).replace('\\', '\\\\')
        sessions_dir_escaped = sessions_dir.replace('\\', '\\\\')
        output_dir_escaped = args.output.replace('\\', '\\\\')
        
        script_content = f'''import sys
import os
from pathlib import Path

# Add MySQL directory to path
sys.path.insert(0, r"{mysql_dir_escaped}")

try:
    from report_generator import MySQLHoneypotReportGenerator
    
    # Set logs directory to the main logs directory
    logs_dir = Path(r"{mysql_dir_escaped}").parent.parent / "logs"
    generator = MySQLHoneypotReportGenerator(sessions_dir=r"{sessions_dir_escaped}", logs_dir=str(logs_dir))
    report_files = generator.generate_comprehensive_report(output_dir=r"{output_dir_escaped}")
    
    if "error" in report_files:
        print(f"[ERROR] {{report_files['error']}}")
        sys.exit(1)
    
    print("[SUCCESS] MySQL Security Report Generated Successfully!")
    if "{args.format}" in ["json", "both"]:
        print(f"[INFO] JSON Report: {{report_files.get('json', 'Not generated')}}")
    if "{args.format}" in ["html", "both"]:
        print(f"[INFO] HTML Report: {{report_files.get('html', 'Not generated')}}")
    
    # Verify HTML file was created and has content
    html_file = report_files.get('html')
    if html_file and os.path.exists(html_file):
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
        if len(content) < 100:
            print(f"[WARNING] HTML file appears to be empty or truncated")
        else:
            print(f"[INFO] HTML report verified: {{len(content)}} characters")
    
except Exception as e:
    print(f"[ERROR] {{e}}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
        
        # Write script to temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            temp_script = f.name
        
        try:
            print(f"[INFO] Generating MySQL security report...")
            print(f"[INFO] Sessions directory: {sessions_dir}")
            print(f"[INFO] Output directory: {args.output}")
            print(f"[INFO] Format: {args.format}")
            
            # Run the temporary script
            result = subprocess.run([sys.executable, temp_script], 
                                  cwd=mysql_dir, 
                                  capture_output=True, 
                                  text=True, 
                                  encoding='utf-8',
                                  env=dict(os.environ, PYTHONIOENCODING='utf-8'))
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            if result.returncode != 0:
                print(f"[ERROR] Report generation failed with exit code {result.returncode}")
                return 1
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_script)
            except (OSError, FileNotFoundError):
                pass
        
        return 0
    
    def _generate_smb_report(self, args):
        """Generate SMB-specific security report"""
        smb_dir = self.services['smb']['path'].parent
        sessions_dir = args.sessions_dir or str(smb_dir / 'sessions')
        
        # Build command for SMB report generator with proper path handling
        import tempfile
        
        # Escape paths properly for Windows
        smb_dir_escaped = str(smb_dir).replace('\\', '\\\\')
        sessions_dir_escaped = sessions_dir.replace('\\', '\\\\')
        output_dir_escaped = args.output.replace('\\', '\\\\')
        
        script_content = f'''import sys
from pathlib import Path

# Add SMB directory to path
sys.path.insert(0, r"{smb_dir_escaped}")

try:
    from report_generator import SMBHoneypotReportGenerator
    
    generator = SMBHoneypotReportGenerator(sessions_dir=r"{sessions_dir_escaped}")
    report_files = generator.generate_comprehensive_report(output_dir=r"{output_dir_escaped}", format_type="{args.format}")
    
    if "error" in report_files:
        print(f"[ERROR] {{report_files['error']}}")
        sys.exit(1)
    
    print("[SUCCESS] SMB Security Report Generated Successfully!")
    if "{args.format}" in ["json", "both"]:
        print(f"[INFO] JSON Report: {{report_files.get('json', 'Not generated')}}")
    if "{args.format}" in ["html", "both"]:
        print(f"[INFO] HTML Report: {{report_files.get('html', 'Not generated')}}")
    
except Exception as e:
    print(f"[ERROR] {{e}}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
        
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            temp_script = f.name
        
        cmd = [sys.executable, temp_script]
        
        try:
            print(f"[INFO] Generating SMB security report...")
            print(f"[INFO] Sessions directory: {sessions_dir}")
            print(f"[INFO] Output directory: {args.output}")
            print(f"[INFO] Format: {args.format}")
            
            result = subprocess.run(cmd, cwd=smb_dir, capture_output=True, text=True, encoding='utf-8')
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            if result.returncode != 0:
                print(f"[ERROR] Report generation failed with exit code {result.returncode}")
                return 1
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_script)
            except:
                pass
        
        return 0

    def list_services(self):
        """List all available services"""
        print("\n" + "=" * 80)
        print("NEXUS Honeypot Services")
        print("=" * 80)
        print()
        
        for service, info in self.services.items():
            status = "[IMPLEMENTED]" if info['implemented'] else "[PLANNED]"
            print(f"  {service.upper():<12} {status:<15} {info['description']}")
        
        print()
        print("Usage:")
        print("  nexus_cli.py <service> [options]")
        print("  nexus_cli.py report --service <service>")
        print("=" * 80 + "\n")

    def run_placeholder_service(self, service_name):
        """Handle placeholder services"""
        print(f"[ERROR] {service_name.upper()} honeypot is not yet implemented")
        print(f"[INFO] Service location: {self.services[service_name]['path']}")
        print("[INFO] This service is planned for future development.")
        return 1
    
    def view_logs(self, args):
        """View and analyze session logs using dedicated log viewer module"""
        service_info = self.services.get(args.service)
        if not service_info:
            print(f"[ERROR] Unknown service {args.service}")
            return 1
            
        if not service_info['implemented']:
            print(f"[ERROR] Log viewing for {args.service} not implemented")
            print(f"[INFO] Service {args.service.upper()} is planned but not yet available")
            return 1
        
        # Use dedicated log viewer module
        log_viewer_script = self.base_dir / 'logs' / 'log_viewer.py'
        if not log_viewer_script.exists():
            print(f"[ERROR] Log viewer not found at {log_viewer_script}")
            return 1
        
        # Build command for log viewer
        cmd = [sys.executable, str(log_viewer_script), args.service]
        
        if args.session_id:
            cmd.extend(['--session-id', args.session_id])
        if args.log_file:
            # Validate and sanitize log file path to prevent path traversal
            log_path = Path(args.log_file).resolve()
            try:
                log_path.relative_to(Path.cwd())
                cmd.extend(['--log-file', str(log_path)])
            except ValueError:
                print(f"[ERROR] Log file path must be within current directory")
                return 1
        if args.decode:
            cmd.append('--decode')
        if args.conversation:
            cmd.append('--conversation')
        if args.save:
            # Validate and sanitize save path to prevent path traversal
            save_path = Path(args.save).resolve()
            # Ensure the path is within current directory or subdirectories
            try:
                save_path.relative_to(Path.cwd())
                cmd.extend(['--save', str(save_path)])
            except ValueError:
                print(f"[ERROR] Save path must be within current directory")
                return 1
        if args.format:
            cmd.extend(['--format', args.format])
        if args.filter:
            cmd.extend(['--filter', args.filter])
        
        # Add ML analysis options
        if hasattr(args, 'ml_analysis') and args.ml_analysis:
            cmd.append('--ml-analysis')
        if hasattr(args, 'anomaly_threshold') and args.anomaly_threshold != 0.7:
            cmd.extend(['--anomaly-threshold', str(args.anomaly_threshold)])
        if hasattr(args, 'ml_insights') and args.ml_insights:
            cmd.append('--ml-insights')
        if hasattr(args, 'high_risk_only') and args.high_risk_only:
            cmd.append('--high-risk-only')
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            if result.returncode != 0:
                print(f"[ERROR] Log viewer failed with exit code {result.returncode}")
                return 1
                
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
        
        return 0

    def main():
        parser = self.create_parser()
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return 1
        
        if args.command == 'list':
            self.list_services()
            return 0
        elif args.command == 'report':
            return self.generate_report(args)
        elif args.command == 'logs':
            return self.view_logs(args)
        elif args.command == 'ssh':
            return self.run_ssh_service(args)
        elif args.command == 'ftp':
            return self.run_ftp_service(args)
        elif args.command == 'http':
            return self.run_http_service(args)
        elif args.command == 'mysql':
            return self.run_mysql_service(args)
        elif args.command == 'smb':
            return self.run_smb_service(args)
        elif args.command == 'status':
            return self.show_status(args)
        elif args.command == 'stop-all':
            return self.stop_all(args)
        elif args.command == 'start-all':
            return self.start_all(args)
        elif args.command == 'ml':
            return self.handle_ml_command(args)
        else:
            print(f"Unknown command: {args.command}")
            return 1

    def check_service_status(self, service_name):
        """Check if a service is running"""
        service_info = self.services.get(service_name)
        if not service_info:
            return {'status': 'unknown', 'pid': None, 'port': None}
        
        port = self.get_default_port(service_name)
        
        # Check if port is in use
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    return {'status': 'running', 'pid': 'unknown', 'port': port}
                else:
                    return {'status': 'stopped', 'pid': None, 'port': port}
        except Exception:
            return {'status': 'unknown', 'pid': None, 'port': port}
    
    def get_service_config(self, service_name, config_dir=None):
        """Get service configuration dynamically"""
        service_info = self.services.get(service_name)
        if not service_info:
            return None
        
        config_file = None
        if config_dir:
            config_file = Path(config_dir) / f"{service_name}_config.ini"
        else:
            config_file = service_info['path'].parent / "config.ini"
        
        config: dict = {'port': None}
        
        if config_file.exists():
            try:
                from configparser import ConfigParser
                parser = ConfigParser()
                # amazonq-ignore-next-line
                parser.read(config_file)
                
                # Get port from config
                port_value = None
                if service_name == 'ssh' and 'ssh' in parser:
                    port_value = parser['ssh'].getint('port', fallback=None)
                elif service_name == 'ftp' and 'ftp' in parser:
                    port_value = parser['ftp'].getint('port', fallback=None)
                elif service_name == 'http' and 'http' in parser:
                    port_value = parser['http'].getint('port', fallback=None)
                elif service_name == 'mysql' and 'mysql' in parser:
                    port_value = parser['mysql'].getint('port', fallback=None)
                elif service_name == 'smb' and 'smb' in parser:
                    port_value = parser['smb'].getint('port', fallback=None)

                if port_value is not None:
                    config['port'] = port_value
            # amazonq-ignore-next-line
            # amazonq-ignore-next-line
            except Exception:
                pass
        
        return config
    
    def get_default_port(self, service_name):
        """Get default port for service from config or fallback"""
        config = self.get_service_config(service_name)
        if config and config['port']:
            return config['port']
        
        # Fallback defaults only if no config found
        fallback_ports = {
            'ssh': 8022,
            'ftp': 2121,
            'http': 8080,
            'mysql': 3306,
            'smb': 445
        }
        return fallback_ports.get(service_name, 0)
    
    def find_service_processes(self):
        """Find running service processes"""
        processes = []
        
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if any(service in cmdline for service in ['ssh_server.py', 'ftp_server.py', 'http_server.py', 'mysql_server.py', 'smb_server.py']):
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': cmdline
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            pass
        
        return processes
    
    def stop_all_services(self):
        """Stop all running services"""
        stopped_count = 0
        
        try:
            import psutil
            processes = self.find_service_processes()
            
            for proc_info in processes:
                try:
                    proc = psutil.Process(proc_info['pid'])
                    proc.terminate()
                    stopped_count += 1
                    print(f"Stopped process {proc_info['pid']}: {proc_info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"Could not stop process {proc_info['pid']}: {e}")
                    
        except ImportError:
            print("psutil not available - cannot stop processes automatically")
            return 0
        
        return stopped_count

    def show_status(self, args):
        """Show service status"""
        if args.service:
            if args.service not in self.services:
                print(f"[ERROR] Unknown service: {args.service}")
                return 1
            
            if not self.services[args.service]['implemented']:
                print(f"[INFO] Service {args.service} is not implemented")
                return 1
            
            status = self.check_service_status(args.service)
            print(f"\n{args.service.upper()} Service Status:")
            print(f"  Status: {status['status']}")
            print(f"  Port: {status['port']}")
            if status['pid']:
                print(f"  PID: {status['pid']}")
        else:
            print("\n[INFO] NEXUS Services Status:")
            print("=" * 40)
            
            for service_name, service_info in self.services.items():
                if service_info['implemented']:
                    status = self.check_service_status(service_name)
                    status_text = "[RUNNING]" if status['status'] == 'running' else "[STOPPED]"
                    print(f"  {service_name.upper():<12} {status_text:<15} Port: {status['port']}")
                else:
                    print(f"  {service_name.upper():<12} [NOT IMPLEMENTED]")
            
            processes = self.find_service_processes()
            if processes:
                print("\n[INFO] Running Processes:")
                for proc in processes:
                    print(f"  PID {proc['pid']}: {proc['name']}")
            else:
                print("\n[INFO] No emulators running currently")
        
        
        return 0
    
    def stop_all(self, args):
        """Stop all services"""
        print("[INFO] Stopping all service emulators...")
        
        stopped_count = self.stop_all_services()
        
        if stopped_count > 0:
            print(f"[SUCCESS] Stopped {stopped_count} service(s)")
        else:
            print("[INFO] No running services found")
        
        return 0
    
    def _build_service_command(self, service_name, service_info, args):
        """Build command for starting a service"""
        cmd = [sys.executable, str(service_info['path'])]
        
        # Add global arguments based on service type
        if args.llm_provider:
            if service_name == 'mysql':
                cmd.extend(['--llm-provider', args.llm_provider])
            else:
                cmd.extend(['-l', args.llm_provider])
        
        if args.model_name:
            if service_name == 'mysql':
                cmd.extend(['--model-name', args.model_name])
            else:
                cmd.extend(['-m', args.model_name])
        
        # Add config file if specified
        if args.config_dir:
            config_file = Path(args.config_dir) / f"{service_name}_config.ini"
            if config_file.exists():
                cmd.extend(['-c', str(config_file)])
        
        return cmd
    
    def _start_single_service(self, service_name, service_info, args):
        """Start a single service and return success status"""
        status = self.check_service_status(service_name)
        if status['status'] == 'running':
            print(f"[INFO] {service_name.upper()} already running on port {status['port']}")
            return True
        
        print(f"[INFO] Starting {service_name.upper()}...")
        
        try:
            cmd = self._build_service_command(service_name, service_info, args)
            
            import subprocess
            import threading
            import time
            
            def run_service():
                try:
                    subprocess.run(cmd, cwd=service_info['path'].parent)
                except Exception as e:
                    print(f"[ERROR] {{e}}")
            
            thread = threading.Thread(target=run_service, daemon=True)
            thread.start()
            time.sleep(2)
            
            new_status = self.check_service_status(service_name)
            if new_status['status'] == 'running':
                print(f"[SUCCESS] {service_name.upper()} started on port {new_status['port']}")
                return True
            else:
                print(f"[ERROR] Failed to start {service_name.upper()}")
                return False
        except Exception as e:
            print(f"[ERROR] {{e}}")
            return False

    def start_all(self, args):
        """Start all implemented services"""
        print("[INFO] Starting all service emulators...")
        started_count = 0
        failed_count = 0
        
        for service_name, service_info in self.services.items():
            if not service_info['implemented']:
                continue
            
            if self._start_single_service(service_name, service_info, args):
                started_count += 1
            else:
                failed_count += 1
        
        print(f"\n[SUMMARY]")
        print(f"  Started: {started_count} service(s)")
        if failed_count > 0:
            print(f"  Failed: {failed_count} service(s)")
        
        return 0 if failed_count == 0 else 1

    def _build_smb_command(self, args, smb_script):
        """Build SMB command arguments"""
        cmd = [sys.executable, str(smb_script)]
        
        arg_mappings = [
            (args.config, ['-c', args.config]),
            (args.port, ['-P', str(args.port)]),
            (args.log_file, ['-L', args.log_file]),
            (args.sensor_name, ['-S', args.sensor_name]),
            (args.llm_provider, ['-l', args.llm_provider]),
            (args.model_name, ['-m', args.model_name]),
            (args.temperature is not None, ['-r', str(args.temperature)]),
            (args.max_tokens, ['-t', str(args.max_tokens)]),
            (args.prompt, ['-p', args.prompt]),
            (args.prompt_file, ['-f', args.prompt_file])
        ]
        
        for condition, extension in arg_mappings:
            if condition:
                cmd.extend(extension)
        
        if args.user_account:
            for account in args.user_account:
                cmd.extend(['-u', account])
        
        return cmd

    def handle_ml_command(self, args):
        """Handle ML subcommands"""
        if not args.ml_command:
            print("Error: ML subcommand required")
            return 1
        
        try:
            # Import ML modules with proper path handling
            sys.path.insert(0, str(self.base_dir))
            sys.path.insert(0, str(self.base_dir.parent))  # Add parent directory for 'src' imports
            
            from ai.data_processor import DataProcessor
            from ai.training import ModelTrainer
            from ai.detectors import MLDetector
            from ai.config import MLConfig
            
            if args.ml_command == 'extract':
                return self._ml_extract_features(args)
            elif args.ml_command == 'train':
                return self._ml_train_models(args)
            elif args.ml_command == 'eval':
                return self._ml_evaluate_models(args)
            elif args.ml_command == 'predict':
                return self._ml_predict(args)
            elif args.ml_command == 'update-models':
                return self._ml_update_models(args)
            else:
                print(f"Unknown ML command: {args.ml_command}")
                return 1
                
        except ImportError as e:
            print(f"Error: ML modules not available: {e}")
            print("Please ensure all ML dependencies are installed.")
            return 1
        except Exception as e:
            print(f"Error executing ML command: {e}")
            return 1
    
    def _ml_extract_features(self, args):
        """Extract features from datasets"""
        print(f"[INFO] Extracting features for {args.service}...")
        
        datasets_dir = Path(args.datasets_dir)
        if not datasets_dir.exists():
            print(f"Error: Datasets directory not found: {datasets_dir}")
            return 1
        
        from ai.data_processor import DataProcessor
        processor = DataProcessor(str(datasets_dir))
        
        if args.service == 'all':
            services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
        else:
            services = [args.service]
        
        for service in services:
            print(f"\n[INFO] Processing {service.upper()} data...")
            try:
                data = processor.get_processed_data(service)
                service_data = data.get(service, [])
                
                if service_data:
                    print(f"[INFO] Extracted {len(service_data)} samples for {service}")
                    
                    if args.output:
                        output_file = Path(args.output) / f"{service}_features.json"
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        import json
                        with open(output_file, 'w') as f:
                            json.dump(service_data, f, indent=2)
                        print(f"[INFO] Saved to {output_file}")
                else:
                    print(f"[INFO] No data found for {service}")
                    
            except Exception as e:
                print(f"[ERROR] Error processing {service}: {e}")
        
        return 0
    
    def _ml_train_models(self, args):
        """Train ML models"""
        print(f"[INFO] Training ML models for {args.service}...")
        
        from ai.training import ModelTrainer
        from ai.data_processor import DataProcessor
        
        if args.service == 'all':
            services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
        else:
            services = [args.service]
        
        processor = DataProcessor()
        
        for service in services:
            print(f"\n[INFO] Training models for {service.upper()}...")
            
            try:
                trainer = ModelTrainer(service)
                
                # Get training data
                if args.data:
                    # Load from file
                    import json
                    import numpy as np
                    with open(args.data, 'r') as f:
                        all_data = json.load(f)
                        # Split data
                        np.random.shuffle(all_data)
                        split_idx = int(len(all_data) * (1 - args.test_size))
                        train_data = all_data[:split_idx]
                        test_data = all_data[split_idx:]
                else:
                    # Use processed datasets and split
                    train_data, test_data = processor.get_training_data(service, args.test_size)

                if not train_data:
                    print(f"[INFO] No training data available for {service}")
                    continue

                print(f"[INFO] Training with {len(train_data)} samples...")
                
                if args.algorithm == 'all':
                    results = trainer.train_all_models(train_data)
                else:
                    if args.algorithm in ['isolation_forest', 'one_class_svm', 'lof']:
                        results = {args.algorithm: trainer.train_anomaly_detector(train_data, args.algorithm)}
                    elif args.algorithm == 'xgboost':
                        results = {args.algorithm: trainer.train_supervised_classifier(train_data)}
                    elif args.algorithm in ['hdbscan', 'kmeans']:
                        results = {args.algorithm: trainer.train_clustering_model(train_data, args.algorithm)}
                    else:
                        print(f"[ERROR] Unknown algorithm: {args.algorithm}")
                        continue
                
                # Save models
                trainer.save_models()
                
                # Print results
                for algo, result in results.items():
                    accuracy = result.get('accuracy', 'N/A')
                    if isinstance(accuracy, (int, float)):
                        print(f"[INFO] {algo}: {accuracy:.3f} accuracy")
                    else:
                        print(f"[INFO] {algo}: {accuracy} accuracy")
                
            except Exception as e:
                print(f"[ERROR] Error training {service}: {e}")
                import traceback
                traceback.print_exc()
        
        return 0
    
    def _ml_evaluate_models(self, args):
        """Evaluate trained models"""
        print(f"[INFO] Evaluating ML models for {args.service}...")
        
        from ai.training import ModelTrainer
        from ai.data_processor import DataProcessor
        
        try:
            trainer = ModelTrainer(args.service)
            processor = DataProcessor()
            
            # Get test data
            if args.test_data:
                import json
                with open(args.test_data, 'r') as f:
                    test_data = json.load(f)
            else:
                _, test_data = processor.get_training_data(args.service, 0.2)
            
            if not test_data:
                print(f"[INFO] No test data available for {args.service}")
                return 1
            
            print(f"[INFO] Evaluating with {len(test_data)} test samples...")
            
            # Evaluate models
            if args.model:
                results = trainer.evaluate_model(args.model, test_data)
                print(f"[INFO] {args.model} Results:")
                for metric, value in results.items():
                    if isinstance(value, float):
                        print(f"[INFO]  {metric}: {value:.3f}")
                    else:
                        print(f"[INFO]  {metric}: {value}")
            else:
                # Evaluate all available models
                for model_name in trainer.models.keys():
                    try:
                        results = trainer.evaluate_model(model_name, test_data)
                        print(f"[INFO] {model_name} Results:")
                        for metric, value in results.items():
                            if isinstance(value, float):
                                print(f"[INFO]  {metric}: {value:.3f}")
                            else:
                                print(f"[INFO]  {metric}: {value}")
                        print()
                    except Exception as e:
                        print(f"[ERROR] Error evaluating {model_name}: {e}")
            
        except Exception as e:
            print(f"[ERROR] Error during evaluation: {e}")
            return 1
        
        return 0
    
    def _ml_predict(self, args):
        """Make predictions with trained models"""
        print(f"[INFO] Making predictions for {args.service}...")
        
        from ai.detectors import MLDetector
        from ai.config import MLConfig
        
        try:
            config = MLConfig(args.service)
            detector = MLDetector(args.service, config)
            
            if not detector.is_trained:
                print(f" No trained models found for {args.service}")
                print("Please train models first using: nexus_cli.py ml train")
                return 1
            
            # Prepare input data
            if Path(args.input).exists():
                # Input is a file
                import json
                with open(args.input, 'r') as f:
                    input_data = json.load(f)
                
                if isinstance(input_data, list):
                    predictions = []
                    for item in input_data:
                        result = detector.score(item)
                        predictions.append(result)
                        print(f" Anomaly Score: {result['ml_anomaly_score']:.3f}, Labels: {result['ml_labels']}")
                else:
                    result = detector.score(input_data)
                    predictions = [result]
                    print(f" Anomaly Score: {result['ml_anomaly_score']:.3f}, Labels: {result['ml_labels']}")
            else:
                # Input is a single command/query
                if args.service == 'ssh':
                    data = {'command': args.input}
                elif args.service == 'http':
                    data = {'request': args.input, 'method': 'GET', 'url': args.input}
                elif args.service == 'mysql':
                    data = {'query': args.input}
                elif args.service == 'ftp':
                    data = {'command': args.input}
                elif args.service == 'smb':
                    data = {'command': args.input, 'path': args.input}
                else:
                    data = {'text': args.input}
                
                result = detector.score(data)
                predictions = [result]
                print(f" Input: {args.input}")
                print(f" Anomaly Score: {result['ml_anomaly_score']:.3f}")
                print(f" Labels: {result['ml_labels']}")
                print(f" Reason: {result['ml_reason']}")
            
            # Save predictions if output specified
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    json.dump(predictions, f, indent=2)
                print(f" Predictions saved to {args.output}")
            
        except Exception as e:
            print(f" Error during prediction: {e}")
            return 1
        
        return 0
    
    def _ml_update_models(self, args):
        """Update/retrain models"""
        print(f"[INFO] Updating ML models for {args.service}...")
        
        if args.service == 'all':
            services = ['ssh', 'http', 'ftp', 'mysql', 'smb']
        else:
            services = [args.service]
        
        for service in services:
            print(f"\n Updating models for {service.upper()}...")
            
            try:
                from ai.config import MLConfig
                config = MLConfig(service)
                
                if args.model_path:
                    # Copy new models from specified path
                    import shutil
                    source_path = Path(args.model_path) / service
                    target_path = config.models_dir / service
                    
                    if source_path.exists():
                        if args.force or input(f"Replace existing models for {service}? (y/N): ").lower() == 'y':
                            shutil.copytree(source_path, target_path, dirs_exist_ok=True)
                            print(f" Models updated for {service}")
                        else:
                            print(f"  Skipped {service}")
                    else:
                        print(f" Model path not found: {source_path}")
                else:
                    # Retrain models
                    from ai.training import ModelTrainer
                    from ai.data_processor import DataProcessor
                    
                    trainer = ModelTrainer(service)
                    processor = DataProcessor()
                    
                    data = processor.get_processed_data(service)
                    training_data = data.get(service, [])
                    
                    if training_data:
                        train_data, _ = processor.get_training_data(service, 0.2)
                        results = trainer.train_all_models(train_data)
                        trainer.save_models()
                        print(f" Retrained models for {service}")
                    else:
                        print(f"  No training data available for {service}")
                
            except Exception as e:
                print(f" Error updating {service}: {e}")
        
        return 0

    def run_smb_service(self, args):
        """Run SMB honeypot with provided arguments"""
        if not self.services['smb']['implemented']:
            print("Error: SMB service not implemented")
            return 1
            
        smb_script = self.services['smb']['path']
        if not smb_script.exists():
            print(f"Error: SMB script not found at {smb_script}")
            return 1
        
        cmd = self._build_smb_command(args, smb_script)
        env = self._setup_environment(args)
        smb_dir = self.services['smb']['path'].parent
        
        try:
            subprocess.run(cmd, cwd=smb_dir, env=env)
        except KeyboardInterrupt:
            print("\nSMB honeypot stopped")
        except Exception as e:
            print(f"Error running SMB honeypot: {e}")
            return 1
        
        return 0

if __name__ == '__main__':
    cli = NexusCLI()
    sys.exit(cli.main())