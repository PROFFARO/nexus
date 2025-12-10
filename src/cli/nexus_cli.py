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
        report_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql'], 
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
        
        # AI Insights options
        report_parser.add_argument('--ai-provider', choices=['ollama', 'openai', 'google', 'none'], 
                                 default='ollama',
                                 help='AI provider for generating insights (default: ollama)')
        report_parser.add_argument('--ai-model', 
                                 help='AI model name (e.g., llama3.2, gpt-4o-mini, gemini-1.5-flash)')

        
        # Logs command for viewing session conversations
        logs_parser = subparsers.add_parser('logs', help='View and analyze session logs')
        logs_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql'],
                               help='Service to view logs for')
        logs_parser.add_argument('--session-id', '-i', help='Specific session ID to view')
        logs_parser.add_argument('--log-file', '-f', help='Log file path (default: service-specific)')
        logs_parser.add_argument('--decode', '-d', action='store_true', 
                               help='Decode base64 encoded details')
        logs_parser.add_argument('--conversation', '-c', action='store_true',
                               help='Show full conversation format')
        logs_parser.add_argument('--save', '-s', help='Save analysis to file or directory (dynamic filename generated if directory)')
        logs_parser.add_argument('--format', choices=['text', 'json', 'both'], default='text',
                               help='Output format (text, json, or both for dual output)')
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
        # MySQL service parser
        mysql_parser = subparsers.add_parser('mysql', help='Start MySQL honeypot')
        self._add_mysql_arguments(mysql_parser)
        
        # ML commands
        ml_parser = subparsers.add_parser('ml', help='Machine Learning operations')
        ml_subparsers = ml_parser.add_subparsers(dest='ml_command', help='ML commands')
        
        # ML extract command
        extract_parser = ml_subparsers.add_parser('extract', help='Extract features from datasets')
        extract_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql', 'all'],
                                  help='Service to extract features for')
        extract_parser.add_argument('--datasets-dir', default='datasets', help='Datasets directory')
        extract_parser.add_argument('--output', '-o', help='Output file path')
        # Verbosity options for extract
        extract_parser.add_argument('-v', '--verbose', action='count', default=0,
                                  help='Increase verbosity level (-v, -vv, -vvv for levels 1-3)')
        extract_parser.add_argument('--verbose-level', type=int, default=None, choices=[0, 1, 2, 3],
                                  help='Set verbosity level directly (0=minimal, 1=normal, 2=verbose, 3=debug)')
        
        # ML train command
        train_parser = ml_subparsers.add_parser('train', help='Train ML models')
        train_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql', 'all'],
                                help='Service to train models for')
        train_parser.add_argument('--algorithm', choices=['isolation_forest', 'one_class_svm', 'lof', 'hdbscan', 'kmeans', 'xgboost', 'all'],
                                default='all', help='ML algorithm to train')
        train_parser.add_argument('--data', help='Training data file path')
        train_parser.add_argument('--test-size', type=float, default=0.2, help='Test set size (0.0-1.0)')
        # Verbosity options for train
        train_parser.add_argument('-v', '--verbose', action='count', default=0,
                                help='Increase verbosity level (-v, -vv, -vvv for levels 1-3)')
        train_parser.add_argument('--verbose-level', type=int, default=None, choices=[0, 1, 2, 3],
                                help='Set verbosity level directly (0=minimal, 1=normal, 2=verbose, 3=debug)')

        
        # ML evaluate command
        eval_parser = ml_subparsers.add_parser('eval', help='Evaluate trained models')
        eval_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql'],
                               help='Service to evaluate models for')
        eval_parser.add_argument('--test-data', help='Test data file path')
        eval_parser.add_argument('--model', help='Specific model to evaluate')
        # Verbosity options for eval
        eval_parser.add_argument('-v', '--verbose', action='count', default=0,
                               help='Increase verbosity level (-v, -vv, -vvv for levels 1-3)')
        eval_parser.add_argument('--verbose-level', type=int, default=None, choices=[0, 1, 2, 3],
                               help='Set verbosity level directly (0=minimal, 1=normal, 2=verbose, 3=debug)')
        
        # ML predict command
        predict_parser = ml_subparsers.add_parser('predict', help='Make predictions with trained models')
        predict_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql'],
                                  help='Service to make predictions for')
        predict_parser.add_argument('--input', required=True, help='Input data file or single command/query')
        predict_parser.add_argument('--output', help='Output file for predictions')
        # Verbosity options for predict
        predict_parser.add_argument('-v', '--verbose', action='count', default=0,
                                  help='Increase verbosity level (-v, -vv, -vvv for levels 1-3)')
        predict_parser.add_argument('--verbose-level', type=int, default=None, choices=[0, 1, 2, 3],
                                  help='Set verbosity level directly (0=minimal, 1=normal, 2=verbose, 3=debug)')
        
        # ML update-models command
        update_parser = ml_subparsers.add_parser('update-models', help='Update/retrain models')
        update_parser.add_argument('service', choices=['ssh', 'ftp', 'mysql', 'all'],
                                 help='Service to update models for')
        update_parser.add_argument('--model-path', help='Path to new model files')
        update_parser.add_argument('--force', action='store_true', help='Force model update')
        # Verbosity options for update-models
        update_parser.add_argument('-v', '--verbose', action='count', default=0,
                                 help='Increase verbosity level (-v, -vv, -vvv for levels 1-3)')
        update_parser.add_argument('--verbose-level', type=int, default=None, choices=[0, 1, 2, 3],
                                 help='Set verbosity level directly (0=minimal, 1=normal, 2=verbose, 3=debug)')

        
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

    def run_ftp_service(self, args):
        """Run FTP honeypot with provided arguments"""
        if not self.services['ftp']['implemented']:
            print("Error: FTP service not implemented")
            return 1
            
        ftp_script = self.services['ftp']['path']
        if not ftp_script.exists():
            print(f"Error: FTP script not found at {ftp_script}")
            return 1
        
        cmd = [sys.executable, str(ftp_script)]
        env = self._setup_environment(args)
        ftp_dir = self.services['ftp']['path'].parent
        
        try:
            subprocess.run(cmd, cwd=ftp_dir, env=env)
        except KeyboardInterrupt:
            print("\nFTP honeypot stopped")
        except Exception as e:
            print(f"Error running FTP honeypot: {e}")
            return 1
        
        return 0

    def run_mysql_service(self, args):
        """Run MySQL honeypot with provided arguments"""
        if not self.services['mysql']['implemented']:
            print("Error: MySQL service not implemented")
            return 1
            
        mysql_script = self.services['mysql']['path']
        if not mysql_script.exists():
            print(f"Error: MySQL script not found at {mysql_script}")
            return 1
        
        cmd = [sys.executable, str(mysql_script)]
        env = self._setup_environment(args)
        mysql_dir = self.services['mysql']['path'].parent
        
        try:
            subprocess.run(cmd, cwd=mysql_dir, env=env)
        except KeyboardInterrupt:
            print("\nMySQL honeypot stopped")
        except Exception as e:
            print(f"Error running MySQL honeypot: {e}")
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
    
    # Get AI provider settings
    ai_provider = "{getattr(args, 'ai_provider', 'ollama')}"
    ai_model = {repr(getattr(args, 'ai_model', None))}
    
    generator = MySQLHoneypotReportGenerator(
        sessions_dir=r"{sessions_dir_escaped}", 
        logs_dir=str(logs_dir),
        ai_provider=ai_provider if ai_provider != 'none' else 'ollama',
        ai_model=ai_model
    )
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
            # Allow any log file path - no path restriction needed for reading logs
            log_path = Path(args.log_file)
            if not log_path.is_absolute():
                log_path = Path.cwd() / log_path
            cmd.extend(['--log-file', str(log_path.resolve())])
        if args.decode:
            cmd.append('--decode')
        if args.conversation:
            cmd.append('--conversation')
        if args.save:
            # Allow saving to any directory - generate dynamic filename if needed
            save_path = Path(args.save)
            if not save_path.is_absolute():
                save_path = Path.cwd() / save_path
            
            # If it's a directory or ends with separator, generate dynamic filename
            if save_path.is_dir() or str(args.save).endswith(('/', '\\')):
                save_path.mkdir(parents=True, exist_ok=True)
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                base_filename = f"{args.service}_logs_{timestamp}"
                
                if args.format == 'both':
                    # For 'both' format, pass directory and let log_viewer handle it
                    cmd.extend(['--save', str(save_path / base_filename)])
                else:
                    ext = 'json' if args.format == 'json' else 'txt'
                    cmd.extend(['--save', str(save_path / f"{base_filename}.{ext}")])
            else:
                # Ensure parent directory exists
                save_path.parent.mkdir(parents=True, exist_ok=True)
                cmd.extend(['--save', str(save_path.resolve())])
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

    def main(self):
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
        elif args.command == 'mysql':
            return self.run_mysql_service(args)
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
                elif service_name == 'mysql' and 'mysql' in parser:
                    port_value = parser['mysql'].getint('port', fallback=None)

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
            'mysql': 3307
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
                    if any(service in cmdline for service in ['ssh_server.py', 'ftp_server.py', 'mysql_server.py']):
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': cmdline
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Find API process
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if "src.api.main" in cmdline:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': "API Server",
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
                
            # Check API status
            import socket
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex(('127.0.0.1', 8000))
                    if result == 0:
                         print(f"\n[INFO] API Server: [RUNNING] Port: 8000")
            except:
                pass
        
        
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
                    subprocess.run(cmd, cwd=service_info['path'].parent, 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            
            thread = threading.Thread(target=run_service, daemon=True)
            thread.start()
            
            # Check status with retries (up to 8 seconds total with 0.5s intervals)
            for attempt in range(16):
                time.sleep(0.5)
                new_status = self.check_service_status(service_name)
                if new_status['status'] == 'running':
                    print(f"[SUCCESS] {service_name.upper()} started on port {new_status['port']}")
                    return True
            
            print(f"[ERROR] Failed to start {service_name.upper()}")
            return False
        except Exception as e:
            print(f"[ERROR] {e}")
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
        
        # Start API Server
        api_port = 8000
        print(f"[INFO] Starting API Server on port {api_port}...")
        try:
            # Run as module to support relative imports
            cmd = [sys.executable, "-m", "src.api.main"]
            
            import subprocess
            # Run in background
            subprocess.Popen(cmd, cwd=self.base_dir.parent)
            print(f"[SUCCESS] API Server started on port {api_port}")
            started_count += 1
        except Exception as e:
            print(f"[ERROR] Failed to start API Server: {e}")
            failed_count += 1

        print(f"\n[SUMMARY]")
        print(f"  Started: {started_count} service(s) (including API)")
        if failed_count > 0:
            print(f"  Failed: {failed_count} service(s)")
        
        return 0 if failed_count == 0 else 1

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
        """Extract features from datasets with verbose logging"""
        import time
        import json
        
        from ai.data_processor import DataProcessor
        from ai.ml_logger import get_ml_logger, VerbosityLevel
        
        # Determine verbosity level
        if args.verbose_level is not None:
            verbosity = args.verbose_level
        elif args.verbose:
            verbosity = min(args.verbose, 3)
        else:
            verbosity = VerbosityLevel.NORMAL
        
        ml_logger = get_ml_logger(verbosity)
        
        # Print banner
        config = {
            'service': args.service,
            'datasets_dir': args.datasets_dir,
            'output': args.output if args.output else 'console',
            'verbosity': verbosity
        }
        ml_logger.print_banner("NEXUS Feature Extraction", config)
        
        ml_logger.start_operation("Feature Extraction")
        extract_start = time.time()
        
        datasets_dir = Path(args.datasets_dir)
        if not datasets_dir.exists():
            ml_logger.log_error(f"Datasets directory not found: {datasets_dir}")
            return 1
        
        processor = DataProcessor(str(datasets_dir))
        processor.set_verbosity(verbosity)
        
        if args.service == 'all':
            services = ['ssh', 'ftp', 'mysql']
        else:
            services = [args.service]
        
        all_stats = {}
        
        for service_idx, service in enumerate(services):
            ml_logger.start_phase(f"{service.upper()} Extraction", len(services), service_idx + 1)
            service_start = time.time()
            
            try:
                ml_logger.log_step(f"Processing {service.upper()} datasets...", level="info")
                
                data = processor.get_processed_data(service)
                service_data = data.get(service, [])
                
                if service_data:
                    service_time = time.time() - service_start
                    
                    ml_logger.log_step(
                        f"Extracted {len(service_data):,} samples ({service_time:.2f}s)", 
                        level="success", indent=2
                    )
                    
                    # Show label distribution in verbose mode
                    if verbosity >= VerbosityLevel.VERBOSE:
                        labels = [item.get('label', 'unknown') for item in service_data]
                        ml_logger.log_label_distribution(labels, f"{service.upper()} Labels")
                    
                    all_stats[service] = {
                        'samples': len(service_data),
                        'time': service_time
                    }
                    
                    if args.output:
                        output_file = Path(args.output) / f"{service}_features.json"
                        output_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        save_start = time.time()
                        with open(output_file, 'w') as f:
                            json.dump(service_data, f, indent=2)
                        
                        file_size = output_file.stat().st_size
                        ml_logger.log_step(
                            f"Saved to {output_file.name} ({file_size/1024:.1f} KB, {time.time() - save_start:.2f}s)",
                            level="success", indent=2
                        )
                else:
                    ml_logger.log_step(f"No data found for {service}", level="warning")
                    all_stats[service] = {'samples': 0, 'time': 0}
                
                ml_logger.end_phase(f"{service.upper()} Extraction", success=True)
                    
            except Exception as e:
                ml_logger.log_error(f"Error processing {service}", exception=e)
                ml_logger.end_phase(f"{service.upper()} Extraction", success=False)
        
        total_time = time.time() - extract_start
        ml_logger.end_operation("Feature Extraction", success=True, duration=total_time)
        
        # Print summary
        total_samples = sum(s.get('samples', 0) for s in all_stats.values())
        ml_logger.log_step(f"\nTotal: {total_samples:,} samples extracted in {total_time:.2f}s", level="success")
        
        return 0

    
    def _ml_train_models(self, args):
        """Train ML models with comprehensive verbose logging"""
        import time
        import json
        import numpy as np
        
        from ai.training import ModelTrainer
        from ai.data_processor import DataProcessor
        from ai.ml_logger import get_ml_logger, VerbosityLevel
        
        # Determine verbosity level
        if args.verbose_level is not None:
            verbosity = args.verbose_level
        elif args.verbose:
            verbosity = min(args.verbose, 3)  # Cap at DEBUG level (3)
        else:
            verbosity = VerbosityLevel.NORMAL
        
        # Initialize ML Logger
        ml_logger = get_ml_logger(verbosity)
        
        # Configuration for banner
        config = {
            'service': args.service,
            'algorithm': args.algorithm,
            'test_size': args.test_size,
            'data_source': args.data if args.data else 'datasets',
            'verbosity': verbosity
        }
        
        # Print startup banner
        ml_logger.print_banner("NEXUS ML Training", config)
        
        # Start main training operation
        ml_logger.start_operation("ML Model Training")
        training_start = time.time()
        
        if args.service == 'all':
            services = ['ssh', 'ftp', 'mysql']
        else:
            services = [args.service]
        
        processor = DataProcessor()
        processor.set_verbosity(verbosity)
        
        all_results = {}
        
        for service_idx, service in enumerate(services):
            # Start service phase
            ml_logger.start_phase(f"{service.upper()} Training", len(services), service_idx + 1)
            service_start = time.time()
            
            try:
                trainer = ModelTrainer(service)
                trainer.set_verbosity(verbosity)
                
                # Get training data
                ml_logger.log_step(f"Loading training data for {service}...", level="info")
                
                if args.data:
                    # Load from file
                    data_start = time.time()
                    with open(args.data, 'r') as f:
                        all_data = json.load(f)
                    
                    # Split data
                    np.random.shuffle(all_data)
                    split_idx = int(len(all_data) * (1 - args.test_size))
                    train_data = all_data[:split_idx]
                    test_data = all_data[split_idx:]
                    
                    if verbosity >= VerbosityLevel.VERBOSE:
                        ml_logger.log_step(
                            f"Loaded {len(all_data):,} samples from file ({time.time() - data_start:.2f}s)",
                            level="data", indent=2
                        )
                else:
                    # Use processed datasets and split
                    train_data, test_data = processor.get_training_data(service, args.test_size)
                
                if not train_data:
                    ml_logger.log_step(f"No training data available for {service}", level="warning")
                    ml_logger.end_phase(f"{service.upper()} Training", success=False)
                    continue
                
                # Log data statistics
                if verbosity >= VerbosityLevel.VERBOSE:
                    ml_logger.log_step(f"Training samples: {len(train_data):,}", level="data", indent=2)
                    ml_logger.log_step(f"Test samples: {len(test_data):,}", level="data", indent=2)
                    
                    # Label distribution
                    labels = [item.get('label', 'unknown') for item in train_data]
                    label_counts = {}
                    for label in labels:
                        label_counts[label] = label_counts.get(label, 0) + 1
                    ml_logger.log_label_distribution(labels, f"{service.upper()} Training Labels")
                
                # Determine algorithms to train
                if args.algorithm == 'all':
                    algorithms = ['isolation_forest', 'one_class_svm', 'xgboost', 'hdbscan']
                else:
                    algorithms = [args.algorithm]
                
                results = {}
                
                for algo_idx, algorithm in enumerate(algorithms):
                    algo_start = time.time()
                    ml_logger.log_algorithm_start(algorithm, len(train_data))
                    
                    try:
                        if algorithm in ['isolation_forest', 'one_class_svm', 'lof']:
                            result = trainer.train_anomaly_detector(train_data, algorithm)
                        elif algorithm == 'xgboost':
                            result = trainer.train_supervised_classifier(train_data)
                        elif algorithm in ['hdbscan', 'kmeans']:
                            result = trainer.train_clustering_model(train_data, algorithm)
                        else:
                            ml_logger.log_error(f"Unknown algorithm: {algorithm}")
                            continue
                        
                        algo_time = time.time() - algo_start
                        results[algorithm] = result
                        
                        # Log algorithm completion with metrics
                        ml_logger.log_algorithm_end(algorithm, algo_time, result)
                        
                    except Exception as e:
                        ml_logger.log_error(f"Failed to train {algorithm}", exception=e)
                
                # Save models
                if verbosity >= VerbosityLevel.VERBOSE:
                    ml_logger.log_step("Saving trained models...", level="info", indent=2)
                
                save_start = time.time()
                trainer.save_models()
                
                if verbosity >= VerbosityLevel.DEBUG:
                    ml_logger.log_step(f"Models saved ({time.time() - save_start:.2f}s)", level="success", indent=2)
                
                all_results[service] = results
                
                # End service phase
                service_time = time.time() - service_start
                ml_logger.end_phase(f"{service.upper()} Training", success=True, duration=service_time)
                
            except Exception as e:
                ml_logger.log_error(f"Error training {service}", exception=e)
                ml_logger.end_phase(f"{service.upper()} Training", success=False)
                if verbosity >= VerbosityLevel.DEBUG:
                    import traceback
                    traceback.print_exc()
        
        # End main operation
        total_time = time.time() - training_start
        ml_logger.end_operation("ML Model Training", success=True, duration=total_time)
        
        # Print training summary
        ml_logger.print_training_summary(all_results, total_time)
        
        return 0

    
    def _ml_evaluate_models(self, args):
        """Evaluate trained models with verbose logging"""
        import time
        import json
        
        from ai.training import ModelTrainer
        from ai.data_processor import DataProcessor
        from ai.ml_logger import get_ml_logger, VerbosityLevel
        
        # Determine verbosity level
        if args.verbose_level is not None:
            verbosity = args.verbose_level
        elif args.verbose:
            verbosity = min(args.verbose, 3)
        else:
            verbosity = VerbosityLevel.NORMAL
        
        ml_logger = get_ml_logger(verbosity)
        
        # Print banner
        config = {
            'service': args.service,
            'model': args.model if args.model else 'all',
            'test_data': args.test_data if args.test_data else 'auto',
            'verbosity': verbosity
        }
        ml_logger.print_banner("NEXUS Model Evaluation", config)
        
        ml_logger.start_operation("Model Evaluation")
        eval_start = time.time()
        
        try:
            trainer = ModelTrainer(args.service)
            trainer.set_verbosity(verbosity)
            processor = DataProcessor()
            processor.set_verbosity(verbosity)
            
            # Get test data
            ml_logger.log_step("Loading test data...", level="info")
            
            if args.test_data:
                data_start = time.time()
                with open(args.test_data, 'r') as f:
                    test_data = json.load(f)
                if verbosity >= VerbosityLevel.VERBOSE:
                    ml_logger.log_step(
                        f"Loaded {len(test_data):,} samples from file ({time.time() - data_start:.2f}s)",
                        level="data", indent=2
                    )
            else:
                _, test_data = processor.get_training_data(args.service, 0.2)
            
            if not test_data:
                ml_logger.log_step(f"No test data available for {args.service}", level="warning")
                return 1
            
            ml_logger.log_step(f"Test samples: {len(test_data):,}", level="data", indent=2)
            
            # Evaluate models
            if args.model:
                models_to_eval = [args.model]
            else:
                models_to_eval = list(trainer.models.keys()) if trainer.models else []
            
            if not models_to_eval:
                ml_logger.log_step("No trained models found", level="warning")
                return 1
            
            all_results = {}
            
            for model_idx, model_name in enumerate(models_to_eval):
                ml_logger.start_phase(f"Evaluating {model_name}", len(models_to_eval), model_idx + 1)
                model_start = time.time()
                
                try:
                    results = trainer.evaluate_model(model_name, test_data)
                    model_time = time.time() - model_start
                    
                    all_results[model_name] = results
                    
                    # Display metrics
                    ml_logger.log_metrics({
                        k: v for k, v in results.items() 
                        if isinstance(v, (int, float)) and k != 'test_samples'
                    }, title=f"{model_name} Results", indent=2)
                    
                    if verbosity >= VerbosityLevel.DEBUG:
                        ml_logger.log_step(f"Evaluation time: {model_time:.2f}s", level="debug", indent=2)
                    
                    ml_logger.end_phase(f"Evaluating {model_name}", success=True)
                    
                except Exception as e:
                    ml_logger.log_error(f"Error evaluating {model_name}", exception=e)
                    ml_logger.end_phase(f"Evaluating {model_name}", success=False)
            
            total_time = time.time() - eval_start
            ml_logger.end_operation("Model Evaluation", success=True, duration=total_time)
            
            # Summary
            ml_logger.log_step(
                f"\nEvaluated {len(all_results)} models in {total_time:.2f}s",
                level="success"
            )
            
        except Exception as e:
            ml_logger.log_error("Error during evaluation", exception=e)
            return 1
        
        return 0
    
    def _ml_predict(self, args):
        """Make predictions with trained models with verbose logging"""
        import time
        import json
        
        from ai.detectors import MLDetector
        from ai.config import MLConfig
        from ai.ml_logger import get_ml_logger, VerbosityLevel
        
        # Determine verbosity level
        if args.verbose_level is not None:
            verbosity = args.verbose_level
        elif args.verbose:
            verbosity = min(args.verbose, 3)
        else:
            verbosity = VerbosityLevel.NORMAL
        
        ml_logger = get_ml_logger(verbosity)
        
        # Print banner
        config_info = {
            'service': args.service,
            'input': args.input[:50] + '...' if len(args.input) > 50 else args.input,
            'output': args.output if args.output else 'console',
            'verbosity': verbosity
        }
        ml_logger.print_banner("NEXUS ML Prediction", config_info)
        
        ml_logger.start_operation("ML Prediction")
        predict_start = time.time()
        
        try:
            ml_logger.log_step("Loading ML detector...", level="info")
            
            config = MLConfig(args.service)
            detector = MLDetector(args.service, config)
            
            if not detector.is_trained:
                ml_logger.log_step(f"No trained models found for {args.service}", level="error")
                ml_logger.log_step("Please train models first using: nexus_cli.py ml train", level="info")
                return 1
            
            if verbosity >= VerbosityLevel.VERBOSE:
                ml_logger.log_step(f"Detector loaded for {args.service}", level="success", indent=2)
            
            # Prepare input data
            predictions = []
            
            if Path(args.input).exists():
                # Input is a file
                ml_logger.log_step(f"Loading input from file: {args.input}", level="info")
                
                load_start = time.time()
                with open(args.input, 'r') as f:
                    input_data = json.load(f)
                
                if isinstance(input_data, list):
                    ml_logger.log_step(f"Processing {len(input_data):,} samples...", level="info", indent=2)
                    
                    for idx, item in enumerate(input_data):
                        result = detector.score(item)
                        predictions.append(result)
                        
                        if verbosity >= VerbosityLevel.VERBOSE:
                            ml_logger.log_step(
                                f"[{idx+1}/{len(input_data)}] Score: {result['ml_anomaly_score']:.3f}, Labels: {result['ml_labels']}",
                                level="data", indent=3
                            )
                else:
                    result = detector.score(input_data)
                    predictions = [result]
                    ml_logger.log_step(
                        f"Anomaly Score: {result['ml_anomaly_score']:.3f}, Labels: {result['ml_labels']}",
                        level="data", indent=2
                    )
            else:
                # Input is a single command/query
                ml_logger.log_step("Processing single input...", level="info")
                
                if args.service == 'ssh':
                    data = {'command': args.input}
                elif args.service == 'mysql':
                    data = {'query': args.input}
                elif args.service == 'ftp':
                    data = {'command': args.input}
                else:
                    data = {'text': args.input}
                
                result = detector.score(data)
                predictions = [result]
                
                # Display detailed result
                ml_logger.log_step(f"Input: {args.input}", level="info", indent=2)
                ml_logger.log_metrics({
                    'Anomaly Score': result['ml_anomaly_score'],
                    'Labels': ', '.join(result['ml_labels']) if result['ml_labels'] else 'None',
                    'Reason': result['ml_reason']
                }, title="Prediction Result", indent=2)
            
            # Save predictions if output specified
            if args.output:
                save_start = time.time()
                with open(args.output, 'w') as f:
                    json.dump(predictions, f, indent=2)
                ml_logger.log_step(
                    f"Predictions saved to {args.output} ({time.time() - save_start:.2f}s)",
                    level="success", indent=2
                )
            
            total_time = time.time() - predict_start
            ml_logger.end_operation("ML Prediction", success=True, duration=total_time)
            
            ml_logger.log_step(f"\nProcessed {len(predictions)} predictions in {total_time:.2f}s", level="success")
            
        except Exception as e:
            ml_logger.log_error("Error during prediction", exception=e)
            return 1
        
        return 0
    
    def _ml_update_models(self, args):
        """Update/retrain models with verbose logging"""
        import time
        import shutil
        
        from ai.ml_logger import get_ml_logger, VerbosityLevel
        
        # Determine verbosity level
        if args.verbose_level is not None:
            verbosity = args.verbose_level
        elif args.verbose:
            verbosity = min(args.verbose, 3)
        else:
            verbosity = VerbosityLevel.NORMAL
        
        ml_logger = get_ml_logger(verbosity)
        
        # Print banner
        config = {
            'service': args.service,
            'model_path': args.model_path if args.model_path else 'retrain',
            'force': args.force,
            'verbosity': verbosity
        }
        ml_logger.print_banner("NEXUS Model Update", config)
        
        ml_logger.start_operation("Model Update")
        update_start = time.time()
        
        if args.service == 'all':
            services = ['ssh', 'ftp', 'mysql']
        else:
            services = [args.service]
        
        updated_count = 0
        
        for service_idx, service in enumerate(services):
            ml_logger.start_phase(f"{service.upper()} Update", len(services), service_idx + 1)
            service_start = time.time()
            
            try:
                from ai.config import MLConfig
                config = MLConfig(service)
                
                if args.model_path:
                    # Copy new models from specified path
                    ml_logger.log_step(f"Copying models from {args.model_path}...", level="info")
                    
                    source_path = Path(args.model_path) / service
                    target_path = config.models_dir / service
                    
                    if source_path.exists():
                        if args.force or input(f"Replace existing models for {service}? (y/N): ").lower() == 'y':
                            copy_start = time.time()
                            shutil.copytree(source_path, target_path, dirs_exist_ok=True)
                            
                            ml_logger.log_step(
                                f"Models copied ({time.time() - copy_start:.2f}s)",
                                level="success", indent=2
                            )
                            updated_count += 1
                        else:
                            ml_logger.log_step(f"Skipped {service}", level="warning", indent=2)
                    else:
                        ml_logger.log_step(f"Model path not found: {source_path}", level="error", indent=2)
                else:
                    # Retrain models
                    ml_logger.log_step("Retraining models...", level="info")
                    
                    from ai.training import ModelTrainer
                    from ai.data_processor import DataProcessor
                    
                    trainer = ModelTrainer(service)
                    trainer.set_verbosity(verbosity)
                    processor = DataProcessor()
                    processor.set_verbosity(verbosity)
                    
                    data = processor.get_processed_data(service)
                    training_data = data.get(service, [])
                    
                    if training_data:
                        ml_logger.log_step(f"Training with {len(training_data):,} samples...", level="data", indent=2)
                        
                        train_data, _ = processor.get_training_data(service, 0.2)
                        
                        train_start = time.time()
                        results = trainer.train_all_models(train_data)
                        train_time = time.time() - train_start
                        
                        trainer.save_models()
                        
                        ml_logger.log_step(
                            f"Models retrained ({train_time:.2f}s) - {len(results)} algorithms",
                            level="success", indent=2
                        )
                        
                        if verbosity >= VerbosityLevel.VERBOSE:
                            for algo, result in results.items():
                                accuracy = result.get('accuracy', 'N/A')
                                if isinstance(accuracy, (int, float)):
                                    ml_logger.log_step(f"{algo}: {accuracy:.3f} accuracy", level="data", indent=3)
                        
                        updated_count += 1
                    else:
                        ml_logger.log_step(f"No training data available for {service}", level="warning", indent=2)
                
                service_time = time.time() - service_start
                ml_logger.end_phase(f"{service.upper()} Update", success=True, duration=service_time)
                
            except Exception as e:
                ml_logger.log_error(f"Error updating {service}", exception=e)
                ml_logger.end_phase(f"{service.upper()} Update", success=False)
        
        total_time = time.time() - update_start
        ml_logger.end_operation("Model Update", success=True, duration=total_time)
        
        ml_logger.log_step(f"\nUpdated {updated_count}/{len(services)} services in {total_time:.2f}s", level="success")
        
        return 0

if __name__ == '__main__':
    cli = NexusCLI()
    sys.exit(cli.main())