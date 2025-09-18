#!/usr/bin/env python3
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
                'implemented': False,
                'description': 'MySQL database honeypot (not implemented)'
            },
            'smb': {
                'path': self.base_dir / 'service_emulators' / 'SMB' / 'smb_server.py',
                'implemented': False,
                'description': 'SMB file share honeypot (not implemented)'
            }
        }

    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='NEXUS AI-Enhanced Honeypot Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  nexus_cli.py ssh --port 2222 --llm-provider ollama
  nexus_cli.py ssh --config custom.ini --log-file ssh.log
  nexus_cli.py report ssh --output reports/ --format html
  nexus_cli.py report ssh --sessions-dir custom/sessions --severity high
  nexus_cli.py list
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # List services command
        list_parser = subparsers.add_parser('list', help='List all available services')
        
        # Report generation command
        report_parser = subparsers.add_parser('report', help='Generate security reports')
        report_parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql', 'smb'], 
                                 help='Service to generate report for')
        report_parser.add_argument('--output', '-o', default='reports', help='Output directory')
        report_parser.add_argument('--sessions-dir', '-s', help='Sessions directory (default: service-specific)')
        report_parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', 
                                 help='Report format')
        report_parser.add_argument('--period', help='Analysis period (e.g., 7d, 30d, all)')
        report_parser.add_argument('--severity', choices=['all', 'low', 'medium', 'high', 'critical'], 
                                 default='all', help='Minimum severity level')
        
        # Logs command for viewing session conversations
        logs_parser = subparsers.add_parser('logs', help='View and analyze session logs')
        logs_parser.add_argument('service', choices=['ssh', 'ftp', 'http', 'mysql', 'smb'],
                               help='Service to view logs for')
        logs_parser.add_argument('--session-id', '-i', help='Specific session ID to view')
        logs_parser.add_argument('--log-file', '-f', help='Log file path (default: service-specific)')
        logs_parser.add_argument('--decode', '-d', action='store_true', 
                               help='Decode base64 encoded details')
        logs_parser.add_argument('--conversation', '-c', action='store_true',
                               help='Show full conversation format')
        logs_parser.add_argument('--save', '-s', help='Save conversation to file')
        logs_parser.add_argument('--format', choices=['text', 'json'], default='text',
                               help='Output format')
        logs_parser.add_argument('--filter', choices=['all', 'commands', 'responses', 'attacks'],
                               default='all', help='Filter log entries')
        
        # SSH service parser
        ssh_parser = subparsers.add_parser('ssh', help='Start SSH honeypot')
        self._add_ssh_arguments(ssh_parser)
        
        # FTP service parser
        ftp_parser = subparsers.add_parser('ftp', help='Start FTP honeypot')
        self._add_ftp_arguments(ftp_parser)
        # HTTP service parser
        http_parser = subparsers.add_parser('http', help='Start HTTP honeypot')
        self._add_http_arguments(http_parser)
        mysql_parser = subparsers.add_parser('mysql', help='Start MySQL honeypot (not implemented)')
        smb_parser = subparsers.add_parser('smb', help='Start SMB honeypot (not implemented)')
        
        return parser

    def _add_ftp_arguments(self, parser):
        """Add FTP-specific arguments"""
        # Configuration
        parser.add_argument('-c', '--config', help='Configuration file path')
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

    def run_ssh_service(self, args):
        """Run SSH honeypot with provided arguments"""
        if not self.services['ssh']['implemented']:
            print("Error: SSH service not implemented")
            return 1
            
        ssh_script = self.services['ssh']['path']
        if not ssh_script.exists():
            print(f"Error: SSH script not found at {ssh_script}")
            return 1
        
        # Build command arguments
        cmd = [sys.executable, str(ssh_script)]
        
        # Add arguments
        if args.config:
            cmd.extend(['-c', args.config])
        if args.port:
            cmd.extend(['-P', str(args.port)])
        if args.host_key:
            cmd.extend(['-k', args.host_key])
        if args.server_version:
            cmd.extend(['-v', args.server_version])
        if args.log_file:
            cmd.extend(['-L', args.log_file])
        if args.sensor_name:
            cmd.extend(['-S', args.sensor_name])
        if args.llm_provider:
            cmd.extend(['-l', args.llm_provider])
        if args.model_name:
            cmd.extend(['-m', args.model_name])
        if args.temperature is not None:
            cmd.extend(['-r', str(args.temperature)])
        if args.max_tokens:
            cmd.extend(['-t', str(args.max_tokens)])
        if args.prompt:
            cmd.extend(['-p', args.prompt])
        if args.prompt_file:
            cmd.extend(['-f', args.prompt_file])
        if args.user_account:
            for account in args.user_account:
                cmd.extend(['-u', account])
        
        # Set environment variables for additional configs
        env = os.environ.copy()
        if args.base_url:
            env['OLLAMA_BASE_URL'] = args.base_url
        if args.azure_deployment:
            env['AZURE_OPENAI_DEPLOYMENT'] = args.azure_deployment
        if args.azure_endpoint:
            env['AZURE_OPENAI_ENDPOINT'] = args.azure_endpoint
        if args.azure_api_version:
            env['AZURE_OPENAI_API_VERSION'] = args.azure_api_version
        if args.aws_region:
            env['AWS_DEFAULT_REGION'] = args.aws_region
        if args.aws_profile:
            env['AWS_PROFILE'] = args.aws_profile
        
        # Change to SSH directory
        ssh_dir = self.services['ssh']['path'].parent
        
        try:
            print(f"Starting SSH honeypot...")
            print(f"Command: {' '.join(cmd)}")
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
        
        # Build command arguments
        cmd = [sys.executable, str(ftp_script)]
        
        # Add arguments
        if args.config:
            cmd.extend(['-c', args.config])
        if args.port:
            cmd.extend(['-P', str(args.port)])
        if args.log_file:
            cmd.extend(['-L', args.log_file])
        if args.sensor_name:
            cmd.extend(['-S', args.sensor_name])
        if args.llm_provider:
            cmd.extend(['-l', args.llm_provider])
        if args.model_name:
            cmd.extend(['-m', args.model_name])
        if args.temperature is not None:
            cmd.extend(['-r', str(args.temperature)])
        if args.max_tokens:
            cmd.extend(['-t', str(args.max_tokens)])
        if args.prompt:
            cmd.extend(['-p', args.prompt])
        if args.prompt_file:
            cmd.extend(['-f', args.prompt_file])
        if args.user_account:
            for account in args.user_account:
                cmd.extend(['-u', account])
        
        # Set environment variables for additional configs
        env = os.environ.copy()
        if args.base_url:
            env['OLLAMA_BASE_URL'] = args.base_url
        if args.azure_deployment:
            env['AZURE_OPENAI_DEPLOYMENT'] = args.azure_deployment
        if args.azure_endpoint:
            env['AZURE_OPENAI_ENDPOINT'] = args.azure_endpoint
        if args.azure_api_version:
            env['AZURE_OPENAI_API_VERSION'] = args.azure_api_version
        if args.aws_region:
            env['AWS_DEFAULT_REGION'] = args.aws_region
        if args.aws_profile:
            env['AWS_PROFILE'] = args.aws_profile
        
        # Change to FTP directory
        ftp_dir = self.services['ftp']['path'].parent
        
        try:
            print(f"Starting FTP honeypot...")
            print(f"Command: {' '.join(cmd)}")
            subprocess.run(cmd, cwd=ftp_dir, env=env)
        except KeyboardInterrupt:
            print("\nFTP honeypot stopped")
        except Exception as e:
            print(f"Error running FTP honeypot: {e}")
            return 1
        
        return 0

    def run_http_service(self, args):
        """Run HTTP honeypot with provided arguments"""
        if not self.services['http']['implemented']:
            print("Error: HTTP service not implemented")
            return 1
            
        http_script = self.services['http']['path']
        if not http_script.exists():
            print(f"Error: HTTP script not found at {http_script}")
            return 1
        
        # Build command arguments
        cmd = [sys.executable, str(http_script)]
        
        # Add arguments
        if args.config:
            cmd.extend(['-c', args.config])
        if args.port:
            cmd.extend(['-P', str(args.port)])
        if args.log_file:
            cmd.extend(['-L', args.log_file])
        if args.sensor_name:
            cmd.extend(['-S', args.sensor_name])
        if args.llm_provider:
            cmd.extend(['-l', args.llm_provider])
        if args.model_name:
            cmd.extend(['-m', args.model_name])
        if args.temperature is not None:
            cmd.extend(['-r', str(args.temperature)])
        if args.max_tokens:
            cmd.extend(['-t', str(args.max_tokens)])
        if args.prompt:
            cmd.extend(['-p', args.prompt])
        if args.prompt_file:
            cmd.extend(['-f', args.prompt_file])
        if args.user_account:
            for account in args.user_account:
                cmd.extend(['-u', account])
        
        # Set environment variables for additional configs
        env = os.environ.copy()
        if args.base_url:
            env['OLLAMA_BASE_URL'] = args.base_url
        if args.azure_deployment:
            env['AZURE_OPENAI_DEPLOYMENT'] = args.azure_deployment
        if args.azure_endpoint:
            env['AZURE_OPENAI_ENDPOINT'] = args.azure_endpoint
        if args.azure_api_version:
            env['AZURE_OPENAI_API_VERSION'] = args.azure_api_version
        if args.aws_region:
            env['AWS_DEFAULT_REGION'] = args.aws_region
        if args.aws_profile:
            env['AWS_PROFILE'] = args.aws_profile
        
        # Change to HTTP directory
        http_dir = self.services['http']['path'].parent
        
        try:
            print(f"Starting HTTP honeypot...")
            print(f"Command: {' '.join(cmd)}")
            subprocess.run(cmd, cwd=http_dir, env=env)
        except KeyboardInterrupt:
            print("\nHTTP honeypot stopped")
        except Exception as e:
            print(f"Error running HTTP honeypot: {e}")
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
        elif args.service == 'smb':
            return self._generate_smb_report(args)
        else:
            print(f"Error: Report generation not implemented for {args.service}")
            return 1
    
    def _generate_ssh_report(self, args):
        """Generate SSH-specific security report"""
        ssh_dir = self.services['ssh']['path'].parent
        sessions_dir = args.sessions_dir or str(ssh_dir / 'sessions')
        
        # Build command for SSH report generator
        cmd = [sys.executable, '-c', f'''
import sys
sys.path.append("{ssh_dir}")
from report_generator import HoneypotReportGenerator

generator = HoneypotReportGenerator(sessions_dir="{sessions_dir}")
report_files = generator.generate_comprehensive_report(output_dir="{args.output}")

if "error" in report_files:
    print(f"Error: {{report_files['error']}}")
    sys.exit(1)

print("SSH Security Report Generated Successfully!")
if "{args.format}" in ["json", "both"]:
    print(f"JSON Report: {{report_files.get('json', 'Not generated')}}")
if "{args.format}" in ["html", "both"]:
    print(f"HTML Report: {{report_files.get('html', 'Not generated')}}")
print("Visualizations: {args.output}/visualizations/")
''']
        
        try:
            print(f"Generating SSH security report...")
            print(f"Sessions directory: {sessions_dir}")
            print(f"Output directory: {args.output}")
            print(f"Format: {args.format}")
            subprocess.run(cmd, cwd=ssh_dir, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error generating SSH report: {e}")
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}")
            return 1
        
        return 0
    
    def _generate_ftp_report(self, args):
        """Generate FTP-specific security report"""
        ftp_dir = self.services['ftp']['path'].parent
        sessions_dir = args.sessions_dir or str(ftp_dir / 'sessions')
        
        # Build command for FTP report generator
        cmd = [sys.executable, '-c', f'''
import sys
sys.path.append("{ftp_dir}")
from report_generator import FTPHoneypotReportGenerator

generator = FTPHoneypotReportGenerator(sessions_dir="{sessions_dir}")
report_files = generator.generate_comprehensive_report(output_dir="{args.output}")

if "error" in report_files:
    print(f"Error: {{report_files['error']}}")
    sys.exit(1)

print("FTP Security Report Generated Successfully!")
if "{args.format}" in ["json", "both"]:
    print(f"JSON Report: {{report_files.get('json', 'Not generated')}}")
if "{args.format}" in ["html", "both"]:
    print(f"HTML Report: {{report_files.get('html', 'Not generated')}}")
print("Visualizations: {args.output}/visualizations/")
''']
        
        try:
            print(f"Generating FTP security report...")
            print(f"Sessions directory: {sessions_dir}")
            print(f"Output directory: {args.output}")
            print(f"Format: {args.format}")
            subprocess.run(cmd, cwd=ftp_dir, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error generating FTP report: {e}")
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}")
            return 1
        
        return 0
    
    def _generate_http_report(self, args):
        """Generate HTTP-specific security report"""
        http_dir = self.services['http']['path'].parent
        sessions_dir = args.sessions_dir or str(http_dir / 'sessions')
        
        # Build command for HTTP report generator
        cmd = [sys.executable, '-c', f'''
import sys
sys.path.append("{http_dir}")
from report_generator import HTTPHoneypotReportGenerator

generator = HTTPHoneypotReportGenerator(sessions_dir="{sessions_dir}")
report_files = generator.generate_comprehensive_report(output_dir="{args.output}")

if "error" in report_files:
    print(f"Error: {{report_files['error']}}")
    sys.exit(1)

print("HTTP Security Report Generated Successfully!")
if "{args.format}" in ["json", "both"]:
    print(f"JSON Report: {{report_files.get('json', 'Not generated')}}")
if "{args.format}" in ["html", "both"]:
    print(f"HTML Report: {{report_files.get('html', 'Not generated')}}")
print("Visualizations: {args.output}/visualizations/")
''']
        
        try:
            print(f"Generating HTTP security report...")
            print(f"Sessions directory: {sessions_dir}")
            print(f"Output directory: {args.output}")
            print(f"Format: {args.format}")
            subprocess.run(cmd, cwd=http_dir, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error generating HTTP report: {e}")
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}")
            return 1
        
        return 0
    
    def _generate_mysql_report(self, args):
        """Generate MySQL-specific security report (placeholder)"""
        print("MySQL report generation not implemented")
        print("MySQL honeypot data structure:")
        print("  - SQL query logs")
        print("  - Database enumeration")
        print("  - Injection attack attempts")
        print("  - Authentication brute force")
        return 1
    
    def _generate_smb_report(self, args):
        """Generate SMB-specific security report (placeholder)"""
        print("SMB report generation not implemented")
        print("SMB honeypot data structure:")
        print("  - SMB connection logs")
        print("  - File share enumeration")
        print("  - Credential harvesting")
        print("  - Lateral movement attempts")
        return 1

    def list_services(self):
        """List all available services"""
        print("NEXUS Honeypot Services:")
        print("=" * 50)
        
        for service, info in self.services.items():
            status = "✅ IMPLEMENTED" if info['implemented'] else "🚧 PLANNED"
            print(f"{service.upper():<8} {status:<15} {info['description']}")
        
        print("\nUsage:")
        print("  nexus_cli.py <service> [options]")
        print("  nexus_cli.py report --service <service>")

    def run_placeholder_service(self, service_name):
        """Handle placeholder services"""
        print(f"Error: {service_name.upper()} honeypot is not yet implemented")
        print(f"Service location: {self.services[service_name]['path']}")
        print("This service is planned for future development.")
        return 1
    
    def view_logs(self, args):
        """View and analyze session logs using dedicated log viewer module"""
        service_info = self.services.get(args.service)
        if not service_info:
            print(f"Error: Unknown service {args.service}")
            return 1
            
        if not service_info['implemented']:
            print(f"Error: Log viewing for {args.service} not implemented")
            print(f"Service {args.service.upper()} is planned but not yet available")
            return 1
        
        # Use dedicated log viewer module
        log_viewer_script = self.base_dir / 'logs' / 'log_viewer.py'
        if not log_viewer_script.exists():
            print(f"Error: Log viewer not found at {log_viewer_script}")
            return 1
        
        # Build command for log viewer
        cmd = [sys.executable, str(log_viewer_script), args.service]
        
        if args.session_id:
            cmd.extend(['--session-id', args.session_id])
        if args.log_file:
            cmd.extend(['--log-file', args.log_file])
        if args.decode:
            cmd.append('--decode')
        if args.conversation:
            cmd.append('--conversation')
        if args.save:
            cmd.extend(['--save', args.save])
        if args.format:
            cmd.extend(['--format', args.format])
        if args.filter:
            cmd.extend(['--filter', args.filter])
        
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error viewing logs: {e}")
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}")
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
        elif args.command == 'http':
            return self.run_http_service(args)
        elif args.command in ['mysql', 'smb']:
            return self.run_placeholder_service(args.command)
        else:
            print(f"Unknown command: {args.command}")
            return 1

if __name__ == '__main__':
    cli = NexusCLI()
    sys.exit(cli.main())