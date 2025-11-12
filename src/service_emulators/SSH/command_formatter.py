#!/usr/bin/env python3
"""
Enhanced Command Output Formatter for SSH Honeypot
Provides realistic terminal colors and formatting for various Unix commands
"""

import re
from typing import List

class CommandFormatter:
    """Enhanced formatter for realistic Unix command output with colors"""
    
    def __init__(self):
        # ANSI color codes for realistic terminal colors
        self.COLORS = {
            'BLUE': '\033[01;34m',      # Directories
            'GREEN': '\033[01;32m',     # Executables
            'CYAN': '\033[01;36m',      # Links
            'RED': '\033[01;31m',       # Archives
            'MAGENTA': '\033[01;35m',   # Images/media
            'YELLOW': '\033[01;33m',    # Device files
            'WHITE': '\033[01;37m',     # Regular files
            'BOLD': '\033[01m',         # Bold text
            'RESET': '\033[0m'          # Reset color
        }
    
    def colorize_file_item(self, item: str) -> str:
        """Apply appropriate colors to file/directory items"""
        # Directories (ending with / or known directory names)
        if (item.endswith('/') or 
            item.lower() in ['bin', 'etc', 'home', 'usr', 'var', 'tmp', 'opt', 'srv', 'docs', 
                           'config', 'scripts', 'reports', 'projects', 'tools', 'admin', 
                           'backup', 'logs', 'temp', 'cache', 'data']):
            return f"{self.COLORS['BLUE']}{item}{self.COLORS['RESET']}"
        
        # Executables (common executable extensions or no extension)
        elif (item.endswith(('.sh', '.py', '.pl', '.rb', '.exe', '.bin')) or 
              ('.' not in item and len(item) > 2)):
            return f"{self.COLORS['GREEN']}{item}{self.COLORS['RESET']}"
        
        # Archives
        elif item.endswith(('.tar', '.gz', '.zip', '.rar', '.7z', '.bz2', '.xz')):
            return f"{self.COLORS['RED']}{item}{self.COLORS['RESET']}"
        
        # Images and media
        elif item.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.mp4', '.avi', '.mp3')):
            return f"{self.COLORS['MAGENTA']}{item}{self.COLORS['RESET']}"
        
        # Links (items with @ or -> indicators)
        elif '@' in item or '->' in item:
            return f"{self.COLORS['CYAN']}{item}{self.COLORS['RESET']}"
        
        # Configuration files
        elif item.endswith(('.conf', '.cfg', '.ini', '.yaml', '.yml', '.json', '.xml')):
            return f"{self.COLORS['YELLOW']}{item}{self.COLORS['RESET']}"
        
        # Regular files
        else:
            return f"{self.COLORS['WHITE']}{item}{self.COLORS['RESET']}"
    
    def format_ls_output(self, output: str, command: str = '') -> str:
        """Format ls command output with realistic colors and spacing"""
        if not output or not output.strip():
            return ""
        
        # Check for long format
        if '-l' in command:
            return self.format_ls_long(output)
        
        # Check for no-color flags
        if '--color=never' in command or '--color=no' in command:
            return self.format_ls_plain(output)
        
        # Parse items from output
        items = self.parse_ls_items(output)
        
        if not items:
            return ""
        
        # Format with colors
        formatted_items = []
        for item in items:
            colored_item = self.colorize_file_item(item)
            # Adjust spacing to account for ANSI codes
            display_width = len(item)
            padding = max(0, 20 - display_width)
            formatted_items.append(colored_item + ' ' * padding)
        
        # Arrange in rows of 3-4 items for better readability
        rows = []
        items_per_row = 4 if len(items) > 12 else 3
        
        for i in range(0, len(formatted_items), items_per_row):
            row = formatted_items[i:i+items_per_row]
            rows.append(''.join(row).rstrip())
        
        return '\n'.join(rows)
    
    def format_ls_long(self, output: str) -> str:
        """Format ls -l output with proper alignment and colors"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse ls -l format: permissions user group size date time name
            parts = line.split()
            if len(parts) >= 9:
                perms = parts[0]
                links = parts[1]
                user = parts[2]
                group = parts[3]
                size = parts[4]
                month = parts[5]
                day = parts[6]
                time_or_year = parts[7]
                filename = ' '.join(parts[8:])
                
                # Color the filename based on type
                colored_filename = self.colorize_file_item(filename)
                
                # Format with proper alignment
                formatted_line = f"{perms:<11} {links:>3} {user:<8} {group:<8} {size:>8} {month} {day:>2} {time_or_year:>5} {colored_filename}"
                formatted_lines.append(formatted_line)
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_ls_plain(self, output: str) -> str:
        """Format ls output without colors"""
        items = self.parse_ls_items(output)
        
        if not items:
            return ""
        
        # Simple formatting without colors
        formatted_items = [f'{item:<20}' for item in items]
        
        rows = []
        for i in range(0, len(formatted_items), 4):
            row = formatted_items[i:i+4]
            rows.append(''.join(row).rstrip())
        
        return '\n'.join(rows)
    
    def parse_ls_items(self, output: str) -> List[str]:
        """Parse and clean ls output to extract file/directory names"""
        # Clean up the output
        clean_output = re.sub(r'\s+', ' ', output.strip())
        
        items = []
        words = clean_output.split()
        
        for word in words:
            # Handle concatenated filenames
            if len(word) > 25 and ('.' in word or '/' in word):
                # Try to split on file extensions and directory patterns
                parts = re.split(r'(\.[a-zA-Z0-9]{2,4}(?=[A-Z]|[a-z][A-Z])|/(?=[A-Z]|[a-z]))', word)
                current = ""
                for part in parts:
                    if part:
                        current += part
                        if (part.endswith('/') or 
                            re.match(r'\.[a-zA-Z0-9]{2,4}$', part) or
                            (len(current) > 3 and not part.startswith('.'))):
                            items.append(current)
                            current = ""
                if current:
                    items.append(current)
            else:
                items.append(word)
        
        return items
    
    def format_ps_output(self, output: str) -> str:
        """Format ps command output with proper alignment"""
        lines = output.strip().split('\n')
        if not lines:
            return ""
        
        formatted_lines = []
        for i, line in enumerate(lines):
            if i == 0:  # Header line
                formatted_lines.append(f"{self.COLORS['BOLD']}{line}{self.COLORS['RESET']}")
            else:
                # Color process names
                parts = line.split()
                if len(parts) >= 4:
                    pid = parts[0]
                    tty = parts[1] if len(parts) > 1 else ""
                    time = parts[2] if len(parts) > 2 else ""
                    cmd = ' '.join(parts[3:]) if len(parts) > 3 else ""
                    
                    # Color important processes
                    if any(proc in cmd.lower() for proc in ['ssh', 'bash', 'python', 'systemd']):
                        cmd = f"{self.COLORS['GREEN']}{cmd}{self.COLORS['RESET']}"
                    
                    formatted_line = f"{pid:>7} {tty:<8} {time:>8} {cmd}"
                    formatted_lines.append(formatted_line)
                else:
                    formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_netstat_output(self, output: str) -> str:
        """Format netstat output with colors for different connection states"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for i, line in enumerate(lines):
            if i == 0 or line.startswith('Active') or line.startswith('Proto'):
                formatted_lines.append(f"{self.COLORS['BOLD']}{line}{self.COLORS['RESET']}")
            else:
                # Color connection states
                if 'ESTABLISHED' in line:
                    line = line.replace('ESTABLISHED', f"{self.COLORS['GREEN']}ESTABLISHED{self.COLORS['RESET']}")
                elif 'LISTEN' in line:
                    line = line.replace('LISTEN', f"{self.COLORS['BLUE']}LISTEN{self.COLORS['RESET']}")
                elif 'TIME_WAIT' in line:
                    line = line.replace('TIME_WAIT', f"{self.COLORS['YELLOW']}TIME_WAIT{self.COLORS['RESET']}")
                
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_df_output(self, output: str) -> str:
        """Format df output with proper alignment and usage colors"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for i, line in enumerate(lines):
            if i == 0:  # Header
                formatted_lines.append(f"{self.COLORS['BOLD']}{line}{self.COLORS['RESET']}")
            else:
                parts = line.split()
                if len(parts) >= 6:
                    # Extract usage percentage
                    usage_str = parts[4] if len(parts) > 4 else "0%"
                    usage_pct = int(usage_str.rstrip('%')) if usage_str.rstrip('%').isdigit() else 0
                    
                    # Color based on usage
                    if usage_pct > 90:
                        colored_usage = f"{self.COLORS['RED']}{usage_str}{self.COLORS['RESET']}"
                    elif usage_pct > 75:
                        colored_usage = f"{self.COLORS['YELLOW']}{usage_str}{self.COLORS['RESET']}"
                    else:
                        colored_usage = f"{self.COLORS['GREEN']}{usage_str}{self.COLORS['RESET']}"
                    
                    # Reconstruct line with colored usage
                    new_parts = parts.copy()
                    new_parts[4] = colored_usage
                    formatted_lines.append(' '.join(new_parts))
                else:
                    formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_top_output(self, output: str) -> str:
        """Format top command output with colors for system monitoring"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for i, line in enumerate(lines):
            if i < 5:  # Header lines (load avg, tasks, cpu, memory)
                if 'load average' in line.lower():
                    # Color load averages based on values
                    formatted_lines.append(f"{self.COLORS['BOLD']}{line}{self.COLORS['RESET']}")
                elif 'cpu' in line.lower():
                    # Highlight CPU usage
                    formatted_lines.append(f"{self.COLORS['CYAN']}{line}{self.COLORS['RESET']}")
                elif 'mem' in line.lower() or 'swap' in line.lower():
                    # Highlight memory info
                    formatted_lines.append(f"{self.COLORS['YELLOW']}{line}{self.COLORS['RESET']}")
                else:
                    formatted_lines.append(f"{self.COLORS['BOLD']}{line}{self.COLORS['RESET']}")
            elif 'PID' in line and 'USER' in line:  # Process header
                formatted_lines.append(f"{self.COLORS['BOLD']}{line}{self.COLORS['RESET']}")
            else:
                # Color process lines based on CPU/memory usage
                parts = line.split()
                if len(parts) >= 9:
                    try:
                        cpu_usage = float(parts[8]) if parts[8].replace('.', '').isdigit() else 0
                        if cpu_usage > 50:
                            line = f"{self.COLORS['RED']}{line}{self.COLORS['RESET']}"
                        elif cpu_usage > 20:
                            line = f"{self.COLORS['YELLOW']}{line}{self.COLORS['RESET']}"
                    except (ValueError, IndexError):
                        pass
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_find_output(self, output: str, command: str = '') -> str:
        """Format find command output with file type colors"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            if line.strip():
                # Extract filename from path
                filename = line.split('/')[-1] if '/' in line else line
                colored_line = line.replace(filename, self.colorize_file_item(filename))
                formatted_lines.append(colored_line)
        
        return '\n'.join(formatted_lines)
    
    def format_grep_output(self, output: str, command: str = '') -> str:
        """Format grep output with highlighted matches"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        # Extract search pattern from command
        pattern = ""
        cmd_parts = command.split()
        for i, part in enumerate(cmd_parts):
            if part == 'grep' and i + 1 < len(cmd_parts):
                pattern = cmd_parts[i + 1].strip('"\'')
                break
        
        for line in lines:
            if pattern and pattern in line:
                # Highlight the matched pattern
                highlighted = line.replace(pattern, f"{self.COLORS['RED']}{pattern}{self.COLORS['RESET']}")
                formatted_lines.append(highlighted)
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_cat_output(self, output: str, command: str = '') -> str:
        """Format cat output with syntax highlighting for common file types"""
        # Determine file type from command
        cmd_parts = command.split()
        filename = ""
        for part in cmd_parts:
            if part != 'cat' and not part.startswith('-'):
                filename = part
                break
        
        # Basic syntax highlighting for common files
        if filename.endswith(('.conf', '.cfg', '.ini')):
            return self.highlight_config_file(output)
        elif filename.endswith(('.log',)):
            return self.highlight_log_file(output)
        elif filename.endswith(('.py', '.sh', '.pl')):
            return self.highlight_script_file(output)
        else:
            return output
    
    def highlight_config_file(self, content: str) -> str:
        """Add basic highlighting for configuration files"""
        lines = content.split('\n')
        formatted_lines = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith(';'):
                # Comments
                formatted_lines.append(f"{self.COLORS['GRAY']}{line}{self.COLORS['RESET']}")
            elif '=' in line and not stripped.startswith('['):
                # Key-value pairs
                key, value = line.split('=', 1)
                formatted_lines.append(f"{self.COLORS['CYAN']}{key}{self.COLORS['RESET']}={self.COLORS['YELLOW']}{value}{self.COLORS['RESET']}")
            elif stripped.startswith('[') and stripped.endswith(']'):
                # Section headers
                formatted_lines.append(f"{self.COLORS['BOLD']}{self.COLORS['BLUE']}{line}{self.COLORS['RESET']}")
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def highlight_log_file(self, content: str) -> str:
        """Add highlighting for log files"""
        lines = content.split('\n')
        formatted_lines = []
        
        for line in lines:
            lower_line = line.lower()
            if any(level in lower_line for level in ['error', 'err', 'fatal']):
                formatted_lines.append(f"{self.COLORS['RED']}{line}{self.COLORS['RESET']}")
            elif any(level in lower_line for level in ['warn', 'warning']):
                formatted_lines.append(f"{self.COLORS['YELLOW']}{line}{self.COLORS['RESET']}")
            elif any(level in lower_line for level in ['info', 'notice']):
                formatted_lines.append(f"{self.COLORS['CYAN']}{line}{self.COLORS['RESET']}")
            elif any(level in lower_line for level in ['debug', 'trace']):
                formatted_lines.append(f"{self.COLORS['GRAY']}{line}{self.COLORS['RESET']}")
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def highlight_script_file(self, content: str) -> str:
        """Add basic highlighting for script files"""
        lines = content.split('\n')
        formatted_lines = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                # Comments and shebangs
                if stripped.startswith('#!'):
                    formatted_lines.append(f"{self.COLORS['MAGENTA']}{line}{self.COLORS['RESET']}")
                else:
                    formatted_lines.append(f"{self.COLORS['GRAY']}{line}{self.COLORS['RESET']}")
            elif any(keyword in stripped for keyword in ['def ', 'class ', 'function ', 'if ', 'for ', 'while ']):
                # Keywords
                formatted_lines.append(f"{self.COLORS['BLUE']}{line}{self.COLORS['RESET']}")
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_ifconfig_output(self, output: str) -> str:
        """Format ifconfig/ip command output with network interface colors"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            if ':' in line and ('eth' in line or 'wlan' in line or 'lo' in line):
                # Interface names
                formatted_lines.append(f"{self.COLORS['BOLD']}{self.COLORS['GREEN']}{line}{self.COLORS['RESET']}")
            elif 'inet ' in line:
                # IP addresses
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'inet' and i + 1 < len(parts):
                        ip = parts[i + 1]
                        line = line.replace(ip, f"{self.COLORS['CYAN']}{ip}{self.COLORS['RESET']}")
                formatted_lines.append(line)
            elif 'UP' in line or 'RUNNING' in line:
                # Status indicators
                line = line.replace('UP', f"{self.COLORS['GREEN']}UP{self.COLORS['RESET']}")
                line = line.replace('RUNNING', f"{self.COLORS['GREEN']}RUNNING{self.COLORS['RESET']}")
                formatted_lines.append(line)
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_mount_output(self, output: str) -> str:
        """Format mount command output with filesystem colors"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            # Color filesystem types
            if ' ext4 ' in line:
                line = line.replace(' ext4 ', f" {self.COLORS['GREEN']}ext4{self.COLORS['RESET']} ")
            elif ' tmpfs ' in line:
                line = line.replace(' tmpfs ', f" {self.COLORS['YELLOW']}tmpfs{self.COLORS['RESET']} ")
            elif ' proc ' in line:
                line = line.replace(' proc ', f" {self.COLORS['MAGENTA']}proc{self.COLORS['RESET']} ")
            elif ' sysfs ' in line:
                line = line.replace(' sysfs ', f" {self.COLORS['CYAN']}sysfs{self.COLORS['RESET']} ")
            
            # Color mount points
            parts = line.split(' on ')
            if len(parts) == 2:
                device = parts[0]
                rest = parts[1]
                mount_point = rest.split(' type ')[0] if ' type ' in rest else rest
                line = line.replace(f' on {mount_point}', f" on {self.COLORS['BLUE']}{mount_point}{self.COLORS['RESET']}")
            
            formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_generic_output(self, output: str) -> str:
        """Format generic command output with basic enhancements"""
        # Don't modify if it's already well-formatted or contains errors
        if any(keyword in output.lower() for keyword in ['error', 'permission denied', 'not found', 'usage:', 'command not found']):
            # Color error messages
            lines = output.split('\n')
            formatted_lines = []
            for line in lines:
                lower_line = line.lower()
                if any(err in lower_line for err in ['error', 'permission denied', 'not found', 'command not found']):
                    formatted_lines.append(f"{self.COLORS['RED']}{line}{self.COLORS['RESET']}")
                elif 'usage:' in lower_line:
                    formatted_lines.append(f"{self.COLORS['YELLOW']}{line}{self.COLORS['RESET']}")
                else:
                    formatted_lines.append(line)
            return '\n'.join(formatted_lines)
        
        return output
