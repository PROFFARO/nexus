#!/usr/bin/env python3
"""
Enhanced Command Output Formatter for SSH Honeypot
Parses LLM-provided raw content and formats it to match real Linux command output
"""

import re
from typing import List, Dict, Any


class CommandFormatter:
    """Formatter that parses LLM raw content and structures it like real Linux commands"""
    
    def __init__(self):
        pass
    
    def format_ls_output(self, output: str, command: str = '') -> str:
        """Parse LLM-provided file/directory names and format like real Linux ls command"""
        if not output or not output.strip():
            return ""
        
        # Check for long format
        if '-l' in command:
            return self.format_ls_long(output)
        
        # Parse items from LLM output (space-separated names)
        items = self.parse_ls_items(output)
        
        if not items:
            return ""
        
        # Format in multi-column layout like real ls
        # Calculate optimal column width
        max_width = max(len(item) for item in items) if items else 20
        col_width = min(max_width + 2, 25)  # Add padding, cap at 25
        
        # Determine number of columns (assume 80-char terminal width)
        terminal_width = 80
        num_cols = max(1, terminal_width // col_width)
        
        # Format items in columns
        rows = []
        for i in range(0, len(items), num_cols):
            row_items = items[i:i+num_cols]
            formatted_row = ''.join(item.ljust(col_width) for item in row_items)
            rows.append(formatted_row.rstrip())
        
        return '\n'.join(rows)
    
    def format_ls_long(self, output: str) -> str:
        """Parse LLM data and format as ls -l output with proper column alignment"""
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            if not line.strip():
                continue
            
            # Parse ls -l format from LLM: permissions user group size month day time name
            parts = line.split()
            if len(parts) >= 8:
                perms = parts[0]
                links = parts[1]
                user = parts[2]
                group = parts[3]
                size = parts[4]
                month = parts[5]
                day = parts[6]
                time_or_year = parts[7]
                filename = ' '.join(parts[8:]) if len(parts) > 8 else ''
                
                # Format with proper alignment like real ls -l
                formatted_line = f"{perms:<11} {links:>3} {user:<8} {group:<8} {size:>8} {month} {day:>2} {time_or_year:>5} {filename}"
                formatted_lines.append(formatted_line)
            else:
                # If format doesn't match, pass through as-is
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def parse_ls_items(self, output: str) -> List[str]:
        """Parse space-separated file/directory names from LLM output"""
        # Clean up the output
        clean_output = output.strip()
        
        # Split on whitespace
        items = clean_output.split()
        
        return items
    
    def format_ps_output(self, output: str) -> str:
        """Parse LLM process data and format like real ps command"""
        lines = output.strip().split('\n')
        if not lines:
            return ""
        
        # Add header
        formatted_lines = ["  PID TTY          TIME CMD"]
        
        for line in lines:
            if not line.strip():
                continue
            
            # Parse process data from LLM: pid tty time cmd
            parts = line.split(None, 3)  # Split into max 4 parts
            if len(parts) >= 4:
                pid = parts[0]
                tty = parts[1]
                time = parts[2]
                cmd = parts[3]
                
                # Format like real ps output
                formatted_line = f"{pid:>5} {tty:<12} {time:>8} {cmd}"
                formatted_lines.append(formatted_line)
            elif len(parts) >= 1:
                # Minimal format, just pass through
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_netstat_output(self, output: str) -> str:
        """Parse LLM network data and format like real netstat command"""
        lines = output.strip().split('\n')
        
        # Add header
        formatted_lines = ["Proto Recv-Q Send-Q Local Address           Foreign Address         State"]
        
        for line in lines:
            if not line.strip():
                continue
            
            # Parse network data from LLM: proto recv-q send-q local foreign state
            parts = line.split()
            if len(parts) >= 6:
                proto = parts[0]
                recv_q = parts[1]
                send_q = parts[2]
                local = parts[3]
                foreign = parts[4]
                state = parts[5] if len(parts) > 5 else ""
                
                # Format with proper column alignment
                formatted_line = f"{proto:<5} {recv_q:>6} {send_q:>6} {local:<23} {foreign:<23} {state}"
                formatted_lines.append(formatted_line)
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_df_output(self, output: str) -> str:
        """Parse LLM filesystem data and format like real df command"""
        lines = output.strip().split('\n')
        
        # Add header
        formatted_lines = ["Filesystem     1K-blocks    Used Available Use% Mounted on"]
        
        for line in lines:
            if not line.strip():
                continue
            
            # Parse filesystem data: filesystem blocks used available use% mounted
            parts = line.split()
            if len(parts) >= 6:
                filesystem = parts[0]
                blocks = parts[1]
                used = parts[2]
                available = parts[3]
                use_pct = parts[4]
                mounted = ' '.join(parts[5:])
                
                # Format with proper alignment
                formatted_line = f"{filesystem:<14} {blocks:>10} {used:>7} {available:>9} {use_pct:>4} {mounted}"
                formatted_lines.append(formatted_line)
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_top_output(self, output: str) -> str:
        """Parse LLM process data and format like real top command"""
        lines = output.strip().split('\n')
        if not lines:
            return ""
        
        formatted_lines = []
        
        # First few lines are usually headers from LLM, pass through
        header_count = 0
        for i, line in enumerate(lines):
            if 'PID' in line and 'USER' in line:
                # This is the process list header
                formatted_lines.append("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND")
                header_count = i + 1
                break
            else:
                formatted_lines.append(line)
        
        # Format process lines
        for line in lines[header_count:]:
            if not line.strip():
                continue
            
            # Parse process data
            parts = line.split()
            if len(parts) >= 11:
                pid = parts[0]
                user = parts[1]
                pr = parts[2]
                ni = parts[3]
                virt = parts[4]
                res = parts[5]
                shr = parts[6]
                s = parts[7]
                cpu = parts[8]
                mem = parts[9]
                time = parts[10]
                cmd = ' '.join(parts[11:]) if len(parts) > 11 else ''
                
                # Format like real top
                formatted_line = f"{pid:>5} {user:<9} {pr:>3} {ni:>3} {virt:>8} {res:>7} {shr:>7} {s} {cpu:>6} {mem:>6} {time:>9} {cmd}"
                formatted_lines.append(formatted_line)
            else:
                formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
    
    def format_find_output(self, output: str, command: str = '') -> str:
        """Format find command output - usually just paths, pass through"""
        return output.strip()
    
    def format_grep_output(self, output: str, command: str = '') -> str:
        """Format grep output - pass through with cleanup"""
        return output.strip()
    
    def format_cat_output(self, output: str, command: str = '') -> str:
        """Format cat output - pass through as-is"""
        return output.strip()
    
    def format_ifconfig_output(self, output: str) -> str:
        """Parse LLM network interface data and format like real ifconfig"""
        # ifconfig has complex multi-line format, mostly pass through
        # but ensure proper indentation
        lines = output.strip().split('\n')
        formatted_lines = []
        
        for line in lines:
            # Interface name lines (no leading space)
            if ':' in line and not line.startswith(' '):
                formatted_lines.append(line)
            # Detail lines (should be indented)
            elif line.strip():
                if not line.startswith(' '):
                    formatted_lines.append('        ' + line.strip())
                else:
                    formatted_lines.append(line)
            else:
                formatted_lines.append('')
        
        return '\n'.join(formatted_lines)
    
    def format_mount_output(self, output: str) -> str:
        """Format mount command output - pass through with cleanup"""
        return output.strip()
    
    def format_generic_output(self, output: str) -> str:
        """Format generic command output - minimal processing"""
        return output.strip()
