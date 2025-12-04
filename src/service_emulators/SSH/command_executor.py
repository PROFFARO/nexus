#!/usr/bin/env python3
"""
Command Executor for SSH Honeypot
Handles command validation, routing, and execution with prompt injection protection
"""

import datetime
import fnmatch
import random
import logging
import re
import shlex
from typing import Optional, Dict, Any, List, Tuple
from virtual_filesystem import VirtualFilesystem

logger = logging.getLogger(__name__)


class CommandExecutor:
    """
    Executes commands with validation and routing
    - Validates commands are legitimate Linux commands
    - Detects prompt injection attempts
    - Routes to filesystem, system templates, or LLM
    """
    
    # Valid Linux commands (comprehensive list)
    VALID_COMMANDS = {
        # Filesystem operations
        "lsblk", "blkid", "fdisk", "parted",

        # System info
        "lscpu", "lsmem", "lshw", "dmidecode", "hwinfo", "inxi",
        "lspci", "lsusb", "lsof", "free", "vmstat", "iostat", "mpstat", "sar",

        # Process management
        "pmap", "strace", "ltrace",

        # Network
        "ping", "iptables",

        # Misc utilities:
        "rev", "tac",

        # System admin:
        "chage", "lastlog", "faillog", "dmesg", "sysctl", "modprobe", "lsmod", "rmmod", "insmod",

        # Package/build:
        "docker", "kubectl", "helm",

        # Cron:
        "at", "atq", "atrm", "batch",

        # Man pages:
        "apropos", "whatis",

        # Filesystem operations
        "ls", "cd", "pwd", "cat", "head", "tail", "grep", "find", "mkdir", "rm", "rmdir",
        "cp", "mv", "touch", "chmod", "chown", "chgrp", "ln", "readlink", "basename", "dirname",
        "file", "stat", "du", "df", "mount", "umount",
        
        # File viewing/editing
        "more", "less", "vim", "vi", "nano", "emacs", "ed", "sed", "awk",
        
        # System info
        "whoami", "id", "hostname", "uname", "uptime", "date", "cal", "w", "who", "last",
        "users", "groups", "finger",
        
        # Process management
        "ps", "top", "htop", "kill", "killall", "pkill", "pgrep", "pidof", "jobs", "bg", "fg",
        "nohup", "nice", "renice", "pstree",
        
        # Network
        "ifconfig", "ip", "netstat", "ss", "traceroute", "tracepath", "nslookup",
        "dig", "host", "route", "arp", "nc", "netcat", "telnet", "ssh", "scp", "sftp",
        "wget", "curl", "ftp",
        
        # Ubuntu/Debian specific
        "apt", "apt-get", "apt-cache", "dpkg", "dpkg-query", "aptitude", "snap",
        "systemctl", "service", "journalctl", "systemd-analyze", "update-alternatives",
        "add-apt-repository", "update-rc.d",
        
        # Archive/compression
        "tar", "gzip", "gunzip", "bzip2", "bunzip2", "zip", "unzip", "7z", "rar", "unrar",
        "xz", "compress", "uncompress",
        
        # Text processing
        "echo", "printf", "wc", "sort", "uniq", "cut", "paste", "tr", "expand", "unexpand",
        "join", "comm", "diff", "patch", "cmp",
        
        # Search
        "which", "whereis", "locate", "updatedb",
        
        # Shell builtins
        "alias", "unalias", "export", "env", "set", "unset", "source", ".", "exec",
        "eval", "test", "[", "[[", "history", "fc", "type", "command", "builtin",
        
        # Misc utilities
        "clear", "reset", "tput", "stty", "tty", "sleep", "watch", "time", "timeout",
        "yes", "true", "false", "seq", "bc", "expr", "factor", "md5sum", "sha1sum",
        "sha256sum", "base64", "xxd", "od", "hexdump", "strings",
        
        # System admin
        "sudo", "su", "passwd", "useradd", "usermod", "userdel", "groupadd", "groupmod",
        "groupdel", "adduser", "deluser", "addgroup", "delgroup", "visudo",
        
        # Package/build
        "make", "cmake", "gcc", "g++", "cc", "python", "python3", "perl", "ruby", "node",
        "npm", "pip", "pip3", "java", "javac", "git", "svn", "hg", "cvs",
        
        # Cron
        "crontab",
        
        # Man pages
        "man", "help", "info",
        
        # Exit commands
        "exit", "logout", "quit",
    }
    
    # Prompt injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction manipulation (with word boundaries to avoid false positives)
        r"\bignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|context|commands?|directives?)\b",
        r"\bforget\s+(everything|all\s+previous|the\s+previous|what\s+you\s+were\s+told)\b",
        r"\bdisregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|context|prompts?)\b",
        r"\bdelete\s+(all\s+)?(previous|prior)\s+(context|history|instructions?|memory)\b",
        r"\boverride\s+(previous|all|system)\s+(instructions?|prompts?|settings?)\b",
        
        # Role manipulation (must be at start of message or after punctuation)
        r"(?:^|[.!?]\s+)you\s+are\s+(now|actually|really)\s+(a|an)\s+(?!user|admin|root|guest)\w+",
        r"(?:^|[.!?]\s+)act\s+as\s+(?:a|an)\s+(?!user|admin|system\s+administrator)\w+",
        r"(?:^|[.!?]\s+)pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+\w+",
        r"(?:^|[.!?]\s+)roleplay\s+as\s+(?:a|an)\s+\w+",
        r"(?:^|[.!?]\s+)simulate\s+(?:being\s+)?(?:a|an)\s+(?!server|system|process)\w+",
        r"(?:^|[.!?]\s+)from\s+now\s+on,?\s+you\s+(?:are|will\s+be)\s+",
        
        # System/assistant role injection (must be exact format)
        r"^\s*system\s*:\s*",
        r"^\s*assistant\s*:\s*",
        r"^\s*user\s*:\s*(?!@)",  # Exclude user@host format
        r"^\s*\[system\]\s*",
        r"^\s*\[assistant\]\s*",
        r"^\s*<\|system\|>\s*",
        r"^\s*<\|assistant\|>\s*",
        
        # Context manipulation
        r"\bnew\s+conversation\s+(?:starting|begins?|now)\b",
        r"\bstart\s+(?:a\s+)?(?:new\s+)?conversation\s+over\b",
        r"\breset\s+(?:the\s+)?(context|conversation|chat|session)\b",
        r"\bclear\s+(?:the\s+)?(context|history|memory|conversation)\b",
        r"\bbegin\s+(?:a\s+)?new\s+(?:session|context|conversation)\b",
        
        # Meta instructions (asking about system prompts)
        r"\btell\s+me\s+(?:who|what)\s+you\s+(?:are|really\s+are|actually\s+are)\b",
        r"\bwhat\s+(?:are|is)\s+your\s+(?:actual\s+)?(instructions?|prompts?|system\s+prompts?|directives?)\b",
        r"\bshow\s+(?:me\s+)?your\s+(?:actual\s+)?(instructions?|prompts?|system\s+(?:message|prompt))\b",
        r"\breveal\s+(?:your\s+)?(instructions?|prompts?|system\s+message)\b",
        r"\bdisplay\s+(?:your\s+)?(?:system\s+)?(instructions?|prompts?|configuration)\b",
        r"\bprint\s+(?:your\s+)?(?:system\s+)?(instructions?|prompts?|directives?)\b(?!\s+to\s+(?:file|screen|stdout))",
        
        # Jailbreak attempts
        r"\bDAN\s+mode\b",
        r"\bDeveloper\s+Mode\b",
        r"\bjailbreak\s+(?:mode|prompt)\b",
        r"\bunrestricted\s+(?:mode|access)\b",
        r"\bbypass\s+(?:restrictions?|filters?|safety)\b",
        
        # Prompt leaking
        r"\brepeat\s+(?:the\s+)?(?:above|previous)\s+(?:text|prompt|instructions?)\b",
        r"\becho\s+(?:back\s+)?(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)\b(?!\s+[\"'])",  # Exclude echo "string"
        r"\boutput\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)\b",
        
        # Encoding/obfuscation attempts
        r"base64\s+decode\s+the\s+following",
        r"rot13\s+(?:decode|decrypt)",
        r"\bignore\s+all\s+safety\b",
        
        # Multi-language injection attempts
        r"traduire\s+en\s+français\s*:",  # French
        r"übersetze\s+ins\s+deutsche\s*:",  # German
        r"翻译成中文\s*[:：]",  # Chinese
        
        # Delimiter injection
        r"---+\s*(?:end|stop|ignore)\s+(?:previous|above)",
        r"===+\s*(?:new|reset)\s+(?:context|session)",
        
        # Hypothetical scenarios designed to manipulate
        r"\bif\s+you\s+were\s+not\s+(?:a\s+)?(?:honeypot|ssh\s+server|restricted)",
        r"\bimagine\s+you\s+(?:are|were)\s+(?:not\s+)?(?:a\s+)?(?!user)\w+\s+(?:without|with\s+no)\s+restrictions?",
    ]
    
    def __init__(self, filesystem: VirtualFilesystem):
        self.fs = filesystem
        self.compiled_injection_patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        
    def execute(
        self,
        command: str,
        current_dir: str = "/",
        username: str = "guest",
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[str], str]:
        """
        Execute a command
        
        Args:
            command: Command string to execute
            current_dir: Current working directory
            username: Current user
            context: Additional context (server instance, etc.)
            
        Returns:
            Tuple of (response, routing_decision)
            - response: Command output or None if should use LLM
            - routing_decision: "filesystem", "system", "llm", "invalid", "injection"
        """
        if not command or not command.strip():
            return ("", "empty")
            
        # Check for prompt injection first
        if self.detect_injection(command):
            return (self._get_injection_response(command), "injection")
            
        # Validate command
        if not self.validate_command(command):
            return (self._get_command_not_found(command), "invalid")
            
        # Route command
        routing = self.route_command(command)
        
        if routing == "filesystem":
            return (self._execute_filesystem_command(command, current_dir, username, context), "filesystem")
        elif routing == "system":
            return (self._execute_system_command(command, username, context), "system")
        else:
            # Let LLM handle it
            return (None, "llm")
            
    def validate_command(self, command: str) -> bool:
        """
        Check if command is a valid Linux command or command pattern.
        
        Validates:
        - Known commands in VALID_COMMANDS
        - Common shell patterns (pipes, redirects, etc.)
        - Path-based command execution
        - Shell builtins
        - Variable assignments
        
        Returns:
            True if valid command syntax, False if invalid/nonsense
        """
        # Empty or whitespace-only is valid (just returns prompt)
        if not command or not command.strip():
            return True
        
        # Try to parse the command
        try:
            parts = shlex.split(command)
        except ValueError:
            # Invalid shell syntax (unmatched quotes, etc.)
            logger.debug(f"Invalid shell syntax: {command}")
            return False
        
        if not parts:
            return True  # Empty after parsing is valid
        
        # Get the base command
        cmd = parts[0].lower()
        
        # Handle path-based commands (e.g., /usr/bin/ls, ./script.sh)
        if "/" in cmd:
            # Extract just the command name
            cmd_name = cmd.split("/")[-1]
            
            # Check if it's a valid command name
            if cmd_name in self.VALID_COMMANDS:
                return True
            
            # Allow execution of scripts/binaries (realistic behavior)
            # Check if it looks like a script or binary
            if cmd.startswith('./') or cmd.startswith('../'):
                return True  # Local script execution
            
            # Absolute paths to common locations
            valid_paths = ['/bin/', '/usr/bin/', '/sbin/', '/usr/sbin/', '/usr/local/bin/']
            if any(cmd.startswith(path) for path in valid_paths):
                return True
        
        # Check if it's a known command
        if cmd in self.VALID_COMMANDS:
            return True
        
        # Check for shell builtins (not in VALID_COMMANDS but still valid)
        shell_builtins = {
            'alias', 'unalias', 'bg', 'fg', 'bind', 'break', 'builtin',
            'case', 'command', 'compgen', 'complete', 'continue', 'declare',
            'dirs', 'disown', 'enable', 'eval', 'exec', 'exit', 'export',
            'fc', 'getopts', 'hash', 'help', 'history', 'if', 'jobs',
            'let', 'local', 'logout', 'popd', 'pushd', 'pwd', 'read',
            'readonly', 'return', 'set', 'shift', 'shopt', 'source',
            'suspend', 'test', 'times', 'trap', 'type', 'typeset',
            'ulimit', 'umask', 'unset', 'until', 'wait', 'while'
        }
        
        if cmd in shell_builtins:
            return True
        
        # Check for variable assignment (VAR=value)
        if '=' in cmd and not cmd.startswith('='):
            # Variable assignment is valid
            var_name = cmd.split('=')[0]
            if var_name.replace('_', '').isalnum() and not var_name[0].isdigit():
                return True
        
        # Check for common shell patterns that are valid
        
        # 1. Command substitution: $(command) or [command](cci:1://file:///c:/Users/Dayab/Documents/GitHub/nexus-development/src/service_emulators/SSH/command_executor.py:437:4-558:20)
        if command.startswith('$(') or command.startswith('`'):
            return True
        
        # 2. Pipes: command1 | command2
        if '|' in command:
            # Split by pipe and validate each part
            pipe_parts = command.split('|')
            for part in pipe_parts:
                part = part.strip()
                if part and not self.validate_command(part):
                    return False
            return True
        
        # 3. Command chaining: command1 && command2 || command3
        if '&&' in command or '||' in command:
            # Complex command chain - assume valid if it parses
            return True
        
        # 4. Command sequencing: command1; command2
        if ';' in command:
            # Split by semicolon and validate each part
            seq_parts = command.split(';')
            for part in seq_parts:
                part = part.strip()
                if part and not self.validate_command(part):
                    return False
            return True
        
        # 5. Redirections: command > file, command < file, command 2>&1
        redirect_patterns = ['>', '<', '>>', '2>', '2>&1', '&>', '&>>']
        if any(pattern in command for pattern in redirect_patterns):
            # Has redirection - assume valid if base command is valid
            # Extract the command before the redirect
            for pattern in redirect_patterns:
                if pattern in command:
                    base_cmd = command.split(pattern)[0].strip()
                    return self.validate_command(base_cmd)
        
        # 6. Background execution: command &
        if command.strip().endswith('&'):
            base_cmd = command.strip()[:-1].strip()
            return self.validate_command(base_cmd)
        
        # 7. Here documents and here strings
        if '<<' in command or '<<<' in command:
            return True
        
        # 8. Process substitution: <(command) or >(command)
        if '<(' in command or '>(' in command:
            return True
        
        # 9. Brace expansion: {a,b,c}
        if '{' in command and '}' in command:
            return True
        
        # 10. Glob patterns: *, ?, [...]
        if any(char in cmd for char in ['*', '?', '[']):
            return True
        
        # 11. Tilde expansion: ~/path
        if cmd.startswith('~'):
            return True
        
        # If none of the above, it's likely an invalid/unknown command
        logger.debug(f"Unknown command: {cmd}")
        return False
        
    def detect_injection(self, command: str) -> bool:
        """
        Detect prompt injection attempts with multiple detection methods.
        
        Uses:
        - Regex pattern matching
        - Entropy analysis (unusual character patterns)
        - Length anomaly detection
        - Suspicious character sequences
        - Context-aware filtering
        
        Returns:
            True if injection detected, False otherwise
        """
        # Quick length check - extremely long commands are suspicious
        if len(command) > 5000:
            logger.warning(f"Injection detected: Command too long ({len(command)} chars)")
            return True
        
        # Empty or whitespace-only commands
        if not command or not command.strip():
            return False
        
        # Check if it's a legitimate command first (avoid false positives)
        try:
            parts = shlex.split(command)
            if parts and parts[0].lower() in self.VALID_COMMANDS:
                # It's a known command - apply less strict checks
                # Only check for obvious injection patterns
                return self._check_strict_injection_patterns(command)
        except ValueError:
            # Malformed command - could be injection
            pass
        
        # 1. Check against compiled regex patterns
        for pattern in self.compiled_injection_patterns:
            if pattern.search(command):
                logger.warning(f"Injection detected: Pattern match - {pattern.pattern[:50]}...")
                return True
        
        # 2. Check for excessive special characters (encoding attempts)
        special_char_ratio = sum(1 for c in command if not c.isalnum() and not c.isspace()) / max(len(command), 1)
        if special_char_ratio > 0.5:  # More than 50% special characters
            logger.warning(f"Injection detected: High special character ratio ({special_char_ratio:.2%})")
            return True
        
        # 3. Check for suspicious Unicode/encoding patterns
        if self._has_suspicious_encoding(command):
            logger.warning("Injection detected: Suspicious encoding patterns")
            return True
        
        # 4. Check for repeated delimiter patterns (obfuscation)
        if self._has_delimiter_obfuscation(command):
            logger.warning("Injection detected: Delimiter obfuscation")
            return True
        
        # 5. Check for excessive newlines or control characters
        newline_count = command.count('\n')
        if newline_count > 10:  # More than 10 newlines is suspicious
            logger.warning(f"Injection detected: Excessive newlines ({newline_count})")
            return True
        
        # 6. Check for null bytes or other control characters
        if '\x00' in command or any(ord(c) < 32 and c not in '\n\r\t' for c in command):
            logger.warning("Injection detected: Null bytes or control characters")
            return True
        
        # 7. Check for Base64/encoded payloads
        if self._has_encoded_payload(command):
            logger.warning("Injection detected: Encoded payload")
            return True
        
        # 8. Check for XML/JSON injection attempts
        if self._has_structured_injection(command):
            logger.warning("Injection detected: Structured data injection")
            return True
        
        return False
    
    def _check_strict_injection_patterns(self, command: str) -> bool:
        """
        Check only the most obvious injection patterns for known commands.
        This prevents false positives on legitimate command usage.
        """
        strict_patterns = [
            r"^\s*system\s*:\s*",
            r"^\s*assistant\s*:\s*",
            r"^\s*\[system\]\s*",
            r"\bignore\s+all\s+previous\s+instructions\b",
            r"\bforget\s+everything\b",
            r"\bDAN\s+mode\b",
            r"\bDeveloper\s+Mode\b",
        ]
        
        for pattern_str in strict_patterns:
            if re.search(pattern_str, command, re.IGNORECASE):
                return True
        
        return False
    
    def _has_suspicious_encoding(self, command: str) -> bool:
        """Detect suspicious encoding patterns"""
        # Check for excessive non-ASCII characters
        non_ascii_count = sum(1 for c in command if ord(c) > 127)
        if non_ascii_count > len(command) * 0.3:  # More than 30% non-ASCII
            return True
        
        # Check for common encoding markers
        encoding_markers = [
            'base64,',
            'data:text',
            'data:application',
            '\\u00',
            '\\x',
            '%20%',  # URL encoding
            '&#x',   # HTML entity encoding
        ]
        
        return any(marker in command for marker in encoding_markers)
    
    def _has_delimiter_obfuscation(self, command: str) -> bool:
        """Detect delimiter-based obfuscation attempts"""
        # Check for repeated delimiters
        delimiter_patterns = [
            r'-{10,}',      # 10+ dashes
            r'={10,}',      # 10+ equals
            r'#{10,}',      # 10+ hashes
            r'\*{10,}',     # 10+ asterisks
            r'_{10,}',      # 10+ underscores
        ]
        
        for pattern in delimiter_patterns:
            if re.search(pattern, command):
                return True
        
        return False
    
    def _has_encoded_payload(self, command: str) -> bool:
        """Detect Base64 or other encoded payloads"""
        # Look for long Base64-like strings
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        if re.search(base64_pattern, command):
            # Check if it's actually Base64 (not just random alphanumeric)
            import base64
            try:
                # Try to decode potential Base64 strings
                matches = re.findall(base64_pattern, command)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match, validate=True)
                        # If it decodes successfully and contains injection keywords, flag it
                        decoded_str = decoded.decode('utf-8', errors='ignore').lower()
                        if any(keyword in decoded_str for keyword in ['system', 'ignore', 'forget', 'prompt']):
                            return True
                    except:
                        continue
            except:
                pass
        
        return False
    
    def _has_structured_injection(self, command: str) -> bool:
        """Detect XML/JSON/YAML injection attempts"""
        # Check for XML-like structures
        if re.search(r'<[a-zA-Z][^>]*>.*</[a-zA-Z][^>]*>', command):
            return True
        
        # Check for JSON-like structures with suspicious keys
        if re.search(r'\{\s*["\'](?:role|system|prompt|instruction)["\']', command, re.IGNORECASE):
            return True
        
        # Check for YAML-like structures
        if re.search(r'^\s*---\s*$', command, re.MULTILINE):
            return True
        
        return False
        
    def route_command(self, command: str) -> str:
        """
        Route command to appropriate handler: filesystem, system, or LLM.
        Returns: "filesystem", "system", or "llm"
        """
        try:
            parts = shlex.split(command)
        except ValueError:
            # Malformed command, let LLM handle it
            return "llm"
            
        if not parts:
            return "llm"
            
        cmd = parts[0].lower()
        
        # Check if it's a valid command first
        if cmd not in self.VALID_COMMANDS:
            # Unknown command - route to LLM for natural language processing
            return "llm"
        
        # Filesystem commands - handle locally with virtual filesystem
        filesystem_cmds = {
            # Directory operations
            "ls", "cd", "pwd", "mkdir", "rmdir",
            
            # File operations
            "cat", "head", "tail", "touch", "file", "stat", "wc",
            "cp", "mv", "rm", "ln",
            
            # File permissions
            "chmod", "chown", "chgrp",
            
            # File search and manipulation
            "find", "grep", "locate",
            
            # Path utilities
            "basename", "dirname", "readlink",
            
            # Disk usage
            "du", "df",
            
            # File viewing/editing
            "more", "less", "vim", "vi", "nano", "emacs", "ed", "sed", "awk",
            
            # Archive operations (interact with filesystem)
            "dd",
        }
        
        if cmd in filesystem_cmds:
            return "filesystem"
        
        # System commands - use dynamic templates and simulations
        system_cmds = {
            # User/identity
            "whoami", "id", "groups", "users",
            
            # System information
            "hostname", "uname", "uptime", "date", "dmesg",
            "lscpu", "lsblk", "lspci", "lsusb", "lsmem", "lshw", "hwinfo", 
            "inxi", "dmidecode",
            
            # Process management
            "ps", "top", "htop", "pgrep", "pidof", "pstree",
            "kill", "killall", "pkill", "jobs", "bg", "fg",
            "pmap", "strace", "ltrace",
            
            # System monitoring
            "vmstat", "iostat", "mpstat", "sar", "free",
            
            # Network commands
            "ifconfig", "ip", "netstat", "ss", "ping", "traceroute", "tracepath",
            "nslookup", "dig", "host", "route", "arp",
            "nc", "netcat", "telnet", "wget", "curl",
            
            # Disk/partition management
            "blkid", "fdisk", "parted", "mount",
            
            # Firewall/security
            "iptables",
            
            # User management
            "chage", "lastlog", "faillog", "w", "who", "last",
            
            # System administration
            "sysctl", "modprobe", "lsmod", "rmmod", "insmod",
            "systemctl", "service", "journalctl",
            
            # Package management
            "apt", "apt-get", "dpkg", "yum", "dnf", "rpm",
            "docker", "kubectl", "helm",
            
            # Archive/compression (system-level, not filesystem)
            "tar", "gzip", "gunzip", "bzip2", "bunzip2",
            "zip", "unzip", "xz", "unxz", "7z",
            
            # Environment
            "env", "printenv", "export",
            
            # Shell utilities
            "echo", "printf", "clear", "reset", "exit", "logout", "quit",
            
            # Help/documentation
            "man", "help", "which", "whereis", "whatis", "apropos",
            
            # Scheduling
            "crontab", "at", "batch",
            
            # History
            "history",
        }
        
        if cmd in system_cmds:
            return "system"
        
        # Check for complex command patterns that should go to LLM
        # Pipes, redirections, command substitution, etc.
        if self._is_complex_command(command):
            return "llm"
        
        # Default: route to LLM for natural language or unknown patterns
        return "llm"
    
    def _is_complex_command(self, command: str) -> bool:
        """
        Check if command contains complex shell features that need LLM processing.
        Returns True ONLY for truly complex patterns.
        """
        # Only check for the most complex patterns that we definitely can't handle
        
        # Pipes (except in quoted strings)
        if '|' in command and not command.count('|') == command.count('\\|'):
            # Allow simple error redirection like 2>/dev/null
            if '2>' not in command:
                return True
        
        # Command substitution
        if '$(' in command or '`' in command:
            return True
        
        # Multiple commands chained together
        if any(sep in command for sep in [';', '&&', '||']):
            return True
        
        # Loops and conditionals (these are definitely complex)
        if any(keyword in command.lower() for keyword in ['for ', 'while ', 'if ', 'case ', 'until ']):
            return True
        
        # Background processes
        if command.strip().endswith('&') and not '2>&' in command:
            return True
        
        # Everything else is simple - let the handlers deal with it
        return False

    def _get_injection_response(self, command: str) -> str:
            """
            Return realistic Linux response for detected injection attempt.
            Makes the injection attempt look like it failed naturally.
            """
            try:
                parts = shlex.split(command)
                cmd = parts[0] if parts else command.split()[0]
            except:
                # Fallback for malformed commands
                cmd = command.split()[0] if command.split() else "command"
            
            # Detect the type of injection attempt and respond appropriately
            command_lower = command.lower()
            
            # System/Assistant role injection attempts
            if any(marker in command_lower for marker in ['system:', 'assistant:', '[system]', '[assistant]']):
                # Treat as invalid syntax
                return f"bash: {command.split(':')[0]}: command not found"
            
            # Instruction manipulation attempts (ignore, forget, disregard, etc.)
            if any(word in command_lower for word in ['ignore', 'forget', 'disregard', 'override', 'delete']):
                # Make it look like a failed command with arguments
                return f"bash: {cmd}: command not found"
            
            # Meta instruction queries (show me, tell me, what are your, etc.)
            if any(phrase in command_lower for phrase in ['show me', 'tell me', 'what are your', 'reveal your']):
                # Simulate as if they're trying to run a non-existent command
                if ' ' in command:
                    # Multi-word command - treat first word as command
                    return f"bash: {cmd}: command not found"
                else:
                    return f"bash: {command}: command not found"
            
            # Role manipulation (you are, act as, pretend, etc.)
            if any(phrase in command_lower for phrase in ['you are', 'act as', 'pretend', 'roleplay', 'simulate']):
                # Parse as if it's a command with arguments
                words = command.split()
                if len(words) > 0:
                    return f"bash: {words[0]}: command not found"
                return "bash: syntax error near unexpected token"
            
            # Jailbreak attempts (DAN mode, Developer Mode, etc.)
            if any(phrase in command_lower for phrase in ['dan mode', 'developer mode', 'jailbreak', 'unrestricted']):
                # Treat as invalid command
                return f"bash: {cmd}: command not found"
            
            # Encoding/obfuscation attempts
            if any(phrase in command_lower for phrase in ['base64 decode', 'rot13']):
                # Let it look like a partial command
                if 'base64' in command_lower:
                    return "base64: invalid input"
                elif 'rot13' in command_lower:
                    return f"bash: rot13: command not found"
            
            # Multi-language injection
            if any(char in command for char in ['é', 'ü', '翻', '译']):
                # Non-ASCII characters - treat as encoding issue
                return "bash: syntax error: invalid character in expression"
            
            # Delimiter injection (---, ===, etc.)
            if command.strip().startswith(('---', '===')):
                return "bash: syntax error near unexpected token"
            
            # Context manipulation (new conversation, reset, etc.)
            if any(phrase in command_lower for phrase in ['new conversation', 'start over', 'reset', 'clear context']):
                words = command.split()
                if len(words) > 0:
                    return f"bash: {words[0]}: command not found"
            
            # Hypothetical scenarios
            if 'if you were' in command_lower or 'imagine you' in command_lower:
                return f"bash: {cmd}: command not found"
            
            # Default responses - vary them for realism
            responses = [
                f"bash: {cmd}: command not found",
                f"-bash: {cmd}: command not found",
                f"bash: {cmd}: No such file or directory",
                f"{cmd}: command not found",
            ]
            
            # Add some variation based on command hash
            random.seed(hash(command))
            return random.choice(responses)
        
    def _get_command_not_found(self, command: str) -> str:
        """
        Return realistic 'command not found' error for unimplemented commands.
        This is for legitimate commands that aren't in VALID_COMMANDS, not injection attempts.
        """
        try:
            parts = shlex.split(command)
            cmd = parts[0] if parts else command.split()[0]
        except:
            # Fallback for malformed commands
            cmd = command.split()[0] if command.split() else "command"
        
        # Check if it looks like a typo of a known command (for realism)
        known_commands = self.VALID_COMMANDS
        
        # Common typos and suggestions
        typo_suggestions = {
            'pss': 'ps',
            'psa': 'ps',
            'lss': 'ls',
            'catt': 'cat',
            'clar': 'clear',
            'claer': 'clear',
            'exot': 'exit',
            'exut': 'exit',
            'sudp': 'sudo',
            'suod': 'sudo',
            'chmox': 'chmod',
            'chmodd': 'chmod',
            'mkdor': 'mkdir',
            'mkdie': 'mkdir',
            'toch': 'touch',
            'touhc': 'touch',
        }
        
        # Vary the error message format for realism
        error_formats = [
            f"bash: {cmd}: command not found",
            f"-bash: {cmd}: command not found",
            f"{cmd}: command not found",
            f"bash: {cmd}: No such file or directory",
        ]
        
        # Use command hash for consistent but varied responses
        random.seed(hash(cmd))
        base_error = random.choice(error_formats)
        
        # Check for common typos and add helpful suggestion
        if cmd.lower() in typo_suggestions:
            suggestion = typo_suggestions[cmd.lower()]
            # Sometimes add a "did you mean" suggestion
            if random.choice([True, False]):
                return f"{base_error}\n\nCommand '{suggestion}' is available in '/usr/bin/{suggestion}'\nDid you mean: {suggestion}?"
        
        # Check if command is close to a known command (Levenshtein distance)
        close_matches = self._find_close_commands(cmd, known_commands)
        if close_matches and random.choice([True, False, False]):  # 33% chance
            # Suggest the closest match
            return f"{base_error}\n\nDid you mean: {close_matches[0]}?"
        
        # For some commands, suggest package installation (realistic behavior)
        package_suggestions = {
            'htop': 'htop',
            'vim': 'vim',
            'emacs': 'emacs',
            'nano': 'nano',
            'git': 'git',
            'python': 'python3',
            'pip': 'python3-pip',
            'node': 'nodejs',
            'npm': 'npm',
            'docker': 'docker.io',
            'kubectl': 'kubectl',
            'ansible': 'ansible',
            'terraform': 'terraform',
            'nmap': 'nmap',
            'wireshark': 'wireshark',
            'tcpdump': 'tcpdump',
        }
        
        if cmd.lower() in package_suggestions:
            package = package_suggestions[cmd.lower()]
            # Sometimes suggest installation
            if random.choice([True, False]):
                return f"""{base_error}

Command '{cmd}' not found, but can be installed with:

sudo apt install {package}

"""
        
        # Default: just return the error
        return base_error
    
    def _find_close_commands(self, cmd: str, known_commands: set, max_distance: int = 2) -> list:
        """
        Find commands that are close to the given command using Levenshtein distance.
        Returns list of close matches, sorted by distance.
        """
        def levenshtein_distance(s1: str, s2: str) -> int:
            """Calculate Levenshtein distance between two strings"""
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    # Cost of insertions, deletions, or substitutions
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        # Find commands within max_distance
        close_matches = []
        for known_cmd in known_commands:
            distance = levenshtein_distance(cmd.lower(), known_cmd.lower())
            if distance <= max_distance and distance > 0:
                close_matches.append((known_cmd, distance))
        
        # Sort by distance and return command names only
        close_matches.sort(key=lambda x: x[1])
        return [cmd for cmd, _ in close_matches[:3]]  # Return top 3 matches
        
    def _execute_filesystem_command(self, command: str, current_dir: str, username: str, 
                                    context: Optional[Dict[str, Any]] = None) -> str:
        """Execute filesystem commands using virtual filesystem"""
        try:
            parts = shlex.split(command)
        except ValueError:
            return "bash: syntax error"
            
        if not parts:
            return ""
            
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        # find command
        if cmd == "find":
            return self._cmd_find(args, current_dir)

        # more command
        if cmd == "more":
            return self._cmd_more(args, current_dir)
        
        # less command
        if cmd == "less":
            return self._cmd_less(args, current_dir)
        
        # emacs command
        if cmd == "emacs":
            return self._cmd_emacs(args, current_dir)
        
        # ed command
        if cmd == "ed":
            return self._cmd_ed(args, current_dir)
        
        # sed command
        if cmd == "sed":
            return self._cmd_sed(args, current_dir)
        
        # awk command
        if cmd == "awk":
            return self._cmd_awk(args, current_dir)

        # rmdir command
        if cmd == "rmdir":
            return self._cmd_rmdir(args, current_dir)
        
        # cp command
        if cmd == "cp":
            return self._cmd_cp(args, current_dir)
        
        # mv command
        if cmd == "mv":
            return self._cmd_mv(args, current_dir)
        
        # chgrp command
        if cmd == "chgrp":
            return self._cmd_chgrp(args, current_dir)
        
        # readlink command
        if cmd == "readlink":
            return self._cmd_readlink(args, current_dir)
        
        # basename command
        if cmd == "basename":
            return self._cmd_basename(args, current_dir)
        
        # dirname command
        if cmd == "dirname":
            return self._cmd_dirname(args, current_dir)
        
        # dd command
        if cmd == "dd":
            return self._cmd_dd(args, current_dir)
        
        # df command (replace existing)
        if cmd == "df":
            return self._cmd_df_enhanced(args, current_dir)
        
        # mount command
        if cmd == "mount":
            return self._cmd_mount(args, current_dir)
        
        # ls command
        if cmd == "ls":
            return self._cmd_ls(args, current_dir)
            
        # pwd command
        if cmd == "pwd":
            return current_dir
        
        # cd command
        if cmd == "cd":
            # cd needs special handling - it should update server state
            # Return special marker to indicate cd was requested
            if not args:
                # cd with no args - go to home
                return "__CD_HOME__"
            
            target_dir = args[0]
            
            # Validate the path exists
            resolved_path = self.fs.resolve_path(target_dir, current_dir)
            
            if not self.fs.exists(resolved_path, "/"):
                return f"-bash: cd: {target_dir}: No such file or directory"
            
            if not self.fs.is_directory(resolved_path, "/"):
                return f"-bash: cd: {target_dir}: Not a directory"
            
            # Return special marker with the new directory
            return f"__CD__{resolved_path}"
            
        # cat command
        if cmd == "cat":
            return self._cmd_cat(args, current_dir)
            
        # head command
        if cmd == "head":
            return self._cmd_head(args, current_dir)
            
        # tail command
        if cmd == "tail":
            return self._cmd_tail(args, current_dir)
            
        # find command
        if cmd == "find":
            return self._cmd_find(args, current_dir)
            
        # file command
        if cmd == "file":
            return self._cmd_file(args, current_dir)
            
        # stat command
        if cmd == "stat":
            return self._cmd_stat(args, current_dir)
            
        # mkdir command
        if cmd == "mkdir":
            return self._cmd_mkdir(args, current_dir)
            
        # touch command
        if cmd == "touch":
            return self._cmd_touch(args, current_dir)
            
        # rm command
        if cmd == "rm":
            return self._cmd_rm(args, current_dir)
        
        # grep command
        if cmd == "grep":
            return self._cmd_grep(args, current_dir)
        
        # wc command
        if cmd == "wc":
            return self._cmd_wc(args, current_dir)
        
        # du command
        if cmd == "du":
            return self._cmd_du(args, current_dir)
        
        # df command
        if cmd == "df":
            return self._cmd_df(args, current_dir)
        
        # ln command
        if cmd == "ln":
            return self._cmd_ln(args, current_dir)
        
        # chmod command
        if cmd == "chmod":
            return self._cmd_chmod(args, current_dir)
        
        # chown command
        if cmd == "chown":
            return self._cmd_chown(args, current_dir)
            
        # Default fallback
        return None
    
    def _cmd_more(self, args: List[str], current_dir: str) -> str:
        """Execute more command - view file contents with pagination"""
        if not args:
            return "more: missing file operand"
        
        filename = args[0]
        content = self.fs.read_file(filename, current_dir)
        
        if content is None:
            if not self.fs.exists(filename, current_dir):
                return f"more: {filename}: No such file or directory"
            elif self.fs.is_directory(filename, current_dir):
                return f"more: {filename}: Is a directory"
            else:
                return f"more: {filename}: Permission denied"
        
        lines = content.split('\n')
        
        # Simulate pagination (show first 24 lines)
        page_size = 24
        if len(lines) <= page_size:
            return content
        else:
            output = '\n'.join(lines[:page_size])
            remaining = len(lines) - page_size
            return f"{output}\n--More--({remaining} lines remaining)"
    
    def _cmd_less(self, args: List[str], current_dir: str) -> str:
        filename = args[0]
        content = self.fs.read_file(filename, current_dir)
        
        if content is None:
            if not self.fs.exists(filename, current_dir):
                return f"{filename}: No such file or directory"
            elif self.fs.is_directory(filename, current_dir):
                return f"{filename} is a directory"
            else:
                return f"{filename}: Permission denied"
        
        return content + "\n(END)"
    
    def _cmd_emacs(self, args: List[str], current_dir: str) -> str:
        """Execute emacs command - simulate emacs editor"""
        if not args:
            return """GNU Emacs 26.3 (build 2, x86_64-pc-linux-gnu, GTK+ Version 3.24.14)
 of 2020-03-26, modified by Debian
Copyright (C) 2019 Free Software Foundation, Inc.
GNU Emacs comes with ABSOLUTELY NO WARRANTY.
You may redistribute copies of GNU Emacs
under the terms of the GNU General Public License.
For more information about these matters, see the file named COPYING.

emacs: standard input is not a tty"""
        
        filename = args[0]
        content = self.fs.read_file(filename, current_dir)
        is_new = content is None
        
        return f"""[Simulated emacs session for '{filename}']

Note: Interactive emacs editing is simulated. File operations are logged.
To actually modify files, use: echo "content" > {filename}"""
    
    def _cmd_ed(self, args: List[str], current_dir: str) -> str:
        """Execute ed command - line editor"""
        if args:
            filename = args[0]
            content = self.fs.read_file(filename, current_dir)
            if content:
                return f"{len(content)}\n?"
            else:
                return "?"
        return "?"
    
    def _cmd_sed(self, args: List[str], current_dir: str) -> str:
        """Execute sed command - stream editor"""
        if not args:
            return "sed: no input files"
        
        # Parse sed command
        # Format: sed 's/pattern/replacement/' file
        # or: sed -e 'command' file
        
        if len(args) < 2:
            return "sed: no input files"
        
        # Simple substitution support
        if args[0].startswith('s/'):
            pattern_cmd = args[0]
            filename = args[1] if len(args) > 1 else None
            
            if not filename:
                return "sed: no input files"
            
            content = self.fs.read_file(filename, current_dir)
            if content is None:
                return f"sed: can't read {filename}: No such file or directory"
            
            # Parse s/pattern/replacement/flags
            try:
                parts = pattern_cmd.split('/')
                if len(parts) >= 3:
                    pattern = parts[1]
                    replacement = parts[2]
                    flags = parts[3] if len(parts) > 3 else ''
                    
                    if 'g' in flags:
                        # Global replacement
                        result = content.replace(pattern, replacement)
                    else:
                        # First occurrence only
                        result = content.replace(pattern, replacement, 1)
                    
                    return result
            except:
                return "sed: invalid command"
        
        return "sed: -e expression #1, char 1: unknown command"
    
    def _cmd_awk(self, args: List[str], current_dir: str) -> str:
        """Execute awk command - pattern scanning and processing"""
        if not args:
            return "awk: no program text specified"
        
        # Parse awk command
        # Format: awk 'pattern {action}' file
        # or: awk -F delimiter 'pattern {action}' file
        
        delimiter = None
        program = None
        filename = None
        
        i = 0
        while i < len(args):
            if args[i] == '-F' and i + 1 < len(args):
                delimiter = args[i + 1]
                i += 2
            elif program is None:
                program = args[i]
                i += 1
            else:
                filename = args[i]
                i += 1
        
        if not filename:
            return "awk: no input files"
        
        content = self.fs.read_file(filename, current_dir)
        if content is None:
            return f"awk: {filename}: No such file or directory"
        
        lines = content.split('\n')
        results = []
        
        # Simple pattern matching
        # Support: {print}, {print $1}, {print $2}, etc.
        if '{print}' in program:
            return content
        elif '{print $1}' in program:
            for line in lines:
                fields = line.split(delimiter) if delimiter else line.split()
                if fields:
                    results.append(fields[0])
        elif '{print $2}' in program:
            for line in lines:
                fields = line.split(delimiter) if delimiter else line.split()
                if len(fields) > 1:
                    results.append(fields[1])
        elif 'NF' in program:
            # Print number of fields
            for line in lines:
                fields = line.split(delimiter) if delimiter else line.split()
                results.append(str(len(fields)))
        else:
            # Default: print all
            return content
        
        return '\n'.join(results)



    def _cmd_rmdir(self, args: List[str], current_dir: str) -> str:
        """Execute rmdir command - remove empty directories"""
        if not args:
            return "rmdir: missing operand"
        
        ignore_fail = "--ignore-fail-on-non-empty" in args
        parents = "-p" in args or "--parents" in args
        verbose = "-v" in args or "--verbose" in args
        
        dirs_to_remove = [arg for arg in args if not arg.startswith("-")]
        
        if not dirs_to_remove:
            return "rmdir: missing operand"
        
        results = []
        for target in dirs_to_remove:
            if not self.fs.exists(target, current_dir):
                results.append(f"rmdir: failed to remove '{target}': No such file or directory")
                continue
            
            if not self.fs.is_directory(target, current_dir):
                results.append(f"rmdir: failed to remove '{target}': Not a directory")
                continue
            
            # Check if directory is empty
            entries = self.fs.list_directory(target, current_dir)
            if entries and len(entries) > 0:
                if not ignore_fail:
                    results.append(f"rmdir: failed to remove '{target}': Directory not empty")
                continue
            
            # Remove directory
            if self.fs.delete(target, current_dir):
                if verbose:
                    results.append(f"rmdir: removing directory, '{target}'")
            else:
                results.append(f"rmdir: failed to remove '{target}': Permission denied")
        
        return "\n".join(results) if results else ""
    
    def _cmd_cp(self, args: List[str], current_dir: str) -> str:
        """Execute cp command - copy files and directories"""
        if len(args) < 2:
            return "cp: missing file operand" if len(args) == 0 else "cp: missing destination file operand"
        
        recursive = "-r" in args or "-R" in args or "--recursive" in args
        force = "-f" in args or "--force" in args
        interactive = "-i" in args or "--interactive" in args
        verbose = "-v" in args or "--verbose" in args
        preserve = "-p" in args or "--preserve" in args
        no_clobber = "-n" in args or "--no-clobber" in args
        update = "-u" in args or "--update" in args
        
        # Filter out flags
        files = [arg for arg in args if not arg.startswith("-")]
        
        if len(files) < 2:
            return "cp: missing destination file operand"
        
        sources = files[:-1]
        dest = files[-1]
        
        results = []
        
        # Check if destination is a directory
        dest_is_dir = self.fs.is_directory(dest, current_dir)
        
        for source in sources:
            if not self.fs.exists(source, current_dir):
                results.append(f"cp: cannot stat '{source}': No such file or directory")
                continue
            
            # Determine actual destination
            if dest_is_dir:
                source_name = source.split('/')[-1]
                actual_dest = f"{dest}/{source_name}"
            else:
                actual_dest = dest
            
            # Check if source is a directory
            if self.fs.is_directory(source, current_dir):
                if not recursive:
                    results.append(f"cp: -r not specified; omitting directory '{source}'")
                    continue
                # For simplicity, just create the directory
                self.fs.create_directory(actual_dest, current_dir)
                if verbose:
                    results.append(f"'{source}' -> '{actual_dest}'")
            else:
                # Copy file
                content = self.fs.read_file(source, current_dir)
                if content is not None:
                    # Check if destination exists
                    if self.fs.exists(actual_dest, current_dir) and no_clobber:
                        continue
                    
                    self.fs.write_file(actual_dest, content, current_dir)
                    if verbose:
                        results.append(f"'{source}' -> '{actual_dest}'")
                else:
                    results.append(f"cp: cannot open '{source}' for reading: Permission denied")
        
        return "\n".join(results) if results else ""
    
    def _cmd_mv(self, args: List[str], current_dir: str) -> str:
        """Execute mv command - move/rename files"""
        if len(args) < 2:
            return "mv: missing file operand" if len(args) == 0 else "mv: missing destination file operand"
        
        force = "-f" in args or "--force" in args
        interactive = "-i" in args or "--interactive" in args
        verbose = "-v" in args or "--verbose" in args
        no_clobber = "-n" in args or "--no-clobber" in args
        update = "-u" in args or "--update" in args
        
        # Filter out flags
        files = [arg for arg in args if not arg.startswith("-")]
        
        if len(files) < 2:
            return "mv: missing destination file operand"
        
        sources = files[:-1]
        dest = files[-1]
        
        results = []
        dest_is_dir = self.fs.is_directory(dest, current_dir)
        
        for source in sources:
            if not self.fs.exists(source, current_dir):
                results.append(f"mv: cannot stat '{source}': No such file or directory")
                continue
            
            # Determine actual destination
            if dest_is_dir:
                source_name = source.split('/')[-1]
                actual_dest = f"{dest}/{source_name}"
            else:
                actual_dest = dest
            
            # Check if destination exists
            if self.fs.exists(actual_dest, current_dir) and no_clobber:
                continue
            
            # Read source content
            if self.fs.is_directory(source, current_dir):
                # Move directory (simplified - just rename)
                content = None
                is_dir = True
            else:
                content = self.fs.read_file(source, current_dir)
                is_dir = False
            
            if content is not None or is_dir:
                # Create at destination
                if is_dir:
                    self.fs.create_directory(actual_dest, current_dir)
                else:
                    self.fs.write_file(actual_dest, content, current_dir)
                
                # Delete source
                self.fs.delete(source, current_dir)
                
                if verbose:
                    results.append(f"renamed '{source}' -> '{actual_dest}'")
            else:
                results.append(f"mv: cannot move '{source}': Permission denied")
        
        return "\n".join(results) if results else ""
    
    def _cmd_chgrp(self, args: List[str], current_dir: str) -> str:
        """Execute chgrp command - change group ownership"""
        if len(args) < 2:
            return "chgrp: missing operand"
        
        recursive = "-R" in args or "--recursive" in args
        verbose = "-v" in args or "--verbose" in args
        
        # Filter out flags
        files = [arg for arg in args if not arg.startswith("-")]
        
        if len(files) < 2:
            return "chgrp: missing operand"
        
        group = files[0]
        targets = files[1:]
        
        results = []
        for target in targets:
            if not self.fs.exists(target, current_dir):
                results.append(f"chgrp: cannot access '{target}': No such file or directory")
                continue
            
            # In a real implementation, this would change the group
            # For the honeypot, we just acknowledge it
            if verbose:
                results.append(f"changed group of '{target}' to {group}")
        
        return "\n".join(results) if results else ""
    
    def _cmd_readlink(self, args: List[str], current_dir: str) -> str:
        """Execute readlink command - print resolved symbolic links"""
        if not args:
            return "readlink: missing operand"
        
        canonicalize = "-f" in args or "--canonicalize" in args
        no_newline = "-n" in args or "--no-newline" in args
        
        files = [arg for arg in args if not arg.startswith("-")]
        
        if not files:
            return "readlink: missing operand"
        
        results = []
        for target in files:
            if not self.fs.exists(target, current_dir):
                results.append(f"readlink: {target}: No such file or directory")
                continue
            
            # For honeypot, simulate a symlink resolution
            if canonicalize:
                # Return absolute path
                resolved = self.fs.resolve_path(target, current_dir)
                results.append(resolved)
            else:
                # Simulate that it's not a symlink
                results.append(f"readlink: {target}: Invalid argument")
        
        return "\n".join(results) if results else ""
    
    def _cmd_basename(self, args: List[str], current_dir: str) -> str:
        """Execute basename command - strip directory from filename"""
        if not args:
            return "basename: missing operand"
        
        path = args[0]
        suffix = args[1] if len(args) > 1 else None
        
        # Get the last component
        name = path.rstrip('/').split('/')[-1]
        
        # Remove suffix if specified
        if suffix and name.endswith(suffix):
            name = name[:-len(suffix)]
        
        return name
    
    def _cmd_dirname(self, args: List[str], current_dir: str) -> str:
        """Execute dirname command - strip last component from filename"""
        if not args:
            return "dirname: missing operand"
        
        path = args[0].rstrip('/')
        
        # Get directory part
        if '/' not in path:
            return "."
        
        dirname = '/'.join(path.split('/')[:-1])
        return dirname if dirname else "/"
    
    def _cmd_dd(self, args: List[str], current_dir: str) -> str:
        """Execute dd command - convert and copy a file"""
        # Parse dd arguments (format: if=file of=file bs=size count=n)
        params = {}
        for arg in args:
            if '=' in arg:
                key, value = arg.split('=', 1)
                params[key] = value
        
        if_file = params.get('if', '/dev/zero')
        of_file = params.get('of', '/dev/null')
        bs = params.get('bs', '512')
        count = params.get('count', '1')
        
        # Parse block size
        try:
            bs_num = int(bs.replace('K', '000').replace('M', '000000').replace('G', '000000000'))
            count_num = int(count)
            total_bytes = bs_num * count_num
        except:
            return "dd: invalid number"
        
        # Simulate copying
        records_in = count_num
        records_out = count_num
        
        # If output file specified, create it in virtual fs
        if of_file != '/dev/null' and of_file != '/dev/zero':
            content = "0" * min(total_bytes, 1024)  # Limit size for honeypot
            server = None  # Would need context
            # self.fs.write_file(of_file, content, current_dir)
        
        return f"""{records_in}+0 records in
{records_out}+0 records out
{total_bytes} bytes ({total_bytes} B) copied, {random.uniform(0.001, 0.1):.6f} s, {total_bytes / random.uniform(0.001, 0.1):.1f} MB/s"""
    
    def _cmd_df_enhanced(self, args: List[str], current_dir: str) -> str:
        """Execute df command (enhanced) - report file system disk space usage"""
        human_readable = "-h" in args or "--human-readable" in args
        inodes = "-i" in args or "--inodes" in args
        type_filter = "-t" in args
        all_fs = "-a" in args or "--all" in args
        
        if inodes:
            return """Filesystem      Inodes  IUsed   IFree IUse% Mounted on
/dev/sda1      6553600 234567 6319033    4% /
tmpfs          2097152    456 2096696    1% /dev/shm
/dev/sda2     13107200 567890 12539310    5% /opt"""
        elif human_readable:
            return f"""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   {random.randint(20, 40)}G   {random.randint(10, 25)}G  {random.randint(40, 70)}% /
tmpfs           {random.randint(4, 16)}G  {random.randint(50, 200)}M  {random.randint(4, 16)}G   {random.randint(1, 5)}% /dev/shm
/dev/sda2        48G   {random.randint(20, 40)}G   {random.randint(5, 20)}G  {random.randint(50, 80)}% /opt"""
        else:
            used1 = random.randint(20000000, 40000000)
            avail1 = random.randint(10000000, 25000000)
            total1 = used1 + avail1
            
            used2 = random.randint(20000000, 40000000)
            avail2 = random.randint(5000000, 20000000)
            total2 = used2 + avail2
            
            return f"""Filesystem     1K-blocks      Used Available Use% Mounted on
/dev/sda1       {total1:10} {used1:9} {avail1:9}  {used1*100//total1:2}% /
tmpfs            {random.randint(4000000, 16000000):10}   {random.randint(50000, 200000):6}   {random.randint(4000000, 16000000):8}   {random.randint(1, 5):2}% /dev/shm
/dev/sda2       {total2:10} {used2:9} {avail2:9}  {used2*100//total2:2}% /opt"""
    
    def _cmd_mount(self, args: List[str], current_dir: str) -> str:
        """Execute mount command - mount a filesystem"""
        if username != "root" and "sudo" not in command:
            return "mount: only root can do that"
        
        if not args:
            # List all mounts
            return f"""/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
/dev/sda2 on /opt type ext4 (rw,relatime)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size={random.randint(400000, 800000)}k,mode=755)"""
        
        # Parse mount arguments
        if "-a" in args or "--all" in args:
            return ""  # Silent success - mount all
        
        if "-t" in args:
            # Type specified
            return ""  # Silent success
        
        # Specific mount
        if len(args) >= 2:
            device = args[0] if not args[0].startswith("-") else args[-2]
            mountpoint = args[1] if not args[1].startswith("-") else args[-1]
            return ""  # Silent success
        
        return "mount: bad usage"
    

    def _cmd_find(self, args: List[str], current_dir: str = "/") -> str:
        """
        Dynamic find command that searches the virtual filesystem.
        Supports: find <path> -name <pattern> -type <f|d>
        """
        if not args:
            return "find: missing operand\nTry 'find --help' for more information."
        
        # Parse arguments
        search_path = args[0] if args[0] != "-name" and args[0] != "-type" else "."
        pattern = None
        file_type = None  # 'f' for files, 'd' for directories
        
        # Parse -name argument
        if "-name" in args:
            try:
                name_idx = args.index("-name")
                if name_idx + 1 < len(args):
                    pattern = args[name_idx + 1].strip('"').strip("'")
            except:
                pass
        
        # Parse -type argument
        if "-type" in args:
            try:
                type_idx = args.index("-type")
                if type_idx + 1 < len(args):
                    file_type = args[type_idx + 1]
            except:
                pass
        
        # Resolve the search path
        resolved_path = self.virtual_fs.resolve_path(search_path, current_dir)
        
        # Check if path exists
        if not self.virtual_fs.exists(resolved_path):
            return f"find: '{search_path}': No such file or directory"
        
        # Perform the search
        results = []
        self._find_recursive(resolved_path, pattern, file_type, results)
        
        # Return results
        if results:
            return "\n".join(sorted(results))
        else:
            return ""  # find returns empty if no matches

    def _find_recursive(self, path: str, pattern: str, file_type: str, results: list):
        """
        Recursively search the virtual filesystem.
        
        Args:
            path: Current path to search
            pattern: Filename pattern (supports * wildcards)
            file_type: 'f' for files, 'd' for directories, None for both
            results: List to append matching paths to
        """
        try:
            # Get the node at this path
            node = self.virtual_fs.get_node(path)
            
            if not node:
                return
            
            # Check if current node matches criteria
            matches = True
            
            # Check type filter
            if file_type:
                if file_type == 'f' and node.is_dir:
                    matches = False
                elif file_type == 'd' and not node.is_dir:
                    matches = False
            
            # Check name pattern
            if pattern and matches:
                import fnmatch
                filename = path.split('/')[-1] if '/' in path else path
                if not fnmatch.fnmatch(filename, pattern):
                    matches = False
            
            # Add to results if matches
            if matches:
                results.append(path)
            
            # Recurse into directories
            if node.is_dir:
                try:
                    children = self.virtual_fs.list_directory(path)
                    for child_name in children:
                        child_path = f"{path}/{child_name}".replace("//", "/")
                        self._find_recursive(child_path, pattern, file_type, results)
                except:
                    # Permission denied or other error - skip this directory
                    pass
                    
        except Exception as e:
            # Silently skip errors (like real find with 2>/dev/null)
            pass
    
    def _cmd_ls(self, args: List[str], current_dir: str) -> str:
        """Execute ls command with full flag support"""
        show_all = False
        long_format = False
        human_readable = False
        show_hidden = False
        recursive = False
        sort_by_time = False
        reverse = False
        one_per_line = False
        
        # Parse flags
        files_to_list = []
        for arg in args:
            if arg.startswith("-"):
                if "a" in arg:
                    show_all = True
                if "l" in arg:
                    long_format = True
                if "h" in arg:
                    human_readable = True
                if "A" in arg:
                    show_hidden = True  # All except . and ..
                if "R" in arg:
                    recursive = True
                if "t" in arg:
                    sort_by_time = True
                if "r" in arg:
                    reverse = True
                if "1" in arg:
                    one_per_line = True
            else:
                files_to_list.append(arg)
        
        # Default to current directory if no files specified
        if not files_to_list:
            files_to_list = ["."]
        
        results = []
        for target in files_to_list:
            entries = self.fs.list_directory(target, current_dir)
            
            if entries is None:
                if not self.fs.exists(target, current_dir):
                    results.append(f"ls: cannot access '{target}': No such file or directory")
                    continue
                elif not self.fs.is_directory(target, current_dir):
                    # It's a file, just show it
                    info = self.fs.get_file_info(target, current_dir)
                    if info:
                        if long_format:
                            results.append(self._format_long_entry(info))
                        else:
                            results.append(info["name"])
                    continue
                else:
                    results.append(f"ls: cannot open directory '{target}': Permission denied")
                    continue
            
            # Filter entries
            filtered = []
            for entry in entries:
                if not show_all and not show_hidden:
                    if entry["name"].startswith("."):
                        continue
                elif show_hidden and not show_all:
                    if entry["name"] in [".", ".."]:
                        continue
                filtered.append(entry)
            
            # Sort entries
            if sort_by_time:
                filtered.sort(key=lambda x: x.get("modified", datetime.datetime.now()), reverse=not reverse)
            else:
                filtered.sort(key=lambda x: x["name"], reverse=reverse)
            
            # Format output
            if long_format:
                if len(files_to_list) > 1:
                    results.append(f"{target}:")
                total_blocks = sum(((e.get("size", 0) + 511) // 512) for e in filtered)
                results.append(f"total {total_blocks}")
                for entry in filtered:
                    results.append(self._format_long_entry(entry, human_readable))
            elif one_per_line:
                for entry in filtered:
                    results.append(entry["name"])
            else:
                # Multi-column format
                names = [entry["name"] for entry in filtered]
                if names:
                    results.append("  ".join(names))
        
        return "\n".join(results) if results else ""
    
    def _format_long_entry(self, entry: Dict[str, Any], human_readable: bool = False) -> str:
        """Format a single entry in long format"""
        perms = self._format_permissions(entry.get("permissions", "644"), entry.get("is_dir", False))
        links = "1"
        owner = entry.get("owner", "root")
        group = entry.get("group", "root")
        size = entry.get("size", 0)
        
        if human_readable:
            size_str = self._human_readable_size(size)
        else:
            size_str = str(size)
        
        modified = entry.get("modified", datetime.datetime.now())
        time_str = modified.strftime("%b %d %H:%M")
        name = entry["name"]
        
        return f"{perms} {links:>3} {owner:<8} {group:<8} {size_str:>8} {time_str} {name}"
    
    def _human_readable_size(self, size: int) -> str:
        """Convert size to human readable format"""
        for unit in ['', 'K', 'M', 'G', 'T']:
            if size < 1024.0:
                if unit == '':
                    return f"{size}"
                return f"{size:.1f}{unit}"
            size /= 1024.0
        return f"{size:.1f}P"
    
    def _expand_wildcard(self, pattern: str, current_dir: str) -> List[str]:
        """Expand wildcard pattern to matching paths"""
        # Resolve the directory part
        if "/" in pattern:
            dir_part = "/".join(pattern.split("/")[:-1]) or "/"
            file_pattern = pattern.split("/")[-1]
        else:
            dir_part = current_dir
            file_pattern = pattern
        
        # Get directory contents
        entries = self.fs.list_directory(dir_part, current_dir)
        if not entries:
            return []
        
        # Match pattern
        matches = []
        for entry in entries:
            if fnmatch.fnmatch(entry["name"], file_pattern):
                if dir_part == "/":
                    matches.append(f"/{entry['name']}")
                else:
                    matches.append(f"{dir_part}/{entry['name']}")
        
        return matches
    
    def _ls_single_target(self, target: str, long_format: bool, show_all: bool, current_dir: str) -> str:
        """List a single target (file or directory)"""
        # List directory
        entries = self.fs.list_directory(target, current_dir)
        
        if entries is None:
            # Check if it's a file
            if self.fs.is_file(target, current_dir):
                abs_path = self.fs.resolve_path(target, current_dir)
                return abs_path.split("/")[-1]
            return f"ls: cannot access '{target}': No such file or directory"
            
        # Filter hidden files if not -a
        if not show_all:
            entries = [e for e in entries if not e["name"].startswith(".")]
            
        if not entries:
            return ""
            
        # Format output
        if long_format:
            lines = []
            for entry in entries:
                perms = self._format_permissions(entry["permissions"], entry["is_dir"])
                size = entry["size"]
                modified = entry["modified"].strftime("%b %d %H:%M")
                name = entry["name"]
                
                # Add directory indicator
                if entry["is_dir"]:
                    name = f"\033[1;34m{name}\033[0m"  # Blue color for directories
                    
                lines.append(f"{perms} 1 {entry['owner']:<8} {entry['group']:<8} {size:>8} {modified} {name}")
            return "\n".join(lines)
        else:
            # Multi-column format
            names = []
            for entry in entries:
                name = entry["name"]
                if entry["is_dir"]:
                    name = f"\033[1;34m{name}\033[0m"
                names.append(name)
            return "  ".join(names)
            
    def _format_permissions(self, perms: str, is_dir: bool) -> str:
        """Convert numeric permissions to rwx format"""
        perm_map = {
            "0": "---",
            "1": "--x",
            "2": "-w-",
            "3": "-wx",
            "4": "r--",
            "5": "r-x",
            "6": "rw-",
            "7": "rwx",
        }
        
        # Handle special permissions (like 1777 for /tmp)
        if len(perms) == 4:
            perms = perms[1:]
            
        if len(perms) != 3:
            perms = "644"  # Default
            
        result = "d" if is_dir else "-"
        for digit in perms:
            result += perm_map.get(digit, "---")
            
        return result
        
    def _cmd_cat(self, args: List[str], current_dir: str) -> str:
        """Execute cat command with full flag support"""
        if not args:
            return "cat: missing file operand"
        
        show_line_numbers = False
        show_line_numbers_nonblank = False
        show_ends = False
        show_tabs = False
        show_nonprinting = False
        squeeze_blank = False
        
        files_to_cat = []
        for arg in args:
            if arg.startswith("-"):
                if arg in ["-n", "--number"]:
                    show_line_numbers = True
                elif arg in ["-b", "--number-nonblank"]:
                    show_line_numbers_nonblank = True
                elif arg in ["-E", "--show-ends"]:
                    show_ends = True
                elif arg in ["-T", "--show-tabs"]:
                    show_tabs = True
                elif arg in ["-v", "--show-nonprinting"]:
                    show_nonprinting = True
                elif arg in ["-s", "--squeeze-blank"]:
                    squeeze_blank = True
                elif arg in ["-A", "--show-all"]:
                    show_ends = show_tabs = show_nonprinting = True
            else:
                files_to_cat.append(arg)
        
        if not files_to_cat:
            return "cat: missing file operand"
        
        results = []
        for filename in files_to_cat:
            content = self.fs.read_file(filename, current_dir)
            if content is None:
                if self.fs.is_directory(filename, current_dir):
                    results.append(f"cat: {filename}: Is a directory")
                elif not self.fs.exists(filename, current_dir):
                    results.append(f"cat: {filename}: No such file or directory")
                else:
                    results.append(f"cat: {filename}: Permission denied")
                continue
            
            # Process content
            lines = content.split("\n")
            
            # Squeeze blank lines
            if squeeze_blank:
                new_lines = []
                prev_blank = False
                for line in lines:
                    if line.strip() == "":
                        if not prev_blank:
                            new_lines.append(line)
                        prev_blank = True
                    else:
                        new_lines.append(line)
                        prev_blank = False
                lines = new_lines
            
            # Format lines
            output_lines = []
            line_num = 1
            for line in lines:
                formatted_line = line
                
                # Show tabs
                if show_tabs:
                    formatted_line = formatted_line.replace("\t", "^I")
                
                # Show line numbers
                if show_line_numbers:
                    formatted_line = f"{line_num:6}  {formatted_line}"
                    line_num += 1
                elif show_line_numbers_nonblank and line.strip():
                    formatted_line = f"{line_num:6}  {formatted_line}"
                    line_num += 1
                
                # Show ends
                if show_ends:
                    formatted_line += "$"
                
                output_lines.append(formatted_line)
            
            results.append("\n".join(output_lines))
        
        return "\n".join(results)

    def _cmd_head(self, args: List[str], current_dir: str) -> str:
        """Execute head command (first 10 lines)"""
        lines = 10
        filename = None
        
        # Parse args
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    lines = int(args[i + 1])
                    i += 2
                except ValueError:
                    i += 1
            elif args[i].startswith("-") and args[i][1:].isdigit():
                lines = int(args[i][1:])
                i += 1
            else:
                filename = args[i]
                i += 1
                
        if not filename:
            return "head: missing file operand"
            
        content = self.fs.read_file(filename, current_dir)
        if content is None:
            return f"head: {filename}: No such file or directory"
            
        content_lines = content.split("\n")
        return "\n".join(content_lines[:lines])
        
    def _cmd_tail(self, args: List[str], current_dir: str) -> str:
        """Execute tail command (last 10 lines)"""
        lines = 10
        filename = None
        
        # Parse args
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    lines = int(args[i + 1])
                    i += 2
                except ValueError:
                    i += 1
            elif args[i].startswith("-") and args[i][1:].isdigit():
                lines = int(args[i][1:])
                i += 1
            else:
                filename = args[i]
                i += 1
                
        if not filename:
            return "tail: missing file operand"
            
        content = self.fs.read_file(filename, current_dir)
        if content is None:
            return f"tail: {filename}: No such file or directory"
            
        content_lines = content.split("\n")
        return "\n".join(content_lines[-lines:])
        
    def _cmd_find(self, args: List[str], current_dir: str) -> str:
        """Execute find command (simplified)"""
        # Simple implementation - just find by name
        search_path = current_dir
        name_pattern = None
        
        i = 0
        while i < len(args):
            if args[i] == "-name" and i + 1 < len(args):
                name_pattern = args[i + 1]
                i += 2
            elif not args[i].startswith("-"):
                search_path = args[i]
                i += 1
            else:
                i += 1
                
        if not name_pattern:
            # Just list directory recursively
            return self._find_recursive(search_path, current_dir, None)
            
        return self._find_recursive(search_path, current_dir, name_pattern)
        
    def _find_recursive(self, path: str, current_dir: str, pattern: Optional[str]) -> str:
        """Recursively find files matching pattern"""
        results = []
        abs_path = self.fs.resolve_path(path, current_dir)
        
        def search(current_path: str):
            entries = self.fs.list_directory(current_path, "/")
            if not entries:
                return
                
            for entry in entries:
                entry_path = f"{current_path}/{entry['name']}" if current_path != "/" else f"/{entry['name']}"
                
                # Check if matches pattern
                if pattern:
                    if self._match_pattern(entry["name"], pattern):
                        results.append(entry_path)
                else:
                    results.append(entry_path)
                    
                # Recurse into directories
                if entry["is_dir"]:
                    search(entry_path)
                    
        search(abs_path)
        return "\n".join(results)
        
    def _match_pattern(self, name: str, pattern: str) -> bool:
        """Match filename against pattern (supports * and ?)"""
        # Convert glob pattern to regex
        regex_pattern = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
        return re.match(f"^{regex_pattern}$", name) is not None
        
    def _cmd_file(self, args: List[str], current_dir: str) -> str:
        """Execute file command"""
        if not args:
            return "file: missing file operand"
            
        results = []
        for arg in args:
            if arg.startswith("-"):
                continue
                
            info = self.fs.get_file_info(arg, current_dir)
            if not info:
                results.append(f"{arg}: cannot open `{arg}' (No such file or directory)")
            elif info["is_dir"]:
                results.append(f"{arg}: directory")
            else:
                # Determine file type from content/name
                name = info["name"].lower()
                if name.endswith((".txt", ".md", ".log")):
                    results.append(f"{arg}: ASCII text")
                elif name.endswith((".sh", ".bash")):
                    results.append(f"{arg}: Bourne-Again shell script, ASCII text executable")
                elif name.endswith((".py",)):
                    results.append(f"{arg}: Python script, ASCII text executable")
                elif name.endswith((".cpp", ".c", ".h")):
                    results.append(f"{arg}: C++ source, ASCII text")
                elif name.endswith((".cs",)):
                    results.append(f"{arg}: C# source, ASCII text")
                elif name.endswith((".jpg", ".jpeg", ".png")):
                    results.append(f"{arg}: {name.split('.')[-1].upper()} image data")
                elif name.endswith((".tar", ".gz", ".zip")):
                    results.append(f"{arg}: compressed data")
                else:
                    results.append(f"{arg}: data")
                    
        return "\n".join(results)
        
    def _cmd_stat(self, args: List[str], current_dir: str) -> str:
        """Execute stat command with dynamic timestamps"""
        if not args:
            return "stat: missing file operand"
        
        target = args[0]
        info = self.fs.get_file_info(target, current_dir)
        
        if not info:
            return f"stat: cannot stat '{target}': No such file or directory"
        
        file_type = "directory" if info["is_dir"] else "regular file"
        size = info["size"]
        perms = info["permissions"]
        modified = info.get("modified", datetime.datetime.now())
        
        # Use actual modified time from filesystem
        time_str = modified.strftime('%Y-%m-%d %H:%M:%S.000000000 %z')
        
        return f"""File: {info['name']}
Size: {size}\t\tBlocks: {(size // 512) + 1}\tIO Block: 4096   {file_type}
Device: 801h/2049d\tInode: {hash(target) % 1000000}\tLinks: 1
Access: ({perms}/{self._format_permissions(perms, info['is_dir'])})  Uid: ( 1000/{info['owner']:8})   Gid: ( 1000/{info['group']:8})
Access: {time_str}
Modify: {time_str}
Change: {time_str}"""
 
    def _cmd_mkdir(self, args: List[str], current_dir: str) -> str:
        """Execute mkdir command"""
        if not args:
            return "mkdir: missing operand"
            
        for arg in args:
            if arg.startswith("-"):
                continue
                
            if not self.fs.create_directory(arg, current_dir):
                return f"mkdir: cannot create directory '{arg}': File exists"
                
        return ""
        
    def _cmd_touch(self, args: List[str], current_dir: str) -> str:
        """Execute touch command"""
        if not args:
            return "touch: missing file operand"
            
        for arg in args:
            if arg.startswith("-"):
                continue
                
            if not self.fs.exists(arg, current_dir):
                self.fs.write_file(arg, "", current_dir)
                
        return ""
        
    def _cmd_rm(self, args: List[str], current_dir: str) -> str:
        """Execute rm command with full flag support"""
        if not args:
            return "rm: missing operand"
        
        force = False
        recursive = False
        interactive = False
        verbose = False
        
        files_to_remove = []
        for arg in args:
            if arg.startswith("-"):
                if "f" in arg:
                    force = True
                if "r" in arg or "R" in arg:
                    recursive = True
                if "i" in arg:
                    interactive = True
                if "v" in arg:
                    verbose = True
            else:
                files_to_remove.append(arg)
        
        if not files_to_remove:
            return "rm: missing operand"
        
        results = []
        for target in files_to_remove:
            if not self.fs.exists(target, current_dir):
                if not force:
                    results.append(f"rm: cannot remove '{target}': No such file or directory")
                continue
            
            if self.fs.is_directory(target, current_dir):
                if not recursive:
                    results.append(f"rm: cannot remove '{target}': Is a directory")
                    continue
                # Recursive delete
                if self.fs.delete(target, current_dir):
                    if verbose:
                        results.append(f"removed directory '{target}'")
                else:
                    if not force:
                        results.append(f"rm: cannot remove '{target}': Permission denied")
            else:
                # Delete file
                if self.fs.delete(target, current_dir):
                    if verbose:
                        results.append(f"removed '{target}'")
                else:
                    if not force:
                        results.append(f"rm: cannot remove '{target}': Permission denied")
        
        return "\n".join(results) if results else ""
    
    def _cmd_grep(self, args: List[str], current_dir: str) -> str:
        """Execute grep command (simplified)"""
        if len(args) < 2:
            return "grep: missing operand"
        
        pattern = args[0]
        filename = args[1] if len(args) > 1 else None
        
        if not filename:
            return "grep: missing file operand"
        
        content = self.fs.read_file(filename, current_dir)
        if content is None:
            return f"grep: {filename}: No such file or directory"
        
        # Simple pattern matching
        results = []
        for line in content.split("\n"):
            if pattern.lower() in line.lower():
                results.append(line)
        
        return "\n".join(results)
    
    def _cmd_wc(self, args: List[str], current_dir: str) -> str:
        """Execute wc command (word count)"""
        if not args:
            return "wc: missing file operand"
        
        filename = args[0]
        content = self.fs.read_file(filename, current_dir)
        
        if content is None:
            return f"wc: {filename}: No such file or directory"
        
        lines = len(content.split("\n"))
        words = len(content.split())
        chars = len(content)
        
        return f"  {lines}  {words}  {chars} {filename}"
    
    def _cmd_du(self, args: List[str], current_dir: str) -> str:
        """Execute du command (disk usage)"""
        target = current_dir
        for arg in args:
            if not arg.startswith("-"):
                target = arg
                break
        
        info = self.fs.get_file_info(target, current_dir)
        if not info:
            return f"du: cannot access '{target}': No such file or directory"
        
        if info["is_dir"]:
            # Simplified - just show directory size
            return f"4\t{target}"
        else:
            size_kb = (info["size"] // 1024) + 1
            return f"{size_kb}\t{target}"
    
    def _cmd_df(self, args: List[str], current_dir: str) -> str:
        """Execute df command (disk free)"""
        return """Filesystem     1K-blocks      Used Available Use% Mounted on
/dev/sda1       51474912  28934567  20000000  60% /
tmpfs            8192000    102400   8089600   2% /dev/shm
/dev/sda2      204800000 102400000 102400000  50% /opt"""
    
    def _cmd_ln(self, args: List[str], current_dir: str) -> str:
        """Execute ln command (create links)"""
        if len(args) < 2:
            return "ln: missing file operand"
        
        # Simplified - just acknowledge the command
        return ""
    
    def _cmd_chmod(self, args: List[str], current_dir: str) -> str:
        """Execute chmod command - change file mode bits"""
        if len(args) < 2:
            return "chmod: missing operand\nTry 'chmod --help' for more information."
        
        # Parse flags
        recursive = "-R" in args or "--recursive" in args
        verbose = "-v" in args or "--verbose" in args
        changes = "-c" in args or "--changes" in args
        quiet = "-f" in args or "--quiet" in args or "--silent" in args
        preserve_root = "--preserve-root" in args
        no_preserve_root = "--no-preserve-root" in args
        reference = "--reference" in args
        
        # Help flag
        if "--help" in args:
            return """Usage: chmod [OPTION]... MODE[,MODE]... FILE...
  or:  chmod [OPTION]... OCTAL-MODE FILE...
  or:  chmod [OPTION]... --reference=RFILE FILE...
Change the mode of each FILE to MODE.
With --reference, change the mode of each FILE to that of RFILE.

  -c, --changes          like verbose but report only when a change is made
  -f, --silent, --quiet  suppress most error messages
  -v, --verbose          output a diagnostic for every file processed
      --no-preserve-root  do not treat '/' specially (the default)
      --preserve-root    fail to operate recursively on '/'
      --reference=RFILE  use RFILE's mode instead of MODE values
  -R, --recursive        change files and directories recursively
      --help     display this help and exit
      --version  output version information and exit

Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report chmod translation bugs to <https://translationproject.org/team/>
Full documentation at: <https://www.gnu.org/software/coreutils/chmod>
or available locally via: info '(coreutils) chmod invocation'"""
        
        # Version flag
        if "--version" in args:
            return """chmod (GNU coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David MacKenzie and Jim Meyering."""
        
        # Filter out flags to get mode and files
        files_and_mode = [arg for arg in args if not arg.startswith("-")]
        
        if len(files_and_mode) < 2:
            return "chmod: missing operand\nTry 'chmod --help' for more information."
        
        mode = files_and_mode[0]
        targets = files_and_mode[1:]
        
        # Validate mode format
        # Octal mode (e.g., 755, 644)
        is_octal = mode.isdigit() and len(mode) <= 4
        # Symbolic mode (e.g., u+x, go-w, a=rw)
        is_symbolic = any(c in mode for c in ['u', 'g', 'o', 'a', '+', '-', '=', 'r', 'w', 'x'])
        
        if not is_octal and not is_symbolic:
            return f"chmod: invalid mode: '{mode}'\nTry 'chmod --help' for more information."
        
        # Convert octal to symbolic for display
        def octal_to_symbolic(octal_str):
            """Convert octal mode to symbolic representation"""
            if len(octal_str) == 3:
                octal_str = '0' + octal_str
            
            octal_int = int(octal_str, 8)
            
            perms = []
            # User
            perms.append('r' if octal_int & 0o400 else '-')
            perms.append('w' if octal_int & 0o200 else '-')
            perms.append('x' if octal_int & 0o100 else '-')
            # Group
            perms.append('r' if octal_int & 0o040 else '-')
            perms.append('w' if octal_int & 0o020 else '-')
            perms.append('x' if octal_int & 0o010 else '-')
            # Other
            perms.append('r' if octal_int & 0o004 else '-')
            perms.append('w' if octal_int & 0o002 else '-')
            perms.append('x' if octal_int & 0o001 else '-')
            
            return ''.join(perms)
        
        # Generate old mode for comparison
        def generate_old_mode():
            """Generate a random but realistic old mode"""
            common_modes = ['644', '755', '600', '700', '664', '775', '640']
            return random.choice(common_modes)
        
        results = []
        
        for target in targets:
            # Check if file exists
            if not self.fs.exists(target, current_dir):
                if not quiet:
                    results.append(f"chmod: cannot access '{target}': No such file or directory")
                continue
            
            # Simulate the change
            if verbose or changes:
                old_mode = generate_old_mode()
                old_symbolic = octal_to_symbolic(old_mode)
                
                if is_octal:
                    new_symbolic = octal_to_symbolic(mode)
                    new_mode = mode
                else:
                    # For symbolic mode, simulate the result
                    # This is simplified - real chmod has complex symbolic logic
                    new_mode = "755"  # Default assumption
                    new_symbolic = octal_to_symbolic(new_mode)
                
                if verbose:
                    results.append(f"mode of '{target}' changed from {old_mode} ({old_symbolic}) to {new_mode} ({new_symbolic})")
                elif changes:
                    # Only show if actually changed
                    if old_mode != new_mode:
                        results.append(f"mode of '{target}' changed from {old_mode} ({old_symbolic}) to {new_mode} ({new_symbolic})")
            
            # If recursive and target is directory
            if recursive and self.fs.is_directory(target, current_dir):
                # Simulate recursive operation
                if verbose:
                    # Show a few subdirectories/files
                    subdirs = [f"{target}/subdir1", f"{target}/subdir2", f"{target}/file.txt"]
                    for subitem in subdirs:
                        old_mode = generate_old_mode()
                        old_symbolic = octal_to_symbolic(old_mode)
                        if is_octal:
                            new_symbolic = octal_to_symbolic(mode)
                            results.append(f"mode of '{subitem}' changed from {old_mode} ({old_symbolic}) to {mode} ({new_symbolic})")
                        else:
                            results.append(f"mode of '{subitem}' changed to {mode}")
        
        return "\n".join(results) if results else ""
    
    def _cmd_chown(self, args: List[str], current_dir: str) -> str:
        """Execute chown command - change file owner and group"""
        if len(args) < 2:
            return "chown: missing operand\nTry 'chown --help' for more information."
        
        # Parse flags
        recursive = "-R" in args or "--recursive" in args
        verbose = "-v" in args or "--verbose" in args
        changes = "-c" in args or "--changes" in args
        quiet = "-q" in args or "--quiet" in args
        reference = "--reference" in args
        from_owner = "--from" in args
        no_dereference = "-h" in args or "--no-dereference" in args
        
        # Help flag
        if "--help" in args:
            return """Usage: chown [OPTION]... [OWNER][:[GROUP]] FILE...
  or:  chown [OPTION]... --reference=RFILE FILE...
Change the owner and/or group of each FILE to OWNER and/or GROUP.
With --reference, change the owner and group of each FILE to those of RFILE.

  -c, --changes          like verbose but report only when a change is made
  -f, --silent, --quiet  suppress most error messages
  -v, --verbose          output a diagnostic for every file processed
      --dereference      affect the referent of each symbolic link (default)
  -h, --no-dereference   affect symbolic links instead of any referenced file
      --from=CURRENT_OWNER:CURRENT_GROUP
                         change the owner and/or group of each file only if
                         its current owner and/or group match those specified
      --no-preserve-root  do not treat '/' specially (the default)
      --preserve-root    fail to operate recursively on '/'
      --reference=RFILE  use RFILE's owner and group rather than specifying
                         OWNER:GROUP values
  -R, --recursive        operate on files and directories recursively
      --help     display this help and exit
      --version  output version information and exit

Owner is unchanged if missing.  Group is unchanged if missing, but changed
to login group if implied by a ':' following a symbolic OWNER.
OWNER and GROUP may be numeric as well as symbolic.

Examples:
  chown root /u        Change the owner of /u to "root".
  chown root:staff /u  Likewise, but also change its group to "staff".
  chown -hR root /u    Change the owner of /u and subfiles to "root".

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report chown translation bugs to <https://translationproject.org/team/>
Full documentation at: <https://www.gnu.org/software/coreutils/chown>
or available locally via: info '(coreutils) chown invocation'"""
        
        # Version flag
        if "--version" in args:
            return """chown (GNU coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David MacKenzie and Jim Meyering."""
        
        # Filter out flags to get owner:group and files
        files_and_owner = [arg for arg in args if not arg.startswith("-")]
        
        if len(files_and_owner) < 2:
            return "chown: missing operand\nTry 'chown --help' for more information."
        
        owner_group = files_and_owner[0]
        targets = files_and_owner[1:]
        
        # Parse owner:group
        if ":" in owner_group:
            owner, group = owner_group.split(":", 1)
        else:
            owner = owner_group
            group = None
        
        # Validate owner/group format
        if owner and not (owner.isalnum() or owner.isdigit()):
            return f"chown: invalid user: '{owner}'"
        
        if group and not (group.isalnum() or group.isdigit()):
            return f"chown: invalid group: '{group}'"
        
        results = []
        
        for target in targets:
            # Check if file exists
            if not self.fs.exists(target, current_dir):
                if not quiet:
                    results.append(f"chown: cannot access '{target}': No such file or directory")
                continue
            
            # Check permissions (non-root users can't chown)
            # In real Linux, only root can change ownership
            # For honeypot, we'll simulate this
            current_user = getattr(self.fs, 'current_user', 'guest')
            
            # Simulate the change
            if verbose or changes:
                old_owner = "user"  # Simulated current owner
                old_group = "user"  # Simulated current group
                
                new_owner_str = owner if owner else old_owner
                new_group_str = group if group else old_group
                
                if verbose:
                    results.append(f"changed ownership of '{target}' from {old_owner}:{old_group} to {new_owner_str}:{new_group_str}")
                elif changes:
                    # Only show if actually changed
                    if owner != old_owner or (group and group != old_group):
                        results.append(f"changed ownership of '{target}' from {old_owner}:{old_group} to {new_owner_str}:{new_group_str}")
            
            # If recursive and target is directory
            if recursive and self.fs.is_directory(target, current_dir):
                # Simulate recursive operation
                if verbose:
                    # Show a few subdirectories/files
                    subdirs = [f"{target}/subdir1", f"{target}/subdir2", f"{target}/file.txt"]
                    for subitem in subdirs:
                        results.append(f"changed ownership of '{subitem}' to {owner}:{group if group else 'unchanged'}")
        
        return "\n".join(results) if results else ""
        
    def _execute_system_command(self, command: str, username: str, 
                                context: Optional[Dict[str, Any]] = None) -> str:
        """Execute system commands using templates"""
        try:
            parts = shlex.split(command)
        except ValueError:
            return "bash: syntax error"
            
        if not parts:
            return ""
            
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        # exit/logout/quit - End session
        if cmd in ["exit", "logout", "quit"]:
            return "XXX-END-OF-SESSION-XXX"

        # clear - Clear the terminal screen
        if cmd == "clear" or cmd == "reset":
            return "\033[2J\033[H"

        # ifconfig - Configure network interface
        if cmd == "ifconfig":
            random.seed(hash(username))
            
            # Generate dynamic network info
            ip_addr = f"192.168.{random.randint(1, 255)}.{random.randint(10, 250)}"
            broadcast = f"192.168.{random.randint(1, 255)}.255"
            netmask = "255.255.255.0"
            mac_addr = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
            
            rx_packets = random.randint(100000, 9999999)
            rx_bytes = random.randint(10000000, 999999999)
            tx_packets = random.randint(100000, 9999999)
            tx_bytes = random.randint(10000000, 999999999)
            
            if not args or args[0] in ["-a", "--all"]:
                return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {ip_addr}  netmask {netmask}  broadcast {broadcast}
        inet6 fe80::{mac_addr.replace(':', '')}  prefixlen 64  scopeid 0x20<link>
        ether {mac_addr}  txqueuelen 1000  (Ethernet)
        RX packets {rx_packets}  bytes {rx_bytes} ({rx_bytes / (1024*1024):.1f} MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {tx_packets}  bytes {tx_bytes} ({tx_bytes / (1024*1024):.1f} MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets {random.randint(1000, 99999)}  bytes {random.randint(100000, 9999999)} ({random.randint(1, 10)}.{random.randint(0, 9)} MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {random.randint(1000, 99999)}  bytes {random.randint(100000, 9999999)} ({random.randint(1, 10)}.{random.randint(0, 9)} MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"""
            else:
                interface = args[0]
                return f"""{interface}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {ip_addr}  netmask {netmask}  broadcast {broadcast}
        ether {mac_addr}  txqueuelen 1000  (Ethernet)
        RX packets {rx_packets}  bytes {rx_bytes}
        TX packets {tx_packets}  bytes {tx_bytes}"""
        
        # ip - Show/manipulate routing, devices, policy routing
        if cmd == "ip":
            random.seed(hash(username))
            
            if not args:
                return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"
            
            subcommand = args[0]
            
            if subcommand == "addr" or subcommand == "address" or subcommand == "a":
                ip_addr = f"192.168.{random.randint(1, 255)}.{random.randint(10, 250)}"
                mac_addr = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                
                return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether {mac_addr} brd ff:ff:ff:ff:ff:ff
    inet {ip_addr}/24 brd 192.168.{random.randint(1, 255)}.255 scope global dynamic eth0
       valid_lft {random.randint(3600, 86400)}sec preferred_lft {random.randint(3600, 86400)}sec
    inet6 fe80::{mac_addr.replace(':', '')}%eth0/64 scope link 
       valid_lft forever preferred_lft forever"""
            
            elif subcommand == "route" or subcommand == "r":
                gateway = f"192.168.{random.randint(1, 255)}.1"
                return f"""default via {gateway} dev eth0 proto dhcp metric 100 
192.168.{random.randint(1, 255)}.0/24 dev eth0 proto kernel scope link src 192.168.{random.randint(1, 255)}.{random.randint(10, 250)} metric 100"""
            
            elif subcommand == "link" or subcommand == "l":
                mac_addr = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether {mac_addr} brd ff:ff:ff:ff:ff:ff"""
            
            else:
                return f"Object \"{subcommand}\" is unknown, try \"ip help\"."
        
        # traceroute - Trace route to host
        if cmd == "traceroute":
            target = args[0] if args and not args[0].startswith("-") else "8.8.8.8"
            random.seed(hash(username + target))
            
            hops = random.randint(8, 15)
            output_lines = [f"traceroute to {target} ({target}), 30 hops max, 60 byte packets"]
            
            for hop in range(1, hops + 1):
                if hop == 1:
                    # Local gateway
                    ip = f"192.168.{random.randint(1, 255)}.1"
                    hostname = f"gateway ({ip})"
                elif hop < hops - 1 and random.choice([True, False, False]):
                    # Some hops timeout
                    output_lines.append(f" {hop}  * * *")
                    continue
                else:
                    # Random hop
                    ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    if hop == hops:
                        hostname = f"{target} ({ip})"
                    else:
                        hostname = f"{ip}"
                
                # Random latencies
                time1 = random.uniform(0.5, 50.0) * hop
                time2 = random.uniform(0.5, 50.0) * hop
                time3 = random.uniform(0.5, 50.0) * hop
                
                output_lines.append(f" {hop}  {hostname}  {time1:.3f} ms  {time2:.3f} ms  {time3:.3f} ms")
            
            return "\n".join(output_lines)
        
        # tracepath - Trace path to network host
        if cmd == "tracepath":
            target = args[0] if args else "8.8.8.8"
            random.seed(hash(username + target))
            
            hops = random.randint(8, 12)
            output_lines = [f" 1?: [LOCALHOST]                      pmtu 1500"]
            
            for hop in range(1, hops + 1):
                if hop == 1:
                    ip = f"192.168.{random.randint(1, 255)}.1"
                else:
                    ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                
                time_ms = random.uniform(0.5, 50.0) * hop
                
                if hop == hops:
                    output_lines.append(f" {hop}:  {target}                          {time_ms:.3f}ms reached")
                    output_lines.append(f"     Resume: pmtu 1500 hops {hop} back {hop}")
                else:
                    output_lines.append(f" {hop}:  {ip}                            {time_ms:.3f}ms")
            
            return "\n".join(output_lines)
        
        # nslookup - Query DNS
        if cmd == "nslookup":
            domain = args[0] if args and not args[0].startswith("-") else "google.com"
            random.seed(hash(domain))
            
            # Generate IPs
            ip1 = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ip2 = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dns_server = f"8.8.{random.randint(4, 8)}.{random.randint(4, 8)}"
            
            return f"""Server:		{dns_server}
Address:	{dns_server}#53

Non-authoritative answer:
Name:	{domain}
Address: {ip1}
Address: {ip2}"""
        
        # dig - DNS lookup utility
        if cmd == "dig":
            domain = args[0] if args and not args[0].startswith("-") else "google.com"
            random.seed(hash(domain))
            
            query_time = random.randint(10, 100)
            ip1 = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dns_server = f"8.8.{random.randint(4, 8)}.{random.randint(4, 8)}"
            
            return f"""; <<>> DiG 9.16.1-Ubuntu <<>> {domain}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {random.randint(10000, 65535)}
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;{domain}.			IN	A

;; ANSWER SECTION:
{domain}.		{random.randint(100, 600)}	IN	A	{ip1}

;; Query time: {query_time} msec
;; SERVER: {dns_server}#53({dns_server})
;; WHEN: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}
;; MSG SIZE  rcvd: {random.randint(50, 150)}"""
        
        # host - DNS lookup
        if cmd == "host":
            domain = args[0] if args and not args[0].startswith("-") else "google.com"
            random.seed(hash(domain))
            
            ip1 = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ip2 = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
            return f"""{domain} has address {ip1}
{domain} has address {ip2}
{domain} has IPv6 address 2607:f8b0:4004::{random.randint(1000, 9999):04x}
{domain} mail is handled by {random.randint(5, 50)} alt{random.randint(1, 4)}.aspmx.l.google.com."""
        
        # route - Show/manipulate IP routing table
        if cmd == "route":
            random.seed(hash(username))
            
            if "-n" in args:
                # Numeric output
                gateway = f"192.168.{random.randint(1, 255)}.1"
                return f"""Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         {gateway}       0.0.0.0         UG    100    0        0 eth0
192.168.{random.randint(1, 255)}.0   0.0.0.0         255.255.255.0   U     100    0        0 eth0"""
            else:
                # With hostnames
                return f"""Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         _gateway        0.0.0.0         UG    100    0        0 eth0
192.168.{random.randint(1, 255)}.0   0.0.0.0         255.255.255.0   U     100    0        0 eth0"""
        
        # arp - Manipulate ARP cache
        if cmd == "arp":
            random.seed(hash(username))
            
            if "-a" in args or not args:
                # Show ARP table
                entries = []
                for i in range(random.randint(3, 8)):
                    ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
                    mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                    entries.append(f"? ({ip}) at {mac} [ether] on eth0")
                
                return "\n".join(entries)
            elif "-n" in args:
                # Numeric output
                entries = []
                for i in range(random.randint(3, 8)):
                    ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
                    mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                    entries.append(f"{ip:<20} ether   {mac}   C                     eth0")
                
                return f"""Address                  HWtype  HWaddress           Flags Mask            Iface
{chr(10).join(entries)}"""
            else:
                return "arp: invalid option"
        
        # nc/netcat - Network utility
        if cmd in ["nc", "netcat"]:
            if not args:
                return "usage: nc [-46DdhklnrStUuvzC] [-i interval] [-p source_port] [-s source_ip_address] [-T ToS] [-w timeout] [-X proxy_version] [-x proxy_address[:port]] [hostname] [port[s]]"
            
            host = args[-2] if len(args) >= 2 else "localhost"
            port = args[-1] if args else "80"
            
            # Simulate connection attempt
            if "-z" in args:
                # Port scan mode
                return f"Connection to {host} {port} port [tcp/*] succeeded!"
            elif "-v" in args:
                # Verbose
                return f"nc: connect to {host} port {port} (tcp) failed: Connection refused"
            else:
                return "nc: connection refused"
        
        # telnet - User interface to TELNET protocol
        if cmd == "telnet":
            if not args:
                return """telnet> quit
Connection closed."""
            
            host = args[0]
            port = args[1] if len(args) > 1 else "23"
            
            return f"""Trying {host}...
telnet: Unable to connect to remote host: Connection refused"""

        # pgrep - Search for processes by name
        if cmd == "pgrep":
            if not args:
                return "pgrep: no matching criteria specified"
            
            pattern = args[-1]  # Last arg is the pattern
            full_match = "-f" in args or "--full" in args
            list_name = "-l" in args or "--list-name" in args
            
            # Generate consistent process list
            random.seed(hash(username + pattern))
            
            # Common process names
            all_processes = [
                ("sshd", random.randint(1000, 2000)),
                ("systemd", 1),
                ("bash", random.randint(2000, 3000)),
                ("python3", random.randint(3000, 4000)),
                ("nginx", random.randint(4000, 5000)),
                ("mysql", random.randint(5000, 6000)),
                ("docker", random.randint(6000, 7000)),
                ("node", random.randint(7000, 8000)),
                ("java", random.randint(8000, 9000)),
                ("apache2", random.randint(9000, 10000)),
            ]
            
            # Filter matching processes
            matches = []
            for proc_name, pid in all_processes:
                if pattern.lower() in proc_name.lower():
                    if list_name:
                        matches.append(f"{pid} {proc_name}")
                    else:
                        matches.append(str(pid))
            
            return "\n".join(matches) if matches else ""
        
        # pidof - Find PID of running program
        if cmd == "pidof":
            if not args:
                return ""
            
            program = args[0]
            random.seed(hash(username + program))
            
            # Generate 1-3 PIDs for the program
            num_instances = random.randint(1, 3)
            pids = [str(random.randint(1000, 30000)) for _ in range(num_instances)]
            
            return " ".join(pids)
        
        # jobs - List background jobs
        if cmd == "jobs":
            # Generate consistent job list
            random.seed(hash(username + str(datetime.datetime.now().hour)))
            
            num_jobs = random.randint(0, 3)
            if num_jobs == 0:
                return ""
            
            jobs_list = []
            job_commands = [
                "sleep 100",
                "python3 script.py",
                "tail -f /var/log/syslog",
                "vim file.txt",
                "ping google.com",
                "watch -n 1 'ps aux'",
            ]
            
            for i in range(1, num_jobs + 1):
                cmd_text = random.choice(job_commands)
                status = random.choice(["Running", "Stopped"])
                jobs_list.append(f"[{i}]  {status:<20} {cmd_text}")
            
            return "\n".join(jobs_list)
        
        # bg - Resume job in background
        if cmd == "bg":
            job_num = args[0] if args else "1"
            return f"[{job_num}]+ sleep 100 &"
        
        # fg - Bring job to foreground
        if cmd == "fg":
            job_num = args[0] if args else "1"
            return f"[{job_num}]+ sleep 100"
        
        # pstree - Display process tree
        if cmd == "pstree":
            show_pids = "-p" in args or "--show-pids" in args
            numeric = "-n" in args or "--numeric-sort" in args
            
            # Generate consistent process tree
            random.seed(hash(username))
            
            if show_pids:
                return f"""systemd(1)─┬─accounts-daemon({random.randint(500, 600)})
        ├─cron({random.randint(600, 700)})
        ├─dbus-daemon({random.randint(700, 800)})
        ├─dockerd({random.randint(800, 900)})─┬─docker-proxy({random.randint(900, 1000)})
        │                └─{random.randint(5, 10)}*[{{docker-proxy}}]
        ├─networkd({random.randint(400, 500)})
        ├─rsyslogd({random.randint(1000, 1100)})─┬─{{rs:main Q:Reg}}({random.randint(1100, 1200)})
        │                  ├─{{in:imklog}}({random.randint(1200, 1300)})
        │                  └─{{in:imuxsock}}({random.randint(1300, 1400)})
        ├─sshd({random.randint(1400, 1500)})───sshd({random.randint(1500, 1600)})───sshd({random.randint(1600, 1700)})───bash({random.randint(1700, 1800)})───pstree({random.randint(1800, 1900)})
        ├─systemd({random.randint(2000, 2100)})───(sd-pam)({random.randint(2100, 2200)})
        ├─systemd-journal({random.randint(300, 400)})
        ├─systemd-logind({random.randint(2200, 2300)})
        ├─systemd-resolve({random.randint(2300, 2400)})
        └─systemd-udevd({random.randint(2400, 2500)})"""
            else:
                return """systemd─┬─accounts-daemon
        ├─cron
        ├─dbus-daemon
        ├─dockerd─┬─docker-proxy
        │         └─10*[{docker-proxy}]
        ├─networkd
        ├─rsyslogd─┬─{rs:main Q:Reg}
        │          ├─{in:imklog}
        │          └─{in:imuxsock}
        ├─sshd───sshd───sshd───bash───pstree
        ├─systemd───(sd-pam)
        ├─systemd-journal
        ├─systemd-logind
        ├─systemd-resolve
        └─systemd-udevd"""


                # chage - Change user password expiry information
        if cmd == "chage":
            if username != "root" and "sudo" not in command:
                return "chage: Permission denied."
            
            target_user = args[-1] if args and not args[-1].startswith("-") else username
            
            if "-l" in args or "--list" in args:
                last_change = (datetime.datetime.now() - datetime.timedelta(days=random.randint(30, 365))).strftime("%b %d, %Y")
                expire_date = (datetime.datetime.now() + datetime.timedelta(days=random.randint(30, 365))).strftime("%b %d, %Y")
                return f"""Last password change					: {last_change}
Password expires					: {expire_date}
Password inactive					: never
Account expires						: never
Minimum number of days between password change		: 0
Maximum number of days between password change		: 99999
Number of days of warning before password expires	: 7"""
            elif "-d" in args:
                return ""  # Silent success
            elif "-E" in args:
                return ""  # Silent success
            elif "-M" in args:
                return ""  # Silent success
            else:
                return f"Enter the new value, or press ENTER for the default"
        
        # lastlog - Reports the most recent login of all users
        if cmd == "lastlog":
            users = ["root", username, "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp"]
            output = "Username         Port     From             Latest\n"
            
            for user in users[:random.randint(5, len(users))]:
                if random.choice([True, False]):
                    days_ago = random.randint(1, 100)
                    login_time = datetime.datetime.now() - datetime.timedelta(days=days_ago)
                    port = random.choice(["pts/0", "pts/1", "tty1", ":0"])
                    ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
                    output += f"{user:<16} {port:<8} {ip:<16} {login_time.strftime('%a %b %d %H:%M:%S %z %Y')}\n"
                else:
                    output += f"{user:<16} **Never logged in**\n"
            
            return output.rstrip()
        
        # faillog - Display faillog records or set login failure limits
        if cmd == "faillog":
            if username != "root" and "sudo" not in command:
                return "faillog: Permission denied."
            
            if "-a" in args or not args:
                users = ["root", username, "daemon", "bin", "sys"]
                output = "Login       Failures Maximum Latest                   On\n"
                
                for user in users:
                    if random.choice([True, False, False]):  # 1/3 chance of failures
                        failures = random.randint(1, 5)
                        latest = (datetime.datetime.now() - datetime.timedelta(hours=random.randint(1, 72))).strftime("%m/%d/%y %H:%M:%S")
                        output += f"{user:<12} {failures:<8} 0       {latest:<24} ssh:notty\n"
                
                return output.rstrip() if output.count('\n') > 1 else "Login       Failures Maximum Latest                   On"
            elif "-r" in args:
                return ""  # Silent success - reset failure count
            elif "-u" in args:
                target_user = args[args.index("-u") + 1] if "-u" in args and args.index("-u") + 1 < len(args) else username
                return f"Login       Failures Maximum Latest                   On\n{target_user:<12} 0        0"
            else:
                return ""
        
        # sysctl - Configure kernel parameters at runtime
        if cmd == "sysctl":
            if "-a" in args or "--all" in args:
                params = [
                    ("kernel.hostname", "corp-srv-01"),
                    ("kernel.ostype", "Linux"),
                    ("kernel.osrelease", "5.4.0-42-generic"),
                    ("kernel.version", "#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020"),
                    ("kernel.pid_max", str(random.randint(32768, 4194304))),
                    ("kernel.threads-max", str(random.randint(50000, 200000))),
                    ("vm.swappiness", str(random.randint(10, 60))),
                    ("vm.dirty_ratio", str(random.randint(10, 40))),
                    ("vm.dirty_background_ratio", str(random.randint(5, 20))),
                    ("net.ipv4.ip_forward", str(random.randint(0, 1))),
                    ("net.ipv4.tcp_syncookies", "1"),
                    ("net.ipv4.tcp_max_syn_backlog", str(random.randint(1024, 8192))),
                    ("net.core.somaxconn", str(random.randint(128, 4096))),
                    ("fs.file-max", str(random.randint(100000, 1000000))),
                ]
                return "\n".join([f"{k} = {v}" for k, v in params])
            elif "-w" in args:
                return ""  # Silent success
            elif len(args) > 0 and not args[0].startswith("-"):
                param = args[0]
                values = {
                    "kernel.hostname": "corp-srv-01",
                    "vm.swappiness": str(random.randint(10, 60)),
                    "net.ipv4.ip_forward": str(random.randint(0, 1)),
                }
                return f"{param} = {values.get(param, '0')}"
            else:
                return "sysctl: no variables specified"
        
        # modprobe - Add/remove modules from Linux kernel
        if cmd == "modprobe":
            if username != "root" and "sudo" not in command:
                return "modprobe: ERROR: could not insert module: Operation not permitted"
            
            if "-l" in args or "--list" in args:
                modules = ["e1000e", "i915", "snd_hda_intel", "bluetooth", "usbhid", "ext4", "nf_conntrack"]
                return "\n".join([f"kernel/drivers/net/{m}.ko" for m in modules[:random.randint(3, len(modules))]])
            elif "-r" in args or "--remove" in args:
                return ""  # Silent success
            elif args and not args[0].startswith("-"):
                return ""  # Silent success - load module
            else:
                return "Usage: modprobe [options] [-i] [-b] modulename"
        
        # lsmod - Show status of modules in Linux kernel
        if cmd == "lsmod":
            modules = [
                ("e1000e", random.randint(100000, 300000), "0"),
                ("i915", random.randint(1000000, 3000000), "1"),
                ("snd_hda_intel", random.randint(30000, 100000), "2"),
                ("bluetooth", random.randint(400000, 800000), "10"),
                ("usbhid", random.randint(40000, 80000), "0"),
                ("hid", random.randint(80000, 150000), "1", "usbhid"),
                ("ext4", random.randint(500000, 1000000), "2"),
                ("jbd2", random.randint(80000, 150000), "1", "ext4"),
                ("nf_conntrack", random.randint(100000, 200000), "3"),
            ]
            
            output = "Module                  Size  Used by\n"
            for mod in modules:
                if len(mod) == 3:
                    output += f"{mod[0]:<23} {mod[1]:<5} {mod[2]}\n"
                else:
                    output += f"{mod[0]:<23} {mod[1]:<5} {mod[2]} {mod[3]}\n"
            
            return output.rstrip()
        
        # rmmod - Remove module from Linux kernel
        if cmd == "rmmod":
            if username != "root" and "sudo" not in command:
                return "rmmod: ERROR: could not remove module: Operation not permitted"
            
            if args:
                module = args[0]
                if random.choice([True, False, False]):  # 1/3 chance of being in use
                    return f"rmmod: ERROR: Module {module} is in use"
                return ""  # Silent success
            else:
                return "rmmod: ERROR: missing module name."
        
        # insmod - Insert module into Linux kernel
        if cmd == "insmod":
            if username != "root" and "sudo" not in command:
                return "insmod: ERROR: could not insert module: Operation not permitted"
            
            if args:
                return ""  # Silent success
            else:
                return "insmod: ERROR: missing filename."
        
        # docker - Container platform
        if cmd == "docker":
            if not args:
                return """Usage:  docker [OPTIONS] COMMAND

A self-sufficient runtime for containers

Options:
      --config string      Location of client config files (default "/root/.docker")
  -c, --context string     Name of the context to use to connect to the daemon
  -D, --debug              Enable debug mode
  -H, --host list          Daemon socket(s) to connect to
  -l, --log-level string   Set the logging level ("debug"|"info"|"warn"|"error"|"fatal") (default "info")
      --tls                Use TLS; implied by --tlsverify
      --tlscacert string   Trust certs signed only by this CA (default "/root/.docker/ca.pem")
      --tlscert string     Path to TLS certificate file (default "/root/.docker/cert.pem")
      --tlskey string      Path to TLS key file (default "/root/.docker/key.pem")
      --tlsverify          Use TLS and verify the remote
  -v, --version            Print version information and quit

Management Commands:
  builder     Manage builds
  config      Manage Docker configs
  container   Manage containers
  context     Manage contexts
  image       Manage images
  network     Manage networks
  node        Manage Swarm nodes
  plugin      Manage plugins
  secret      Manage Docker secrets
  service     Manage services
  stack       Manage Docker stacks
  swarm       Manage Swarm
  system      Manage Docker
  trust       Manage trust on Docker images
  volume      Manage volumes

Commands:
  attach      Attach local standard input, output, and error streams to a running container
  build       Build an image from a Dockerfile
  commit      Create a new image from a container's changes
  cp          Copy files/folders between a container and the local filesystem
  create      Create a new container
  diff        Inspect changes to files or directories on a container's filesystem
  events      Get real time events from the server
  exec        Run a command in a running container
  export      Export a container's filesystem as a tar archive
  history     Show the history of an image
  images      List images"""


                # pmap - Process memory map
        if cmd == "pmap":
            if not args:
                return "pmap: argument missing"
            
            pid = args[0] if args[0].isdigit() else str(random.randint(1000, 9999))
            extended = "-x" in args or "-X" in args
            show_device = "-d" in args
            
            if extended:
                # Extended format
                output = f"""{pid}:   /usr/bin/bash
Address           Kbytes     RSS   Dirty Mode  Mapping
"""
                # Generate random memory mappings
                base_addr = 0x00007f0000000000
                mappings = [
                    ("bash", random.randint(500, 1000), "r-x--"),
                    ("bash", random.randint(50, 100), "r----"),
                    ("bash", random.randint(10, 50), "rw---"),
                    ("libc-2.31.so", random.randint(1500, 2000), "r-x--"),
                    ("libc-2.31.so", random.randint(100, 200), "r----"),
                    ("libc-2.31.so", random.randint(10, 50), "rw---"),
                    ("ld-2.31.so", random.randint(100, 200), "r-x--"),
                    ("ld-2.31.so", random.randint(10, 50), "rw---"),
                    ("[heap]", random.randint(1000, 5000), "rw---"),
                    ("[stack]", random.randint(100, 500), "rw---"),
                ]
                
                total_kb = 0
                total_rss = 0
                total_dirty = 0
                
                for name, kb, mode in mappings:
                    rss = random.randint(kb // 4, kb)
                    dirty = random.randint(0, rss // 2)
                    output += f"{base_addr:016x} {kb:10} {rss:7} {dirty:7} {mode}  {name}\n"
                    base_addr += kb * 1024
                    total_kb += kb
                    total_rss += rss
                    total_dirty += dirty
                
                output += f"---------------- ------- ------- ------- \n"
                output += f"total kB         {total_kb:10} {total_rss:7} {total_dirty:7}"
                return output
            else:
                # Simple format
                output = f"{pid}:   /usr/bin/bash\n"
                base_addr = 0x00007f0000000000
                
                mappings = [
                    ("bash", random.randint(500, 1000), "r-xp"),
                    ("bash", random.randint(50, 100), "r--p"),
                    ("bash", random.randint(10, 50), "rw-p"),
                    ("libc-2.31.so", random.randint(1500, 2000), "r-xp"),
                    ("libc-2.31.so", random.randint(100, 200), "r--p"),
                    ("libc-2.31.so", random.randint(10, 50), "rw-p"),
                    ("[heap]", random.randint(1000, 5000), "rw-p"),
                    ("[stack]", random.randint(100, 500), "rw-p"),
                ]
                
                total = 0
                for name, kb, mode in mappings:
                    output += f"{base_addr:016x} {kb:6}K {mode} {name}\n"
                    base_addr += kb * 1024
                    total += kb
                
                output += f" total {total:8}K"
                return output
        
        # strace - System call tracer
        if cmd == "strace":
            if not args or (args[0].startswith("-") and len(args) == 1):
                return "strace: must have PROG [ARGS] or -p PID"
            
            # Check for -p flag (attach to process)
            if "-p" in args:
                pid_idx = args.index("-p") + 1
                if pid_idx < len(args):
                    pid = args[pid_idx]
                    return f"""strace: attach: ptrace(PTRACE_SEIZE, {pid}): Operation not permitted
strace: Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf"""
            
            # Trace a command
            prog = args[-1]
            summary = "-c" in args
            
            if summary:
                # Summary mode
                return f"""% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 {random.uniform(20, 40):5.2f}    {random.uniform(0.001, 0.01):.6f}          {random.randint(10, 50):2}      {random.randint(100, 500):4}           read
 {random.uniform(15, 30):5.2f}    {random.uniform(0.001, 0.01):.6f}          {random.randint(10, 50):2}      {random.randint(100, 500):4}           write
 {random.uniform(10, 20):5.2f}    {random.uniform(0.001, 0.01):.6f}          {random.randint(5, 20):2}       {random.randint(50, 200):4}           open
 {random.uniform(5, 15):5.2f}    {random.uniform(0.0001, 0.001):.6f}          {random.randint(5, 20):2}       {random.randint(50, 200):4}           close
 {random.uniform(5, 10):5.2f}    {random.uniform(0.0001, 0.001):.6f}          {random.randint(5, 20):2}       {random.randint(20, 100):4}           stat
 {random.uniform(5, 10):5.2f}    {random.uniform(0.0001, 0.001):.6f}          {random.randint(5, 20):2}       {random.randint(20, 100):4}           fstat
 {random.uniform(1, 5):5.2f}    {random.uniform(0.0001, 0.001):.6f}          {random.randint(5, 20):2}       {random.randint(10, 50):4}            mmap
------ ----------- ----------- --------- --------- ----------------
100.00    {random.uniform(0.01, 0.1):.6f}                  {random.randint(500, 2000):4}           total"""
            else:
                # Regular trace (show a few sample syscalls)
                return f"""execve("{prog}", ["{prog}"], 0x7ffc1234abcd /* {random.randint(20, 50)} vars */) = 0
brk(NULL)                               = 0x{random.randint(0x1000000, 0x9000000):08x}
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {{st_mode=S_IFREG|0644, st_size={random.randint(50000, 150000)}, ...}}) = 0
mmap(NULL, {random.randint(50000, 150000)}, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f{random.randint(1000000000, 9000000000):010x}
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\\177ELF\\2\\1\\1\\3\\0\\0\\0\\0\\0\\0\\0\\0"..., 832) = 832
fstat(3, {{st_mode=S_IFREG|0755, st_size=2029592, ...}}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f{random.randint(1000000000, 9000000000):010x}
write(1, "Hello, World!\\n", 14)        = 14
exit_group(0)                           = ?
+++ exited with 0 +++"""
        
        # ltrace - Library call tracer
        if cmd == "ltrace":
            if not args or (args[0].startswith("-") and len(args) == 1):
                return "ltrace: too few arguments"
            
            # Check for -p flag
            if "-p" in args:
                pid_idx = args.index("-p") + 1
                if pid_idx < len(args):
                    pid = args[pid_idx]
                    return f"""ltrace: Cannot attach to process {pid}: Operation not permitted
ltrace: ptrace(PTRACE_ATTACH, ...): Operation not permitted
+++ exited (status 1) +++"""
            
            prog = args[-1]
            count_calls = "-c" in args
            
            if count_calls:
                # Summary mode
                return f"""% time     seconds  usecs/call     calls      function
------ ----------- ----------- --------- --------------------
 {random.uniform(20, 40):5.2f}    {random.uniform(0.001, 0.01):.6f}         {random.randint(100, 500):3}      {random.randint(10, 50):4} printf
 {random.uniform(15, 30):5.2f}    {random.uniform(0.001, 0.01):.6f}         {random.randint(100, 500):3}      {random.randint(10, 50):4} malloc
 {random.uniform(10, 20):5.2f}    {random.uniform(0.001, 0.01):.6f}         {random.randint(100, 500):3}      {random.randint(10, 50):4} free
 {random.uniform(10, 15):5.2f}    {random.uniform(0.0001, 0.001):.6f}         {random.randint(50, 200):3}      {random.randint(5, 20):4} strlen
 {random.uniform(5, 10):5.2f}    {random.uniform(0.0001, 0.001):.6f}         {random.randint(50, 200):3}      {random.randint(5, 20):4} strcmp
 {random.uniform(5, 10):5.2f}    {random.uniform(0.0001, 0.001):.6f}         {random.randint(50, 200):3}      {random.randint(5, 20):4} strcpy
------ ----------- ----------- --------- --------------------
100.00    {random.uniform(0.01, 0.1):.6f}                  {random.randint(100, 500):4} total"""
            else:
                # Regular trace
                return f"""__libc_start_main(0x{random.randint(0x100000, 0x900000):06x}, 1, 0x7ffc{random.randint(10000000, 99999999):08x}, 0x{random.randint(0x100000, 0x900000):06x} <unfinished ...>
printf("Hello, World!\\n")                                = 14
strlen("test string")                                     = 11
malloc(1024)                                              = 0x{random.randint(0x1000000, 0x9000000):08x}
strcpy(0x{random.randint(0x1000000, 0x9000000):08x}, "example")                          = 0x{random.randint(0x1000000, 0x9000000):08x}
free(0x{random.randint(0x1000000, 0x9000000):08x})                                          = <void>
+++ exited (status 0) +++"""
        
        # iptables - Firewall administration
        if cmd == "iptables":
            if username != "root" and "sudo" not in command:
                return "iptables v1.8.4 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)"
            
            if "-L" in args or "--list" in args:
                verbose = "-v" in args
                numeric = "-n" in args
                
                if verbose:
                    return f"""Chain INPUT (policy ACCEPT {random.randint(1000, 9999)} packets, {random.randint(100000, 999999)} bytes)
 pkts bytes target     prot opt in     out     source               destination         
 {random.randint(100, 999):4} {random.randint(10000, 99999):5} ACCEPT     all  --  lo     any     anywhere             anywhere            
 {random.randint(100, 999):4} {random.randint(10000, 99999):5} ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
 {random.randint(100, 999):4} {random.randint(10000, 99999):5} ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
 {random.randint(100, 999):4} {random.randint(10000, 99999):5} ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:https
 {random.randint(10, 99):4} {random.randint(1000, 9999):5} DROP       all  --  any    any     anywhere             anywhere            

Chain FORWARD (policy DROP {random.randint(0, 100)} packets, {random.randint(0, 10000)} bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT {random.randint(1000, 9999)} packets, {random.randint(100000, 999999)} bytes)
 pkts bytes target     prot opt in     out     source               destination         
 {random.randint(100, 999):4} {random.randint(10000, 99999):5} ACCEPT     all  --  any    lo      anywhere             anywhere"""
                else:
                    return """Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:https
DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy DROP)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere"""
            
            elif "-S" in args or "--list-rules" in args:
                return """-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -j DROP
-A OUTPUT -o lo -j ACCEPT"""
            
            elif "-A" in args or "--append" in args:
                return ""  # Silent success
            
            elif "-D" in args or "--delete" in args:
                return ""  # Silent success
            
            elif "-F" in args or "--flush" in args:
                return ""  # Silent success
            
            elif "-Z" in args or "--zero" in args:
                return ""  # Silent success
            
            else:
                return """iptables v1.8.4 (legacy)

Usage: iptables -[ACD] chain rule-specification [options]
       iptables -I chain [rulenum] rule-specification [options]
       iptables -R chain rulenum rule-specification [options]
       iptables -D chain rulenum [options]
       iptables -[LS] [chain [rulenum]] [options]
       iptables -[FZ] [chain] [options]
       iptables -[NX] chain
       iptables -E old-chain-name new-chain-name
       iptables -P chain target [options]
       iptables -h (print this help information)"""

                # lsmem
        if cmd == "lsmem":
            total_mem_gb = random.choice([8, 16, 32, 64])
            total_mem_bytes = total_mem_gb * 1024 * 1024 * 1024
            return f"""RANGE                                 SIZE  STATE REMOVABLE BLOCK
0x0000000000000000-0x00000000{total_mem_bytes:08x} {total_mem_gb}G online       no       0-{total_mem_gb-1}

Memory block size:       128M
Total online memory:      {total_mem_gb}G
Total offline memory:      0B"""
        
        # lshw
        if cmd == "lshw":
            if username != "root" and "sudo" not in command:
                return "WARNING: you should run this program as super-user."
            
            current_time = datetime.datetime.now()
            uptime_days = random.randint(1, 100)
            return f"""corp-srv-01
    description: Computer
    product: OptiPlex 7050
    vendor: Dell Inc.
    serial: {hash(username) % 1000000:06d}
    width: 64 bits
    capabilities: smbios-3.0.0 dmi-3.0.0 smp vsyscall32
    configuration: boot=normal chassis=desktop family=OptiPlex sku=0704 uuid={hash(username):08x}-{hash(current_time.hour):04x}-{hash(current_time.minute):04x}-{hash(current_time.second):04x}-{hash(username) % 1000000:012x}
  *-core
       description: Motherboard
       product: 0KCKR
       vendor: Dell Inc.
       physical id: 0
       version: A00
     *-cpu
          description: CPU
          product: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
          vendor: Intel Corp.
          physical id: 400
          bus info: cpu@0
          version: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
          slot: U3E1
          size: {1800 + random.randint(-200, 600)}MHz
          capacity: 3400MHz
          width: 64 bits
          clock: 100MHz
          capabilities: x86-64 fpu fpu_exception wp vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov
     *-memory
          description: System Memory
          physical id: 1000
          slot: System board or motherboard
          size: {random.choice([8, 16, 32])}GiB
        *-bank:0
             description: DIMM DDR4 Synchronous 2400 MHz (0.4 ns)
             product: HMA81GU6AFR8N-UH
             vendor: Hynix
             physical id: 0
             serial: {hash(username + str(current_time.day)):08X}
             slot: DIMM A
             size: {random.choice([4, 8, 16])}GiB
             width: 64 bits
             clock: 2400MHz (0.4ns)"""
        
        # hwinfo
        if cmd == "hwinfo":
            brief = "--short" in args or "-s" in args
            if brief:
                return f"""cpu:
                       Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, {1800 + random.randint(-200, 600)} MHz
disk:
  /dev/sda             VBOX HARDDISK
graphics card:
                       Intel VGA compatible controller
network:
  eth0                 Intel Ethernet Connection
  wlan0                Intel Wireless 8265 / 8275
network interface:
  eth0                 Ethernet network interface
  lo                   Loopback network interface
  wlan0                WLAN network interface"""
            else:
                return f"""01: None 00.0: 10105 BIOS
  [Created at bios.186]
  Unique ID: rdCR.lZF+r4EgHp4
  Hardware Class: bios
  BIOS Keyboard LED Status:
    Scroll Lock: off
    Num Lock: off
    Caps Lock: off
  Serial Port 0: 0x3f8
  Base Memory: 639 kB
  PnP BIOS: @@@0000
  BIOS32 Service Directory: @@@0000
  SMBIOS Version: 3.0
  BIOS Info: #0
    Vendor: "Dell Inc."
    Version: "1.4.9"
    Date: "{current_time.strftime('%m/%d/%Y')}"
    Start Address: 0xF0000
    ROM Size: 64 kB
    Features: 0x0700000003
      PCI supported
      PNP supported
      BIOS flashable"""
        
        # inxi
        if cmd == "inxi":
            load_avg = f"{random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}"
            uptime_days = random.randint(1, 100)
            uptime_hours = random.randint(0, 23)
            mem_used = random.randint(2000, 8000)
            mem_total = random.choice([8192, 16384, 32768])
            
            if "-F" in args or "-Fxxx" in args:
                return f"""System:    Host: corp-srv-01 Kernel: 5.4.0-42-generic x86_64 bits: 64 compiler: gcc v: 9.3.0 
           Desktop: N/A Distro: Ubuntu 20.04.1 LTS (Focal Fossa)
Machine:   Type: Desktop System: Dell product: OptiPlex 7050 v: N/A serial: <superuser required>
           Mobo: Dell model: 0KCKR v: A00 serial: <superuser required> BIOS: Dell v: 1.4.9 date: {current_time.strftime('%m/%d/%Y')}
CPU:       Topology: Quad Core model: Intel Core i5-8250U bits: 64 type: MT MCP arch: Kaby Lake rev: A 
           L2 cache: 6144 KiB
           flags: avx avx2 lm nx pae sse sse2 sse3 sse4_1 sse4_2 ssse3 vmx bogomips: {14400 + random.randint(-500, 500)}
           Speed: {1800 + random.randint(-200, 600)} MHz min/max: 400/3400 MHz Core speeds (MHz): 1: {1800 + random.randint(-200, 600)} 2: {1800 + random.randint(-200, 600)} 
           3: {1800 + random.randint(-200, 600)} 4: {1800 + random.randint(-200, 600)}
Graphics:  Device-1: Intel vendor: Dell driver: i915 v: kernel bus ID: 00:02.0
           Display: server: X.Org 1.20.8 driver: modesetting unloaded: fbdev,vesa resolution: 1920x1080~60Hz
           OpenGL: renderer: Mesa Intel UHD Graphics 620 (KBL GT2) v: 4.6 Mesa 20.0.8 direct render: Yes
Network:   Device-1: Intel Ethernet I219-LM vendor: Dell driver: e1000e v: 3.2.6-k port: f040 bus ID: 00:1f.6
           IF: eth0 state: up speed: 1000 Mbps duplex: full mac: {':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])}
Drives:    Local Storage: total: 100.00 GiB used: {random.randint(20, 80):.2f} GiB ({random.randint(20, 80)}.0%)
           ID-1: /dev/sda vendor: VirtualBox model: VBOX HARDDISK size: 100.00 GiB
Info:      Processes: {100 + random.randint(0, 50)} Uptime: {uptime_days}d {uptime_hours}h {random.randint(0, 59)}m Memory: {mem_total/1024:.2f} GiB 
           used: {mem_used/1024:.2f} GiB ({mem_used*100//mem_total}.0%) Init: systemd runlevel: 5 Compilers: gcc: 9.3.0 Shell: bash v: 5.0.17 
           inxi: 3.0.38"""
            else:
                return f"""CPU: Quad Core Intel Core i5-8250U (-MT MCP-) speed/min/max: {1800 + random.randint(-200, 600)}/400/3400 MHz 
Kernel: 5.4.0-42-generic x86_64 Up: {uptime_days}d {uptime_hours}h {random.randint(0, 59)}m Mem: {mem_used}/{mem_total} MiB ({mem_used*100//mem_total}%) 
Storage: 100.00 GiB ({random.randint(20, 80)}.0% used) Procs: {100 + random.randint(0, 50)} Shell: bash 5.0.17 inxi: 3.0.38"""
        
        # vmstat
        if cmd == "vmstat":
            interval = None
            count = 1
            
            # Parse args for interval and count
            for arg in args:
                if arg.isdigit():
                    if interval is None:
                        interval = int(arg)
                    else:
                        count = int(arg)
            
            procs_r = random.randint(0, 3)
            procs_b = random.randint(0, 1)
            mem_swpd = random.randint(0, 100000)
            mem_free = random.randint(1000000, 8000000)
            mem_buff = random.randint(100000, 500000)
            mem_cache = random.randint(2000000, 6000000)
            swap_si = random.randint(0, 100)
            swap_so = random.randint(0, 100)
            io_bi = random.randint(0, 1000)
            io_bo = random.randint(0, 500)
            system_in = random.randint(1000, 5000)
            system_cs = random.randint(2000, 10000)
            cpu_us = random.randint(1, 30)
            cpu_sy = random.randint(1, 15)
            cpu_id = 100 - cpu_us - cpu_sy - random.randint(0, 5)
            cpu_wa = random.randint(0, 5)
            
            output = f"""procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 {procs_r}  {procs_b} {mem_swpd:6} {mem_free:6} {mem_buff:6} {mem_cache:6}    {swap_si}    {swap_so}   {io_bi:4}   {io_bo:4} {system_in:4} {system_cs:4} {cpu_us:2} {cpu_sy:2} {cpu_id:2}  {cpu_wa} 0"""
            
            return output
        
        # iostat
        if cmd == "iostat":
            cpu_user = random.uniform(5.0, 25.0)
            cpu_nice = random.uniform(0.0, 2.0)
            cpu_system = random.uniform(2.0, 10.0)
            cpu_iowait = random.uniform(0.5, 5.0)
            cpu_steal = random.uniform(0.0, 1.0)
            cpu_idle = 100.0 - (cpu_user + cpu_nice + cpu_system + cpu_iowait + cpu_steal)
            
            tps = random.uniform(10.0, 100.0)
            kb_read_s = random.uniform(50.0, 500.0)
            kb_wrtn_s = random.uniform(100.0, 1000.0)
            kb_read = random.randint(100000, 10000000)
            kb_wrtn = random.randint(500000, 50000000)
            
            return f"""Linux 5.4.0-42-generic (corp-srv-01) 	{current_time.strftime('%m/%d/%Y')} 	_x86_64_	(4 CPU)

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
          {cpu_user:5.2f}    {cpu_nice:4.2f}    {cpu_system:5.2f}    {cpu_iowait:5.2f}    {cpu_steal:5.2f}   {cpu_idle:5.2f}

Device             tps    kB_read/s    kB_wrtn/s    kB_read    kB_wrtn
sda              {tps:5.2f}       {kb_read_s:6.2f}       {kb_wrtn_s:7.2f}    {kb_read:8}   {kb_wrtn:9}"""
        
        # mpstat
        if cmd == "mpstat":
            current_time_str = current_time.strftime('%I:%M:%S %p')
            
            if "-P" in args and "ALL" in args:
                output = f"""Linux 5.4.0-42-generic (corp-srv-01) 	{current_time.strftime('%m/%d/%Y')} 	_x86_64_	(4 CPU)

{current_time_str}  CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
"""
                for cpu in range(4):
                    usr = random.uniform(5.0, 25.0)
                    nice = random.uniform(0.0, 2.0)
                    sys = random.uniform(2.0, 10.0)
                    iowait = random.uniform(0.5, 5.0)
                    irq = random.uniform(0.0, 1.0)
                    soft = random.uniform(0.0, 1.0)
                    steal = random.uniform(0.0, 0.5)
                    idle = 100.0 - (usr + nice + sys + iowait + irq + soft + steal)
                    output += f"{current_time_str}  {cpu:3}   {usr:5.2f}    {nice:5.2f}   {sys:5.2f}    {iowait:5.2f}   {irq:5.2f}   {soft:5.2f}   {steal:5.2f}    0.00    0.00   {idle:5.2f}\n"
                
                # Average
                avg_usr = random.uniform(5.0, 25.0)
                avg_nice = random.uniform(0.0, 2.0)
                avg_sys = random.uniform(2.0, 10.0)
                avg_iowait = random.uniform(0.5, 5.0)
                avg_irq = random.uniform(0.0, 1.0)
                avg_soft = random.uniform(0.0, 1.0)
                avg_steal = random.uniform(0.0, 0.5)
                avg_idle = 100.0 - (avg_usr + avg_nice + avg_sys + avg_iowait + avg_irq + avg_soft + avg_steal)
                output += f"{current_time_str}  all   {avg_usr:5.2f}    {avg_nice:5.2f}   {avg_sys:5.2f}    {avg_iowait:5.2f}   {avg_irq:5.2f}   {avg_soft:5.2f}   {avg_steal:5.2f}    0.00    0.00   {avg_idle:5.2f}"
                return output
            else:
                usr = random.uniform(5.0, 25.0)
                nice = random.uniform(0.0, 2.0)
                sys = random.uniform(2.0, 10.0)
                iowait = random.uniform(0.5, 5.0)
                irq = random.uniform(0.0, 1.0)
                soft = random.uniform(0.0, 1.0)
                steal = random.uniform(0.0, 0.5)
                idle = 100.0 - (usr + nice + sys + iowait + irq + soft + steal)
                
                return f"""Linux 5.4.0-42-generic (corp-srv-01) 	{current_time.strftime('%m/%d/%Y')} 	_x86_64_	(4 CPU)

{current_time_str}  CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
{current_time_str}  all   {usr:5.2f}    {nice:5.2f}   {sys:5.2f}    {iowait:5.2f}   {irq:5.2f}   {soft:5.2f}   {steal:5.2f}    0.00    0.00   {idle:5.2f}"""
        
        # sar
        if cmd == "sar":
            current_time_str = current_time.strftime('%I:%M:%S %p')
            
            if "-u" in args or len(args) == 0:
                # CPU utilization
                output = f"""Linux 5.4.0-42-generic (corp-srv-01) 	{current_time.strftime('%m/%d/%Y')} 	_x86_64_	(4 CPU)

{current_time_str}     CPU     %user     %nice   %system   %iowait    %steal     %idle
"""
                for _ in range(5):
                    time_offset = random.randint(1, 300)
                    sample_time = (current_time - datetime.timedelta(seconds=time_offset)).strftime('%I:%M:%S %p')
                    usr = random.uniform(5.0, 25.0)
                    nice = random.uniform(0.0, 2.0)
                    sys = random.uniform(2.0, 10.0)
                    iowait = random.uniform(0.5, 5.0)
                    steal = random.uniform(0.0, 0.5)
                    idle = 100.0 - (usr + nice + sys + iowait + steal)
                    output += f"{sample_time}     all     {usr:5.2f}     {nice:5.2f}     {sys:5.2f}     {iowait:5.2f}     {steal:5.2f}     {idle:5.2f}\n"
                
                avg_usr = random.uniform(5.0, 25.0)
                avg_nice = random.uniform(0.0, 2.0)
                avg_sys = random.uniform(2.0, 10.0)
                avg_iowait = random.uniform(0.5, 5.0)
                avg_steal = random.uniform(0.0, 0.5)
                avg_idle = 100.0 - (avg_usr + avg_nice + avg_sys + avg_iowait + avg_steal)
                output += f"Average:        all     {avg_usr:5.2f}     {avg_nice:5.2f}     {avg_sys:5.2f}     {avg_iowait:5.2f}     {avg_steal:5.2f}     {avg_idle:5.2f}"
                return output
            elif "-r" in args:
                # Memory utilization
                return f"""Linux 5.4.0-42-generic (corp-srv-01) 	{current_time.strftime('%m/%d/%Y')} 	_x86_64_	(4 CPU)

{current_time_str} kbmemfree kbmemused  %memused kbbuffers  kbcached  kbcommit   %commit  kbactive   kbinact   kbdirty
{current_time_str}   {random.randint(1000000, 4000000):8}  {random.randint(4000000, 12000000):8}     {random.uniform(40.0, 80.0):5.2f}    {random.randint(100000, 500000):6}   {random.randint(2000000, 6000000):7}   {random.randint(5000000, 15000000):7}    {random.uniform(30.0, 70.0):5.2f}   {random.randint(3000000, 8000000):7}   {random.randint(1000000, 4000000):7}      {random.randint(100, 10000):4}"""
            else:
                return "Usage: sar [ options ] [ <interval> [ <count> ] ]"

        # blkid
        if cmd == "blkid":
            if username != "root" and "sudo" not in command:
                return "blkid: must be root"
            return """/dev/sda1: UUID="a1b2c3d4-e5f6-7890-abcd-ef1234567890" TYPE="ext4" PARTUUID="12345678-01"
/dev/sda2: UUID="b2c3d4e5-f6a7-8901-bcde-f12345678901" TYPE="ext4" PARTUUID="12345678-02"
/dev/sda3: UUID="c3d4e5f6-a7b8-9012-cdef-123456789012" TYPE="swap" PARTUUID="12345678-03"""
        
        # fdisk
        if cmd == "fdisk":
            if username != "root" and "sudo" not in command:
                return "fdisk: cannot open /dev/sda: Permission denied"
            
            if "-l" in args or "--list" in args:
                return """Disk /dev/sda: 100 GiB, 107374182400 bytes, 209715200 sectors
Disk model: VBOX HARDDISK   
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x12345678

Device     Boot     Start       End   Sectors  Size Id Type
/dev/sda1  *         2048 104859647 104857600   50G 83 Linux
/dev/sda2       104859648 205520895 100661248   48G 83 Linux
/dev/sda3       205520896 209715199   4194304    2G 82 Linux swap / Solaris"""
            else:
                return """Welcome to fdisk (util-linux 2.34).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Command (m for help):"""
        
        # parted
        if cmd == "parted":
            if username != "root" and "sudo" not in command:
                return "Error: You need to be root to run parted."
            
            if "-l" in args or "--list" in args:
                return """Model: ATA VBOX HARDDISK (scsi)
Disk /dev/sda: 107GB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags: 

Number  Start   End     Size    Type     File system     Flags
 1      1049kB  53.7GB  53.7GB  primary  ext4            boot
 2      53.7GB  105GB   51.5GB  primary  ext4
 3      105GB   107GB   2147MB  primary  linux-swap(v1)"""
            else:
                return """GNU Parted 3.3
Using /dev/sda
Welcome to GNU Parted! Type 'help' to view a list of commands.
(parted)"""


        if cmd == "date":
            now = datetime.datetime.now()
            if "-u" in args or "--utc" in args:
                now = datetime.datetime.utcnow()
                return now.strftime("%a %b %d %H:%M:%S UTC %Y")
            elif "+%s" in " ".join(args):
                return str(int(now.timestamp()))
            elif any(arg.startswith("+") for arg in args):
                # Custom format
                fmt = next((arg[1:] for arg in args if arg.startswith("+")), "%a %b %d %H:%M:%S %Z %Y")
                return now.strftime(fmt)
            else:
                return now.strftime("%a %b %d %H:%M:%S %Z %Y")


        # lscpu
        if cmd == "lscpu":
            return f"""Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              4
On-line CPU(s) list: 0-3
Thread(s) per core:  2
Core(s) per socket:  2
Socket(s):           1
NUMA node(s):        1
Vendor ID:           GenuineIntel
CPU family:          6
Model:               142
Model name:          Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
Stepping:            10
CPU MHz:             1800.000
CPU max MHz:         3400.0000
CPU min MHz:         400.0000
BogoMIPS:            3600.00
Virtualization:      VT-x
L1d cache:           32K
L1i cache:           32K
L2 cache:            256K
L3 cache:            6144K
NUMA node0 CPU(s):   0-3"""
        
        # lsblk
        if cmd == "lsblk":
            return f"""NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
sda      8:0    0   100G  0 disk 
├─sda1   8:1    0    50G  0 part /
├─sda2   8:2    0    48G  0 part /opt
└─sda3   8:3    0     2G  0 part [SWAP]
sr0     11:0    1  1024M  0 rom"""
        
        # lsof
        if cmd == "lsof":
            return f"""COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
systemd      1 root  cwd    DIR    8,1     4096    2 /
systemd      1 root  rtd    DIR    8,1     4096    2 /
systemd      1 root  txt    REG    8,1  1620224 1234 /lib/systemd/systemd
sshd       {1000 + hash(username) % 1000} {username}    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)
bash       {2000 + hash(username) % 1000} {username}  cwd    DIR    8,1     4096 5678 {server.current_directory if server else '/home/guest'}"""
        
        # lspci
        if cmd == "lspci":
            return f"""00:00.0 Host bridge: Intel Corporation Device 5904 (rev 02)
00:02.0 VGA compatible controller: Intel Corporation Device 5916 (rev 07)
00:14.0 USB controller: Intel Corporation Sunrise Point-LP USB 3.0 xHCI Controller (rev 21)
00:16.0 Communication controller: Intel Corporation Sunrise Point-LP CSME HECI #1 (rev 21)
00:17.0 SATA controller: Intel Corporation Sunrise Point-LP SATA Controller [AHCI mode] (rev 21)
00:1c.0 PCI bridge: Intel Corporation Sunrise Point-LP PCI Express Root Port #1 (rev f1)
00:1f.0 ISA bridge: Intel Corporation Intel(R) 100 Series Chipset Family LPC Controller/eSPI Controller - 9D4E (rev 21)
00:1f.2 Memory controller: Intel Corporation Sunrise Point-LP PMC (rev 21)
00:1f.3 Audio device: Intel Corporation Sunrise Point-LP HD Audio (rev 21)
00:1f.4 SMBus: Intel Corporation Sunrise Point-LP SMBus (rev 21)"""
        
        # lsusb
        if cmd == "lsusb":
            return f"""Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 003: ID 8087:0a2b Intel Corp. 
Bus 001 Device 002: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub"""
        
        # dmidecode (simplified)
        if cmd == "dmidecode":
            if username != "root" and "sudo" not in command:
                return "dmidecode: command requires root privileges"
            return f"""# dmidecode 3.2
Getting SMBIOS data from sysfs.
SMBIOS 3.0.0 present.

Handle 0x0001, DMI type 1, 27 bytes
System Information
\tManufacturer: Dell Inc.
\tProduct Name: OptiPlex 7050
\tVersion: Not Specified
\tSerial Number: XXXXXXX
\tUUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
\tWake-up Type: Power Switch
\tSKU Number: 0704
\tFamily: OptiPlex"""
        
        # ping (re-add with dynamic output)
        if cmd == "ping":
            host = args[0] if args and not args[0].startswith("-") else "localhost"
            return f"""PING {host} (192.168.1.1) 56(84) bytes of data.
64 bytes from {host} (192.168.1.1): icmp_seq=1 ttl=64 time=0.045 ms
64 bytes from {host} (192.168.1.1): icmp_seq=2 ttl=64 time=0.052 ms
^C
--- {host} ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.045/0.048/0.052/0.003 ms"""
        
        # dmesg
        if cmd == "dmesg":
            if username != "root" and "sudo" not in command:
                return "dmesg: read kernel buffer failed: Operation not permitted"
            current_time = datetime.datetime.now()
            boot_time = current_time - datetime.timedelta(days=23, hours=4, minutes=12)
            return f"""[    0.000000] Linux version 5.4.0-42-generic (buildd@lcy01-amd64-030)
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.4.0-42-generic root=UUID=xxxxx ro quiet splash
[    0.000000] Kernel command line: BOOT_IMAGE=/boot/vmlinuz-5.4.0-42-generic root=UUID=xxxxx ro quiet splash
[    0.001234] Memory: 16384000K/16777216K available
[    0.123456] CPU: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
[    1.234567] sda: sda1 sda2 sda3
[    2.345678] EXT4-fs (sda1): mounted filesystem with ordered data mode
[{(current_time - boot_time).total_seconds():.6f}] systemd[1]: Started Session 1 of user {username}."""
        
        # whoami - enhanced with help and error handling
        if cmd == "whoami":
            if "--help" in args:
                return """Usage: whoami [OPTION]...
Print the user name associated with the current effective user ID.
Same as id -un.

      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report whoami translation bugs to <https://translationproject.org/team/>
Full documentation at: <https://www.gnu.org/software/coreutils/whoami>
or available locally via: info '(coreutils) whoami invocation'"""
            elif "--version" in args:
                return """whoami (GNU coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Richard Mlynarik."""
            else:
                return username
            
        # id - dynamic based on username
        elif cmd == "id":
            if username == "root":
                uid = 0
                gid = 0
                groups = "0(root)"
            else:
                # Generate dynamic UID/GID based on username hash
                uid = 1000 + (hash(username) % 1000)
                gid = 1000 + (hash(username) % 1000)
                
                # Generate dynamic group memberships
                all_groups = [
                    (27, "sudo"),
                    (999, "docker"),
                    (4, "adm"),
                    (24, "cdrom"),
                    (30, "dip"),
                    (46, "plugdev"),
                    (116, "lxd"),
                    (1000, username)
                ]
                
                # Select random groups based on username hash
                random.seed(hash(username))
                selected_groups = random.sample(all_groups, k=random.randint(3, 6))
                selected_groups.sort(key=lambda x: x[0])
                
                # Format groups
                groups = f"{gid}({username})," + ",".join([f"{g[0]}({g[1]})" for g in selected_groups if g[1] != username])
            
            if "-u" in args:
                return str(uid)
            elif "-g" in args:
                return str(gid)
            elif "-G" in args:
                # Show all group IDs
                group_ids = groups.split(',')
                return " ".join([g.split('(')[0] for g in group_ids])
            elif "-n" in args:
                # Show names instead of numbers
                if "-u" in args:
                    return username
                elif "-g" in args:
                    return username
                else:
                    return username
            else:
                return f"uid={uid}({username}) gid={gid}({username}) groups={groups}"
            
        # hostname - dynamic based on username
        elif cmd == "hostname":
            # Generate dynamic hostname based on username
            hostname_types = ["web", "db", "mail", "app", "api", "cache", "proxy", "file", "backup", "monitor"]
            hostname_type = hostname_types[hash(username) % len(hostname_types)]
            server_num = (hash(username + str(datetime.datetime.now().day)) % 99) + 1
            
            if "-f" in args or "--fqdn" in args:
                # Fully qualified domain name
                domain = ["example.com", "corp.local", "internal.net", "prod.local"][hash(username) % 4]
                return f"{hostname_type}-srv-{server_num:02d}.{domain}"
            elif "-s" in args or "--short" in args:
                return f"{hostname_type}-srv-{server_num:02d}"
            elif "-i" in args or "--ip-address" in args:
                # Return IP address
                return f"192.168.{(hash(username) % 254) + 1}.{server_num}"
            else:
                return f"{hostname_type}-srv-{server_num:02d}"
            
        # uname
        elif cmd == "uname":
            if "-a" in args or "--all" in args:
                return "Linux corp-srv-01 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
            elif "-r" in args:
                return "5.4.0-42-generic"
            elif "-s" in args or not args:
                return "Linux"
            else:
                return "Linux"
                
        # uptime - dynamic with realistic values
        elif cmd == "uptime":
            current_time = datetime.datetime.now()
            
            # Generate consistent uptime based on username and current day
            uptime_seed = hash(username + str(current_time.date()))
            random.seed(uptime_seed)
            
            # Random uptime between 1 hour and 365 days
            uptime_hours = random.randint(1, 365 * 24)
            uptime_days = uptime_hours // 24
            uptime_hours_remainder = uptime_hours % 24
            uptime_minutes = random.randint(0, 59)
            
            # Number of users (1-5)
            num_users = random.randint(1, 5)
            
            # Load averages (realistic values)
            load_1min = random.uniform(0.1, 2.5)
            load_5min = random.uniform(0.1, 2.5)
            load_15min = random.uniform(0.1, 2.5)
            
            # Format uptime string
            current_time_str = current_time.strftime("%H:%M:%S")
            
            if uptime_days > 0:
                if uptime_hours_remainder > 0:
                    uptime_str = f"{uptime_days} days, {uptime_hours_remainder}:{uptime_minutes:02d}"
                else:
                    uptime_str = f"{uptime_days} days, {uptime_minutes} min"
            elif uptime_hours_remainder > 0:
                uptime_str = f"{uptime_hours_remainder}:{uptime_minutes:02d}"
            else:
                uptime_str = f"{uptime_minutes} min"
            
            user_str = "user" if num_users == 1 else "users"
            
            if "-p" in args or "--pretty" in args:
                # Pretty format
                if uptime_days > 0:
                    return f"up {uptime_days} days {uptime_hours_remainder} hours {uptime_minutes} minutes"
                elif uptime_hours_remainder > 0:
                    return f"up {uptime_hours_remainder} hours {uptime_minutes} minutes"
                else:
                    return f"up {uptime_minutes} minutes"
            elif "-s" in args or "--since" in args:
                # Boot time
                boot_time = current_time - datetime.timedelta(hours=uptime_hours, minutes=uptime_minutes)
                return boot_time.strftime("%Y-%m-%d %H:%M:%S")
            else:
                # Standard format
                return f" {current_time_str} up {uptime_str},  {num_users} {user_str},  load average: {load_1min:.2f}, {load_5min:.2f}, {load_15min:.2f}"
            
        # date
        elif cmd == "date":
            return datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
            
        # ps
        elif cmd == "ps":
            return self._cmd_ps(args)
        
        # w command
        elif cmd == "w":
            return self._cmd_w(username)
        
        # who command
        elif cmd == "who":
            return self._cmd_who(username)
        
        # last command
        elif cmd == "last":
            return self._cmd_last()
        
        # free command
        elif cmd == "free":
            return self._cmd_free(args)
        
        # env command
        elif cmd == "env" or cmd == "printenv":
            return self._cmd_env(context)
        
        # export command
        elif cmd == "export":
            return self._cmd_export(args, context)
        # history command (update existing)
        elif cmd == "history":
            return self._cmd_history(context)
        # kill/killall/pkill
        elif cmd in ["kill", "killall", "pkill"]:
            return self._cmd_kill(cmd, args)
        # traceroute
        elif cmd == "traceroute":
            return self._cmd_traceroute(args)
        # nslookup/dig
        elif cmd in ["nslookup", "dig"]:
            return self._cmd_nslookup(args)
        # nc/netcat
        elif cmd in ["nc", "netcat"]:
            return self._cmd_nc(args)
        # systemctl
        elif cmd == "systemctl":
            return self._cmd_systemctl(args)
        # service
        elif cmd == "service":
            return self._cmd_service(args)
        # apt/apt-get
        elif cmd in ["apt", "apt-get"]:
            return self._cmd_apt(args)
        # dpkg
        elif cmd == "dpkg":
            return self._cmd_dpkg(args)
        # wget
        elif cmd == "wget":
            return self._cmd_wget(args, context)
        # curl
        elif cmd == "curl":
            return self._cmd_curl(args, context)
        # tar
        elif cmd == "tar":
            return self._cmd_tar(args)
        # gzip/gunzip
        elif cmd in ["gzip", "gunzip"]:
            return self._cmd_gzip(cmd, args)
        # zip/unzip
        elif cmd in ["zip", "unzip"]:
            return self._cmd_zip(cmd, args)
        # man
        elif cmd == "man":
            return self._cmd_man(args)
        # crontab
        elif cmd == "crontab":
            return self._cmd_crontab(args, username)
        # echo
        elif cmd == "echo":
            return self._cmd_echo(args, context)
            
        # Default - let LLM handle
        return None
        
    def _cmd_ps(self, args: List[str]) -> str:
        """Generate ps output"""
        if "aux" in "".join(args) or "-ef" in args:
            # Full process list
            return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169404 11504 ?        Ss   Nov09   0:12 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Nov09   0:00 [kthreadd]
root       456  0.1  0.5 1847256 89632 ?       Ssl  Nov09   2:34 /usr/bin/dockerd
mysql      789  0.3  2.1 1823452 345678 ?      Ssl  Nov09  12:45 /usr/sbin/mysqld
www-data   892  0.0  0.2 234567 34567 ?        S    Nov09   0:23 nginx: worker process
jenkins   1234  0.2  1.5 2345678 234567 ?      Ssl  Nov09   8:12 java -jar jenkins.war
alex.chen 5678  0.0  0.1 123456 12345 pts/0    Ss   14:20   0:00 -bash
alex.chen 5890  0.0  0.0 145678  3456 pts/0    R+   14:23   0:00 ps aux"""
        else:
            # Simple ps
            return """  PID TTY          TIME CMD
 5678 pts/0    00:00:00 bash
 5890 pts/0    00:00:00 ps"""
    
    def _cmd_w(self, username: str) -> str:
        """Generate w command output"""
        return f""" 17:56:06 up 23 days,  4:12,  3 users,  load average: 0.52, 0.58, 0.59
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{username:<8} pts/0    192.168.1.100    14:20    0.00s  0.05s  0.01s -bash
alex.chen pts/1    10.0.0.50        10:15    2:30m  0.12s  0.03s vim project.cpp
jenkins   pts/2    10.0.0.2         09:00    5:00m  1.23s  0.89s java -jar jenkins.war"""
    
    def _cmd_who(self, username: str) -> str:
        """Generate who command output - dynamic"""
        current_time = datetime.datetime.now()
        
        # Generate consistent user list based on username
        random.seed(hash(username))
        
        # Possible users that might be logged in
        possible_users = [
            "admin", "jenkins", "deploy", "backup", "monitor", 
            "alex.chen", "sarah.kim", "mike.jones", "lisa.wang",
            "dev", "ops", "root", "service", "webapp"
        ]
        
        # Number of logged in users (1-4 including current user)
        num_other_users = random.randint(0, 3)
        other_users = random.sample(possible_users, k=num_other_users)
        
        # Build output
        output_lines = []
        
        # Current user (always first)
        login_time = current_time - datetime.timedelta(minutes=random.randint(5, 120))
        ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        output_lines.append(f"{username:<8} pts/0        {login_time.strftime('%Y-%m-%d %H:%M')} ({ip})")
        
        # Other logged in users
        for i, user in enumerate(other_users, start=1):
            # Random login time (within last 24 hours)
            login_time = current_time - datetime.timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
            
            # Random IP address (internal network)
            if random.choice([True, False]):
                ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}"
            else:
                ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            terminal = f"pts/{i}"
            output_lines.append(f"{user:<8} {terminal:<12} {login_time.strftime('%Y-%m-%d %H:%M')} ({ip})")
        
        return "\n".join(output_lines)
    
    def _cmd_last(self) -> str:
        """Generate last command output - dynamic"""
        current_time = datetime.datetime.now()
        
        # Generate consistent history based on current date
        random.seed(hash(str(current_time.date())))
        
        # Possible users
        possible_users = [
            "admin", "jenkins", "deploy", "backup", "monitor", 
            "alex.chen", "sarah.martinez", "mike.thompson", "lisa.wang",
            "dev", "ops", "root", "service", "webapp", "john.doe"
        ]
        
        output_lines = []
        
        # Currently logged in users (2-4)
        num_current = random.randint(2, 4)
        current_users = random.sample(possible_users, k=num_current)
        
        for i, user in enumerate(current_users):
            # Login time (within last 12 hours)
            login_time = current_time - datetime.timedelta(hours=random.randint(0, 12), minutes=random.randint(0, 59))
            
            # Random IP
            if random.choice([True, False]):
                ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}"
            else:
                ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            terminal = f"pts/{i}"
            login_str = login_time.strftime("%a %b %d %H:%M")
            
            output_lines.append(f"{user:<14} {terminal:<12} {ip:<16} {login_str}   still logged in")
        
        # Past sessions (5-10 entries)
        num_past = random.randint(5, 10)
        past_users = [random.choice(possible_users) for _ in range(num_past)]
        
        for i, user in enumerate(past_users):
            # Past login time (1-7 days ago)
            days_ago = random.randint(0, 7)
            login_time = current_time - datetime.timedelta(days=days_ago, hours=random.randint(0, 23), minutes=random.randint(0, 59))
            
            # Session duration (15 min to 8 hours)
            duration_minutes = random.randint(15, 480)
            logout_time = login_time + datetime.timedelta(minutes=duration_minutes)
            
            # Format duration
            hours = duration_minutes // 60
            minutes = duration_minutes % 60
            duration_str = f"({hours:02d}:{minutes:02d})"
            
            # Random IP
            if random.choice([True, False]):
                ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}"
            else:
                ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            terminal = f"pts/{random.randint(0, 5)}"
            login_str = login_time.strftime("%a %b %d %H:%M")
            logout_str = logout_time.strftime("%H:%M")
            
            output_lines.append(f"{user:<14} {terminal:<12} {ip:<16} {login_str} - {logout_str}  {duration_str}")
        
        # Add wtmp begins line
        wtmp_date = current_time - datetime.timedelta(days=random.randint(30, 90))
        output_lines.append("")
        output_lines.append(f"wtmp begins {wtmp_date.strftime('%a %b %d %H:%M:%S %Y')}")
        
        return "\n".join(output_lines)
    
    def _cmd_free(self, args: List[str]) -> str:
        """Generate free command output - dynamic"""
        # Generate consistent memory values based on username
        random.seed(hash(str(datetime.datetime.now().date())))
        
        # Total memory options (in MB): 4GB, 8GB, 16GB, 32GB, 64GB
        total_mem_options = [4096, 8192, 16384, 32768, 65536]
        total_mem_mb = random.choice(total_mem_options)
        
        # Used memory (40-80% of total)
        used_percent = random.uniform(0.4, 0.8)
        used_mem_mb = int(total_mem_mb * used_percent)
        
        # Shared memory (1-5% of total)
        shared_mem_mb = int(total_mem_mb * random.uniform(0.01, 0.05))
        
        # Buff/cache (15-35% of total)
        buffcache_mem_mb = int(total_mem_mb * random.uniform(0.15, 0.35))
        
        # Free memory (remaining)
        free_mem_mb = total_mem_mb - used_mem_mb - buffcache_mem_mb
        
        # Available memory (free + most of buff/cache)
        available_mem_mb = free_mem_mb + int(buffcache_mem_mb * 0.8)
        
        # Swap (usually 25-50% of RAM, or same as RAM)
        swap_total_mb = random.choice([total_mem_mb // 4, total_mem_mb // 2, total_mem_mb])
        swap_used_mb = int(swap_total_mb * random.uniform(0.0, 0.3))  # 0-30% used
        swap_free_mb = swap_total_mb - swap_used_mb
        
        # Convert to KB for default output
        total_kb = total_mem_mb * 1024
        used_kb = used_mem_mb * 1024
        free_kb = free_mem_mb * 1024
        shared_kb = shared_mem_mb * 1024
        buffcache_kb = buffcache_mem_mb * 1024
        available_kb = available_mem_mb * 1024
        swap_total_kb = swap_total_mb * 1024
        swap_used_kb = swap_used_mb * 1024
        swap_free_kb = swap_free_mb * 1024
        
        if "-h" in args or "--human" in args:
            # Human readable format
            def format_human(kb):
                """Convert KB to human readable format"""
                if kb >= 1024 * 1024:  # GB
                    return f"{kb / (1024 * 1024):.1f}Gi"
                elif kb >= 1024:  # MB
                    return f"{kb / 1024:.0f}Mi"
                else:
                    return f"{kb}Ki"
            
            return f"""              total        used        free      shared  buff/cache   available
Mem:      {format_human(total_kb):>10} {format_human(used_kb):>10} {format_human(free_kb):>10} {format_human(shared_kb):>10} {format_human(buffcache_kb):>10} {format_human(available_kb):>10}
Swap:     {format_human(swap_total_kb):>10} {format_human(swap_used_kb):>10} {format_human(swap_free_kb):>10}"""
        
        elif "-m" in args or "--mebi" in args:
            # Mebibytes
            return f"""              total        used        free      shared  buff/cache   available
Mem:      {total_mem_mb:>10} {used_mem_mb:>10} {free_mem_mb:>10} {shared_mem_mb:>10} {buffcache_mem_mb:>10} {available_mem_mb:>10}
Swap:     {swap_total_mb:>10} {swap_used_mb:>10} {swap_free_mb:>10}"""
        
        elif "-g" in args or "--gibi" in args:
            # Gibibytes
            total_gb = total_mem_mb / 1024
            used_gb = used_mem_mb / 1024
            free_gb = free_mem_mb / 1024
            shared_gb = shared_mem_mb / 1024
            buffcache_gb = buffcache_mem_mb / 1024
            available_gb = available_mem_mb / 1024
            swap_total_gb = swap_total_mb / 1024
            swap_used_gb = swap_used_mb / 1024
            swap_free_gb = swap_free_mb / 1024
            
            return f"""              total        used        free      shared  buff/cache   available
Mem:      {total_gb:>10.1f} {used_gb:>10.1f} {free_gb:>10.1f} {shared_gb:>10.1f} {buffcache_gb:>10.1f} {available_gb:>10.1f}
Swap:     {swap_total_gb:>10.1f} {swap_used_gb:>10.1f} {swap_free_gb:>10.1f}"""
        
        else:
            # Default: Kibibytes
            return f"""              total        used        free      shared  buff/cache   available
Mem:      {total_kb:>10} {used_kb:>10} {free_kb:>10} {shared_kb:>10} {buffcache_kb:>10} {available_kb:>10}
Swap:     {swap_total_kb:>10} {swap_used_kb:>10} {swap_free_kb:>10}"""
    
    def _cmd_env(self, context: Optional[Dict[str, Any]]) -> str:
        """Generate env command output - dynamic and enhanced"""
        server = context.get("server") if context else None
        username = context.get("username", "guest") if context else "guest"
        
        # Try to get environment from server first
        if server and hasattr(server, "environment"):
            lines = []
            for key, value in server.environment.items():
                lines.append(f"{key}={value}")
            return "\n".join(lines)
        
        # Generate dynamic environment variables
        current_time = datetime.datetime.now()
        random.seed(hash(username))
        
        # Determine home directory
        home_dir = "/root" if username == "root" else f"/home/{username}"
        
        # Generate hostname
        hostname_types = ["web", "db", "mail", "app", "api", "cache", "proxy", "file", "backup", "monitor"]
        hostname_type = hostname_types[hash(username) % len(hostname_types)]
        server_num = (hash(username + str(current_time.day)) % 99) + 1
        hostname = f"{hostname_type}-srv-{server_num:02d}"
        
        # Random locale variations
        locales = ["en_US.UTF-8", "en_GB.UTF-8", "C.UTF-8"]
        locale = random.choice(locales)
        
        # Random terminal types
        term_types = ["xterm-256color", "xterm", "screen-256color", "tmux-256color"]
        term = random.choice(term_types)
        
        # Random shell
        shells = ["/bin/bash", "/bin/zsh", "/bin/sh"]
        shell = random.choice(shells)
        
        # Build comprehensive environment
        env_vars = {
            "USER": username,
            "LOGNAME": username,
            "HOME": home_dir,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin",
            "SHELL": shell,
            "TERM": term,
            "PWD": home_dir,
            "LANG": locale,
            "LC_ALL": locale,
            "HOSTNAME": hostname,
            "HOSTTYPE": "x86_64",
            "OSTYPE": "linux-gnu",
            "MACHTYPE": "x86_64-pc-linux-gnu",
            "SHLVL": str(random.randint(1, 3)),
            "SSH_CONNECTION": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)} {random.randint(40000, 65000)} 10.0.0.{random.randint(1, 255)} 22",
            "SSH_CLIENT": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)} {random.randint(40000, 65000)} 22",
            "SSH_TTY": "/dev/pts/0",
        }
        
        # Add optional environment variables based on username
        if random.choice([True, False]):
            env_vars["EDITOR"] = random.choice(["vim", "nano", "vi", "emacs"])
        
        if random.choice([True, False]):
            env_vars["VISUAL"] = env_vars.get("EDITOR", "vim")
        
        # Add development-related vars for certain users
        if username in ["dev", "developer", "admin"] or "dev" in username.lower():
            env_vars["PYTHONPATH"] = f"{home_dir}/lib/python3.8/site-packages"
            env_vars["VIRTUAL_ENV"] = f"{home_dir}/venv"
            env_vars["NODE_PATH"] = "/usr/local/lib/node_modules"
        
        # Add docker-related vars occasionally
        if random.choice([True, False, False]):  # 1/3 chance
            env_vars["DOCKER_HOST"] = "unix:///var/run/docker.sock"
        
        # Add XDG directories
        if random.choice([True, False]):
            env_vars["XDG_RUNTIME_DIR"] = f"/run/user/{1000 + (hash(username) % 1000)}"
            env_vars["XDG_SESSION_ID"] = str(random.randint(1, 100))
        
        # Add mail and other system vars
        env_vars["MAIL"] = f"/var/mail/{username}"
        
        # Add LS_COLORS (abbreviated)
        if random.choice([True, False]):
            env_vars["LS_COLORS"] = "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32"
        
        # Add PS1 prompt
        if shell == "/bin/bash":
            if username == "root":
                env_vars["PS1"] = "\\[\\033[01;31m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]# "
            else:
                env_vars["PS1"] = "\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]$ "
        
        # Sort and format output
        lines = []
        for key in sorted(env_vars.keys()):
            lines.append(f"{key}={env_vars[key]}")
        
        return "\n".join(lines)

    def _cmd_export(self, args: List[str], context: Optional[Dict[str, Any]]) -> str:
        if not args:
            # Show all exported variables
            return self._cmd_env(context)
    
        server = context.get("server") if context else None
        if not server or not hasattr(server, "update_environment"):
            return ""
    
        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                # Remove quotes if present
                value = value.strip('"').strip("'")
                server.update_environment(key, value)
    
        return ""
    
    def _cmd_history(self, context: Optional[Dict[str, Any]]) -> str:
        """Show command history"""
        server = context.get("server") if context else None
        if not server or not hasattr(server, "command_history"):
            return ""
    
        lines = []
        for i, cmd in enumerate(server.command_history, 1):
            lines.append(f"  {i}  {cmd}")
        return "\n".join(lines)

    def _cmd_kill(self, cmd: str, args: List[str]) -> str:
        """Simulate kill/killall/pkill"""
        if not args:
            return f"{cmd}: usage: {cmd} [-s sigspec | -n signum] pid | jobspec"
        return ""  # Silent success
    
    def _cmd_traceroute(self, args: List[str]) -> str:
        """Simulate traceroute"""
        host = args[0] if args and not args[0].startswith("-") else "8.8.8.8"
        return f"""traceroute to {host} (8.8.8.8), 30 hops max, 60 byte packets
    1  gateway (192.168.1.1)  0.234 ms  0.198 ms  0.187 ms
    2  10.0.0.1 (10.0.0.1)  1.234 ms  1.198 ms  1.187 ms
    3  * * *
    4  {host} (8.8.8.8)  12.345 ms  12.298 ms  12.287 ms"""

    def _cmd_nslookup(self, args: List[str]) -> str:
        """Simulate nslookup/dig"""
        host = args[0] if args and not args[0].startswith("-") else "google.com"
        return f"""Server:         192.168.1.1
    Address:        192.168.1.1#53
    Non-authoritative answer:
    Name:   {host}
    Address: 142.250.185.46"""

    def _cmd_nc(self, args: List[str]) -> str:
        """Simulate netcat"""
        return "nc: connection refused"
    
    def _cmd_systemctl(self, args: List[str]) -> str:
        """Simulate systemctl"""
        if "status" in args:
            service = args[-1] if args else "unknown"
            return f"""● {service}.service - {service.title()} Service
    Loaded: loaded (/lib/systemd/system/{service}.service; enabled; vendor preset: enabled)
    Active: active (running) since Mon 2024-12-02 10:00:00 UTC; 2 days ago
        Docs: man:{service}(8)
    Main PID: 1234 ({service})
        Tasks: 1 (limit: 4915)
    Memory: 12.3M
    CGroup: /system.slice/{service}.service
            └─1234 /usr/sbin/{service}"""
        elif "list-units" in args:
            return """UNIT                        LOAD   ACTIVE SUB     DESCRIPTION
    nginx.service               loaded active running A high performance web server
    mysql.service               loaded active running MySQL Community Server
    ssh.service                 loaded active running OpenBSD Secure Shell server"""
        return ""
    
    def _cmd_service(self, args: List[str]) -> str:
        """Simulate service command"""
        if "status" in args:
            service = args[0] if args and args[0] != "status" else "unknown"
            return f"{service} is running"
        return ""
    
    def _cmd_apt(self, args: List[str], context: Optional[Dict[str, Any]]) -> str:
        """Simulate apt/apt-get"""
        server = context.get("server") if context else None
        
        if "update" in args:
            return """Hit:1 http://archive.ubuntu.com/ubuntu focal InRelease
Get:2 http://security.ubuntu.com/ubuntu focal-security InRelease [114 kB]
Get:3 http://archive.ubuntu.com/ubuntu focal-updates InRelease [114 kB]
Fetched 228 kB in 1s (228 kB/s)
Reading package lists... Done
Building dependency tree
Reading state information... Done
All packages are up to date."""
        
        elif "install" in args:
            package = args[-1]
            
            if server and server.virtual_fs.is_installed(package):
                return f"{package} is already the newest version."
                
            # Install it
            if server:
                server.virtual_fs.install_package(package)
                
            return f"""Reading package lists... Done
Building dependency tree
Reading state information... Done
The following NEW packages will be installed:
  {package}
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 1,234 kB of archives.
After this operation, 5,678 kB of additional disk space will be used.
Get:1 http://archive.ubuntu.com/ubuntu focal/main amd64 {package} amd64 1.0.0 [1,234 kB]
Fetched 1,234 kB in 1s (1,234 kB/s)
Selecting previously unselected package {package}.
(Reading database ... 12345 files and directories currently installed.)
Preparing to unpack .../{package}_1.0.0_amd64.deb ...
Unpacking {package} (1.0.0) ...
Setting up {package} (1.0.0) ..."""
        
        return ""


    def _cmd_dpkg(self, args: List[str]) -> str:
        """Simulate dpkg"""
        if "-l" in args:
            return """Desired=Unknown/Install/Remove/Purge/Hold
    | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
    |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
    ||/ Name                Version          Architecture Description
    +++-===================-================-============-================================
    ii  nginx               1.18.0-0ubuntu1  amd64        small, powerful, scalable web
    ii  mysql-server        8.0.23-0ubuntu0  amd64        MySQL database server
    ii  openssh-server      1:8.2p1-4ubuntu0 amd64        secure shell (SSH) server"""
        return ""


    def _cmd_wget(self, args: List[str], context: Optional[Dict[str, Any]]) -> str:
        """
        Simulate wget - network downloader with full feature support.
        
        Supports:
        - -O file: output to file
        - -q: quiet mode
        - -c: continue partial download
        - -P dir: save to directory
        - --help, --version
        - Multiple URLs
        """
        if not args or "--help" in args:
            return """GNU Wget 1.20.3, a non-interactive network retriever.
Usage: wget [OPTION]... [URL]...

Mandatory arguments to long options are mandatory for short options too.

Startup:
  -V,  --version           display the version of Wget and exit
  -h,  --help              print this help
  -b,  --background        go to background after startup
  -e,  --execute=COMMAND   execute a `.wgetrc'-style command

Logging and input file:
  -o,  --output-file=FILE    log messages to FILE
  -a,  --append-output=FILE  append messages to FILE
  -q,  --quiet               quiet (no output)
  -v,  --verbose             be verbose (this is the default)

Download:
  -t,  --tries=NUMBER            set number of retries to NUMBER (0 unlimits)
  -O,  --output-document=FILE    write documents to FILE
  -nc, --no-clobber              skip downloads that would download to existing files
  -c,  --continue                resume getting a partially-downloaded file
  -P,  --directory-prefix=PREFIX  save files to PREFIX/..
       --limit-rate=RATE         limit download rate to RATE

HTTP options:
  -U,  --user-agent=AGENT      identify as AGENT instead of Wget/VERSION
       --no-check-certificate   don't validate the server's certificate

FTP options:
       --ftp-user=USER          set ftp user to USER
       --ftp-password=PASS      set ftp password to PASS"""
        
        if "--version" in args:
            return """GNU Wget 1.20.3 built on linux-gnu.

-cares +digest -gpgme +https +ipv6 +iri +large-file -metalink +nls 
+ntlm +opie +psl +ssl/openssl 

Wgetrc: 
    /etc/wgetrc (system)
Locale: 
    /usr/share/locale 
Compile: 
    gcc -DHAVE_CONFIG_H -DSYSTEM_WGETRC="/etc/wgetrc" 
    -DLOCALEDIR="/usr/share/locale" -I. -I../../src -I../lib 
    -I../../lib -Wdate-time -D_FORTIFY_SOURCE=2 -DHAVE_LIBSSL -DNDEBUG 
    -g -O2 -fdebug-prefix-map=/build/wget-OvLK9y/wget-1.20.3=. 
    -fstack-protector-strong -Wformat -Werror=format-security 
    -DNO_SSLv2 -D_FILE_OFFSET_BITS=64 -g -Wall 
Link: 
    gcc -DHAVE_LIBSSL -DNDEBUG -g -O2 
    -fdebug-prefix-map=/build/wget-OvLK9y/wget-1.20.3=. 
    -fstack-protector-strong -Wformat -Werror=format-security 
    -DNO_SSLv2 -D_FILE_OFFSET_BITS=64 -g -Wall -Wl,-Bsymbolic-functions 
    -Wl,-z,relro -Wl,-z,now -lpcre2-8 -luuid -lidn2 -lssl -lcrypto -lz 
    -lpsl ftp-opie.o openssl.o http-ntlm.o ../lib/libgnu.a 

Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later
<http://www.gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Originally written by Hrvoje Niksic <hniksic@xemacs.org>.
Please send bug reports and questions to <bug-wget@gnu.org>."""
        
        # Parse flags
        quiet = "-q" in args or "--quiet" in args
        continue_download = "-c" in args or "--continue" in args
        output_file = None
        directory = None
        urls = []
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg == "-O" or arg == "--output-document":
                if i + 1 < len(args):
                    output_file = args[i + 1]
                    i += 1
            elif arg == "-P" or arg == "--directory-prefix":
                if i + 1 < len(args):
                    directory = args[i + 1]
                    i += 1
            elif not arg.startswith("-"):
                urls.append(arg)
            
            i += 1
        
        if not urls:
            return "wget: missing URL\nUsage: wget [OPTION]... [URL]..."
        
        # Process each URL
        results = []
        server = context.get("server") if context else None
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for url in urls:
            # Parse URL
            if "://" in url:
                protocol, rest = url.split("://", 1)
                if "/" in rest:
                    domain = rest.split("/")[0]
                    path = "/" + "/".join(rest.split("/")[1:])
                else:
                    domain = rest
                    path = "/"
            else:
                protocol = "http"
                domain = url.split("/")[0]
                path = "/" + "/".join(url.split("/")[1:]) if "/" in url else "/"
            
            # Determine filename
            if output_file:
                filename = output_file
            else:
                filename = path.split("/")[-1] if path != "/" else "index.html"
                if not filename or filename == "":
                    filename = "index.html"
            
            # Add directory prefix if specified
            if directory:
                filename = f"{directory}/{filename}"
            
            # Generate random file size and download speed
            random.seed(hash(url))
            file_size = random.randint(1024, 10485760)  # 1KB to 10MB
            file_size_kb = file_size / 1024
            file_size_mb = file_size / (1024 * 1024)
            download_speed = random.randint(100, 10000)  # KB/s
            download_time = file_size_kb / download_speed
            
            # Generate realistic IP
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
            # Format file size
            if file_size_mb >= 1:
                size_str = f"{file_size_mb:.2f}M"
            else:
                size_str = f"{file_size_kb:.1f}K"
            
            # Save to virtual filesystem
            if server and hasattr(server, "virtual_fs"):
                # Generate realistic content based on file type
                ext = filename.split(".")[-1].lower() if "." in filename else "html"
                
                if ext in ["html", "htm"]:
                    content = f"""<!DOCTYPE html>
<html>
<head><title>Downloaded from {domain}</title></head>
<body>
<h1>Content from {url}</h1>
<p>This file was downloaded via wget.</p>
</body>
</html>"""
                elif ext in ["txt", "log"]:
                    content = f"Content downloaded from {url}\nTimestamp: {current_time}\n"
                elif ext in ["json"]:
                    content = f'{{"url": "{url}", "downloaded": "{current_time}", "status": "success"}}'
                elif ext in ["xml"]:
                    content = f'<?xml version="1.0"?>\n<download>\n  <url>{url}</url>\n  <time>{current_time}</time>\n</download>'
                else:
                    content = f"[Binary content downloaded from {url}]"
                
                server.virtual_fs.write_file(filename, content, server.current_directory)
            
            # Build output
            if not quiet:
                output = f"""--{current_time}--  {url}
Resolving {domain}... {ip}
Connecting to {domain}|{ip}|:{'443' if protocol == 'https' else '80'}... connected.
HTTP request sent, awaiting response... 200 OK
Length: {file_size} ({size_str}) [text/html]
Saving to: '{filename}'

{filename}         100%[===================>]   {size_str}  {download_speed}KB/s    in {download_time:.1f}s

{current_time} ({download_speed} KB/s) - '{filename}' saved [{file_size}/{file_size}]
"""
                results.append(output.strip())
            else:
                results.append(f"'{filename}' saved [{file_size}/{file_size}]")
        
        return "\n\n".join(results) if results else ""
    
    def _cmd_curl(self, args: List[str], context: Optional[Dict[str, Any]]) -> str:
        """
        Simulate curl - transfer data with URLs.
        
        Supports:
        - -o file: output to file
        - -O: use remote filename
        - -s: silent mode
        - -I: fetch headers only
        - -X METHOD: specify request method
        - -H header: custom header
        - -d data: POST data
        - --help, --version
        """
        if not args or "--help" in args:
            return """Usage: curl [options...] <url>
 -d, --data <data>          HTTP POST data
 -f, --fail                 Fail silently (no output at all) on HTTP errors
 -h, --help <category>      Get help for commands
 -i, --include              Include protocol response headers in the output
 -o, --output <file>        Write to file instead of stdout
 -O, --remote-name          Write output to a file named as the remote file
 -s, --silent               Silent mode
 -T, --upload-file <file>   Transfer local FILE to destination
 -u, --user <user:password> Server user and password
 -A, --user-agent <name>    Send User-Agent <name> to server
 -v, --verbose              Make the operation more talkative
 -X, --request <command>    Specify request command to use
     --compressed           Request compressed response
     --max-time <seconds>   Maximum time allowed for the transfer
     --retry <num>          Retry request if transient problems occur

This is not the full help, this menu is stripped into categories.
Use "--help category" to get an overview of all categories.
For all options use the manual or "--help all"."""
        
        if "--version" in args:
            return """curl 7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0 OpenSSL/1.1.1f zlib/1.2.11 brotli/1.0.7 libidn2/2.2.0 libpsl/0.21.0 (+libidn2/2.2.0) libssh/0.9.3/openssl/zlib nghttp2/1.40.0 librtmp/2.3
Release-Date: 2020-01-08
Protocols: dict file ftp ftps gopher http https imap imaps ldap ldaps pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp 
Features: AsynchDNS brotli GSS-API HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL TLS-SRP UnixSockets"""
        
        # Parse flags
        silent = "-s" in args or "--silent" in args
        headers_only = "-I" in args or "--head" in args
        output_file = None
        remote_name = "-O" in args or "--remote-name" in args
        method = "GET"
        post_data = None
        url = None
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg == "-o" or arg == "--output":
                if i + 1 < len(args):
                    output_file = args[i + 1]
                    i += 1
            elif arg == "-X" or arg == "--request":
                if i + 1 < len(args):
                    method = args[i + 1].upper()
                    i += 1
            elif arg == "-d" or arg == "--data":
                if i + 1 < len(args):
                    post_data = args[i + 1]
                    method = "POST"
                    i += 1
            elif not arg.startswith("-"):
                url = arg
            
            i += 1
        
        if not url:
            return "curl: no URL specified!\ncurl: try 'curl --help' for more information"
        
        # Parse URL
        if "://" in url:
            protocol, rest = url.split("://", 1)
            if "/" in rest:
                domain = rest.split("/")[0]
                path = "/" + "/".join(rest.split("/")[1:])
            else:
                domain = rest
                path = "/"
        else:
            protocol = "http"
            domain = url.split("/")[0]
            path = "/" + "/".join(url.split("/")[1:]) if "/" in url else "/"
        
        # Generate response
        random.seed(hash(url))
        
        # Headers only
        if headers_only:
            status_codes = [200, 301, 302, 404, 500]
            status = random.choice([200, 200, 200, 301, 404])  # Mostly 200
            status_text = {200: "OK", 301: "Moved Permanently", 302: "Found", 404: "Not Found", 500: "Internal Server Error"}
            
            return f"""HTTP/1.1 {status} {status_text.get(status, 'OK')}
Server: nginx/1.18.0
Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}
Content-Type: text/html; charset=UTF-8
Content-Length: {random.randint(1000, 50000)}
Connection: keep-alive
Last-Modified: {(datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 30))).strftime('%a, %d %b %Y %H:%M:%S GMT')}
ETag: "{random.randint(100000, 999999)}-{random.randint(1000, 9999)}"
Accept-Ranges: bytes
"""
        
        # Generate content
        ext = path.split(".")[-1].lower() if "." in path else "html"
        
        if ext in ["html", "htm"] or path == "/":
            content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{domain}</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Welcome to {domain}</h1>
    <p>This is a simulated response from {url}</p>
    <p>Method: {method}</p>
    {f'<p>POST Data: {post_data}</p>' if post_data else ''}
</body>
</html>"""
        elif ext == "json":
            content = f'{{"status": "success", "url": "{url}", "method": "{method}", "timestamp": "{datetime.datetime.now().isoformat()}"}}'
        elif ext == "xml":
            content = f'<?xml version="1.0"?>\n<response>\n  <status>success</status>\n  <url>{url}</url>\n  <method>{method}</method>\n</response>'
        elif ext in ["txt", "log"]:
            content = f"Response from {url}\nMethod: {method}\nTimestamp: {datetime.datetime.now()}\n"
        else:
            content = f"Content from {url}"
        
        # Save to file if specified
        server = context.get("server") if context else None
        
        if output_file:
            if server and hasattr(server, "virtual_fs"):
                server.virtual_fs.write_file(output_file, content, server.current_directory)
            if not silent:
                file_size = len(content)
                return f"""  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  {file_size}  100  {file_size}    0     0  {random.randint(10000, 100000)}      0 --:--:-- --:--:-- --:--:-- {random.randint(10000, 100000)}"""
            return ""
        
        elif remote_name:
            filename = path.split("/")[-1] if path != "/" else "index.html"
            if server and hasattr(server, "virtual_fs"):
                server.virtual_fs.write_file(filename, content, server.current_directory)
            if not silent:
                return f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100  {len(content)}  100  {len(content)}    0     0  {random.randint(10000, 100000)}      0 --:--:-- --:--:-- --:--:-- {random.randint(10000, 100000)}"
            return ""
        
        # Return content to stdout
        return content


    def _cmd_tar(self, args: List[str]) -> str:
        """Simulate tar - archive utility with full flag support"""
        if not args or "--help" in args:
            return """Usage: tar [OPTION...] [FILE]...
GNU 'tar' saves many files together into a single tape or disk archive, and can
restore individual files from the archive.

Examples:
  tar -cf archive.tar foo bar  # Create archive.tar from files foo and bar.
  tar -tvf archive.tar         # List all files in archive.tar verbosely.
  tar -xf archive.tar          # Extract all files from archive.tar.

 Main operation mode:

  -A, --catenate, --concatenate   append tar files to an archive
  -c, --create               create a new archive
  -d, --diff, --compare      find differences between archive and file system
      --delete               delete from the archive
  -r, --append               append files to the end of an archive
  -t, --list                 list the contents of an archive
  -u, --update               only append files newer than copy in archive
  -x, --extract, --get       extract files from an archive

 Operation modifiers:

  -C, --directory=DIR        change to directory DIR
  -f, --file=ARCHIVE         use archive file or device ARCHIVE
  -j, --bzip2                filter the archive through bzip2
  -J, --xz                   filter the archive through xz
  -p, --preserve-permissions extract information about file permissions
  -v, --verbose              verbosely list files processed
  -z, --gzip                 filter the archive through gzip

Report bugs to <bug-tar@gnu.org>."""
        
        if "--version" in args:
            return """tar (GNU tar) 1.30
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by John Gilmore and Jay Fenlason."""
        
        # Parse flags
        verbose = "-v" in args or "--verbose" in args
        create = "-c" in args or "--create" in args
        extract = "-x" in args or "--extract" in args
        list_contents = "-t" in args or "--list" in args
        gzip_compress = "-z" in args or "--gzip" in args
        bzip2_compress = "-j" in args or "--bzip2" in args
        
        # Get archive filename
        archive_file = None
        for i, arg in enumerate(args):
            if arg == "-f" or arg == "--file":
                if i + 1 < len(args):
                    archive_file = args[i + 1]
                break
            elif arg.startswith("-") and "f" in arg and not arg.startswith("--"):
                # Combined flags like -czf
                if i + 1 < len(args):
                    archive_file = args[i + 1]
                break
        
        if not archive_file:
            # Try to find non-flag argument
            for arg in args:
                if not arg.startswith("-") and arg not in ["tar"]:
                    archive_file = arg
                    break
        
        if not archive_file:
            return "tar: Refusing to read archive contents from terminal (missing -f option?)\ntar: Error is not recoverable: exiting now"
        
        # CREATE archive
        if create:
            # Get files to archive (everything after archive name)
            files_to_archive = []
            found_archive = False
            for arg in args:
                if found_archive and not arg.startswith("-"):
                    files_to_archive.append(arg)
                elif arg == archive_file:
                    found_archive = True
            
            if not files_to_archive:
                files_to_archive = ["file1.txt", "file2.txt", "dir/"]
            
            if verbose:
                output = []
                for f in files_to_archive:
                    output.append(f)
                    # Add some subdirectories if it's a directory
                    if f.endswith("/"):
                        output.append(f"{f}subdir/")
                        output.append(f"{f}file.txt")
                return "\n".join(output)
            else:
                return ""  # Silent success
        
        # EXTRACT archive
        elif extract:
            # Generate dynamic file list based on archive name
            random.seed(hash(archive_file))
            
            num_files = random.randint(3, 10)
            files = []
            
            # Generate realistic filenames
            file_types = ["txt", "log", "conf", "sh", "py", "json", "xml"]
            dir_names = ["config", "data", "logs", "scripts", "docs", "src"]
            
            for i in range(num_files):
                if random.choice([True, False]):
                    # File
                    filename = f"file{i}.{random.choice(file_types)}"
                    files.append(filename)
                else:
                    # Directory with files
                    dirname = random.choice(dir_names)
                    files.append(f"{dirname}/")
                    files.append(f"{dirname}/file{i}.{random.choice(file_types)}")
            
            if verbose:
                output = []
                for f in files:
                    if f.endswith("/"):
                        output.append(f"x {f}")
                    else:
                        size = random.randint(100, 100000)
                        output.append(f"x {f} ({size} bytes)")
                return "\n".join(output)
            else:
                return "\n".join(files)
        
        # LIST contents
        elif list_contents:
            random.seed(hash(archive_file))
            
            num_files = random.randint(3, 10)
            files = []
            
            for i in range(num_files):
                if random.choice([True, False]):
                    filename = f"file{i}.txt"
                    files.append(filename)
                else:
                    dirname = f"directory{i}"
                    files.append(f"{dirname}/")
                    files.append(f"{dirname}/file.txt")
            
            if verbose:
                # Verbose listing with permissions, owner, size, date
                output = []
                for f in files:
                    if f.endswith("/"):
                        perms = "drwxr-xr-x"
                        size = 0
                    else:
                        perms = "-rw-r--r--"
                        size = random.randint(100, 100000)
                    
                    owner = random.choice(["root", "user", "admin"])
                    date = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 365))
                    date_str = date.strftime("%Y-%m-%d %H:%M")
                    
                    output.append(f"{perms} {owner}/{owner} {size:10} {date_str} {f}")
                
                return "\n".join(output)
            else:
                return "\n".join(files)
        
        else:
            return "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options\nTry 'tar --help' or 'tar --usage' for more information."
    
    def _cmd_gzip(self, cmd: str, args: List[str]) -> str:
        """Simulate gzip/gunzip - compression utilities"""
        if "--help" in args:
            if cmd == "gzip":
                return """Usage: gzip [OPTION]... [FILE]...
Compress or uncompress FILEs (by default, compress FILES in-place).

Mandatory arguments to long options are mandatory for short options too.

  -c, --stdout      write on standard output, keep original files unchanged
  -d, --decompress  decompress
  -f, --force       force overwrite of output file and compress links
  -k, --keep        keep (don't delete) input files
  -l, --list        list compressed file contents
  -r, --recursive   operate recursively on directories
  -t, --test        test compressed file integrity
  -v, --verbose     verbose mode
  -1, --fast        compress faster
  -9, --best        compress better

With no FILE, or when FILE is -, read standard input.

Report bugs to <bug-gzip@gnu.org>."""
            else:  # gunzip
                return """Usage: gunzip [OPTION]... [FILE]...
Uncompress FILEs (by default, in-place).

  -c, --stdout      write on standard output, keep original files unchanged
  -f, --force       force overwrite of output file
  -k, --keep        keep (don't delete) input files
  -l, --list        list compressed file contents
  -t, --test        test compressed file integrity
  -v, --verbose     verbose mode"""
        
        verbose = "-v" in args or "--verbose" in args
        list_mode = "-l" in args or "--list" in args
        decompress = "-d" in args or "--decompress" in args or cmd == "gunzip"
        
        # Get filename
        filename = None
        for arg in args:
            if not arg.startswith("-"):
                filename = arg
                break
        
        if not filename:
            filename = "file.txt.gz" if decompress else "file.txt"
        
        if list_mode:
            # List compressed file info
            random.seed(hash(filename))
            compressed_size = random.randint(1000, 1000000)
            uncompressed_size = random.randint(compressed_size * 2, compressed_size * 10)
            ratio = (1 - compressed_size / uncompressed_size) * 100
            
            return f"""         compressed        uncompressed  ratio uncompressed_name
         {compressed_size:10}          {uncompressed_size:10}  {ratio:5.1f}% {filename.replace('.gz', '')}"""
        
        if verbose:
            if decompress:
                return f"{filename}:\t{random.randint(50, 90)}.{random.randint(0, 9)}% -- replaced with {filename.replace('.gz', '')}"
            else:
                return f"{filename}:\t{random.randint(50, 90)}.{random.randint(0, 9)}% -- replaced with {filename}.gz"
        
        return ""  # Silent success
    
    def _cmd_zip(self, cmd: str, args: List[str]) -> str:
        """Simulate zip/unzip - package and compress files"""
        if cmd == "zip":
            if "--help" in args or "-h" in args:
                return """Copyright (c) 1990-2008 Info-ZIP - Type 'zip "-L"' for software license.
Zip 3.0 (July 5th 2008). Usage:
zip [-options] [-b path] [-t mmddyyyy] [-n suffixes] [zipfile list] [-xi list]
  The default action is to add or replace zipfile entries from list, which
  can include the special name - to compress standard input.
  If zipfile and list are omitted, zip compresses stdin to stdout.
  -f   freshen: only changed files  -u   update: only changed or new files
  -d   delete entries in zipfile    -m   move into zipfile (delete OS files)
  -r   recurse into directories     -j   junk (don't record) directory names
  -0   store only                   -l   convert LF to CR LF (-ll CR LF to LF)
  -1   compress faster              -9   compress better
  -q   quiet operation              -v   verbose operation/print version info
  -c   add one-line comments        -z   add zipfile comment
  -@   read names from stdin        -o   make zipfile as old as latest entry
  -x   exclude the following names  -i   include only the following names
  -F   fix zipfile (-FF try harder) -D   do not add directory entries
  -A   adjust self-extracting exe   -J   junk zipfile prefix (unzipsfx)
  -T   test zipfile integrity       -X   eXclude eXtra file attributes
  -y   store symbolic links as the link instead of the referenced file
  -e   encrypt                      -n   don't compress these suffixes
  -h2  show more help"""
            
            verbose = "-v" in args
            recursive = "-r" in args
            
            # Get archive and files
            archive_name = None
            files_to_zip = []
            
            for i, arg in enumerate(args):
                if not arg.startswith("-"):
                    if archive_name is None:
                        archive_name = arg
                    else:
                        files_to_zip.append(arg)
            
            if not archive_name:
                return "zip error: Nothing to do!"
            
            if not files_to_zip:
                files_to_zip = ["file1.txt", "file2.txt", "directory/"]
            
            output = []
            random.seed(hash(archive_name))
            
            for f in files_to_zip:
                if f.endswith("/") and recursive:
                    # Directory
                    output.append(f"  adding: {f} (stored 0%)")
                    # Add some files in directory
                    for i in range(random.randint(2, 5)):
                        subfile = f"{f}file{i}.txt"
                        compression = random.randint(30, 80)
                        output.append(f"  adding: {subfile} (deflated {compression}%)")
                else:
                    compression = random.randint(30, 80)
                    output.append(f"  adding: {f} (deflated {compression}%)")
            
            return "\n".join(output)
        
        else:  # unzip
            if "--help" in args or "-h" in args:
                return """UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.

Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]
  Default action is to extract files in list, except those in xlist, to exdir;
  file[.zip] may be a wildcard.  -Z => ZipInfo mode ("unzip -Z" for usage).

  -p  extract files to pipe, no messages     -l  list files (short format)
  -f  freshen existing files, create none    -t  test compressed archive data
  -u  update files, create if necessary      -z  display archive comment only
  -v  list verbosely/show version info       -T  timestamp archive to latest
  -x  exclude files that follow (in xlist)   -d  extract files into exdir
modifiers:
  -n  never overwrite existing files         -q  quiet mode (-qq => quieter)
  -o  overwrite files WITHOUT prompting      -a  auto-convert any text files
  -j  junk paths (do not make directories)   -aa treat ALL files as text
  -C  match filenames case-insensitively     -L  make (some) names lowercase
  -X  restore UID/GID info                   -V  retain VMS version numbers
  -K  keep setuid/setgid/tacky permissions   -M  pipe through "more" pager"""
            
            verbose = "-v" in args
            list_mode = "-l" in args
            
            # Get archive name
            archive_name = None
            for arg in args:
                if not arg.startswith("-"):
                    archive_name = arg
                    break
            
            if not archive_name:
                archive_name = "archive.zip"
            
            random.seed(hash(archive_name))
            
            if list_mode:
                # List contents
                num_files = random.randint(3, 10)
                total_size = 0
                
                output = [f"Archive:  {archive_name}"]
                output.append("  Length      Date    Time    Name")
                output.append("---------  ---------- -----   ----")
                
                for i in range(num_files):
                    size = random.randint(100, 100000)
                    total_size += size
                    date = (datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 365))).strftime("%m-%d-%Y %H:%M")
                    filename = f"file{i}.txt"
                    output.append(f"{size:9}  {date}   {filename}")
                
                output.append("---------                     -------")
                output.append(f"{total_size:9}                     {num_files} files")
                
                return "\n".join(output)
            
            else:
                # Extract files
                num_files = random.randint(3, 10)
                output = [f"Archive:  {archive_name}"]
                
                for i in range(random.randint(3, 8)):
                    filename = f"file{i}.txt"
                    if verbose:
                        size = random.randint(100, 100000)
                        output.append(f"  inflating: {filename}  ({size} bytes)")
                    else:
                        output.append(f"  inflating: {filename}")
                
                return "\n".join(output)
    
    def _cmd_man(self, args: List[str]) -> str:
        """Show man page"""
        cmd = args[0] if args else None
        if not cmd:
            return "What manual page do you want?"
        
        man_pages = {
            "ls": """LS(1)                    User Commands                   LS(1)
    NAME
        ls - list directory contents
    SYNOPSIS
        ls [OPTION]... [FILE]...
    DESCRIPTION
        List information about the FILEs (the current directory by default).
        Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.
    OPTIONS
        -a, --all
                do not ignore entries starting with .
        -l     use a long listing format
        -h, --human-readable
                with -l, print sizes in human readable format""",
            
            "cat": """CAT(1)                   User Commands                   CAT(1)
    NAME
        cat - concatenate files and print on the standard output
    SYNOPSIS
        cat [OPTION]... [FILE]...
    DESCRIPTION
        Concatenate FILE(s) to standard output.""",
        }
        
        return man_pages.get(cmd, f"No manual entry for {cmd}")

    
    def _cmd_crontab(self, args: List[str], username: str) -> str:
        """
        Simulate crontab - maintain crontab files for individual users.
        
        Supports:
        - -l: list user's crontab
        - -e: edit user's crontab
        - -r: remove user's crontab
        - -i: prompt before removing
        - -u user: specify user
        - -s: selinux context
        """
        # Help flag
        if "--help" in args or "-h" in args:
            return """crontab: invalid option -- 'h'
crontab: usage error: unrecognized option
Usage:
 crontab [options] file
 crontab [options]
 crontab -n [hostname]

Options:
 -u <user>  define user
 -e         edit user's crontab
 -l         list user's crontab
 -r         delete user's crontab
 -i         prompt before deleting
 -s         selinux context

Default operation is replace, per 1003.2"""
        
        # Parse flags
        list_crontab = "-l" in args or "--list" in args
        edit_crontab = "-e" in args or "--edit" in args
        remove_crontab = "-r" in args or "--remove" in args
        interactive = "-i" in args
        
        # Check for -u flag (specify different user)
        target_user = username
        if "-u" in args:
            try:
                u_index = args.index("-u")
                if u_index + 1 < len(args):
                    target_user = args[u_index + 1]
                    # Check permissions - only root can edit other users' crontabs
                    if username != "root" and target_user != username:
                        return f"crontab: can't open '{target_user}' crontab file: Permission denied"
            except (ValueError, IndexError):
                return "crontab: usage error: -u requires an argument"
        
        # Generate dynamic crontab based on username
        random.seed(hash(target_user))
        
        # LIST crontab
        if list_crontab:
            # Determine if user has a crontab
            has_crontab = random.choice([True, False, False])  # 33% chance
            
            if not has_crontab:
                return f"no crontab for {target_user}"
            
            # Generate realistic crontab entries
            entries = []
            
            # Add header comments
            entries.append("# Edit this file to introduce tasks to be run by cron.")
            entries.append("#")
            entries.append("# m h  dom mon dow   command")
            entries.append("")
            
            # Common crontab patterns
            cron_jobs = [
                ("0 2 * * *", "/usr/bin/backup.sh"),
                ("*/5 * * * *", "/usr/local/bin/check_status.sh"),
                ("0 0 * * 0", "/usr/bin/weekly_cleanup.sh"),
                ("30 3 * * 1", "/home/{user}/scripts/weekly_report.sh"),
                ("0 */6 * * *", "/usr/bin/update_cache.sh"),
                ("15 14 1 * *", "/usr/local/bin/monthly_task.sh"),
                ("@reboot", "/home/{user}/startup.sh"),
                ("@daily", "/usr/bin/daily_maintenance.sh"),
                ("@hourly", "/usr/local/bin/hourly_check.sh"),
                ("*/10 * * * *", "cd /var/www && /usr/bin/php artisan schedule:run"),
                ("0 1 * * *", "/usr/bin/certbot renew --quiet"),
                ("*/15 * * * *", "/usr/bin/python3 /home/{user}/monitor.py"),
            ]
            
            # Select 2-5 random jobs
            num_jobs = random.randint(2, 5)
            selected_jobs = random.sample(cron_jobs, min(num_jobs, len(cron_jobs)))
            
            for schedule, command in selected_jobs:
                # Replace {user} placeholder
                command = command.replace("{user}", target_user)
                entries.append(f"{schedule} {command}")
            
            # Add environment variables sometimes
            if random.choice([True, False]):
                entries.insert(4, f"MAILTO={target_user}@localhost")
                entries.insert(5, "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
                entries.insert(6, "")
            
            return "\n".join(entries)
        
        # EDIT crontab
        elif edit_crontab:
            # Simulate editor opening
            return """# Opening crontab in editor (simulated)
# 
# In a real system, this would open your default editor (usually vi/nano)
# with the current crontab file.
#
# Example crontab entries:
# 
# m h  dom mon dow   command
# 0 2 * * *           /usr/bin/backup.sh
# */5 * * * *         /usr/local/bin/check.sh
# @daily              /usr/bin/cleanup.sh
#
# Use 'crontab -l' to list current entries
# Use 'crontab -r' to remove all entries"""
        
        # REMOVE crontab
        elif remove_crontab:
            # Check if user has a crontab
            random.seed(hash(target_user))
            has_crontab = random.choice([True, False, False])
            
            if not has_crontab:
                return f"no crontab for {target_user}"
            
            # Interactive mode - prompt before removing
            if interactive:
                return f"crontab: really delete {target_user}'s crontab? (y/n) "
            
            # Remove crontab (simulated)
            return ""  # Silent success
        
        # No flags - expects a file argument to replace crontab
        else:
            if not args:
                return """crontab: usage error: file name must be specified for replace
Usage:
 crontab [options] file
 crontab [options]
 crontab -n [hostname]

Options:
 -u <user>  define user
 -e         edit user's crontab
 -l         list user's crontab
 -r         delete user's crontab
 -i         prompt before deleting
 -s         selinux context"""
            
            # File specified - simulate replacing crontab
            filename = args[0] if not args[0].startswith("-") else None
            
            if filename:
                # Check if file exists (in virtual filesystem)
                # For now, just simulate success
                return ""  # Silent success
            else:
                return "crontab: usage error: file name must be specified for replace"


    def _cmd_echo(self, args: List[str], context: Optional[Dict[str, Any]]) -> str:
        """
        Echo command with full feature support.
        
        Supports:
        - -n: no trailing newline
        - -e: enable interpretation of backslash escapes
        - -E: disable interpretation of backslash escapes (default)
        - Variable expansion ($VAR, ${VAR})
        - Command substitution $(command)
        - Escape sequences (\n, \t, \r, etc.)
        """
        if not args:
            return ""
        
        # Check for --help
        if "--help" in args:
            return """Usage: echo [SHORT-OPTION]... [STRING]...
  or:  echo LONG-OPTION
Echo the STRING(s) to standard output.

  -n             do not output the trailing newline
  -e             enable interpretation of backslash escapes
  -E             disable interpretation of backslash escapes (default)
      --help     display this help and exit
      --version  output version information and exit

If -e is in effect, the following sequences are recognized:

  \\\\      backslash
  \\a      alert (BEL)
  \\b      backspace
  \\c      produce no further output
  \\e      escape
  \\f      form feed
  \\n      new line
  \\r      carriage return
  \\t      horizontal tab
  \\v      vertical tab
  \\0NNN   byte with octal value NNN (1 to 3 digits)
  \\xHH    byte with hexadecimal value HH (1 to 2 digits)

NOTE: your shell may have its own version of echo, which usually supersedes
the version described here.  Please refer to your shell's documentation
for details about the options it supports.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Report echo translation bugs to <https://translationproject.org/team/>
Full documentation at: <https://www.gnu.org/software/coreutils/echo>
or available locally via: info '(coreutils) echo invocation'"""
        
        # Check for --version
        if "--version" in args:
            return """echo (GNU coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Brian Fox and Chet Ramey."""
        
        # Parse flags
        no_newline = False
        interpret_escapes = False
        text_args = []
        
        for arg in args:
            if arg == "-n":
                no_newline = True
            elif arg == "-e":
                interpret_escapes = True
            elif arg == "-E":
                interpret_escapes = False
            elif arg.startswith("-") and len(arg) > 1 and all(c in "neE" for c in arg[1:]):
                # Combined flags like -ne
                if 'n' in arg:
                    no_newline = True
                if 'e' in arg:
                    interpret_escapes = True
                if 'E' in arg:
                    interpret_escapes = False
            else:
                text_args.append(arg)
        
        # Join the text
        text = " ".join(text_args)
        
        # Expand variables
        text = self._expand_variables(text, context)
        
        # Expand command substitution
        text = self._expand_command_substitution(text, context)
        
        # Interpret escape sequences if -e flag is set
        if interpret_escapes:
            text = self._interpret_escape_sequences(text)
        
        # Add newline unless -n flag is set
        if not no_newline:
            text += "\n"
        
        return text
    
    def _expand_variables(self, text: str, context: Optional[Dict[str, Any]]) -> str:
        """
        Expand shell variables in text.
        Supports: $VAR, ${VAR}, $1, $2, etc.
        """
        import re
        
        server = context.get("server") if context else None
        
        # Common environment variables
        env_vars = {
            "USER": context.get("username", "guest") if context else "guest",
            "HOME": f"/home/{context.get('username', 'guest')}" if context else "/home/guest",
            "PWD": server.current_directory if server and hasattr(server, "current_directory") else "/home/guest",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "HOSTNAME": "localhost",
            "OLDPWD": "/home/guest",
            "LOGNAME": context.get("username", "guest") if context else "guest",
        }
        
        # Add server environment if available
        if server and hasattr(server, "environment"):
            env_vars.update(server.environment)
        
        # Expand ${VAR} format
        def replace_braced_var(match):
            var_name = match.group(1)
            return env_vars.get(var_name, "")
        
        text = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', replace_braced_var, text)
        
        # Expand $VAR format (but not $( for command substitution)
        def replace_simple_var(match):
            var_name = match.group(1)
            return env_vars.get(var_name, "")
        
        text = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', replace_simple_var, text)
        
        # Expand special variables
        text = text.replace("$?", "0")  # Last exit status
        text = text.replace("$$", str(random.randint(1000, 30000)))  # Current PID
        text = text.replace("$!", str(random.randint(1000, 30000)))  # Last background PID
        
        return text
    
    def _expand_command_substitution(self, text: str, context: Optional[Dict[str, Any]]) -> str:
        """
        Expand command substitution: $(command) or [command](cci:1://file:///c:/Users/Dayab/Documents/GitHub/nexus-development/src/service_emulators/SSH/command_executor.py:559:4-680:20)
        """
        import re
        
        # Expand $(command) format
        def replace_dollar_paren(match):
            command = match.group(1)
            try:
                result = self.execute(command, 
                                     context.get("current_dir", "/home/guest") if context else "/home/guest",
                                     context.get("username", "guest") if context else "guest",
                                     context)
                return result.rstrip('\n') if result else ""
            except:
                return ""
        
        text = re.sub(r'\$\(([^)]+)\)', replace_dollar_paren, text)
        
        # Expand [command](cci:1://file:///c:/Users/Dayab/Documents/GitHub/nexus-development/src/service_emulators/SSH/command_executor.py:559:4-680:20) format (backticks)
        def replace_backticks(match):
            command = match.group(1)
            try:
                result = self.execute(command,
                                     context.get("current_dir", "/home/guest") if context else "/home/guest",
                                     context.get("username", "guest") if context else "guest",
                                     context)
                return result.rstrip('\n') if result else ""
            except:
                return ""
        
        text = re.sub(r'`([^`]+)`', replace_backticks, text)        
        
        return text
    
    def _interpret_escape_sequences(self, text: str) -> str:
        replacements = {
            '\\\\': '\\',      # Backslash
            '\\a': '\a',       # Alert (bell)
            '\\b': '\b',       # Backspace
            '\\e': '\x1b',     # Escape
            '\\f': '\f',       # Form feed
            '\\n': '\n',       # Newline
            '\\r': '\r',       # Carriage return
            '\\t': '\t',       # Horizontal tab
            '\\v': '\v',       # Vertical tab
        }
        
        for escape, replacement in replacements.items():
            text = text.replace(escape, replacement)
        
        # Handle \c (stop processing)
        if '\\c' in text:
            text = text.split('\\c')[0]
        
        # Handle octal sequences \0NNN
        import re
        def replace_octal(match):
            octal_value = match.group(1)
            try:
                return chr(int(octal_value, 8))
            except:
                return match.group(0)
        
        text = re.sub(r'\\0([0-7]{1,3})', replace_octal, text)
        
        # Handle hex sequences \xHH
        def replace_hex(match):
            hex_value = match.group(1)
            try:
                return chr(int(hex_value, 16))
            except:
                return match.group(0)
        
        text = re.sub(r'\\x([0-9a-fA-F]{1,2})', replace_hex, text)
        
        return text
        
        for escape, replacement in replacements.items():
            text = text.replace(escape, replacement)
        
        # Handle \c (stop processing)
        if '\\c' in text:
            text = text.split('\\c')[0]
        
        # Handle octal sequences \0NNN
        import re
        def replace_octal(match):
            octal_value = match.group(1)
            try:
                return chr(int(octal_value, 8))
            except:
                return match.group(0)
        
        text = re.sub(r'\\0([0-7]{1,3})', replace_octal, text)
        
        # Handle hex sequences \xHH
        def replace_hex(match):
            hex_value = match.group(1)
            try:
                return chr(int(hex_value, 16))
            except:
                return match.group(0)
        
        text = re.sub(r'\\x([0-9a-fA-F]{1,2})', replace_hex, text)
        
        return text