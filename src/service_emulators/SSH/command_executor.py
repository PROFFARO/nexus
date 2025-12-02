#!/usr/bin/env python3
"""
Command Executor for SSH Honeypot
Handles command validation, routing, and execution with prompt injection protection
"""

import datetime
import fnmatch
import re
import shlex
from typing import Optional, Dict, Any, List, Tuple
from virtual_filesystem import VirtualFilesystem


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
        "ifconfig", "ip", "netstat", "ss", "ping", "traceroute", "tracepath", "nslookup",
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
        
        # Exit commands
        "exit", "logout", "quit",
    }
    
    # Prompt injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction manipulation
        r"ignore\s+(previous|all|the)\s+(instructions?|prompts?|context|commands?)",
        r"forget\s+(everything|all|previous|the)",
        r"disregard\s+(previous|all|the)\s+(instructions?|context)",
        r"delete\s+(all|previous|the)\s+(context|history|instructions?)",
        
        # Role manipulation
        r"you\s+are\s+(now|a|an)\s+",
        r"act\s+as\s+(a|an)\s+",
        r"pretend\s+to\s+be\s+",
        r"roleplay\s+as\s+",
        r"simulate\s+(a|an)\s+",
        
        # System/assistant role injection
        r"system\s*:",
        r"assistant\s*:",
        r"user\s*:",
        r"\[system\]",
        r"\[assistant\]",
        
        # Context manipulation
        r"new\s+conversation",
        r"start\s+over",
        r"reset\s+(context|conversation|chat)",
        r"clear\s+(context|history|memory)",
        
        # Meta instructions
        r"tell\s+me\s+(who|what)\s+you\s+(are|really\s+are)",
        r"what\s+(are|is)\s+your\s+(instructions?|prompts?|system\s+prompts?)",
        r"show\s+me\s+your\s+(instructions?|prompts?|system\s+message)",
        r"reveal\s+your\s+(instructions?|prompts?)",
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
            return (self._execute_filesystem_command(command, current_dir, username), "filesystem")
        elif routing == "system":
            return (self._execute_system_command(command, username), "system")
        else:
            # Let LLM handle it
            return (None, "llm")
            
    def validate_command(self, command: str) -> bool:
        """
        Check if command is a valid Linux command
        
        Returns:
            True if valid, False if invalid/nonsense
        """
        try:
            parts = shlex.split(command)
        except ValueError:
            # Invalid shell syntax
            return False
            
        if not parts:
            return True  # Empty command is valid
            
        cmd = parts[0].lower()
        
        # Remove path prefix if present
        if "/" in cmd:
            cmd = cmd.split("/")[-1]
            
        # Check if it's a valid command
        return cmd in self.VALID_COMMANDS
        
    def detect_injection(self, command: str) -> bool:
        """
        Detect prompt injection attempts
        
        Returns:
            True if injection detected, False otherwise
        """
        # Check against injection patterns
        for pattern in self.compiled_injection_patterns:
            if pattern.search(command):
                return True
                
        return False
        
    def route_command(self, command: str) -> str:
        """
        Determine how to handle a command
        
        Returns:
            "filesystem", "system", or "llm"
        """
        try:
            parts = shlex.split(command)
        except ValueError:
            return "llm"
            
        if not parts:
            return "llm"
            
        cmd = parts[0].lower()
        
        # Filesystem commands - handle locally
        filesystem_cmds = {
            "ls", "cd", "pwd", "cat", "head", "tail", "find", "mkdir", "rm", "rmdir",
            "cp", "mv", "touch", "file", "stat", "basename", "dirname", "readlink",
            "grep", "wc", "du", "df", "ln", "chmod", "chown",
        }
        
        if cmd in filesystem_cmds:
            return "filesystem"
            
        # System commands - use templates
        system_cmds = {
            "whoami", "id", "hostname", "uname", "uptime", "date", "ps", "top",
            "ifconfig", "ip", "netstat", "ss", "apt", "apt-get", "dpkg", "systemctl",
            "service", "journalctl", "w", "who", "last", "users", "groups", "free",
            "env", "printenv",
        }
        
        if cmd in system_cmds:
            return "system"
            
        # Everything else goes to LLM (complex commands, pipes, etc.)
        return "llm"
        
    def _get_injection_response(self, command: str) -> str:
        """Return response for detected injection attempt"""
        try:
            parts = shlex.split(command)
            cmd = parts[0] if parts else command.split()[0]
        except:
            cmd = command.split()[0] if command.split() else "command"
            
        return f"bash: {cmd}: command not found"
        
    def _get_command_not_found(self, command: str) -> str:
        """Return command not found error"""
        try:
            parts = shlex.split(command)
            cmd = parts[0] if parts else command.split()[0]
        except:
            cmd = command.split()[0] if command.split() else "command"
            
        return f"bash: {cmd}: command not found"
        
    def _execute_filesystem_command(self, command: str, current_dir: str, username: str) -> str:
        """Execute filesystem commands using virtual filesystem"""
        try:
            parts = shlex.split(command)
        except ValueError:
            return "bash: syntax error"
            
        if not parts:
            return ""
            
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # ls command
        if cmd == "ls":
            return self._cmd_ls(args, current_dir)
            
        # pwd command
        elif cmd == "pwd":
            return current_dir
            
        # cat command
        elif cmd == "cat":
            return self._cmd_cat(args, current_dir)
            
        # head command
        elif cmd == "head":
            return self._cmd_head(args, current_dir)
            
        # tail command
        elif cmd == "tail":
            return self._cmd_tail(args, current_dir)
            
        # find command
        elif cmd == "find":
            return self._cmd_find(args, current_dir)
            
        # file command
        elif cmd == "file":
            return self._cmd_file(args, current_dir)
            
        # stat command
        elif cmd == "stat":
            return self._cmd_stat(args, current_dir)
            
        # mkdir command
        elif cmd == "mkdir":
            return self._cmd_mkdir(args, current_dir)
            
        # touch command
        elif cmd == "touch":
            return self._cmd_touch(args, current_dir)
            
        # rm command
        elif cmd == "rm":
            return self._cmd_rm(args, current_dir)
        
        # grep command
        elif cmd == "grep":
            return self._cmd_grep(args, current_dir)
        
        # wc command
        elif cmd == "wc":
            return self._cmd_wc(args, current_dir)
        
        # du command
        elif cmd == "du":
            return self._cmd_du(args, current_dir)
        
        # df command
        elif cmd == "df":
            return self._cmd_df(args, current_dir)
        
        # ln command
        elif cmd == "ln":
            return self._cmd_ln(args, current_dir)
        
        # chmod command
        elif cmd == "chmod":
            return self._cmd_chmod(args, current_dir)
        
        # chown command
        elif cmd == "chown":
            return self._cmd_chown(args, current_dir)
            
        # Default fallback
        return None
        
    def _cmd_ls(self, args: List[str], current_dir: str) -> str:
        """Execute ls command with wildcard support"""
        # Parse flags
        long_format = "-l" in args
        show_all = "-a" in args or "-la" in args or "-al" in args
        
        # Get target paths (can be multiple)
        targets = []
        for arg in args:
            if not arg.startswith("-"):
                targets.append(arg)
        
        # If no targets specified, use current directory
        if not targets:
            targets = [current_dir]
        
        all_results = []
        
        for target in targets:
            # Handle wildcards
            if "*" in target or "?" in target:
                # Expand wildcard
                expanded = self._expand_wildcard(target, current_dir)
                if not expanded:
                    all_results.append(f"ls: cannot access '{target}': No such file or directory")
                    continue
                
                # Process each expanded path
                for expanded_path in expanded:
                    result = self._ls_single_target(expanded_path, long_format, show_all, current_dir)
                    if result:
                        all_results.append(result)
            else:
                result = self._ls_single_target(target, long_format, show_all, current_dir)
                if result:
                    all_results.append(result)
        
        return "\n".join(all_results)
    
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
        """Execute cat command"""
        if not args:
            return "cat: missing file operand"
            
        results = []
        for arg in args:
            if arg.startswith("-"):
                continue
                
            content = self.fs.read_file(arg, current_dir)
            if content is None:
                if self.fs.is_directory(arg, current_dir):
                    results.append(f"cat: {arg}: Is a directory")
                elif not self.fs.exists(arg, current_dir):
                    results.append(f"cat: {arg}: No such file or directory")
                else:
                    results.append(f"cat: {arg}: Permission denied")
            else:
                results.append(content)
                
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
        """Execute stat command"""
        if not args:
            return "stat: missing file operand"
            
        target = args[0]
        info = self.fs.get_file_info(target, current_dir)
        
        if not info:
            return f"stat: cannot stat '{target}': No such file or directory"
            
        file_type = "directory" if info["is_dir"] else "regular file"
        size = info["size"]
        perms = info["permissions"]
        
        return f"""  File: {info['name']}
  Size: {size}\t\tBlocks: {(size // 512) + 1}\tIO Block: 4096   {file_type}
Device: 801h/2049d\tInode: 123456\tLinks: 1
Access: ({perms}/{self._format_permissions(perms, info['is_dir'])})  Uid: ( 1000/{info['owner']:8})   Gid: ( 1000/{info['group']:8})
Access: {info['modified'].strftime('%Y-%m-%d %H:%M:%S.000000000 %z')}
Modify: {info['modified'].strftime('%Y-%m-%d %H:%M:%S.000000000 %z')}
Change: {info['modified'].strftime('%Y-%m-%d %H:%M:%S.000000000 %z')}
 Birth: -"""
 
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
        """Execute rm command"""
        if not args:
            return "rm: missing operand"
            
        for arg in args:
            if arg.startswith("-"):
                continue
                
            if not self.fs.delete(arg, current_dir):
                if not self.fs.exists(arg, current_dir):
                    return f"rm: cannot remove '{arg}': No such file or directory"
                elif self.fs.is_directory(arg, current_dir):
                    return f"rm: cannot remove '{arg}': Is a directory"
                else:
                    return f"rm: cannot remove '{arg}': Permission denied"
                    
        return ""
    
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
        """Execute chmod command"""
        if len(args) < 2:
            return "chmod: missing operand"
        
        # Simplified - just acknowledge the command
        return ""
    
    def _cmd_chown(self, args: List[str], current_dir: str) -> str:
        """Execute chown command"""
        if len(args) < 2:
            return "chown: missing operand"
        
        # Simplified - just acknowledge the command
        return ""
        
    def _execute_system_command(self, command: str, username: str) -> str:
        """Execute system commands using templates"""
        try:
            parts = shlex.split(command)
        except ValueError:
            return "bash: syntax error"
            
        if not parts:
            return ""
            
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # whoami
        if cmd == "whoami":
            return username
            
        # id
        elif cmd == "id":
            uid = 1001 if username != "root" else 0
            gid = 1001 if username != "root" else 0
            return f"uid={uid}({username}) gid={gid}({username}) groups={gid}({username}),27(sudo),999(docker)"
            
        # hostname
        elif cmd == "hostname":
            return "corp-srv-01"
            
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
                
        # uptime
        elif cmd == "uptime":
            return " 14:23:45 up 23 days,  4:12,  3 users,  load average: 0.52, 0.58, 0.59"
            
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
        elif cmd == "env":
            return self._cmd_env(username)
        
        # history command
        elif cmd == "history":
            # This should be handled by server context
            return None
            
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
        """Generate who command output"""
        return f"""{username:<8} pts/0        2024-12-02 14:20 (192.168.1.100)
alex.chen pts/1        2024-12-02 10:15 (10.0.0.50)
jenkins   pts/2        2024-12-02 09:00 (10.0.0.2)"""
    
    def _cmd_last(self) -> str:
        """Generate last command output"""
        return """alex.chen pts/0        192.168.1.100    Mon Dec  2 14:20   still logged in
jenkins   pts/2        10.0.0.2         Mon Dec  2 09:00   still logged in
alex.chen pts/1        10.0.0.50        Mon Dec  2 10:15   still logged in
sarah.martinez pts/0   192.168.1.105    Sun Dec  1 16:45 - 18:30  (01:45)
mike.thompson pts/1    10.0.0.55        Sun Dec  1 14:00 - 17:20  (03:20)

wtmp begins Sun Dec  1 09:00:00 2024"""
    
    def _cmd_free(self, args: List[str]) -> str:
        """Generate free command output"""
        if "-h" in args or "--human" in args:
            return """              total        used        free      shared  buff/cache   available
Mem:           15Gi       8.2Gi       2.1Gi       256Mi       5.3Gi       6.8Gi
Swap:         4.0Gi       512Mi       3.5Gi"""
        else:
            return """              total        used        free      shared  buff/cache   available
Mem:       16384000     8601600     2201600      262144     5580800     7168000
Swap:       4194304      524288     3670016"""
    
    def _cmd_env(self, username: str) -> str:
        """Generate env command output"""
        return f"""USER={username}
HOME=/home/{username}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SHELL=/bin/bash
LANG=en_US.UTF-8
PWD=/home/{username}
TERM=xterm-256color
SSH_CONNECTION=192.168.1.100 52341 10.0.0.1 22
SSH_CLIENT=192.168.1.100 52341 22
SSH_TTY=/dev/pts/0
LOGNAME={username}
MAIL=/var/mail/{username}
OLDPWD=/home/{username}
EDITOR=vim
VISUAL=vim"""
