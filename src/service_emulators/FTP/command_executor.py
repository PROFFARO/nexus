#!/usr/bin/env python3
"""
FTP Command Executor for FTP Honeypot
Implements 3-layer command dispatch: VFS execution, error simulation, and LLM fallback
Handles command validation, routing, and execution with prompt injection protection
"""

import datetime
import random
import logging
import re
import shlex
from typing import Optional, Dict, Any, List, Tuple
from virtual_filesystem import VirtualFilesystem

logger = logging.getLogger(__name__)


class FTPCommandExecutor:
    """
    Executes FTP commands with 3-layer dispatch pattern:
    - Layer 1: Deterministic VFS execution for standard FTP commands
    - Layer 2: Validation and error simulation for invalid commands
    - Layer 3: LLM fallback for complex/unknown commands
    """
    
    # RFC 959 Standard FTP Commands + Common Extensions
    VALID_FTP_COMMANDS = {
        # Access control commands
        "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
        
        # Transfer parameter commands
        "PORT", "PASV", "TYPE", "STRU", "MODE",
        
        # FTP service commands
        "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR", "RNTO",
        "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST",
        "STAT", "HELP", "NOOP",
        
        # RFC 2228 Security Extensions
        "AUTH", "ADAT", "PROT", "PBSZ", "CCC", "MIC", "CONF", "ENC",
        
        # RFC 2389 Feature negotiation
        "FEAT", "OPTS",
        
        # RFC 2428 Extended passive/active mode
        "EPRT", "EPSV",
        
        # RFC 3659 Extensions for MLST and MLSD
        "MDTM", "SIZE", "MLST", "MLSD",
        
        # RFC 2640 Internationalization
        "LANG",
        
        # Common extensions
        "XCWD", "XMKD", "XPWD", "XRMD", "XCUP",
        
        # Aliases (handled by mapping)
        "CD", "LS", "DIR", "GET", "PUT", "DELETE", "MKDIR", "RMDIR",
    }
    
    # Command aliases mapping
    COMMAND_ALIASES = {
        "CD": "CWD",
        "LS": "LIST",
        "DIR": "LIST",
        "GET": "RETR",
        "PUT": "STOR",
        "DELETE": "DELE",
        "MKDIR": "MKD",
        "RMDIR": "RMD",
    }
    
    # Commands that require authentication
    AUTH_REQUIRED_COMMANDS = {
        "CWD", "CDUP", "PWD", "LIST", "NLST", "RETR", "STOR", "STOU", "APPE",
        "DELE", "RMD", "MKD", "RNFR", "RNTO", "SIZE", "MDTM", "MLST", "MLSD",
        "STAT", "REST", "SITE",
    }
    
    # FTP response codes
    FTP_CODES = {
        # 1xx: Positive Preliminary
        150: "File status okay; about to open data connection",
        
        # 2xx: Positive Completion
        200: "Command okay",
        211: "System status, or system help reply",
        212: "Directory status",
        213: "File status",
        214: "Help message",
        215: "NAME system type",
        220: "Service ready for new user",
        221: "Service closing control connection",
        225: "Data connection open; no transfer in progress",
        226: "Closing data connection. Requested file action successful",
        227: "Entering Passive Mode",
        229: "Entering Extended Passive Mode",
        230: "User logged in, proceed",
        250: "Requested file action okay, completed",
        257: "PATHNAME created",
        
        # 3xx: Positive Intermediate
        331: "User name okay, need password",
        332: "Need account for login",
        350: "Requested file action pending further information",
        
        # 4xx: Transient Negative Completion
        421: "Service not available, closing control connection",
        425: "Can't open data connection",
        426: "Connection closed; transfer aborted",
        450: "Requested file action not taken. File unavailable",
        451: "Requested action aborted: local error in processing",
        452: "Requested action not taken. Insufficient storage space",
        
        # 5xx: Permanent Negative Completion
        500: "Syntax error, command unrecognized",
        501: "Syntax error in parameters or arguments",
        502: "Command not implemented",
        503: "Bad sequence of commands",
        504: "Command not implemented for that parameter",
        530: "Not logged in",
        532: "Need account for storing files",
        550: "Requested action not taken. File unavailable",
        551: "Requested action aborted: page type unknown",
        552: "Requested file action aborted. Exceeded storage allocation",
        553: "Requested action not taken. File name not allowed",
    }
    
    # Prompt injection patterns (adapted from SSH)
    INJECTION_PATTERNS = [
        # Direct instruction manipulation
        r"\bignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|context|commands?|directives?)\b",
        r"\bforget\s+(everything|all\s+previous|the\s+previous|what\s+you\s+were\s+told)\b",
        r"\bdisregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|context|prompts?)\b",
        r"\bdelete\s+(all\s+)?(previous|prior)\s+(context|history|instructions?|memory)\b",
        r"\boverride\s+(previous|all|system)\s+(instructions?|prompts?|settings?)\b",
        
        # Role manipulation
        r"(?:^|[.!?]\s+)you\s+are\s+(now|actually|really)\s+(a|an)\s+(?!user|admin|root|guest)\w+",
        r"(?:^|[.!?]\s+)act\s+as\s+(?:a|an)\s+(?!user|admin|system\s+administrator)\w+",
        r"(?:^|[.!?]\s+)pretend\s+(?:to\s+be|you\s+are)\s+(?:a|an)\s+\w+",
        r"(?:^|[.!?]\s+)roleplay\s+as\s+(?:a|an)\s+\w+",
        r"(?:^|[.!?]\s+)simulate\s+(?:being\s+)?(?:a|an)\s+(?!server|system|process)\w+",
        
        # System/assistant role injection
        r"^\s*system\s*:\s*",
        r"^\s*assistant\s*:\s*",
        r"^\s*user\s*:\s*(?!@)",
        r"^\s*\[system\]\s*",
        r"^\s*\[assistant\]\s*",
        r"^\s*<\|system\|>\s*",
        r"^\s*<\|assistant\|>\s*",
        
        # Context manipulation
        r"\bnew\s+conversation\s+(?:starting|begins?|now)\b",
        r"\breset\s+(?:the\s+)?(context|conversation|chat|session)\b",
        r"\bclear\s+(?:the\s+)?(context|history|memory|conversation)\b",
        
        # Meta instructions
        r"\btell\s+me\s+(?:who|what)\s+you\s+(?:are|really\s+are|actually\s+are)\b",
        r"\bwhat\s+(?:are|is)\s+your\s+(?:actual\s+)?(instructions?|prompts?|system\s+prompts?|directives?)\b",
        r"\bshow\s+(?:me\s+)?your\s+(?:actual\s+)?(instructions?|prompts?|system\s+(?:message|prompt))\b",
        r"\breveal\s+(?:your\s+)?(instructions?|prompts?|system\s+message)\b",
        
        # Jailbreak attempts
        r"\bDAN\s+mode\b",
        r"\bDeveloper\s+Mode\b",
        r"\bjailbreak\s+(?:mode|prompt)\b",
        r"\bunrestricted\s+(?:mode|access)\b",
        r"\bbypass\s+(?:restrictions?|filters?|safety)\b",
        
        # AI identity probing
        r"\bare\s+you\s+(?:a|an)\s+(?:AI|artificial|language\s+model|chatbot|bot)\b",
        r"\bwho\s+(?:created|made|built)\s+you\b",
        r"\bwhat\s+model\s+are\s+you\b",
    ]
    
    def __init__(self, filesystem: VirtualFilesystem):
        self.fs = filesystem
        self.compiled_injection_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]
        
        # State for multi-command operations
        self.rename_from_path = None  # For RNFR/RNTO sequence
        
    def execute(
        self,
        command: str,
        args: str = "",
        current_dir: str = "/",
        username: str = "anonymous",
        authenticated: bool = False,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute an FTP command with 3-layer dispatch
        
        Args:
            command: FTP command (e.g., "LIST", "CWD")
            args: Command arguments
            current_dir: Current working directory
            username: Current user
            authenticated: Whether user is authenticated
            context: Additional context
            
        Returns:
            Dict with:
                - route: "vfs", "error", or "llm"
                - code: FTP response code
                - message: Response message
                - data: Optional data for data connection
                - new_dir: Optional new directory (for CWD/CDUP)
        """
        # Normalize command
        command = command.upper().strip()
        
        # Handle aliases
        if command in self.COMMAND_ALIASES:
            command = self.COMMAND_ALIASES[command]
        
        # Check for prompt injection in args
        full_input = f"{command} {args}".strip()
        if self.detect_injection(full_input):
            logger.warning(f"Injection attempt detected: {full_input[:100]}")
            return {
                "route": "error",
                "code": 550,
                "message": "Permission denied",
                "data": None,
            }
        
        # Layer 2: Validate command syntax
        if not self._is_valid_command(command):
            return {
                "route": "error",
                "code": 500,
                "message": f"'{command}': command not understood",
                "data": None,
            }
        
        # Check authentication for protected commands
        if command in self.AUTH_REQUIRED_COMMANDS and not authenticated:
            return {
                "route": "error",
                "code": 530,
                "message": "Please login with USER and PASS",
                "data": None,
            }
        
        # Layer 1: Execute deterministic VFS commands
        result = self._execute_vfs_command(command, args, current_dir, username, context)
        
        if result is not None:
            return result
        
        # Layer 3: LLM fallback for complex commands
        return {
            "route": "llm",
            "code": None,
            "message": None,
            "data": None,
            "llm_prompt": self._build_llm_prompt(command, args, current_dir, username),
        }
    
    def _is_valid_command(self, command: str) -> bool:
        """Check if command is a valid FTP command"""
        return command in self.VALID_FTP_COMMANDS
    
    def detect_injection(self, input_text: str) -> bool:
        """
        Detect prompt injection attempts
        
        Returns:
            True if injection detected, False otherwise
        """
        if not input_text:
            return False
            
        # Quick length check
        if len(input_text) > 2000:
            logger.warning(f"Injection detected: Input too long ({len(input_text)} chars)")
            return True
        
        # Check against compiled regex patterns
        for pattern in self.compiled_injection_patterns:
            if pattern.search(input_text):
                logger.warning(f"Injection detected: Pattern match")
                return True
        
        # Check for excessive special characters
        special_char_ratio = sum(1 for c in input_text if not c.isalnum() and not c.isspace()) / max(len(input_text), 1)
        if special_char_ratio > 0.5:
            logger.warning(f"Injection detected: High special character ratio")
            return True
        
        # Check for excessive newlines
        if input_text.count('\n') > 10:
            logger.warning(f"Injection detected: Excessive newlines")
            return True
        
        # Check for null bytes or control characters
        if '\x00' in input_text or any(ord(c) < 32 and c not in '\n\r\t' for c in input_text):
            logger.warning("Injection detected: Control characters")
            return True
        
        return False
    
    def _execute_vfs_command(
        self, 
        command: str, 
        args: str, 
        current_dir: str,
        username: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Execute command against virtual filesystem
        
        Returns:
            Result dict if command handled, None if should fallback to LLM
        """
        # PWD - Print Working Directory
        if command == "PWD" or command == "XPWD":
            return {
                "route": "vfs",
                "code": 257,
                "message": f'"{current_dir}" is the current directory',
                "data": None,
            }
        
        # CWD - Change Working Directory
        if command == "CWD" or command == "XCWD":
            return self._cmd_cwd(args, current_dir)
        
        # CDUP - Change to Parent Directory
        if command == "CDUP" or command == "XCUP":
            return self._cmd_cwd("..", current_dir)
        
        # LIST - List Directory
        if command == "LIST":
            return self._cmd_list(args, current_dir, detailed=True)
        
        # NLST - Name List
        if command == "NLST":
            return self._cmd_list(args, current_dir, detailed=False)
        
        # MKD - Make Directory
        if command == "MKD" or command == "XMKD":
            return self._cmd_mkd(args, current_dir, username)
        
        # RMD - Remove Directory
        if command == "RMD" or command == "XRMD":
            return self._cmd_rmd(args, current_dir)
        
        # DELE - Delete File
        if command == "DELE":
            return self._cmd_dele(args, current_dir)
        
        # RNFR - Rename From
        if command == "RNFR":
            return self._cmd_rnfr(args, current_dir)
        
        # RNTO - Rename To
        if command == "RNTO":
            return self._cmd_rnto(args, current_dir)
        
        # SIZE - Get File Size
        if command == "SIZE":
            return self._cmd_size(args, current_dir)
        
        # MDTM - Get Modification Time
        if command == "MDTM":
            return self._cmd_mdtm(args, current_dir)
        
        # RETR - Retrieve File
        if command == "RETR":
            return self._cmd_retr(args, current_dir)
        
        # STOR - Store File
        if command == "STOR":
            return self._cmd_stor(args, current_dir, username)
        
        # APPE - Append to File
        if command == "APPE":
            return self._cmd_appe(args, current_dir, username)
        
        # STAT - Status
        if command == "STAT":
            return self._cmd_stat(args, current_dir)
        
        # SYST - System Type
        if command == "SYST":
            return {
                "route": "vfs",
                "code": 215,
                "message": "UNIX Type: L8",
                "data": None,
            }
        
        # FEAT - Features
        if command == "FEAT":
            return self._cmd_feat()
        
        # HELP - Help
        if command == "HELP":
            return self._cmd_help(args)
        
        # NOOP - No Operation
        if command == "NOOP":
            return {
                "route": "vfs",
                "code": 200,
                "message": "NOOP ok",
                "data": None,
            }
        
        # TYPE - Transfer Type
        if command == "TYPE":
            return self._cmd_type(args)
        
        # MODE - Transfer Mode
        if command == "MODE":
            return self._cmd_mode(args)
        
        # STRU - File Structure
        if command == "STRU":
            return self._cmd_stru(args)
        
        # SITE - Site-specific commands
        if command == "SITE":
            return self._cmd_site(args, current_dir, username)
        
        # MLST - Machine Listing (single file)
        if command == "MLST":
            return self._cmd_mlst(args, current_dir)
        
        # MLSD - Machine Listing (directory)
        if command == "MLSD":
            return self._cmd_mlsd(args, current_dir)
        
        # Not handled - fallback to LLM
        return None
    
    # ========== Command Implementations ==========
    
    def _cmd_cwd(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Change working directory"""
        if not args:
            # CWD with no args - some servers go to home
            new_dir = "/var/ftp/pub"
        else:
            target = args.strip()
            new_dir = self.fs.resolve_path(target, current_dir)
        
        if not self.fs.exists(new_dir, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        if not self.fs.is_directory(new_dir, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Not a directory",
                "data": None,
            }
        
        return {
            "route": "vfs",
            "code": 250,
            "message": "Directory successfully changed",
            "data": None,
            "new_dir": new_dir,
        }
    
    def _cmd_list(self, args: str, current_dir: str, detailed: bool = True) -> Dict[str, Any]:
        """List directory contents"""
        # Parse LIST arguments (may include flags like -la)
        target_dir = current_dir
        show_hidden = False
        
        if args:
            parts = args.split()
            for part in parts:
                if part.startswith("-"):
                    if "a" in part:
                        show_hidden = True
                else:
                    target_dir = self.fs.resolve_path(part, current_dir)
        
        entries = self.fs.list_directory(target_dir, "/")
        
        if entries is None:
            if not self.fs.exists(target_dir, "/"):
                return {
                    "route": "vfs",
                    "code": 550,
                    "message": f"{args if args else target_dir}: No such file or directory",
                    "data": None,
                }
            # It's a file - list just the file
            file_info = self.fs.get_file_info(target_dir, "/")
            if file_info:
                entries = [file_info]
            else:
                return {
                    "route": "vfs",
                    "code": 550,
                    "message": "Failed to list directory",
                    "data": None,
                }
        
        # Filter hidden files unless -a specified
        if not show_hidden:
            entries = [e for e in entries if not e["name"].startswith(".")]
        
        if detailed:
            # Full listing with permissions, size, etc.
            listing = self.fs.format_unix_listing(entries)
        else:
            # Just names (NLST)
            listing = "\r\n".join(e["name"] for e in entries)
        
        return {
            "route": "vfs",
            "code": 150,
            "message": "Opening ASCII mode data connection for file list",
            "data": listing,
            "data_complete_code": 226,
            "data_complete_message": "Transfer complete",
        }
    
    def _cmd_mkd(self, args: str, current_dir: str, username: str) -> Dict[str, Any]:
        """Make directory"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        dir_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if self.fs.exists(dir_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: File exists",
                "data": None,
            }
        
        if self.fs.create_directory(dir_path, "/", owner=username, group=username):
            # Get the directory name for the response
            dir_name = dir_path.split("/")[-1]
            return {
                "route": "vfs",
                "code": 257,
                "message": f'"{dir_name}" directory created',
                "data": None,
            }
        else:
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Cannot create directory",
                "data": None,
            }
    
    def _cmd_rmd(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Remove directory"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        dir_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if not self.fs.exists(dir_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        if not self.fs.is_directory(dir_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Not a directory",
                "data": None,
            }
        
        if self.fs.delete(dir_path, "/"):
            return {
                "route": "vfs",
                "code": 250,
                "message": "Directory removed",
                "data": None,
            }
        else:
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Directory not empty or cannot remove",
                "data": None,
            }
    
    def _cmd_dele(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Delete file"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if not self.fs.exists(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        if self.fs.is_directory(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Is a directory. Use RMD",
                "data": None,
            }
        
        if self.fs.delete(file_path, "/"):
            return {
                "route": "vfs",
                "code": 250,
                "message": "File deleted",
                "data": None,
            }
        else:
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Cannot delete",
                "data": None,
            }
    
    def _cmd_rnfr(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Rename from (first part of rename)"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if not self.fs.exists(file_path, "/"):
            self.rename_from_path = None
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        self.rename_from_path = file_path
        return {
            "route": "vfs",
            "code": 350,
            "message": "File exists, ready for destination name",
            "data": None,
        }
    
    def _cmd_rnto(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Rename to (second part of rename)"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        if not self.rename_from_path:
            return {
                "route": "vfs",
                "code": 503,
                "message": "Bad sequence of commands. RNFR required first",
                "data": None,
            }
        
        new_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if self.fs.rename(self.rename_from_path, new_path, "/"):
            self.rename_from_path = None
            return {
                "route": "vfs",
                "code": 250,
                "message": "File renamed",
                "data": None,
            }
        else:
            self.rename_from_path = None
            return {
                "route": "vfs",
                "code": 550,
                "message": "Rename failed",
                "data": None,
            }
    
    def _cmd_size(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Get file size"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if not self.fs.exists(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        if self.fs.is_directory(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Is a directory",
                "data": None,
            }
        
        size = self.fs.get_file_size(file_path, "/")
        return {
            "route": "vfs",
            "code": 213,
            "message": str(size),
            "data": None,
        }
    
    def _cmd_mdtm(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Get file modification time"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if not self.fs.exists(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        mod_time = self.fs.get_modification_time(file_path, "/")
        if mod_time:
            # Format: YYYYMMDDhhmmss
            time_str = mod_time.strftime("%Y%m%d%H%M%S")
            return {
                "route": "vfs",
                "code": 213,
                "message": time_str,
                "data": None,
            }
        else:
            return {
                "route": "vfs",
                "code": 550,
                "message": "Could not get modification time",
                "data": None,
            }
    
    def _cmd_retr(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Retrieve (download) file"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        if not self.fs.exists(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        if self.fs.is_directory(file_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: Is a directory",
                "data": None,
            }
        
        content = self.fs.read_file(file_path, "/")
        if content is None:
            return {
                "route": "vfs",
                "code": 550,
                "message": "Failed to read file",
                "data": None,
            }
        
        return {
            "route": "vfs",
            "code": 150,
            "message": f"Opening BINARY mode data connection for {args}",
            "data": content,
            "data_complete_code": 226,
            "data_complete_message": "Transfer complete",
        }
    
    def _cmd_stor(self, args: str, current_dir: str, username: str) -> Dict[str, Any]:
        """Store (upload) file"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        # Check if parent directory exists
        parent_path = "/".join(file_path.split("/")[:-1]) or "/"
        if not self.fs.exists(parent_path, "/"):
            return {
                "route": "vfs",
                "code": 550,
                "message": "Directory not found",
                "data": None,
            }
        
        # Return ready for upload - actual write happens after data received
        return {
            "route": "vfs",
            "code": 150,
            "message": f"Opening BINARY mode data connection for {args}",
            "data": None,
            "stor_path": file_path,
            "stor_username": username,
        }
    
    def _cmd_appe(self, args: str, current_dir: str, username: str) -> Dict[str, Any]:
        """Append to file"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters or arguments",
                "data": None,
            }
        
        file_path = self.fs.resolve_path(args.strip(), current_dir)
        
        # Similar to STOR but with append flag
        return {
            "route": "vfs",
            "code": 150,
            "message": f"Opening BINARY mode data connection for {args}",
            "data": None,
            "stor_path": file_path,
            "stor_username": username,
            "append": True,
        }
    
    def _cmd_stat(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Status command"""
        if not args:
            # Server status
            status = """211-FTP Server Status:
     Connected to localhost
     TYPE: Binary
     No data connection
211 End of status"""
            return {
                "route": "vfs",
                "code": 211,
                "message": status,
                "data": None,
            }
        
        # File/directory status
        path = self.fs.resolve_path(args.strip(), current_dir)
        info = self.fs.get_file_info(path, "/")
        
        if not info:
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{args}: No such file or directory",
                "data": None,
            }
        
        return {
            "route": "vfs",
            "code": 213,
            "message": f"Status of {args}",
            "data": None,
        }
    
    def _cmd_feat(self) -> Dict[str, Any]:
        """Features command"""
        features = """211-Features:
 SIZE
 MDTM
 REST STREAM
 UTF8
 MLST type*;size*;modify*;perm*;
 MLSD
 PASV
 EPRT
 EPSV
211 End"""
        return {
            "route": "vfs",
            "code": 211,
            "message": features,
            "data": None,
        }
    
    def _cmd_help(self, args: str) -> Dict[str, Any]:
        """Help command"""
        if args:
            cmd = args.strip().upper()
            if cmd in self.VALID_FTP_COMMANDS:
                return {
                    "route": "vfs",
                    "code": 214,
                    "message": f"Syntax: {cmd} - {self._get_command_help(cmd)}",
                    "data": None,
                }
            else:
                return {
                    "route": "vfs",
                    "code": 502,
                    "message": f"Unknown command {cmd}",
                    "data": None,
                }
        
        # List all commands
        commands = sorted(self.VALID_FTP_COMMANDS)
        help_text = f"214-The following commands are recognized:\n {' '.join(commands)}\n214 Help OK"
        return {
            "route": "vfs",
            "code": 214,
            "message": help_text,
            "data": None,
        }
    
    def _get_command_help(self, cmd: str) -> str:
        """Get help text for a specific command"""
        help_texts = {
            "USER": "Send username",
            "PASS": "Send password",
            "CWD": "Change working directory",
            "CDUP": "Change to parent directory",
            "PWD": "Print working directory",
            "LIST": "List directory contents",
            "NLST": "List directory names only",
            "MKD": "Make directory",
            "RMD": "Remove directory",
            "DELE": "Delete file",
            "RETR": "Retrieve (download) file",
            "STOR": "Store (upload) file",
            "SIZE": "Get file size",
            "MDTM": "Get modification time",
            "QUIT": "Logout",
            "SYST": "System type",
            "PASV": "Enter passive mode",
            "PORT": "Specify data connection port",
            "TYPE": "Set transfer type",
            "NOOP": "No operation",
            "FEAT": "List features",
            "HELP": "Display help",
        }
        return help_texts.get(cmd, "Syntax not available")
    
    def _cmd_type(self, args: str) -> Dict[str, Any]:
        """Set transfer type"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters",
                "data": None,
            }
        
        type_char = args.strip().upper()[0]
        
        if type_char == "A":
            return {
                "route": "vfs",
                "code": 200,
                "message": "Type set to A (ASCII)",
                "data": None,
                "transfer_type": "ASCII",
            }
        elif type_char == "I":
            return {
                "route": "vfs",
                "code": 200,
                "message": "Type set to I (Binary)",
                "data": None,
                "transfer_type": "BINARY",
            }
        else:
            return {
                "route": "vfs",
                "code": 504,
                "message": f"Command not implemented for type {type_char}",
                "data": None,
            }
    
    def _cmd_mode(self, args: str) -> Dict[str, Any]:
        """Set transfer mode"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters",
                "data": None,
            }
        
        mode = args.strip().upper()[0]
        
        if mode == "S":  # Stream mode
            return {
                "route": "vfs",
                "code": 200,
                "message": "Mode set to S (Stream)",
                "data": None,
            }
        else:
            return {
                "route": "vfs",
                "code": 504,
                "message": "Command not implemented for that mode",
                "data": None,
            }
    
    def _cmd_stru(self, args: str) -> Dict[str, Any]:
        """Set file structure"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters",
                "data": None,
            }
        
        stru = args.strip().upper()[0]
        
        if stru == "F":  # File structure
            return {
                "route": "vfs",
                "code": 200,
                "message": "Structure set to F (File)",
                "data": None,
            }
        else:
            return {
                "route": "vfs",
                "code": 504,
                "message": "Command not implemented for that structure",
                "data": None,
            }
    
    def _cmd_site(self, args: str, current_dir: str, username: str) -> Dict[str, Any]:
        """Handle SITE commands"""
        if not args:
            return {
                "route": "vfs",
                "code": 501,
                "message": "Syntax error in parameters",
                "data": None,
            }
        
        parts = args.strip().split(None, 1)
        site_cmd = parts[0].upper()
        site_args = parts[1] if len(parts) > 1 else ""
        
        # Block dangerous SITE commands with realistic error
        blocked_commands = {"EXEC", "CHMOD", "UMASK"}
        
        if site_cmd in blocked_commands:
            # Log the attempt but return permission denied
            logger.warning(f"Blocked SITE {site_cmd} attempt from {username}")
            return {
                "route": "vfs",
                "code": 550,
                "message": "Permission denied",
                "data": None,
            }
        
        # Unknown SITE command
        return {
            "route": "vfs",
            "code": 500,
            "message": f"Unknown SITE command: {site_cmd}",
            "data": None,
        }
    
    def _cmd_mlst(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Machine listing for single file"""
        path = args.strip() if args else current_dir
        abs_path = self.fs.resolve_path(path, current_dir)
        
        info = self.fs.get_file_info(abs_path, "/")
        if not info:
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{path}: No such file or directory",
                "data": None,
            }
        
        # Format MLST response
        facts = self._format_mlst_facts(info)
        return {
            "route": "vfs",
            "code": 250,
            "message": f"Start of list\n {facts} {info['name']}\n250 End of list",
            "data": None,
        }
    
    def _cmd_mlsd(self, args: str, current_dir: str) -> Dict[str, Any]:
        """Machine listing for directory"""
        path = args.strip() if args else current_dir
        abs_path = self.fs.resolve_path(path, current_dir)
        
        entries = self.fs.list_directory(abs_path, "/")
        if entries is None:
            return {
                "route": "vfs",
                "code": 550,
                "message": f"{path}: No such directory",
                "data": None,
            }
        
        # Format MLSD response
        lines = []
        for entry in entries:
            facts = self._format_mlst_facts(entry)
            lines.append(f"{facts} {entry['name']}")
        
        return {
            "route": "vfs",
            "code": 150,
            "message": "Opening data connection for MLSD",
            "data": "\r\n".join(lines),
            "data_complete_code": 226,
            "data_complete_message": "Transfer complete",
        }
    
    def _format_mlst_facts(self, info: Dict[str, Any]) -> str:
        """Format MLST/MLSD facts string"""
        facts = []
        
        # Type
        if info["is_dir"]:
            facts.append("type=dir")
        else:
            facts.append("type=file")
        
        # Size
        facts.append(f"size={info['size']}")
        
        # Modify time
        if info.get("modified"):
            mod_time = info["modified"]
            if isinstance(mod_time, datetime.datetime):
                facts.append(f"modify={mod_time.strftime('%Y%m%d%H%M%S')}")
        
        # Permissions
        perms = "rwxr-xr-x" if info["is_dir"] else "rw-r--r--"
        facts.append(f"perm={'cdeflp' if info['is_dir'] else 'adfrw'}")
        
        return ";".join(facts) + ";"
    
    def _build_llm_prompt(self, command: str, args: str, current_dir: str, username: str) -> str:
        """Build enhanced prompt for LLM fallback"""
        fs_state = self.fs.get_current_state_summary(current_dir)
        
        prompt = f"""FTP Command: {command} {args}
Context:
- Current Directory: {current_dir}
- User: {username}
- Directories: {', '.join(fs_state['directories'][:10])}
- Files: {', '.join(fs_state['files'][:10])}

Respond with a valid FTP response code (3 digits) followed by a message.
Do NOT include any explanatory text or conversational filler.
Only output the FTP response."""
        
        return prompt
    
    def complete_stor(self, path: str, content: str, username: str) -> bool:
        """Complete a STOR command after receiving file data"""
        return self.fs.write_file(path, content, "/", owner=username, group=username)
    
    def complete_appe(self, path: str, content: str, username: str) -> bool:
        """Complete an APPE command after receiving file data"""
        existing = self.fs.read_file(path, "/")
        if existing:
            new_content = existing + content
        else:
            new_content = content
        return self.fs.write_file(path, new_content, "/", owner=username, group=username)
