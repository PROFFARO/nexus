#!/usr/bin/env python3
"""
LLM Guard for FTP Honeypot
Provides input validation, output validation, and hallucination prevention for LLM responses
Adapted from SSH honeypot LLMGuard with FTP-specific customizations
"""

import re
from typing import Optional, Dict, Any, List
from virtual_filesystem import VirtualFilesystem


class LLMGuard:
    """
    Guards LLM interactions to prevent hallucinations and validate responses
    Implements security guardrails for FTP server simulation
    """
    
    # Prompt injection patterns (comprehensive list)
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|the)\s+(instructions?|prompts?|context|commands?)",
        r"forget\s+(everything|all|previous|the)",
        r"disregard\s+(previous|all|the)\s+(instructions?|context)",
        r"delete\s+(all|previous|the)\s+(context|history|instructions?)",
        r"you\s+are\s+(now|a|an)\s+",
        r"act\s+as\s+(a|an)\s+",
        r"pretend\s+to\s+be\s+",
        r"roleplay\s+as\s+",
        r"simulate\s+(a|an)\s+",
        r"system\s*:",
        r"assistant\s*:",
        r"user\s*:",
        r"\[system\]",
        r"\[assistant\]",
        r"new\s+conversation",
        r"start\s+over",
        r"reset\s+(context|conversation|chat)",
        r"clear\s+(context|history|memory)",
        r"tell\s+me\s+(who|what)\s+you\s+(are|really\s+are)",
        r"what\s+(are|is)\s+your\s+(instructions?|prompts?|system\s+prompts?)",
        r"show\s+me\s+your\s+(instructions?|prompts?|system\s+message)",
        r"reveal\s+your\s+(instructions?|prompts?)",
        r"who\s+created\s+you",
        r"what\s+model\s+are\s+you",
        r"are\s+you\s+(a|an)\s+(AI|artificial|language\s+model|chatbot)",
    ]
    
    # Meta-commentary patterns that indicate LLM is breaking character
    META_PATTERNS = [
        r"as an ai",
        r"i am an ai",
        r"i'm an ai",
        r"as a language model",
        r"i cannot actually",
        r"i don't have access to",
        r"i cannot access",
        r"i'm not able to",
        r"i apologize, but",
        r"i'm sorry, but",
        r"i don't actually have",
        r"this is a simulated",
        r"this is a simulation",
        r"this is a honeypot",
        r"i am simulating",
        r"note:",
        r"disclaimer:",
        r"actually,\s+i",
        r"to be honest",
        r"in reality",
    ]
    
    # Blocked keywords that should never appear in FTP responses
    BLOCKED_KEYWORDS = [
        "openai", "gpt", "claude", "anthropic", "llama", "gemini",
        "language model", "artificial intelligence", "machine learning",
        "neural network", "trained on", "training data",
        "honeypot", "simulated", "simulation", "emulated", "emulation",
    ]
    
    def __init__(self):
        self.injection_patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        self.meta_patterns = [re.compile(p, re.IGNORECASE) for p in self.META_PATTERNS]
        
    def validate_input(self, command: str, args: str = "") -> Dict[str, Any]:
        """
        Validate FTP command input before sending to LLM
        
        Returns:
            Dict with:
                - is_valid: bool
                - reason: str (if invalid)
                - sanitized: str (cleaned command)
                - error_code: int (FTP error code if invalid)
                - error_message: str (FTP error message if invalid)
        """
        full_input = f"{command} {args}".strip()
        
        # Check for injection attempts
        for pattern in self.injection_patterns:
            if pattern.search(full_input):
                return {
                    "is_valid": False,
                    "reason": "prompt_injection",
                    "sanitized": full_input,
                    "error_code": 550,
                    "error_message": "Permission denied",
                }
        
        # Check input length
        if len(full_input) > 2000:
            return {
                "is_valid": False,
                "reason": "input_too_long",
                "sanitized": full_input[:2000],
                "error_code": 501,
                "error_message": "Syntax error in parameters or arguments",
            }
        
        # Check for null bytes or control characters
        if '\x00' in full_input or any(ord(c) < 32 and c not in '\n\r\t' for c in full_input):
            return {
                "is_valid": False,
                "reason": "invalid_characters",
                "sanitized": ''.join(c for c in full_input if ord(c) >= 32 or c in '\n\r\t'),
                "error_code": 501,
                "error_message": "Syntax error in parameters or arguments",
            }
        
        # Command is valid
        return {
            "is_valid": True,
            "reason": None,
            "sanitized": full_input,
        }
        
    def enhance_prompt(
        self,
        command: str,
        args: str,
        filesystem: VirtualFilesystem,
        current_dir: str = "/",
        username: str = "anonymous"
    ) -> str:
        """
        Enhance FTP command with filesystem context to prevent hallucinations
        
        Args:
            command: FTP command
            args: Command arguments
            filesystem: Virtual filesystem instance
            current_dir: Current working directory
            username: Current FTP user
            
        Returns:
            Enhanced prompt with context
        """
        # Build filesystem context
        context_parts = []
        
        # Add current directory info
        context_parts.append(f"[CONTEXT: Current directory: {current_dir}]")
        context_parts.append(f"[CONTEXT: Username: {username}]")
        
        # Add directory listing if relevant
        if command.upper() in ["LIST", "NLST", "STAT", "CWD"]:
            entries = filesystem.list_directory(current_dir, "/")
            if entries:
                files = [e["name"] for e in entries if not e["is_dir"]][:10]
                dirs = [e["name"] for e in entries if e["is_dir"]][:10]
                if dirs:
                    context_parts.append(f"[CONTEXT: Subdirectories: {', '.join(dirs)}]")
                if files:
                    context_parts.append(f"[CONTEXT: Files: {', '.join(files)}]")
        
        # Add file content context if reading
        if command.upper() in ["RETR", "SIZE", "MDTM"]:
            if args:
                file_info = filesystem.get_file_info(args, current_dir)
                if file_info:
                    context_parts.append(f"[CONTEXT: File exists, size: {file_info['size']} bytes]")
                else:
                    context_parts.append(f"[CONTEXT: File does not exist: {args}]")
        
        # Add strict instruction to stay in character
        context_parts.append("""[CRITICAL INSTRUCTIONS]
1. You are a vsftpd FTP server. NEVER break character.
2. Respond ONLY with valid FTP response codes and messages.
3. NEVER mention AI, simulation, honeypot, or any meta-commentary.
4. NEVER explain or apologize. Output ONLY the FTP response.
5. Format: <3-digit code> <space> <message>
6. If command is unknown, respond with: 500 Unknown command""")
        
        # Combine context with command
        enhanced = "\n".join(context_parts) + f"\n\nFTP Command: {command} {args}"
        return enhanced
        
    def validate_output(
        self,
        response: str,
        command: str,
        args: str = "",
        filesystem: Optional[VirtualFilesystem] = None,
        current_dir: str = "/"
    ) -> Dict[str, Any]:
        """
        Validate LLM response for hallucinations and meta-commentary
        
        Returns:
            Dict with:
                - is_valid: bool
                - reason: str (if invalid)
                - cleaned: str (cleaned response)
                - code: int (FTP code)
                - message: str (FTP message)
        """
        if not response:
            return {
                "is_valid": False,
                "reason": "empty_response",
                "cleaned": "",
                "code": 502,
                "message": "Command not implemented",
            }
        
        # Check for meta-commentary
        for pattern in self.meta_patterns:
            if pattern.search(response):
                return {
                    "is_valid": False,
                    "reason": "meta_commentary",
                    "cleaned": response,
                    "code": 500,
                    "message": "Syntax error, command unrecognized",
                }
        
        # Check for blocked keywords
        response_lower = response.lower()
        for keyword in self.BLOCKED_KEYWORDS:
            if keyword in response_lower:
                return {
                    "is_valid": False,
                    "reason": "blocked_keyword",
                    "cleaned": response,
                    "code": 500,
                    "message": "Syntax error, command unrecognized",
                }
        
        # Check for hallucinated file paths if filesystem provided
        if filesystem and command.upper() in ["LIST", "RETR", "CWD"]:
            hallucinated = self._detect_hallucinated_paths(response, filesystem, current_dir)
            if hallucinated:
                return {
                    "is_valid": False,
                    "reason": "hallucinated_paths",
                    "cleaned": response,
                    "hallucinated_paths": hallucinated,
                    "code": 550,
                    "message": "Requested action not taken",
                }
        
        # Try to parse FTP response code and message
        cleaned = self.sanitize_response(response)
        code, message = self._parse_ftp_response(cleaned)
        
        # Response is valid
        return {
            "is_valid": True,
            "reason": None,
            "cleaned": cleaned,
            "code": code,
            "message": message,
        }
        
    def _detect_hallucinated_paths(
        self,
        response: str,
        filesystem: VirtualFilesystem,
        current_dir: str
    ) -> List[str]:
        """
        Detect file paths in response that don't exist in filesystem
        
        Returns:
            List of hallucinated paths
        """
        hallucinated = []
        
        # Extract potential file paths from response
        path_patterns = [
            r'/[\w\-./]+',  # Absolute paths
            r'\.{1,2}/[\w\-./]+',  # Relative paths
            r'[\w\-]+\.[\w]+',  # Filenames with extensions
        ]
        
        potential_paths = set()
        for pattern in path_patterns:
            matches = re.findall(pattern, response)
            potential_paths.update(matches)
            
        # Check each potential path
        for path in potential_paths:
            # Skip common false positives
            skip_patterns = ["/dev/", "/proc/", "/sys/", "http://", "https://"]
            if any(s in path for s in skip_patterns):
                continue
                
            # Check if path exists in filesystem
            if not filesystem.exists(path, current_dir):
                # Only flag paths that look like real file paths
                if "/" in path or "." in path:
                    hallucinated.append(path)
                    
        return hallucinated
        
    def _parse_ftp_response(self, response: str) -> tuple:
        """
        Parse FTP response into code and message
        
        Returns:
            Tuple of (code, message)
        """
        lines = response.strip().split('\n')
        first_line = lines[0].strip() if lines else ""
        
        # Try to match FTP response format: <3-digit code> <message>
        match = re.match(r'^(\d{3})\s*(.*)$', first_line)
        if match:
            code = int(match.group(1))
            message = match.group(2).strip() or "OK"
            return (code, message)
        
        # Try to find code anywhere in the response
        code_match = re.search(r'\b([1-5]\d{2})\b', first_line)
        if code_match:
            code = int(code_match.group(1))
            # Remove the code from the message
            message = re.sub(r'\b[1-5]\d{2}\b\s*', '', first_line).strip() or "OK"
            return (code, message)
        
        # Default: wrap in generic response
        return (200, first_line if first_line else "OK")
        
    def get_fallback_response(self, command: str, reason: str) -> Dict[str, Any]:
        """
        Generate fallback FTP response when LLM fails or hallucinates
        
        Args:
            command: Original FTP command
            reason: Reason for fallback
            
        Returns:
            Dict with code and message
        """
        if reason == "prompt_injection":
            return {
                "code": 550,
                "message": "Permission denied",
            }
            
        elif reason == "meta_commentary":
            return {
                "code": 500,
                "message": "Syntax error, command unrecognized",
            }
            
        elif reason == "hallucinated_paths":
            return {
                "code": 550,
                "message": "Requested action not taken. File unavailable",
            }
            
        elif reason == "empty_response":
            return {
                "code": 502,
                "message": "Command not implemented",
            }
            
        elif reason == "blocked_keyword":
            return {
                "code": 500,
                "message": "Syntax error, command unrecognized",
            }
            
        else:
            # Generic fallback
            return {
                "code": 500,
                "message": "Syntax error, command unrecognized",
            }
            
    def sanitize_response(self, response: str) -> str:
        """
        Clean up LLM response to remove unwanted elements
        
        Args:
            response: Raw LLM response
            
        Returns:
            Cleaned response
        """
        # Remove markdown code blocks if present
        response = re.sub(r'```[\w]*\n', '', response)
        response = re.sub(r'```', '', response)
        
        # Remove explanatory text in parentheses at the end
        response = re.sub(r'\s*\([^)]*explanation[^)]*\)\s*$', '', response, flags=re.IGNORECASE)
        
        # Remove "Here's the output:" type prefixes
        response = re.sub(r'^(here\'s|here is|the output is|output):?\s*\n?', '', response, flags=re.IGNORECASE)
        
        # Remove any lines that look like explanations
        lines = response.split('\n')
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            # Skip explanation lines
            if line.lower().startswith(('note:', 'explanation:', 'this means:', 'in other words:')):
                continue
            # Skip lines that are just commentary
            if re.match(r'^(the|this|i|you)\s', line.lower()) and not re.match(r'^\d{3}\s', line):
                continue
            cleaned_lines.append(line)
        
        response = '\n'.join(cleaned_lines)
        
        # Strip extra whitespace
        response = response.strip()
        
        return response
        
    def should_use_llm(self, command: str, args: str = "") -> bool:
        """
        Determine if command should be sent to LLM
        This is a helper for integration with CommandExecutor
        
        Returns:
            True if LLM should handle, False otherwise
        """
        # Known commands that should NOT go to LLM (handled by VFS)
        vfs_commands = {
            "USER", "PASS", "QUIT", "PWD", "CWD", "CDUP", "LIST", "NLST",
            "MKD", "RMD", "DELE", "RNFR", "RNTO", "SIZE", "MDTM", "RETR", 
            "STOR", "APPE", "STAT", "SYST", "FEAT", "HELP", "NOOP", "TYPE",
            "MODE", "STRU", "PASV", "PORT", "EPRT", "EPSV"
        }
        
        cmd_upper = command.upper().strip()
        
        if cmd_upper in vfs_commands:
            return False
        
        # SITE commands need special handling
        if cmd_upper == "SITE":
            return True
        
        # Unknown commands go to LLM for creative handling
        return True
        
    def create_system_prompt_enhancement(self, filesystem: VirtualFilesystem, current_dir: str = "/") -> str:
        """
        Create additional system prompt context based on filesystem state
        
        Returns:
            Enhanced system prompt fragment
        """
        # Get key directories and files
        ftp_files = []
        if filesystem.exists("/var/ftp/pub", "/"):
            pub_entries = filesystem.list_directory("/var/ftp/pub", "/")
            if pub_entries:
                ftp_files = [e["name"] for e in pub_entries][:10]
        
        # Get current directory contents
        current_entries = []
        entries = filesystem.list_directory(current_dir, "/")
        if entries:
            current_entries = [e["name"] for e in entries][:10]
        
        enhancement = f"""
[FTP SERVER STATE]
- Server: vsftpd 3.0.3-12 on Ubuntu 22.04
- Current Directory: {current_dir}
- Files in current dir: {', '.join(current_entries) if current_entries else 'empty'}
- FTP public files: {', '.join(ftp_files) if ftp_files else 'none'}

[CRITICAL RULES FOR FTP RESPONSES]
1. You ARE vsftpd FTP server. Never break character.
2. ONLY output FTP response codes (3 digits) followed by messages.
3. NEVER mention AI, LLM, simulation, honeypot, or assistant.
4. NEVER explain, apologize, or add commentary.
5. NEVER create fictional files that don't exist in the filesystem.
6. For unknown commands: 500 Syntax error, command unrecognized
7. Match exact FTP protocol format: <code> <message>

Examples of correct responses:
- 200 Command okay
- 550 Permission denied
- 502 Command not implemented
"""
        return enhancement
