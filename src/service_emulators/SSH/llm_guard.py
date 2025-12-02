#!/usr/bin/env python3
"""
LLM Guard for SSH Honeypot
Provides input validation, output validation, and hallucination prevention for LLM responses
"""

import re
from typing import Optional, Dict, Any, List
from virtual_filesystem import VirtualFilesystem


class LLMGuard:
    """
    Guards LLM interactions to prevent hallucinations and validate responses
    """
    
    # Prompt injection patterns (same as CommandExecutor but used for LLM-bound commands)
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
    ]
    
    def __init__(self):
        self.injection_patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        self.meta_patterns = [re.compile(p, re.IGNORECASE) for p in self.META_PATTERNS]
        
    def validate_input(self, command: str) -> Dict[str, Any]:
        """
        Validate command input before sending to LLM
        
        Returns:
            Dict with:
                - is_valid: bool
                - reason: str (if invalid)
                - sanitized: str (cleaned command)
        """
        # Check for injection attempts
        for pattern in self.injection_patterns:
            if pattern.search(command):
                return {
                    "is_valid": False,
                    "reason": "prompt_injection",
                    "sanitized": command,
                }
                
        # Command is valid
        return {
            "is_valid": True,
            "reason": None,
            "sanitized": command,
        }
        
    def enhance_prompt(
        self,
        command: str,
        filesystem: VirtualFilesystem,
        current_dir: str = "/",
        username: str = "guest"
    ) -> str:
        """
        Enhance command with filesystem context to prevent hallucinations
        
        Args:
            command: Original command
            filesystem: Virtual filesystem instance
            current_dir: Current working directory
            username: Current user
            
        Returns:
            Enhanced command with context
        """
        # Build filesystem context
        context_parts = []
        
        # Add current directory info
        context_parts.append(f"[CONTEXT: Current directory: {current_dir}]")
        
        # Add directory listing if command involves listing/searching
        if any(cmd in command.lower() for cmd in ["ls", "find", "locate", "dir"]):
            entries = filesystem.list_directory(current_dir, "/")
            if entries:
                files = [e["name"] for e in entries if not e["is_dir"]]
                dirs = [e["name"] for e in entries if e["is_dir"]]
                if dirs:
                    context_parts.append(f"[CONTEXT: Directories in {current_dir}: {', '.join(dirs)}]")
                if files:
                    context_parts.append(f"[CONTEXT: Files in {current_dir}: {', '.join(files)}]")
                    
        # Add file content context if command involves reading
        if any(cmd in command.lower() for cmd in ["cat", "head", "tail", "more", "less"]):
            # Extract filename from command
            parts = command.split()
            for part in parts[1:]:
                if not part.startswith("-"):
                    content = filesystem.read_file(part, current_dir)
                    if content:
                        # Truncate if too long
                        if len(content) > 500:
                            content = content[:500] + "..."
                        context_parts.append(f"[CONTEXT: Content of {part}: {content}]")
                    break
                    
        # Add user context
        context_parts.append(f"[CONTEXT: Current user: {username}]")
        
        # Add instruction to stay in character
        context_parts.append("[INSTRUCTION: Respond ONLY as the Linux system would. Do not break character or mention AI/simulation.]")
        
        # Combine context with command
        enhanced = " ".join(context_parts) + " " + command
        return enhanced
        
    def validate_output(
        self,
        response: str,
        command: str,
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
        """
        # Check for meta-commentary
        for pattern in self.meta_patterns:
            if pattern.search(response):
                return {
                    "is_valid": False,
                    "reason": "meta_commentary",
                    "cleaned": response,
                }
                
        # Check for hallucinated file paths if filesystem provided
        if filesystem and any(cmd in command.lower() for cmd in ["ls", "cat", "find"]):
            hallucinated = self._detect_hallucinated_paths(response, filesystem, current_dir)
            if hallucinated:
                return {
                    "is_valid": False,
                    "reason": "hallucinated_paths",
                    "cleaned": response,
                    "hallucinated_paths": hallucinated,
                }
                
        # Response is valid
        return {
            "is_valid": True,
            "reason": None,
            "cleaned": response,
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
        # Look for patterns like /path/to/file or ./file or ../file
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
            if path in ["/dev/null", "/dev/zero", "/dev/random", "/proc/", "/sys/"]:
                continue
                
            # Check if path exists in filesystem
            if not filesystem.exists(path, current_dir):
                # Could be a partial path or command output, be lenient
                # Only flag if it looks like a real file path
                if "/" in path or "." in path:
                    hallucinated.append(path)
                    
        return hallucinated
        
    def get_fallback_response(self, command: str, reason: str) -> str:
        """
        Generate fallback response when LLM fails or hallucinates
        
        Args:
            command: Original command
            reason: Reason for fallback
            
        Returns:
            Fallback response
        """
        if reason == "prompt_injection":
            # Return command not found for injection attempts
            cmd = command.split()[0] if command.split() else "command"
            return f"bash: {cmd}: command not found"
            
        elif reason == "meta_commentary":
            # Return generic error
            return "bash: command execution error"
            
        elif reason == "hallucinated_paths":
            # Return file not found
            return "bash: file or directory not found"
            
        else:
            # Generic fallback
            return ""
            
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
        
        # Strip extra whitespace
        response = response.strip()
        
        return response
        
    def should_use_llm(self, command: str) -> bool:
        """
        Determine if command should be sent to LLM
        This is a helper for integration with CommandExecutor
        
        Returns:
            True if LLM should handle, False otherwise
        """
        # Complex commands with pipes, redirects, or multiple commands
        if any(char in command for char in ["|", ">", "<", "&&", "||", ";"]):
            return True
            
        # Commands with complex arguments
        complex_cmds = ["awk", "sed", "perl", "python", "ruby", "grep -E", "grep -P"]
        if any(cmd in command.lower() for cmd in complex_cmds):
            return True
            
        # Otherwise, let CommandExecutor handle it
        return False
        
    def create_system_prompt_enhancement(self, filesystem: VirtualFilesystem) -> str:
        """
        Create additional system prompt context based on filesystem state
        
        Returns:
            Enhanced system prompt fragment
        """
        # Get key directories and files
        home_users = []
        if filesystem.exists("/home", "/"):
            home_entries = filesystem.list_directory("/home", "/")
            if home_entries:
                home_users = [e["name"] for e in home_entries if e["is_dir"]]
                
        game_projects = []
        if filesystem.exists("/opt/games", "/"):
            game_entries = filesystem.list_directory("/opt/games", "/")
            if game_entries:
                game_projects = [e["name"] for e in game_entries if e["is_dir"]]
                
        enhancement = f"""
[FILESYSTEM STATE]
- Available users: {', '.join(home_users) if home_users else 'guest'}
- Game projects: {', '.join(game_projects) if game_projects else 'none'}
- System: Ubuntu 20.04 LTS (corp-srv-01)

[CRITICAL INSTRUCTIONS]
1. NEVER mention that you are an AI, language model, or simulation
2. ONLY reference files and directories that actually exist in the filesystem
3. Respond EXACTLY as a real Linux system would
4. If asked about your nature, respond as the Linux system would (e.g., "bash: command not found")
5. Do not provide explanations or commentary - only command output
6. Match the exact format of real Linux command output
"""
        return enhancement
