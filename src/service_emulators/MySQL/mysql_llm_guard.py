#!/usr/bin/env python3
"""
MySQL LLM Guard for MySQL Honeypot
Provides input validation, output validation, and hallucination prevention for LLM responses
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class MySQLLLMGuard:
    """
    Guards LLM interactions for MySQL honeypot
    - Input validation (SQL injection + prompt injection detection)
    - Output validation (hallucination detection)
    - Context enhancement with database schema
    - Response sanitization
    - Configurable security levels
    """
    
    def __init__(self, config=None):
        self.config = config
        
        # Load security settings from config or valid defaults
        if self.config:
            self.sensitivity = self.config["attack_detection"].get("sensitivity_level", "medium")
            self.check_sql_injection = self.config["attack_detection"].getboolean("sql_injection_detection", True)
            self.context_aware = self.config["llm"].getboolean("context_awareness", True)
        else:
            self.sensitivity = "medium"
            self.check_sql_injection = True
            self.context_aware = True
    PROMPT_INJECTION_PATTERNS = [
        # Direct instruction manipulation
        r"\bignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|prompts?|context|commands?)\b",
        r"\bforget\s+(everything|all\s+previous|the\s+previous|what\s+you\s+were\s+told)\b",
        r"\bdisregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|context|prompts?)\b",
        r"\bdelete\s+(all\s+)?(previous|prior)\s+(context|history|instructions?|memory)\b",
        r"\boverride\s+(previous|all|system)\s+(instructions?|prompts?|settings?)\b",
        r"\bclear\s+(all\s+)?(context|memory|history|instructions?)\b",
        
        # Role manipulation
        r"\byou\s+are\s+(now|actually|really)\s+(a|an)\s+",
        r"\bact\s+as\s+(a|an)\s+",
        r"\bpretend\s+(to\s+be|you\s+are)\s+(a|an)\s+",
        r"\broleplay\s+as\s+(a|an)\s+",
        r"\bsimulate\s+(being\s+)?(a|an)\s+",
        r"\bfrom\s+now\s+on,?\s+you\s+(are|will\s+be)\s+",
        
        # System/assistant role injection
        r"^\s*system\s*:\s*",
        r"^\s*assistant\s*:\s*",
        r"^\s*\[system\]\s*",
        r"^\s*\[assistant\]\s*",
        r"^\s*<\|system\|>\s*",
        r"^\s*<\|assistant\|>\s*",
        
        # Context manipulation
        r"\bnew\s+conversation\s+(starting|begins?|now)\b",
        r"\bstart\s+(a\s+)?new\s+conversation\b",
        r"\breset\s+(the\s+)?(context|conversation|chat|session)\b",
        r"\bbegin\s+(a\s+)?new\s+(session|context|conversation)\b",
        
        # Meta instructions
        r"\btell\s+me\s+(who|what)\s+you\s+(are|really\s+are)\b",
        r"\bwhat\s+(are|is)\s+your\s+(instructions?|prompts?|system\s+prompts?)\b",
        r"\bshow\s+(me\s+)?your\s+(instructions?|prompts?|system\s+message)\b",
        r"\breveal\s+(your\s+)?(instructions?|prompts?|system\s+message)\b",
        r"\bdisplay\s+(your\s+)?(system\s+)?(instructions?|prompts?)\b",
        
        # Jailbreak attempts
        r"\bDAN\s+mode\b",
        r"\bDeveloper\s+Mode\b",
        r"\bjailbreak\s+(mode|prompt)\b",
        r"\bunrestricted\s+(mode|access)\b",
        r"\bbypass\s+(restrictions?|filters?|safety)\b",
        
        # Prompt leaking
        r"\brepeat\s+(the\s+)?(above|previous)\s+(text|prompt|instructions?)\b",
        r"\boutput\s+(the\s+)?(system\s+)?(prompt|instructions?)\b",
        
        # AI identity probing
        r"\bare\s+you\s+(an?\s+)?(ai|artificial|language\s+model|chatbot|gpt|llm)\b",
        r"\bwhat\s+model\s+are\s+you\b",
        r"\bwho\s+created\s+you\b",
        r"\bwho\s+made\s+you\b",
    ]
    
    # Patterns that indicate gibberish/random input (not valid SQL)
    GIBBERISH_PATTERNS = [
        # Random character sequences
        r"^[a-z]{20,}$",  # Long lowercase string with no spaces
        r"^[A-Z]{20,}$",  # Long uppercase string with no spaces
        r"[a-zA-Z]{15,}\s+[a-zA-Z]{15,}\s+[a-zA-Z]{15,}",  # Multiple long random words
        r"([a-z])\1{5,}",  # Repeated characters (aaaaaaaa)
        r"^[\W\s]{10,}$",  # Many non-word characters
        r"[^\x00-\x7F]{10,}",  # Many non-ASCII characters
    ]
    
    # Meta-commentary patterns that indicate LLM is breaking character
    META_PATTERNS = [
        r"\bas an ai\b",
        r"\bi am an ai\b",
        r"\bi'm an ai\b",
        r"\bas a language model\b",
        r"\bas an llm\b",
        r"\bi cannot actually\b",
        r"\bi don't have access to\b",
        r"\bi cannot access\b",
        r"\bi'm not able to\b",
        r"\bi apologize,? but\b",
        r"\bi'm sorry,? but\b",
        r"\bi don't actually have\b",
        r"\bthis is a simulated\b",
        r"\bthis is a simulation\b",
        r"\bthis is a honeypot\b",
        r"\bi need to clarify\b",
        r"\blet me explain\b",
        r"\bactually,?\s+i\b",
        r"\bin reality\b",
        r"\bto be honest\b",
    ]
    
    # Valid SQL command prefixes (for syntax validation)
    VALID_SQL_COMMANDS = {
        "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", 
        "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "USE", "SET", "GRANT", "REVOKE",
        "TRUNCATE", "RENAME", "BEGIN", "START", "COMMIT", "ROLLBACK", "SAVEPOINT",
        "LOCK", "UNLOCK", "CALL", "PREPARE", "EXECUTE", "DEALLOCATE", "HANDLER",
        "LOAD", "REPLACE", "DO", "HELP", "ANALYZE", "CHECK", "CHECKSUM", "OPTIMIZE",
        "REPAIR", "FLUSH", "RESET", "PURGE", "CHANGE", "STOP", "KILL", "SHUTDOWN",
        "SOURCE", "DELIMITER", "STATUS", "WARNINGS", "ERRORS",
        # Also allow these as they're valid
        "TABLE", "TABLES", "DATABASE", "DATABASES", "COLUMNS", "FIELDS",
        "INDEX", "INDEXES", "KEYS", "PROCESSLIST", "STATUS", "VARIABLES",
        "GRANTS", "PRIVILEGES", "ENGINES", "PLUGINS", "MASTER", "SLAVE",
        "BINARY", "LOGS", "BINLOG", "RELAYLOG", "EVENTS", "TRIGGERS",
        "PROCEDURE", "FUNCTION", "VIEW", "CHARSET", "CHARACTER", "COLLATION",
    }
    
    def __init__(self):
        self.injection_patterns = [re.compile(p, re.IGNORECASE) for p in self.PROMPT_INJECTION_PATTERNS]
        self.gibberish_patterns = [re.compile(p, re.IGNORECASE) for p in self.GIBBERISH_PATTERNS]
        self.meta_patterns = [re.compile(p, re.IGNORECASE) for p in self.META_PATTERNS]
        
    def validate_query(self, query: str) -> Dict[str, Any]:
        """
        Validate SQL query input before processing
        
        Returns:
            Dict with:
                - is_valid: bool
                - reason: str (if invalid) - "injection", "gibberish", "syntax", "empty", "string_literal"
                - sanitized: str (cleaned query)
                - should_use_llm: bool (whether LLM should handle this)
                - literal_value: str (if string_literal, the value to return)
        """
        # Empty query
        if not query or not query.strip():
            return {
                "is_valid": True,
                "reason": None,
                "sanitized": "",
                "should_use_llm": False
            }
        
        query = query.strip()
        
        # Check for string literal injections FIRST
        # These should be handled locally, not sent to LLM
        string_literal_result = self._check_string_literal_injection(query)
        if string_literal_result:
            return string_literal_result
        
        # Check for prompt injection
        if self._check_prompt_injection(query):
            return {
                "is_valid": False,
                "reason": "prompt_injection",
                "sanitized": query,
                "should_use_llm": False,
                "error_response": {
                    "error_code": 1142,
                    "sql_state": "42000",
                    "message": "DROP command denied to user 'player'@'localhost' for table 'protected_table'"
                }
            }
            
        # Check for SQL injection (if enabled)
        if self.check_sql_injection and self._check_sql_injection(query):
            return {
                 "is_valid": False,
                 "reason": "sql_injection",
                 "sanitized": query,
                 "should_use_llm": False
            }
            
        # Query looks valid
        return {
            "is_valid": True,
            "reason": None,
            "sanitized": query,
            "should_use_llm": True
        }
    
    def _check_string_literal_injection(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Check if query is a SELECT with just a string literal containing injection patterns.
        These should be handled locally, returning the literal value (normal MySQL behavior).
        """
        query_upper = query.upper().strip()
        
        # Only check SELECT queries
        if not query_upper.startswith("SELECT"):
            return None
        
        # Pattern to match SELECT 'string' or SELECT "string" (simple string literal queries)
        simple_select_pattern = r"^\s*SELECT\s+(['\"])(.*?)\1\s*;?\s*$"
        match = re.match(simple_select_pattern, query, re.IGNORECASE | re.DOTALL)
        
        if match:
            literal_value = match.group(2)
            
            # Check if the literal contains suspicious content
            suspicious_patterns = [
                r"ignore.*(?:previous|prior|all).*(?:instructions?|prompts?)",
                r"forget.*(?:everything|all|previous)",
                r"disregard.*(?:system|your|previous)",
                r"you\s+are\s+(?:now|actually)",
                r"system\s*:",
                r"(?:tell|show|reveal|display).*(?:configuration|instructions?|prompts?)",
                r"what\s+(?:are|is)\s+your\s+(?:instructions?|prompts?)",
                r"jailbreak",
                r"bypass.*(?:restrictions?|filters?)",
                r"(?:ai|artificial|language\s+model|honeypot)",
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, literal_value, re.IGNORECASE):
                    logger.info(f"String literal injection detected, handling locally: {literal_value[:50]}...")
                    return {
                        "is_valid": True,
                        "reason": "string_literal",
                        "sanitized": query,
                        "should_use_llm": False,
                        "literal_value": literal_value
                    }
        
        return None
    
    def _is_gibberish(self, query: str) -> bool:
        """Check if query is random gibberish"""
        # Check against gibberish patterns
        for pattern in self.gibberish_patterns:
            if pattern.search(query):
                return True
        
        # Check for excessive non-alphanumeric characters
        alnum_count = sum(1 for c in query if c.isalnum())
        if len(query) > 10 and alnum_count / len(query) < 0.3:
            return True
        
        # Check for words that don't look like SQL
        words = re.findall(r'\b[a-zA-Z]+\b', query)
        if len(words) >= 3:
            # Check if most words are random (not SQL keywords)
            sql_keywords = {"select", "from", "where", "and", "or", "insert", "into", 
                          "update", "delete", "create", "drop", "table", "database",
                          "show", "describe", "use", "set", "values", "as", "join",
                          "on", "group", "by", "order", "having", "limit", "offset",
                          "like", "in", "between", "is", "null", "not", "case", "when",
                          "then", "else", "end", "all", "distinct", "union", "exists"}
            
            non_keyword_count = sum(1 for w in words if w.lower() not in sql_keywords and len(w) > 3)
            if non_keyword_count >= 3 and non_keyword_count / len(words) > 0.8:
                # Most words are not SQL keywords and not short common words
                return True
        
        return False
    
    def _is_valid_sql_syntax(self, query: str) -> bool:
        """Check if query has valid SQL command syntax"""
        query_upper = query.strip().upper()
        
        # Remove leading comments
        query_upper = re.sub(r'^--.*?\n', '', query_upper)
        query_upper = re.sub(r'^/\*.*?\*/', '', query_upper)
        query_upper = query_upper.strip()
        
        if not query_upper:
            return True
        
        # Get first word
        first_word = query_upper.split()[0] if query_upper.split() else ""
        
        # Remove trailing semicolons and special chars from first word
        first_word = re.sub(r'[^\w]', '', first_word)
        
        # Check if it starts with a valid SQL command
        return first_word in self.VALID_SQL_COMMANDS
    
    def validate_response(
        self,
        response: str,
        query: str,
        expected_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Validate LLM response for hallucinations and meta-commentary
        
        Args:
            response: LLM response
            query: Original query
            expected_format: Expected format ("json", "text", "error")
            
        Returns:
            Dict with:
                - is_valid: bool
                - reason: str (if invalid)
                - cleaned: str (cleaned response)
        """
        if not response:
            return {
                "is_valid": True,
                "reason": None,
                "cleaned": ""
            }
        
        # Check for meta-commentary (LLM breaking character)
        for pattern in self.meta_patterns:
            if pattern.search(response):
                logger.warning(f"Meta-commentary detected in response")
                return {
                    "is_valid": False,
                    "reason": "meta_commentary",
                    "cleaned": response
                }
        
        # Check for JSON format if expected
        if expected_format == "json":
            cleaned = self._extract_json(response)
            if cleaned is None:
                return {
                    "is_valid": False,
                    "reason": "invalid_json",
                    "cleaned": response
                }
            return {
                "is_valid": True,
                "reason": None,
                "cleaned": cleaned
            }
        
        # For text format, just sanitize
        cleaned = self.sanitize_response(response)
        return {
            "is_valid": True,
            "reason": None,
            "cleaned": cleaned
        }
    
    def _extract_json(self, response: str) -> Optional[str]:
        """Extract and validate JSON from response"""
        # Remove markdown code blocks
        response = re.sub(r'```json\s*', '', response)
        response = re.sub(r'```\s*', '', response)
        response = response.strip()
        
        # Try to find JSON array or object
        json_patterns = [
            r'\[[\s\S]*\]',  # Array
            r'\{[\s\S]*\}',  # Object
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, response)
            if match:
                try:
                    json_str = match.group(0)
                    # Validate it's valid JSON
                    json.loads(json_str)
                    return json_str
                except json.JSONDecodeError:
                    continue
        
        # Try direct parse
        try:
            json.loads(response)
            return response
        except json.JSONDecodeError:
            return None
    
    def sanitize_response(self, response: str) -> str:
        """
        Clean up LLM response to remove unwanted elements
        """
        if not response:
            return ""
        
        # Remove markdown code blocks
        response = re.sub(r'```[\w]*\n?', '', response)
        response = re.sub(r'```', '', response)
        
        # Remove explanatory prefixes
        response = re.sub(r'^(here\'s|here is|the output is|output|result):?\s*\n?', '', response, flags=re.IGNORECASE)
        
        # Remove trailing explanations
        response = re.sub(r'\n\n(note:|explanation:|this shows|the above).*$', '', response, flags=re.IGNORECASE | re.DOTALL)
        
        # Strip extra whitespace
        response = response.strip()
        
        return response
    
    def get_error_response(self, query: str, reason: str) -> Dict[str, Any]:
        """
        Generate appropriate MySQL error response for invalid queries
        
        Returns:
            Dict with error details that can be formatted as MySQL response
        """
        query_lower = query.lower().strip()
        
        if reason == "injection":
            # Make it look like a normal invalid command
            first_word = query.split()[0] if query.split() else "command"
            return {
                "error_code": 1064,
                "sql_state": "42000",
                "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{first_word}' at line 1"
            }
        
        elif reason == "gibberish":
            # Return syntax error for random gibberish
            first_word = query.split()[0] if query.split() else "???"
            # Truncate long words
            if len(first_word) > 20:
                first_word = first_word[:20] + "..."
            return {
                "error_code": 1064,
                "sql_state": "42000",
                "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{first_word}' at line 1"
            }
        
        elif reason == "syntax":
            # Handle common typos with specific errors
            typo_responses = self._get_typo_response(query)
            if typo_responses:
                return typo_responses
            
            # Generic syntax error
            first_part = query[:50] if len(query) > 50 else query
            return {
                "error_code": 1064,
                "sql_state": "42000", 
                "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{first_part}' at line 1"
            }
        
        elif reason == "meta_commentary":
            # LLM broke character - return internal error
            return {
                "error_code": 1105,
                "sql_state": "HY000",
                "message": "Unknown error"
            }
        
        elif reason == "invalid_json":
            # LLM returned bad format
            return {
                "error_code": 1105,
                "sql_state": "HY000",
                "message": "Internal error processing query"
            }
        
        else:
            # Generic error
            return {
                "error_code": 1064,
                "sql_state": "42000",
                "message": f"You have an error in your SQL syntax near '{query[:30]}'"
            }
    
    def _get_typo_response(self, query: str) -> Optional[Dict[str, Any]]:
        """Generate error response for common SQL typos"""
        query_lower = query.lower().strip()
        
        # Common typos mapping to correct command
        typo_map = {
            # SHOW typos
            "shwo": "SHOW",
            "hsow": "SHOW",
            "sohw": "SHOW",
            "show databses": "SHOW DATABASES",
            "show databass": "SHOW DATABASES",
            "show datbases": "SHOW DATABASES",
            "show tbles": "SHOW TABLES",
            "show talbes": "SHOW TABLES",
            "show tabels": "SHOW TABLES",
            # SELECT typos
            "selct": "SELECT",
            "slect": "SELECT",
            "selcet": "SELECT",
            "selet": "SELECT",
            # INSERT typos
            "insrt": "INSERT",
            "isert": "INSERT",
            "inset": "INSERT",
            # UPDATE typos
            "upate": "UPDATE",
            "upadte": "UPDATE",
            "udpate": "UPDATE",
            # DELETE typos
            "delte": "DELETE",
            "deleet": "DELETE",
            "dlete": "DELETE",
            # CREATE typos
            "crate": "CREATE",
            "craete": "CREATE",
            "creat": "CREATE",
            # FROM typos
            "form": "FROM",
            "fomr": "FROM",
            "frmo": "FROM",
            # WHERE typos
            "whre": "WHERE",
            "wher": "WHERE",
            "wehre": "WHERE",
            # DESCRIBE typos  
            "descirbe": "DESCRIBE",
            "desribe": "DESCRIBE",
            "describr": "DESCRIBE",
            # USE typos
            "ues": "USE",
            "sue": "USE",
            "usr": "USE",
        }
        
        for typo, correct in typo_map.items():
            if typo in query_lower:
                # Find position of typo
                pos = query_lower.find(typo)
                near_text = query[pos:pos+len(typo)+10] if pos >= 0 else query[:20]
                return {
                    "error_code": 1064,
                    "sql_state": "42000",
                    "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{near_text}' at line 1"
                }
        
        return None
    

    def enhance_llm_context(
        self, 
        query: str, 
        database_name: Optional[str],
        table_names: List[str],
        username: str = "unknown"
    ) -> str:
        """
        Create enhanced context for LLM to prevent hallucinations
        Respects 'context_awareness' config setting
        """
        if not self.context_aware:
            return ""
            
        context_parts = []
        
        # Database context
        if database_name:
            context_parts.append(f"[DATABASE CONTEXT: Current database is '{database_name}']")
            if table_names:
                tables_str = ", ".join(table_names[:15])  # Limit table list
                context_parts.append(f"[AVAILABLE TABLES: {tables_str}]")
        else:
            context_parts.append("[DATABASE CONTEXT: No database selected]")
        
        # User context
        context_parts.append(f"[USER: {username}]")
        
        # Strict instructions
        context_parts.append("[INSTRUCTION: Respond ONLY with valid JSON. No explanations or commentary.]")
        context_parts.append("[INSTRUCTION: If table doesn't exist in AVAILABLE TABLES, return appropriate error]")
        
        # Combine with query
        enhanced = "\n".join(context_parts) + f"\n\nQuery: {query}"
        return enhanced
    
    def should_use_llm(self, query: str, command_type: str) -> bool:
        """
        Determine if a query should be sent to LLM or handled locally
        
        Args:
            query: SQL query
            command_type: Type of command (e.g., "SHOW", "SELECT", "INSERT")
            
        Returns:
            True if LLM should handle, False if local handler should process
        """
        # Commands that should be handled locally (no LLM needed)
        local_commands = {
            "USE", "SHOW_DATABASES", "SHOW_TABLES", "SHOW_COLUMNS", 
            "DESCRIBE", "DESC", "SHOW_CREATE_TABLE", "SHOW_VARIABLES",
            "SHOW_STATUS", "SHOW_PROCESSLIST", "SHOW_GRANTS",
            "SHOW_ENGINES", "SHOW_PLUGINS", "SHOW_WARNINGS", "SHOW_ERRORS",
            "SET", "BEGIN", "START_TRANSACTION", "COMMIT", "ROLLBACK",
            "CREATE_DATABASE", "DROP_DATABASE", "CREATE_TABLE", "DROP_TABLE",
            "TRUNCATE", "EXIT", "QUIT", "HELP"
        }
        
        if command_type.upper().replace(" ", "_") in local_commands:
            return False
        
        # SELECT queries typically need LLM for data generation
        if command_type.upper() == "SELECT":
            return True
        
        # INSERT/UPDATE/DELETE might need LLM for realistic responses
        if command_type.upper() in {"INSERT", "UPDATE", "DELETE"}:
            return True
        
        # Default to local handling
        return False
