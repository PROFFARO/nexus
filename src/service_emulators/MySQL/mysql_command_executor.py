#!/usr/bin/env python3
"""
MySQL Command Executor for MySQL Honeypot
Handles SQL command validation, routing, and execution with support for 50+ MySQL commands
"""

import datetime
import logging
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from mysql_database import MySQLDatabaseSystem, Database, Table, Column
from mysql_llm_guard import MySQLLLMGuard

logger = logging.getLogger(__name__)


class MySQLCommandExecutor:
    """
    Executes MySQL commands with validation and routing
    - Validates SQL syntax
    - Detects prompt injection
    - Routes to local handlers or LLM
    - Handles metadata commands, DDL, DML, session commands
    """
    
    def __init__(self, database_system: MySQLDatabaseSystem, llm_guard: MySQLLLMGuard, config=None):
        self.db = database_system
        self.guard = llm_guard
        self.config = config
        self.start_time = datetime.datetime.now()
        self.query_count = 0
        self.connection_id = random.randint(1000000, 9999999)
        
        # Load settings
        if self.config:
            self.schema_evolution = self.config["database_simulation"].getboolean("schema_evolution", True)
            self.deception_techniques = self.config["ai_features"].getboolean("deception_techniques", True)
        else:
            self.schema_evolution = True
            self.deception_techniques = True
        
    def execute(
        self,
        query: str,
        username: str = "unknown",
        client_ip: str = "unknown"
    ) -> Tuple[Optional[Any], str, Optional[Dict[str, Any]]]:
        """
        Execute a MySQL query
        
        Args:
            query: SQL query string
            username: Current username
            client_ip: Client IP address
            
        Returns:
            Tuple of (result, routing, error_info)
            - result: Query result (rows) or None if should use LLM
            - routing: "local", "llm", "error"
            - error_info: Error details if routing is "error"
        """
        self.query_count += 1
        
        if not query or not query.strip():
            return ([], "local", None)
        
        # Check for trailing/multiple semicolons before stripping
        original_query = query.strip()
        if original_query.endswith(';;') or ';;' in original_query:
            return (None, "error", {
                "error_code": 1064,
                "sql_state": "42000",
                "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ';' at line 1"
            })
        
        query = original_query.rstrip(";")
        
        # Run strict syntax validation FIRST
        syntax_error = self._validate_strict_syntax(query)
        if syntax_error:
            return (None, "error", syntax_error)
        
        # Validate query (injection + basic syntax check via guard)
        validation = self.guard.validate_query(query)
        
        if not validation["is_valid"]:
            error_info = self.guard.get_error_response(query, validation["reason"])
            return (None, "error", error_info)
        
        # Handle string literal injections locally (don't send to LLM)
        if validation.get("reason") == "string_literal":
            literal = validation.get("literal_value", "")
            # Return as a simple result like MySQL would
            return ([{literal: literal}], "local", None)
        
        # Classify and route the command
        command_type = self._classify_query(query)
        
        # Try to handle locally first
        result = self._execute_local(query, command_type, username)
        if result is not None:
            return (result, "local", None)
        
        # Route to LLM only if we can't handle locally
        return (None, "llm", None)
    
    def _validate_strict_syntax(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Strict SQL syntax validation to catch typos and malformed queries.
        Returns error dict if invalid, None if valid.
        """
        query_upper = query.upper().strip()
        query_lower = query.lower().strip()
        
        # ===== Check for common SQL keyword typos =====
        typo_check = self._check_keyword_typos(query_lower)
        if typo_check:
            return typo_check
        
        # ===== Validate SHOW command syntax =====
        if query_upper.startswith("SHOW"):
            show_error = self._validate_show_syntax(query_upper, query)
            if show_error:
                return show_error
        
        # ===== Validate SELECT syntax =====
        if query_upper.startswith("SELECT"):
            select_error = self._validate_select_syntax(query_upper, query)
            if select_error:
                return select_error
        
        return None
    
    def _check_keyword_typos(self, query_lower: str) -> Optional[Dict[str, Any]]:
        """Check for common SQL keyword typos"""
        # Define typo patterns: (typo_regex, near_text_extractor)
        typo_patterns = [
            # WHERE typos
            (r'\bwere\b(?!\s+you)', 'were'),
            (r'\bwhre\b', 'whre'),
            (r'\bwher\b(?!\s)', 'wher'),
            (r'\bwehre\b', 'wehre'),
            (r'\bwehere\b', 'wehere'),
            # FROM typos
            (r'\bform\b(?!\s+data)', 'form'),
            (r'\bfomr\b', 'fomr'),
            (r'\bfrmo\b', 'frmo'),
            (r'\bfrom\s+form\b', 'form'),
            # SELECT typos
            (r'^selec\b', 'selec'),
            (r'^slect\b', 'slect'),
            (r'^selcet\b', 'selcet'),
            (r'^selet\b', 'selet'),
            (r'^seelct\b', 'seelct'),
            # INSERT typos
            (r'^insrt\b', 'insrt'),
            (r'^isert\b', 'isert'),
            (r'^inset\b', 'inset'),
            (r'^inesrt\b', 'inesrt'),
            # UPDATE typos
            (r'^upate\b', 'upate'),
            (r'^upadte\b', 'upadte'),
            (r'^udpate\b', 'udpate'),
            (r'^updaet\b', 'updaet'),
            # DELETE typos
            (r'^delte\b', 'delte'),
            (r'^deleet\b', 'deleet'),
            (r'^dlete\b', 'dlete'),
            (r'^deelte\b', 'deelte'),
            # CREATE typos
            (r'^crate\b', 'crate'),
            (r'^craete\b', 'craete'),
            (r'^creat\b(?!e)', 'creat'),
            # DROP typos
            (r'^drpo\b', 'drpo'),
            (r'^dorp\b', 'dorp'),
            (r'^drrop\b', 'drrop'),
            # TABLE typos
            (r'\btabel\b', 'tabel'),
            (r'\btabel\b', 'tabel'),
            (r'\btble\b', 'tble'),
            # DATABASE typos
            (r'\bdatabse\b', 'databse'),
            (r'\bdatabass\b', 'databass'),
            (r'\bdatbase\b', 'datbase'),
            # DESCRIBE typos
            (r'^descirbe\b', 'descirbe'),
            (r'^desribe\b', 'desribe'),
            (r'^describr\b', 'describr'),
        ]
        
        for pattern, near_text in typo_patterns:
            if re.search(pattern, query_lower):
                return {
                    "error_code": 1064,
                    "sql_state": "42000",
                    "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{near_text}' at line 1"
                }
        
        return None
    
    def _validate_show_syntax(self, query_upper: str, original_query: str) -> Optional[Dict[str, Any]]:
        """Validate SHOW command has valid target"""
        # Extract what comes after SHOW
        show_match = re.match(r'^SHOW\s+(.+)$', query_upper)
        if not show_match:
            return {
                "error_code": 1064,
                "sql_state": "42000",
                "message": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1"
            }
        
        show_target = show_match.group(1).strip()
        first_word = show_target.split()[0] if show_target.split() else ""
        
        # Valid SHOW targets
        valid_show_targets = {
            "DATABASES", "TABLES", "COLUMNS", "FIELDS", "INDEX", "INDEXES", "KEYS",
            "CREATE", "VARIABLES", "STATUS", "PROCESSLIST", "GRANTS", "PRIVILEGES",
            "ENGINES", "PLUGINS", "WARNINGS", "ERRORS", "MASTER", "SLAVE", "BINARY",
            "BINLOG", "LOGS", "RELAYLOG", "EVENTS", "TRIGGERS", "PROCEDURE", "FUNCTION",
            "TABLE", "FULL", "EXTENDED", "GLOBAL", "SESSION", "STORAGE", "CHARACTER",
            "CHARSET", "COLLATION", "OPEN", "PROFILES", "PROFILE", "COUNT", "SCHEMAS",
        }
        
        if first_word and first_word not in valid_show_targets:
            # Check for common typos of SHOW targets
            show_typos = {
                "DATABSES": "DATABASES", "DATABASS": "DATABASES", "DATBASES": "DATABASES",
                "DATABASESL": "DATABASES", "DATABASSES": "DATABASES", "DATABAES": "DATABASES",
                "TBLES": "TABLES", "TALBES": "TABLES", "TABELS": "TABLES", 
                "TABLESL": "TABLES", "TABES": "TABLES", "TBALES": "TABLES",
                "COLUMS": "COLUMNS", "COLUMSN": "COLUMNS", "COULMNS": "COLUMNS",
                "VARAIBLES": "VARIABLES", "VARIBLES": "VARIABLES", "VARIABELS": "VARIABLES",
                "STAUS": "STATUS", "STAUTS": "STATUS", "STATTUS": "STATUS",
                "PORCESSLIST": "PROCESSLIST", "PRCESSLIST": "PROCESSLIST",
                "ENGIENS": "ENGINES", "EINGINES": "ENGINES",
                "GRANTES": "GRANTS", "GRNATS": "GRANTS",
            }
            
            if first_word in show_typos:
                near_text = first_word.lower()
            else:
                near_text = first_word.lower() if len(first_word) < 20 else first_word[:20].lower()
            
            return {
                "error_code": 1064,
                "sql_state": "42000",
                "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{near_text}' at line 1"
            }
        
        return None
    
    def _validate_select_syntax(self, query_upper: str, original_query: str) -> Optional[Dict[str, Any]]:
        """Validate SELECT syntax"""
        # Simple SELECT without FROM is valid: SELECT 1, SELECT 'text', SELECT @@var
        # But SELECT * without FROM is not valid
        
        # Check for SELECT * FROM or SELECT columns FROM
        if re.search(r'\*\s*$', query_upper) and 'FROM' not in query_upper:
            # SELECT * without FROM - error
            return {
                "error_code": 1064,
                "sql_state": "42000",
                "message": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SELECT *' at line 1"
            }
        
        # Check if query mentions column names (not just literals) without FROM
        # This is complex, so we only check for obvious errors
        
        return None
    
    def _classify_query(self, query: str) -> str:
        """Classify MySQL query type"""
        query_upper = query.upper().strip()
        
        # Remove comments
        query_upper = re.sub(r'--.*$', '', query_upper, flags=re.MULTILINE)
        query_upper = re.sub(r'/\*.*?\*/', '', query_upper, flags=re.DOTALL)
        query_upper = query_upper.strip()
        
        if not query_upper:
            return "EMPTY"
        
        # SHOW commands
        if query_upper.startswith("SHOW"):
            if "DATABASES" in query_upper:
                return "SHOW_DATABASES"
            elif "TABLES" in query_upper:
                return "SHOW_TABLES"
            elif "COLUMNS" in query_upper or "FIELDS" in query_upper:
                return "SHOW_COLUMNS"
            elif "CREATE TABLE" in query_upper:
                return "SHOW_CREATE_TABLE"
            elif "CREATE DATABASE" in query_upper:
                return "SHOW_CREATE_DATABASE"
            elif "VARIABLES" in query_upper:
                return "SHOW_VARIABLES"
            elif "STATUS" in query_upper:
                return "SHOW_STATUS"
            elif "PROCESSLIST" in query_upper:
                return "SHOW_PROCESSLIST"
            elif "GRANTS" in query_upper:
                return "SHOW_GRANTS"
            elif "ENGINES" in query_upper:
                return "SHOW_ENGINES"
            elif "PLUGINS" in query_upper:
                return "SHOW_PLUGINS"
            elif "WARNINGS" in query_upper:
                return "SHOW_WARNINGS"
            elif "ERRORS" in query_upper:
                return "SHOW_ERRORS"
            elif "INDEX" in query_upper or "INDEXES" in query_upper or "KEYS" in query_upper:
                return "SHOW_INDEX"
            elif "MASTER" in query_upper:
                return "SHOW_MASTER"
            elif "SLAVE" in query_upper:
                return "SHOW_SLAVE"
            elif "BINARY" in query_upper or "BINLOG" in query_upper:
                return "SHOW_BINLOG"
            elif "CHARSET" in query_upper or "CHARACTER SET" in query_upper:
                return "SHOW_CHARSET"
            elif "COLLATION" in query_upper:
                return "SHOW_COLLATION"
            # Unrecognized SHOW command - return as SHOW_UNKNOWN for error handling
            return "SHOW_UNKNOWN"
        
        # DESCRIBE / DESC
        if query_upper.startswith("DESCRIBE") or query_upper.startswith("DESC "):
            return "DESCRIBE"
        
        # USE database
        if query_upper.startswith("USE "):
            return "USE"
        
        # SELECT
        if query_upper.startswith("SELECT"):
            if "@@" in query_upper:
                return "SELECT_VARIABLE"
            if "DATABASE()" in query_upper:
                return "SELECT_DATABASE"
            if "USER()" in query_upper or "CURRENT_USER" in query_upper:
                return "SELECT_USER"
            if "VERSION()" in query_upper:
                return "SELECT_VERSION"
            if "FROM INFORMATION_SCHEMA" in query_upper:
                return "SELECT_INFO_SCHEMA"
            return "SELECT"
        
        # INSERT
        if query_upper.startswith("INSERT"):
            return "INSERT"
        
        # UPDATE
        if query_upper.startswith("UPDATE"):
            return "UPDATE"
        
        # DELETE
        if query_upper.startswith("DELETE"):
            return "DELETE"
        
        # CREATE
        if query_upper.startswith("CREATE"):
            if "DATABASE" in query_upper:
                return "CREATE_DATABASE"
            elif "TABLE" in query_upper:
                return "CREATE_TABLE"
            elif "USER" in query_upper:
                return "CREATE_USER"
            elif "INDEX" in query_upper:
                return "CREATE_INDEX"
            return "CREATE"
        
        # DROP
        if query_upper.startswith("DROP"):
            if "DATABASE" in query_upper:
                return "DROP_DATABASE"
            elif "TABLE" in query_upper:
                return "DROP_TABLE"
            elif "USER" in query_upper:
                return "DROP_USER"
            elif "INDEX" in query_upper:
                return "DROP_INDEX"
            return "DROP"
        
        # ALTER
        if query_upper.startswith("ALTER"):
            if "TABLE" in query_upper:
                return "ALTER_TABLE"
            elif "USER" in query_upper:
                return "ALTER_USER"
            elif "DATABASE" in query_upper:
                return "ALTER_DATABASE"
            return "ALTER"
        
        # TRUNCATE
        if query_upper.startswith("TRUNCATE"):
            return "TRUNCATE"
        
        # Transaction commands
        if query_upper.startswith("BEGIN") or query_upper.startswith("START TRANSACTION"):
            return "BEGIN"
        if query_upper.startswith("COMMIT"):
            return "COMMIT"
        if query_upper.startswith("ROLLBACK"):
            return "ROLLBACK"
        
        # SET
        if query_upper.startswith("SET"):
            return "SET"
        
        # GRANT / REVOKE
        if query_upper.startswith("GRANT"):
            return "GRANT"
        if query_upper.startswith("REVOKE"):
            return "REVOKE"
        
        # FLUSH
        if query_upper.startswith("FLUSH"):
            return "FLUSH"
        
        # File operations
        if "LOAD_FILE" in query_upper:
            return "LOAD_FILE"
        if "INTO OUTFILE" in query_upper or "INTO DUMPFILE" in query_upper:
            return "INTO_OUTFILE"
        if query_upper.startswith("LOAD DATA"):
            return "LOAD_DATA"
        
        # Exit commands
        if query_upper in ("EXIT", "QUIT", "\\Q"):
            return "EXIT"
        
        # Help
        if query_upper.startswith("HELP") or query_upper == "\\H":
            return "HELP"
        
        # EXPLAIN
        if query_upper.startswith("EXPLAIN"):
            return "EXPLAIN"
        
        # KILL
        if query_upper.startswith("KILL"):
            return "KILL"
        
        return "UNKNOWN"
    
    def _execute_local(
        self,
        query: str,
        command_type: str,
        username: str
    ) -> Optional[Any]:
        """
        Execute command locally without LLM
        
        Returns:
            Result rows/data or None if cannot handle locally
        """
        handlers = {
            "SHOW_DATABASES": self._handle_show_databases,
            "SHOW_TABLES": self._handle_show_tables,
            "SHOW_COLUMNS": self._handle_show_columns,
            "SHOW_CREATE_TABLE": self._handle_show_create_table,
            "SHOW_CREATE_DATABASE": self._handle_show_create_database,
            "SHOW_VARIABLES": self._handle_show_variables,
            "SHOW_STATUS": self._handle_show_status,
            "SHOW_PROCESSLIST": self._handle_show_processlist,
            "SHOW_GRANTS": self._handle_show_grants,
            "SHOW_ENGINES": self._handle_show_engines,
            "SHOW_PLUGINS": self._handle_show_plugins,
            "SHOW_WARNINGS": self._handle_show_warnings,
            "SHOW_ERRORS": self._handle_show_errors,
            "SHOW_INDEX": self._handle_show_index,
            "SHOW_CHARSET": self._handle_show_charset,
            "SHOW_COLLATION": self._handle_show_collation,
            "SHOW_MASTER": self._handle_show_master,
            "SHOW_SLAVE": self._handle_show_slave,
            "DESCRIBE": self._handle_describe,
            "USE": self._handle_use,
            "SELECT_VARIABLE": self._handle_select_variable,
            "SELECT_DATABASE": self._handle_select_database,
            "SELECT_USER": self._handle_select_user,
            "SELECT_VERSION": self._handle_select_version,
            "CREATE_DATABASE": self._handle_create_database,
            "DROP_DATABASE": self._handle_drop_database,
            "CREATE_TABLE": self._handle_create_table,
            "DROP_TABLE": self._handle_drop_table,
            "TRUNCATE": self._handle_truncate,
            "BEGIN": self._handle_begin,
            "COMMIT": self._handle_commit,
            "ROLLBACK": self._handle_rollback,
            "SET": self._handle_set,
            "GRANT": self._handle_grant,
            "REVOKE": self._handle_revoke,
            "FLUSH": self._handle_flush,
            "EXIT": self._handle_exit,
            "HELP": self._handle_help,
            "KILL": self._handle_kill,
            "LOAD_FILE": self._handle_load_file,
            "INTO_OUTFILE": self._handle_into_outfile,
            "SELECT": self._handle_select,
            "INSERT": self._handle_insert,
            "UPDATE": self._handle_update,
            "DELETE": self._handle_delete,
            "SHOW_UNKNOWN": self._handle_unknown_show,
            "UNKNOWN": self._handle_unknown_command,
        }
        
        handler = handlers.get(command_type)
        if handler:
            try:
                return handler(query, username)
            except Exception as e:
                logger.error(f"Error executing {command_type}: {e}")
                return None
        
        return None
    
    # ==================== SHOW Handlers ====================
    
    def _handle_show_databases(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW DATABASES"""
        databases = self.db.list_databases()
        return [{"Database": db} for db in sorted(databases)]
    
    def _handle_show_tables(self, query: str, username: str) -> Any:
        """Handle SHOW TABLES [FROM database] [LIKE pattern]"""
        # Check if FROM clause specifies database
        from_match = re.search(r'FROM\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        
        if from_match:
            db_name = from_match.group(1)
        else:
            db_name = self.db.current_database
        
        logger.info(f"[SHOW_TABLES_DEBUG] current_database: {self.db.current_database}, using db_name: {db_name}")
        
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000", 
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        tables = database.list_tables()
        
        logger.info(f"[SHOW_TABLES_DEBUG] Found {len(tables)} tables in {db_name}: {tables[:5]}...")
        
        # Handle LIKE pattern
        like_match = re.search(r"LIKE\s+['\"]([^'\"]+)['\"]", query, re.IGNORECASE)
        if like_match:
            pattern = like_match.group(1).replace("%", ".*").replace("_", ".")
            tables = [t for t in tables if re.match(pattern, t, re.IGNORECASE)]
        
        col_name = f"Tables_in_{db_name}"
        return [{col_name: table} for table in sorted(tables)]
    
    def _handle_show_columns(self, query: str, username: str) -> Any:
        """Handle SHOW COLUMNS FROM table [FROM database]"""
        # Extract table name
        table_match = re.search(r'(?:FROM|IN)\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not table_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = table_match.group(1)
        
        # Check for database specification
        db_match = re.search(r'FROM\s+[`"]?\w+[`"]?\s+FROM\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        db_name = db_match.group(1) if db_match else self.db.current_database
        
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{db_name}.{table_name}' doesn't exist"}}
        
        return self._format_columns_result(table)
    
    def _format_columns_result(self, table: Table) -> List[Dict[str, Any]]:
        """Format columns as SHOW COLUMNS output"""
        results = []
        for col in table.columns:
            results.append({
                "Field": col.name,
                "Type": col.data_type.lower(),
                "Null": col.get_mysql_null_string(),
                "Key": col.get_mysql_key_string(),
                "Default": col.default,
                "Extra": col.get_mysql_extra_string()
            })
        return results
    
    def _handle_show_create_table(self, query: str, username: str) -> Any:
        """Handle SHOW CREATE TABLE"""
        table_match = re.search(r'TABLE\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not table_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = table_match.group(1)
        db_name = self.db.current_database
        
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{db_name}.{table_name}' doesn't exist"}}
        
        create_stmt = table.generate_create_statement(db_name)
        return [{"Table": table_name, "Create Table": create_stmt}]
    
    def _handle_show_create_database(self, query: str, username: str) -> Any:
        """Handle SHOW CREATE DATABASE"""
        db_match = re.search(r'DATABASE\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not db_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        db_name = db_match.group(1)
        database = self.db.get_database(db_name)
        
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        create_stmt = f"CREATE DATABASE `{db_name}` /*!40100 DEFAULT CHARACTER SET {database.charset} COLLATE {database.collation} */"
        return [{"Database": db_name, "Create Database": create_stmt}]
    
    def _handle_show_variables(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW VARIABLES [LIKE pattern]"""
        variables = self.db.variables
        
        # Handle LIKE pattern
        like_match = re.search(r"LIKE\s+['\"]([^'\"]+)['\"]", query, re.IGNORECASE)
        if like_match:
            pattern = like_match.group(1).replace("%", ".*").replace("_", ".")
            variables = {k: v for k, v in variables.items() 
                        if re.match(pattern, k, re.IGNORECASE)}
        
        return [{"Variable_name": k, "Value": str(v)} for k, v in sorted(variables.items())]
    
    def _handle_show_status(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW STATUS"""
        uptime = int((datetime.datetime.now() - self.start_time).total_seconds())
        
        status = {
            "Uptime": uptime,
            "Threads_connected": random.randint(5, 50),
            "Threads_running": random.randint(1, 10),
            "Questions": self.query_count + random.randint(1000, 10000),
            "Queries": self.query_count + random.randint(1000, 10000),
            "Slow_queries": random.randint(0, 100),
            "Opens": random.randint(100, 1000),
            "Flush_commands": random.randint(1, 10),
            "Open_tables": random.randint(50, 200),
            "Connections": random.randint(100, 5000),
            "Com_select": random.randint(5000, 50000),
            "Com_insert": random.randint(1000, 10000),
            "Com_update": random.randint(500, 5000),
            "Com_delete": random.randint(100, 1000),
            "Bytes_received": random.randint(1000000, 100000000),
            "Bytes_sent": random.randint(1000000, 100000000),
        }
        
        # Handle LIKE pattern
        like_match = re.search(r"LIKE\s+['\"]([^'\"]+)['\"]", query, re.IGNORECASE)
        if like_match:
            pattern = like_match.group(1).replace("%", ".*").replace("_", ".")
            status = {k: v for k, v in status.items() 
                     if re.match(pattern, k, re.IGNORECASE)}
        
        return [{"Variable_name": k, "Value": str(v)} for k, v in sorted(status.items())]
    
    def _handle_show_processlist(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW PROCESSLIST"""
        processes = [
            {
                "Id": self.connection_id,
                "User": username,
                "Host": "localhost",
                "db": self.db.current_database or "NULL",
                "Command": "Query",
                "Time": 0,
                "State": "executing",
                "Info": query[:100]
            },
            {
                "Id": self.connection_id - 1,
                "User": "system",
                "Host": "localhost",
                "db": "mysql",
                "Command": "Sleep",
                "Time": random.randint(10, 1000),
                "State": "",
                "Info": "NULL"
            }
        ]
        return processes
    
    def _handle_show_grants(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW GRANTS"""
        grants = [
            f"GRANT ALL PRIVILEGES ON *.* TO '{username}'@'%' WITH GRANT OPTION",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON `nexus_gamedev`.* TO '{username}'@'%'"
        ]
        return [{f"Grants for {username}@%": grant} for grant in grants]
    
    def _handle_show_engines(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW ENGINES"""
        engines = [
            {"Engine": "InnoDB", "Support": "DEFAULT", "Comment": "Supports transactions, row-level locking, and foreign keys", "Transactions": "YES", "XA": "YES", "Savepoints": "YES"},
            {"Engine": "MyISAM", "Support": "YES", "Comment": "MyISAM storage engine", "Transactions": "NO", "XA": "NO", "Savepoints": "NO"},
            {"Engine": "MEMORY", "Support": "YES", "Comment": "Hash based, stored in memory, useful for temporary tables", "Transactions": "NO", "XA": "NO", "Savepoints": "NO"},
            {"Engine": "CSV", "Support": "YES", "Comment": "CSV storage engine", "Transactions": "NO", "XA": "NO", "Savepoints": "NO"},
            {"Engine": "ARCHIVE", "Support": "YES", "Comment": "Archive storage engine", "Transactions": "NO", "XA": "NO", "Savepoints": "NO"},
            {"Engine": "BLACKHOLE", "Support": "YES", "Comment": "/dev/null storage engine", "Transactions": "NO", "XA": "NO", "Savepoints": "NO"},
        ]
        return engines
    
    def _handle_show_plugins(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW PLUGINS"""
        plugins = [
            {"Name": "mysql_native_password", "Status": "ACTIVE", "Type": "AUTHENTICATION", "Library": "NULL", "License": "GPL"},
            {"Name": "sha256_password", "Status": "ACTIVE", "Type": "AUTHENTICATION", "Library": "NULL", "License": "GPL"},
            {"Name": "caching_sha2_password", "Status": "ACTIVE", "Type": "AUTHENTICATION", "Library": "NULL", "License": "GPL"},
            {"Name": "InnoDB", "Status": "ACTIVE", "Type": "STORAGE ENGINE", "Library": "NULL", "License": "GPL"},
            {"Name": "MyISAM", "Status": "ACTIVE", "Type": "STORAGE ENGINE", "Library": "NULL", "License": "GPL"},
        ]
        return plugins
    
    def _handle_show_warnings(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW WARNINGS"""
        return []  # No warnings
    
    def _handle_show_errors(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW ERRORS"""
        return []  # No errors
    
    def _handle_show_index(self, query: str, username: str) -> Any:
        """Handle SHOW INDEX FROM table"""
        table_match = re.search(r'FROM\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not table_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = table_match.group(1)
        db_name = self.db.current_database
        
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{db_name}.{table_name}' doesn't exist"}}
        
        # Generate index info from primary keys
        indexes = []
        seq = 1
        for col in table.columns:
            if col.primary_key:
                indexes.append({
                    "Table": table_name,
                    "Non_unique": 0,
                    "Key_name": "PRIMARY",
                    "Seq_in_index": seq,
                    "Column_name": col.name,
                    "Collation": "A",
                    "Cardinality": table.row_count,
                    "Null": "",
                    "Index_type": "BTREE"
                })
                seq += 1
        
        return indexes
    
    def _handle_show_charset(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW CHARACTER SET / SHOW CHARSET"""
        charsets = [
            {"Charset": "utf8mb4", "Description": "UTF-8 Unicode", "Default collation": "utf8mb4_0900_ai_ci", "Maxlen": 4},
            {"Charset": "utf8", "Description": "UTF-8 Unicode", "Default collation": "utf8_general_ci", "Maxlen": 3},
            {"Charset": "latin1", "Description": "cp1252 West European", "Default collation": "latin1_swedish_ci", "Maxlen": 1},
            {"Charset": "ascii", "Description": "US ASCII", "Default collation": "ascii_general_ci", "Maxlen": 1},
        ]
        return charsets
    
    def _handle_show_collation(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW COLLATION"""
        collations = [
            {"Collation": "utf8mb4_0900_ai_ci", "Charset": "utf8mb4", "Id": 255, "Default": "Yes", "Compiled": "Yes", "Sortlen": 0},
            {"Collation": "utf8mb4_unicode_ci", "Charset": "utf8mb4", "Id": 224, "Default": "", "Compiled": "Yes", "Sortlen": 8},
            {"Collation": "utf8mb4_general_ci", "Charset": "utf8mb4", "Id": 45, "Default": "", "Compiled": "Yes", "Sortlen": 1},
            {"Collation": "utf8_general_ci", "Charset": "utf8", "Id": 33, "Default": "Yes", "Compiled": "Yes", "Sortlen": 1},
            {"Collation": "latin1_swedish_ci", "Charset": "latin1", "Id": 8, "Default": "Yes", "Compiled": "Yes", "Sortlen": 1},
        ]
        return collations
    
    def _handle_show_master(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW MASTER STATUS"""
        return [{
            "File": "mysql-bin.000001",
            "Position": random.randint(10000, 1000000),
            "Binlog_Do_DB": "",
            "Binlog_Ignore_DB": "",
            "Executed_Gtid_Set": ""
        }]
    
    def _handle_show_slave(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SHOW SLAVE STATUS"""
        return []  # Not a slave
    
    # ==================== DESCRIBE Handler ====================
    
    def _handle_describe(self, query: str, username: str) -> Any:
        """Handle DESCRIBE / DESC table"""
        # Extract table name
        parts = query.split()
        if len(parts) < 2:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = parts[1].strip("`\"';")
        
        # Check for database.table format
        if "." in table_name:
            db_name, table_name = table_name.split(".", 1)
        else:
            db_name = self.db.current_database
        
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{db_name}.{table_name}' doesn't exist"}}
        
        return self._format_columns_result(table)
    
    # ==================== USE Handler ====================
    
    def _handle_use(self, query: str, username: str) -> Any:
        """Handle USE database"""
        parts = query.split()
        if len(parts) < 2:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        db_name = parts[1].strip("`\"';")
        
        logger.info(f"[USE_DEBUG] Switching to database: {db_name}, current_before: {self.db.current_database}")
        
        if self.db.use_database(db_name):
            logger.info(f"[USE_DEBUG] Database switched successfully, current_after: {self.db.current_database}")
            return {"success": True, "message": "Database changed"}
        else:
            logger.warning(f"[USE_DEBUG] Database not found: {db_name}, available: {self.db.list_databases()}")
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
    
    # ==================== SELECT Variable Handlers ====================
    
    def _handle_select_variable(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SELECT @@variable"""
        # Extract variable names
        var_matches = re.findall(r'@@(\w+)', query)
        
        result = {}
        for var in var_matches:
            value = self.db.get_variable(var)
            result[f"@@{var}"] = value if value is not None else "NULL"
        
        return [result] if result else []
    
    def _handle_select_database(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SELECT DATABASE()"""
        return [{"DATABASE()": self.db.current_database}]
    
    def _handle_select_user(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SELECT USER() / CURRENT_USER()"""
        query_upper = query.upper()
        if "CURRENT_USER" in query_upper:
            return [{"CURRENT_USER()": f"{username}@%"}]
        return [{"USER()": f"{username}@localhost"}]
    
    def _handle_select_version(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle SELECT VERSION()"""
        version = self.db.get_variable("version")
        return [{"VERSION()": version}]
    
    # ==================== DDL Handlers ====================
    
    def _handle_create_database(self, query: str, username: str) -> Any:
        """Handle CREATE DATABASE"""
        if not self.schema_evolution:
             return {"error": {"code": 1142, "state": "42000",
                             "message": "CREATE command denied to user for this database"}}

        db_match = re.search(r'DATABASE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not db_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        db_name = db_match.group(1)
        if_not_exists = "IF NOT EXISTS" in query.upper()
        
        if self.db.has_database(db_name):
            if if_not_exists:
                return {"success": True, "message": f"Query OK, 1 row affected, 1 warning"}
            else:
                return {"error": {"code": 1007, "state": "HY000",
                                "message": f"Can't create database '{db_name}'; database exists"}}
        
        self.db.create_database(db_name)
        return {"success": True, "message": "Query OK, 1 row affected"}
    
    def _handle_drop_database(self, query: str, username: str) -> Any:
        """Handle DROP DATABASE"""
        db_match = re.search(r'DATABASE\s+(?:IF\s+EXISTS\s+)?[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not db_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        db_name = db_match.group(1)
        if_exists = "IF EXISTS" in query.upper()
        
        # Prevent dropping system databases
        if db_name.lower() in ["mysql", "information_schema", "performance_schema", "sys"]:
            return {"error": {"code": 1044, "state": "42000",
                            "message": f"Access denied for user '{username}'@'%' to database '{db_name}'"}}
        
        if not self.db.has_database(db_name):
            if if_exists:
                return {"success": True, "message": "Query OK, 0 rows affected, 1 warning"}
            else:
                return {"error": {"code": 1008, "state": "HY000",
                                "message": f"Can't drop database '{db_name}'; database doesn't exist"}}
        
        self.db.drop_database(db_name)
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    def _handle_create_table(self, query: str, username: str) -> Any:
        """Handle CREATE TABLE"""
        if not self.schema_evolution:
             return {"error": {"code": 1142, "state": "42000",
                             "message": "CREATE command denied to user for this table"}}

        if not self.db.current_database:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        # Basic table name extraction
        table_match = re.search(r'TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not table_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = table_match.group(1)
        if_not_exists = "IF NOT EXISTS" in query.upper()
        
        database = self.db.get_current_database()
        if database.has_table(table_name):
            if if_not_exists:
                return {"success": True, "message": "Query OK, 0 rows affected, 1 warning"}
            else:
                return {"error": {"code": 1050, "state": "42S01",
                                "message": f"Table '{table_name}' already exists"}}
        
        # Create a basic table
        table = Table(table_name)
        database.add_table(table)
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    def _handle_drop_table(self, query: str, username: str) -> Any:
        """Handle DROP TABLE"""
        if not self.db.current_database:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        table_match = re.search(r'TABLE\s+(?:IF\s+EXISTS\s+)?[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not table_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = table_match.group(1)
        if_exists = "IF EXISTS" in query.upper()
        
        database = self.db.get_current_database()
        if not database.has_table(table_name):
            if if_exists:
                return {"success": True, "message": "Query OK, 0 rows affected, 1 warning"}
            else:
                return {"error": {"code": 1051, "state": "42S02",
                                "message": f"Unknown table '{self.db.current_database}.{table_name}'"}}
        
        database.drop_table(table_name)
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    def _handle_truncate(self, query: str, username: str) -> Any:
        """Handle TRUNCATE TABLE"""
        if not self.db.current_database:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        table_match = re.search(r'TABLE\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if not table_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = table_match.group(1)
        database = self.db.get_current_database()
        
        if not database.has_table(table_name):
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{self.db.current_database}.{table_name}' doesn't exist"}}
        
        # Clear table data
        table = database.get_table(table_name)
        table._data = []
        table.row_count = 0
        
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    # ==================== Transaction Handlers ====================
    
    def _handle_begin(self, query: str, username: str) -> Dict[str, Any]:
        """Handle BEGIN / START TRANSACTION"""
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    def _handle_commit(self, query: str, username: str) -> Dict[str, Any]:
        """Handle COMMIT"""
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    def _handle_rollback(self, query: str, username: str) -> Dict[str, Any]:
        """Handle ROLLBACK"""
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    # ==================== SET Handler ====================
    
    def _handle_set(self, query: str, username: str) -> Dict[str, Any]:
        """Handle SET variable = value"""
        # Extract variable and value
        set_match = re.search(r'SET\s+(?:@@(?:GLOBAL|SESSION)\.)?(\w+)\s*=\s*(.+)', query, re.IGNORECASE)
        if set_match:
            var_name = set_match.group(1)
            value = set_match.group(2).strip().strip(";'\"")
            self.db.set_variable(var_name, value)
        
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    # ==================== GRANT/REVOKE Handlers ====================
    
    def _handle_grant(self, query: str, username: str) -> Dict[str, Any]:
        """Handle GRANT"""
        if not self.deception_techniques:
            return {"error": {"code": 1045, "state": "28000",
                            "message": f"Access denied for user '{username}'@'%'"}}
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    def _handle_revoke(self, query: str, username: str) -> Dict[str, Any]:
        """Handle REVOKE"""
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    # ==================== FLUSH Handler ====================
    
    def _handle_flush(self, query: str, username: str) -> Dict[str, Any]:
        """Handle FLUSH"""
        return {"success": True, "message": "Query OK, 0 rows affected"}
    
    # ==================== Misc Handlers ====================
    
    def _handle_exit(self, query: str, username: str) -> Dict[str, Any]:
        """Handle EXIT / QUIT"""
        return {"exit": True, "message": "Bye"}
    
    def _handle_help(self, query: str, username: str) -> List[Dict[str, Any]]:
        """Handle HELP"""
        return [{
            "help_topic": "For help with MySQL commands, visit: https://dev.mysql.com/doc/"
        }]
    
    def _handle_kill(self, query: str, username: str) -> Any:
        """Handle KILL [CONNECTION | QUERY] id"""
        # Extract process ID
        id_match = re.search(r'KILL\s+(?:CONNECTION\s+|QUERY\s+)?(\d+)', query, re.IGNORECASE)
        if not id_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        process_id = int(id_match.group(1))
        
        # Can't kill own connection
        if process_id == self.connection_id:
            return {"success": True, "message": "Query OK, 0 rows affected"}
        
        # Unknown process
        return {"error": {"code": 1094, "state": "HY000",
                        "message": f"Unknown thread id: {process_id}"}}
    
    # ==================== File Operation Handlers ====================
    
    def _handle_load_file(self, query: str, username: str) -> Any:
        """Handle SELECT LOAD_FILE()"""
        file_match = re.search(r"LOAD_FILE\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", query, re.IGNORECASE)
        if not file_match:
            return [{"LOAD_FILE()": None}]
        
        file_path = file_match.group(1)
        
        # Security: Return NULL for files outside secure_file_priv
        secure_path = self.db.get_variable("secure_file_priv")
        if secure_path and not file_path.startswith(secure_path):
            return [{"LOAD_FILE()": None}]
        
        # Simulate reading /etc/passwd or other common targets
        fake_content = self._get_fake_file_content(file_path)
        return [{f"LOAD_FILE('{file_path}')": fake_content}]
    
    def _get_fake_file_content(self, path: str) -> Optional[str]:
        """Generate fake file content for honeypot"""
        if "passwd" in path:
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
gamedev:x:1000:1000:NexusGames Developer:/home/gamedev:/bin/bash"""
        elif "shadow" in path:
            return None  # No permission
        elif ".ssh" in path:
            return None  # No permission
        elif "my.cnf" in path or "mysql" in path:
            return """[mysqld]
datadir=/var/lib/mysql
socket=/var/run/mysqld/mysqld.sock
user=mysql
bind-address=0.0.0.0"""
        else:
            return None
    
    def _handle_into_outfile(self, query: str, username: str) -> Any:
        """Handle SELECT ... INTO OUTFILE"""
        # Get secure_file_priv
        secure_path = self.db.get_variable("secure_file_priv")
        
        file_match = re.search(r"INTO\s+(?:OUTFILE|DUMPFILE)\s+['\"]([^'\"]+)['\"]", query, re.IGNORECASE)
        if not file_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        file_path = file_match.group(1)
        
        # Check secure_file_priv
        if secure_path and not file_path.startswith(secure_path):
            return {"error": {"code": 1290, "state": "HY000",
                            "message": f"The MySQL server is running with the --secure-file-priv option so it cannot execute this statement"}}
        
        return {"success": True, "message": "Query OK, rows affected"}
    
    # ==================== SELECT Handler ====================
    
    def _handle_select(self, query: str, username: str) -> Any:
        """Handle SELECT queries - fetch data from virtual tables"""
        query_upper = query.upper()
        
        # Handle COUNT(*)
        count_match = re.search(r'SELECT\s+COUNT\s*\(\s*\*\s*\)\s+(?:AS\s+\w+\s+)?FROM\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if count_match:
            table_name = count_match.group(1)
            return self._handle_select_count(table_name, query)
        
        # Parse basic SELECT query
        # SELECT [columns] FROM [table] [WHERE ...] [ORDER BY ...] [LIMIT ...]
        select_match = re.search(
            r'SELECT\s+(.+?)\s+FROM\s+[`"]?(\w+)[`"]?(?:\s+WHERE\s+(.+?))?(?:\s+ORDER\s+BY\s+(.+?))?(?:\s+LIMIT\s+(\d+)(?:\s*,\s*(\d+))?)?$',
            query, re.IGNORECASE | re.DOTALL
        )
        
        if not select_match:
            # Try simpler pattern for SELECT * FROM table
            simple_match = re.search(r'SELECT\s+(.+?)\s+FROM\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
            if simple_match:
                columns_part = simple_match.group(1)
                table_name = simple_match.group(2)
                where_clause = None
                order_by = None
                limit = 10  # Default limit
                offset = 0
            else:
                return None  # Can't parse, send to LLM
        else:
            columns_part = select_match.group(1).strip()
            table_name = select_match.group(2)
            where_clause = select_match.group(3)
            order_by = select_match.group(4)
            limit_val = select_match.group(5)
            offset_val = select_match.group(6)
            
            limit = int(limit_val) if limit_val else 10
            offset = int(offset_val) if offset_val else 0
        
        # Get database
        db_name = self.db.current_database
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{db_name}.{table_name}' doesn't exist"}}
        
        # Get data from table
        data = table.get_data()
        if not data:
            return []  # Empty result set
        
        # Parse columns
        if columns_part.strip() == '*':
            # All columns
            columns = table.get_column_names()
        else:
            # Specific columns
            columns = [col.strip().strip('`"') for col in columns_part.split(',')]
        
        # Apply WHERE clause (basic support)
        if where_clause:
            data = self._apply_where(data, where_clause)
        
        # Apply ORDER BY (basic support)
        if order_by:
            data = self._apply_order_by(data, order_by)
        
        # Apply LIMIT and OFFSET
        if offset:
            data = data[offset:]
        if limit:
            data = data[:limit]
        
        # Filter columns
        result = []
        for row in data:
            filtered_row = {}
            for col in columns:
                # Handle column aliases (col AS alias)
                col_name = col.split(' AS ')[0].strip() if ' AS ' in col.upper() else col
                alias = col.split(' AS ')[1].strip() if ' AS ' in col.upper() else col
                
                if col_name in row:
                    filtered_row[alias] = row[col_name]
                else:
                    filtered_row[alias] = None
            result.append(filtered_row)
        
        return result
    
    def _handle_select_count(self, table_name: str, query: str) -> Any:
        """Handle SELECT COUNT(*) FROM table"""
        db_name = self.db.current_database
        if not db_name:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        database = self.db.get_database(db_name)
        if not database:
            return {"error": {"code": 1049, "state": "42000",
                            "message": f"Unknown database '{db_name}'"}}
        
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{db_name}.{table_name}' doesn't exist"}}
        
        count = table.get_row_count()
        
        # Check for alias
        alias_match = re.search(r'COUNT\s*\(\s*\*\s*\)\s+AS\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        if alias_match:
            alias = alias_match.group(1)
            return [{alias: count}]
        
        return [{"COUNT(*)": count}]
    
    def _apply_where(self, data: List[Dict[str, Any]], where_clause: str) -> List[Dict[str, Any]]:
        """Apply WHERE clause filtering (basic support)"""
        result = []
        
        # Parse simple conditions: column = value, column > value, etc.
        # This is a simplified WHERE parser
        conditions = []
        
        # Split by AND (simple case)
        parts = re.split(r'\s+AND\s+', where_clause, flags=re.IGNORECASE)
        
        for part in parts:
            # Match: column = 'value' or column = number
            eq_match = re.match(r"[`\"]?(\w+)[`\"]?\s*=\s*['\"]?([^'\"]+)['\"]?", part.strip())
            if eq_match:
                conditions.append(('=', eq_match.group(1), eq_match.group(2)))
                continue
            
            # Match: column > value
            gt_match = re.match(r"[`\"]?(\w+)[`\"]?\s*>\s*['\"]?([^'\"]+)['\"]?", part.strip())
            if gt_match:
                conditions.append(('>', gt_match.group(1), gt_match.group(2)))
                continue
            
            # Match: column < value
            lt_match = re.match(r"[`\"]?(\w+)[`\"]?\s*<\s*['\"]?([^'\"]+)['\"]?", part.strip())
            if lt_match:
                conditions.append(('<', lt_match.group(1), lt_match.group(2)))
                continue
            
            # Match: column LIKE 'pattern'
            like_match = re.match(r"[`\"]?(\w+)[`\"]?\s+LIKE\s+['\"]([^'\"]+)['\"]", part.strip(), re.IGNORECASE)
            if like_match:
                conditions.append(('LIKE', like_match.group(1), like_match.group(2)))
                continue
        
        for row in data:
            match = True
            for op, col, val in conditions:
                row_val = row.get(col)
                if row_val is None:
                    match = False
                    break
                
                if op == '=':
                    # Try numeric comparison first
                    try:
                        if float(row_val) != float(val):
                            match = False
                            break
                    except (ValueError, TypeError):
                        if str(row_val) != str(val):
                            match = False
                            break
                elif op == '>':
                    try:
                        if float(row_val) <= float(val):
                            match = False
                            break
                    except (ValueError, TypeError):
                        match = False
                        break
                elif op == '<':
                    try:
                        if float(row_val) >= float(val):
                            match = False
                            break
                    except (ValueError, TypeError):
                        match = False
                        break
                elif op == 'LIKE':
                    pattern = val.replace('%', '.*').replace('_', '.')
                    if not re.match(pattern, str(row_val), re.IGNORECASE):
                        match = False
                        break
            
            if match:
                result.append(row)
        
        return result
    
    def _apply_order_by(self, data: List[Dict[str, Any]], order_by: str) -> List[Dict[str, Any]]:
        """Apply ORDER BY sorting"""
        # Parse order by: column [ASC|DESC]
        parts = order_by.strip().split(',')
        
        for part in reversed(parts):
            part = part.strip()
            desc = 'DESC' in part.upper()
            col = re.sub(r'\s+(ASC|DESC)\s*$', '', part, flags=re.IGNORECASE).strip().strip('`"')
            
            try:
                data = sorted(data, key=lambda x: (x.get(col) is None, x.get(col, '')), reverse=desc)
            except TypeError:
                pass  # Skip sorting if types are incompatible
        
        return data
    
    # ==================== INSERT Handler ====================
    
    def _handle_insert(self, query: str, username: str) -> Any:
        """Handle INSERT queries"""
        if not self.db.current_database:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        # Parse INSERT INTO table (columns) VALUES (values)
        insert_match = re.search(
            r'INSERT\s+INTO\s+[`"]?(\w+)[`"]?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)',
            query, re.IGNORECASE
        )
        
        if not insert_match:
            # Try INSERT INTO table VALUES (values)
            simple_match = re.search(
                r'INSERT\s+INTO\s+[`"]?(\w+)[`"]?\s+VALUES\s*\(([^)]+)\)',
                query, re.IGNORECASE
            )
            if simple_match:
                table_name = simple_match.group(1)
                columns = None
                values_str = simple_match.group(2)
            else:
                return {"error": {"code": 1064, "state": "42000",
                                "message": "You have an error in your SQL syntax"}}
        else:
            table_name = insert_match.group(1)
            columns = [c.strip().strip('`"') for c in insert_match.group(2).split(',')]
            values_str = insert_match.group(3)
        
        database = self.db.get_current_database()
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{self.db.current_database}.{table_name}' doesn't exist"}}
        
        # Parse values
        values = self._parse_values(values_str)
        
        # Build row
        if columns:
            row = dict(zip(columns, values))
        else:
            # Use table column order
            col_names = table.get_column_names()
            row = dict(zip(col_names[:len(values)], values))
        
        # Insert row
        insert_id = table.insert_row(row)
        self.db.save_state()  # Persist changes
        
        return {"success": True, "message": f"Query OK, 1 row affected", "insert_id": insert_id}
    
    def _parse_values(self, values_str: str) -> List[Any]:
        """Parse VALUES clause into list of values"""
        values = []
        current = ""
        in_string = False
        string_char = None
        
        for char in values_str:
            if char in ("'", '"') and not in_string:
                in_string = True
                string_char = char
            elif char == string_char and in_string:
                in_string = False
                string_char = None
            elif char == ',' and not in_string:
                val = current.strip()
                values.append(self._parse_value(val))
                current = ""
                continue
            
            current += char
        
        if current.strip():
            values.append(self._parse_value(current.strip()))
        
        return values
    
    def _parse_value(self, val: str) -> Any:
        """Parse a single value"""
        val = val.strip()
        
        if val.upper() == 'NULL':
            return None
        if val.upper() in ('TRUE', 'FALSE'):
            return 1 if val.upper() == 'TRUE' else 0
        
        # Remove quotes
        if (val.startswith("'") and val.endswith("'")) or \
           (val.startswith('"') and val.endswith('"')):
            return val[1:-1]
        
        # Try numeric
        try:
            if '.' in val:
                return float(val)
            return int(val)
        except ValueError:
            return val
    
    # ==================== UPDATE Handler ====================
    
    def _handle_update(self, query: str, username: str) -> Any:
        """Handle UPDATE queries"""
        if not self.db.current_database:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        # Parse UPDATE table SET col=val [WHERE ...]
        update_match = re.search(
            r'UPDATE\s+[`"]?(\w+)[`"]?\s+SET\s+(.+?)(?:\s+WHERE\s+(.+))?$',
            query, re.IGNORECASE
        )
        
        if not update_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = update_match.group(1)
        set_clause = update_match.group(2)
        where_clause = update_match.group(3)
        
        database = self.db.get_current_database()
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{self.db.current_database}.{table_name}' doesn't exist"}}
        
        # Parse SET clause
        updates = {}
        for part in set_clause.split(','):
            match = re.match(r"[`\"]?(\w+)[`\"]?\s*=\s*(.+)", part.strip())
            if match:
                col = match.group(1)
                val = self._parse_value(match.group(2).strip())
                updates[col] = val
        
        # Apply updates
        data = table.get_data()
        affected = 0
        
        if where_clause:
            filtered = self._apply_where(data, where_clause)
            for row in data:
                if row in filtered:
                    row.update(updates)
                    affected += 1
        else:
            for row in data:
                row.update(updates)
                affected += 1
        
        self.db.save_state()  # Persist changes
        
        return {"success": True, "message": f"Query OK, {affected} row(s) affected"}
    
    # ==================== DELETE Handler ====================
    
    def _handle_delete(self, query: str, username: str) -> Any:
        """Handle DELETE queries"""
        if not self.db.current_database:
            return {"error": {"code": 1046, "state": "3D000",
                            "message": "No database selected"}}
        
        # Parse DELETE FROM table [WHERE ...]
        delete_match = re.search(
            r'DELETE\s+FROM\s+[`"]?(\w+)[`"]?(?:\s+WHERE\s+(.+))?$',
            query, re.IGNORECASE
        )
        
        if not delete_match:
            return {"error": {"code": 1064, "state": "42000",
                            "message": "You have an error in your SQL syntax"}}
        
        table_name = delete_match.group(1)
        where_clause = delete_match.group(2)
        
        database = self.db.get_current_database()
        table = database.get_table(table_name)
        if not table:
            return {"error": {"code": 1146, "state": "42S02",
                            "message": f"Table '{self.db.current_database}.{table_name}' doesn't exist"}}
        
        data = table.get_data()
        original_count = len(data)
        
        if where_clause:
            filtered = self._apply_where(data, where_clause)
            filtered_set = set(id(r) for r in filtered)
            table._data = [r for r in data if id(r) not in filtered_set]
        else:
            table._data = []
        
        affected = original_count - len(table._data)
        table.row_count = len(table._data)
        self.db.save_state()  # Persist changes
        
        return {"success": True, "message": f"Query OK, {affected} row(s) affected"}
    
    # ==================== Unknown Command Handlers ====================
    
    def _handle_unknown_show(self, query: str, username: str) -> Any:
        """Handle unrecognized SHOW commands - return proper MySQL error"""
        # Extract what comes after SHOW
        parts = query.upper().split()
        if len(parts) > 1:
            unknown_keyword = parts[1]
            return {"error": {"code": 1064, "state": "42000",
                            "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{unknown_keyword}' at line 1"}}
        return {"error": {"code": 1064, "state": "42000",
                        "message": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use"}}
    
    def _handle_unknown_command(self, query: str, username: str) -> Any:
        """Handle completely unrecognized commands - return proper MySQL error"""
        first_word = query.split()[0] if query.split() else query
        return {"error": {"code": 1064, "state": "42000",
                        "message": f"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{first_word}' at line 1"}}


