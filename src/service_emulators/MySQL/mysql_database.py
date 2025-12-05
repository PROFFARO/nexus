#!/usr/bin/env python3
"""
MySQL Virtual Database System for MySQL Honeypot
Provides a realistic MySQL database structure with dynamic data generation
"""

import datetime
import hashlib
import json
import logging
import os
import random
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class Column:
    """Represents a database column"""
    
    def __init__(
        self,
        name: str,
        data_type: str,
        nullable: bool = True,
        default: Any = None,
        auto_increment: bool = False,
        primary_key: bool = False,
        unique: bool = False,
        comment: str = ""
    ):
        self.name = name
        self.data_type = data_type.upper()
        self.nullable = nullable
        self.default = default
        self.auto_increment = auto_increment
        self.primary_key = primary_key
        self.unique = unique
        self.comment = comment
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "data_type": self.data_type,
            "nullable": self.nullable,
            "default": self.default,
            "auto_increment": self.auto_increment,
            "primary_key": self.primary_key,
            "unique": self.unique,
            "comment": self.comment
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Column":
        return cls(**data)
    
    def get_mysql_type_string(self) -> str:
        """Get MySQL column type string for SHOW COLUMNS"""
        type_str = self.data_type
        if self.auto_increment:
            return type_str
        return type_str
    
    def get_mysql_null_string(self) -> str:
        return "YES" if self.nullable else "NO"
    
    def get_mysql_key_string(self) -> str:
        if self.primary_key:
            return "PRI"
        elif self.unique:
            return "UNI"
        return ""
    
    def get_mysql_extra_string(self) -> str:
        extras = []
        if self.auto_increment:
            extras.append("auto_increment")
        return " ".join(extras)


class Table:
    """Represents a database table with columns and data generation"""
    
    def __init__(
        self,
        name: str,
        columns: List[Column] = None,
        engine: str = "InnoDB",
        charset: str = "utf8mb4",
        collation: str = "utf8mb4_unicode_ci",
        comment: str = "",
        row_count: int = 0
    ):
        self.name = name
        self.columns = columns or []
        self.engine = engine
        self.charset = charset
        self.collation = collation
        self.comment = comment
        self.row_count = row_count
        self._data: List[Dict[str, Any]] = []
        self._auto_increment_counter = 1
        
    def add_column(self, column: Column):
        self.columns.append(column)
        
    def get_column(self, name: str) -> Optional[Column]:
        for col in self.columns:
            if col.name.lower() == name.lower():
                return col
        return None
    
    def get_column_names(self) -> List[str]:
        return [col.name for col in self.columns]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "columns": [col.to_dict() for col in self.columns],
            "engine": self.engine,
            "charset": self.charset,
            "collation": self.collation,
            "comment": self.comment,
            "row_count": self.row_count,
            "data": self._data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Table":
        columns = [Column.from_dict(c) for c in data.get("columns", [])]
        table = cls(
            name=data["name"],
            columns=columns,
            engine=data.get("engine", "InnoDB"),
            charset=data.get("charset", "utf8mb4"),
            collation=data.get("collation", "utf8mb4_unicode_ci"),
            comment=data.get("comment", ""),
            row_count=data.get("row_count", 0)
        )
        table._data = data.get("data", [])
        return table
    
    def generate_create_statement(self, database_name: str) -> str:
        """Generate CREATE TABLE statement"""
        lines = [f"CREATE TABLE `{self.name}` ("]
        
        col_defs = []
        primary_keys = []
        
        for col in self.columns:
            col_def = f"  `{col.name}` {col.data_type}"
            if not col.nullable:
                col_def += " NOT NULL"
            if col.default is not None:
                if isinstance(col.default, str):
                    col_def += f" DEFAULT '{col.default}'"
                else:
                    col_def += f" DEFAULT {col.default}"
            if col.auto_increment:
                col_def += " AUTO_INCREMENT"
            if col.comment:
                col_def += f" COMMENT '{col.comment}'"
            col_defs.append(col_def)
            
            if col.primary_key:
                primary_keys.append(col.name)
        
        lines.append(",\n".join(col_defs))
        
        if primary_keys:
            lines.append(f",\n  PRIMARY KEY (`{'`,`'.join(primary_keys)}`)")
        
        lines.append(f") ENGINE={self.engine} DEFAULT CHARSET={self.charset} COLLATE={self.collation}")
        
        if self.comment:
            lines[-1] += f" COMMENT='{self.comment}'"
        
        return "\n".join(lines)
    
    def generate_rows(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate realistic sample data rows"""
        rows = []
        for i in range(count):
            row = {}
            for col in self.columns:
                row[col.name] = self._generate_value_for_column(col, i)
            rows.append(row)
        return rows
    
    def _generate_value_for_column(self, col: Column, row_index: int) -> Any:
        """Generate a realistic value for a column based on its type and name"""
        col_name = col.name.lower()
        col_type = col.data_type.upper()
        
        # Handle auto_increment
        if col.auto_increment:
            self._auto_increment_counter += 1
            return self._auto_increment_counter - 1
        
        # Generate based on column name patterns
        if "id" in col_name and "INT" in col_type:
            return row_index + 1
        
        if col_name in ("created_at", "created_date", "create_time"):
            base = datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 365))
            return base.strftime("%Y-%m-%d %H:%M:%S")
        
        if col_name in ("updated_at", "modified_at", "update_time"):
            base = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 30))
            return base.strftime("%Y-%m-%d %H:%M:%S")
        
        if col_name in ("last_login", "login_time", "last_seen"):
            base = datetime.datetime.now() - datetime.timedelta(hours=random.randint(1, 720))
            return base.strftime("%Y-%m-%d %H:%M:%S")
        
        if "email" in col_name:
            names = ["john", "jane", "mike", "sarah", "alex", "emma", "chris", "lisa"]
            domains = ["nexusgames.com", "game.dev", "player.io", "studio.net"]
            return f"{random.choice(names)}{random.randint(1, 999)}@{random.choice(domains)}"
        
        if col_name in ("username", "user_name", "player_name", "name"):
            prefixes = ["Shadow", "Dark", "Light", "Storm", "Fire", "Ice", "Thunder", "Dragon"]
            suffixes = ["Hunter", "Master", "King", "Lord", "Knight", "Wizard", "Warrior", "Slayer"]
            return f"{random.choice(prefixes)}{random.choice(suffixes)}{random.randint(1, 9999)}"
        
        if "password" in col_name or "hash" in col_name:
            return hashlib.sha256(f"pass{row_index}".encode()).hexdigest()[:64]
        
        if col_name in ("score", "points", "xp", "experience"):
            return random.randint(100, 100000)
        
        if col_name in ("level", "rank"):
            return random.randint(1, 100)
        
        if col_name in ("balance", "coins", "gold", "credits"):
            return random.randint(0, 1000000)
        
        if col_name in ("wins", "losses", "kills", "deaths"):
            return random.randint(0, 10000)
        
        if col_name in ("playtime", "time_played"):
            return random.randint(60, 360000)  # seconds
        
        if col_name in ("status", "state"):
            statuses = ["active", "inactive", "pending", "banned", "premium"]
            return random.choice(statuses)
        
        if col_name in ("is_active", "is_admin", "is_premium", "enabled", "verified"):
            return random.choice([0, 1])
        
        if "ip" in col_name:
            return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        if "uuid" in col_name or "guid" in col_name:
            return str(uuid.uuid4())
        
        if col_name in ("title", "game_title"):
            titles = ["Shadow Quest", "Dragon Realm", "Star Commander", "Zombie Siege", "Racing Pro"]
            return random.choice(titles)
        
        if col_name in ("description", "desc", "content", "text"):
            descriptions = [
                "An exciting adventure awaits",
                "Join the battle for glory",
                "Explore new worlds",
                "Compete with players worldwide",
                "Unlock powerful abilities"
            ]
            return random.choice(descriptions)
        
        if "version" in col_name:
            return f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 99)}"
        
        if "count" in col_name:
            return random.randint(0, 1000)
        
        if "price" in col_name or "amount" in col_name or "cost" in col_name:
            return round(random.uniform(0.99, 99.99), 2)
        
        # Generate based on data type
        if "INT" in col_type:
            return random.randint(1, 10000)
        
        if "FLOAT" in col_type or "DOUBLE" in col_type or "DECIMAL" in col_type:
            return round(random.uniform(0, 1000), 2)
        
        if "DATETIME" in col_type or "TIMESTAMP" in col_type:
            base = datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 365))
            return base.strftime("%Y-%m-%d %H:%M:%S")
        
        if "DATE" in col_type:
            base = datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 365))
            return base.strftime("%Y-%m-%d")
        
        if "TIME" in col_type:
            return f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"
        
        if "BOOL" in col_type or "TINYINT(1)" in col_type:
            return random.choice([0, 1])
        
        if "TEXT" in col_type or "BLOB" in col_type:
            return f"Data block {row_index + 1}"
        
        if "VARCHAR" in col_type or "CHAR" in col_type:
            return f"value_{row_index + 1}"
        
        if "ENUM" in col_type:
            # Extract enum values
            match = re.search(r"ENUM\s*\((.*?)\)", col_type, re.IGNORECASE)
            if match:
                values = [v.strip().strip("'\"") for v in match.group(1).split(",")]
                return random.choice(values)
            return "unknown"
        
        if "JSON" in col_type:
            return json.dumps({"key": f"value_{row_index}"})
        
        # Default
        return None


class Database:
    """Represents a MySQL database with tables"""
    
    def __init__(
        self,
        name: str,
        charset: str = "utf8mb4",
        collation: str = "utf8mb4_unicode_ci"
    ):
        self.name = name
        self.charset = charset
        self.collation = collation
        self.tables: Dict[str, Table] = {}
        
    def add_table(self, table: Table):
        self.tables[table.name.lower()] = table
        
    def get_table(self, name: str) -> Optional[Table]:
        return self.tables.get(name.lower())
    
    def has_table(self, name: str) -> bool:
        return name.lower() in self.tables
    
    def list_tables(self) -> List[str]:
        return list(self.tables.keys())
    
    def drop_table(self, name: str) -> bool:
        if name.lower() in self.tables:
            del self.tables[name.lower()]
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "charset": self.charset,
            "collation": self.collation,
            "tables": {name: table.to_dict() for name, table in self.tables.items()}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Database":
        db = cls(
            name=data["name"],
            charset=data.get("charset", "utf8mb4"),
            collation=data.get("collation", "utf8mb4_unicode_ci")
        )
        for name, table_data in data.get("tables", {}).items():
            db.tables[name] = Table.from_dict(table_data)
        return db


class MySQLDatabaseSystem:
    """
    Complete MySQL database system with multiple databases
    Provides realistic schema and data for honeypot deception
    """
    
    def __init__(self, session_dir: Optional[str] = None):
        self.databases: Dict[str, Database] = {}
        self.current_database: Optional[str] = None
        self.session_dir = Path(session_dir) if session_dir else None
        self.variables: Dict[str, Any] = {}
        
        # Initialize with default databases
        self._initialize_system_databases()
        self._initialize_game_databases()
        self._initialize_variables()
        
    def _initialize_variables(self):
        """Initialize MySQL system variables"""
        self.variables = {
            "version": "8.0.32-0ubuntu0.20.04.2",
            "version_comment": "(Ubuntu)",
            "hostname": "nexus-db-01",
            "datadir": "/var/lib/mysql/",
            "basedir": "/usr/",
            "tmpdir": "/tmp",
            "port": 3306,
            "socket": "/var/run/mysqld/mysqld.sock",
            "pid_file": "/var/run/mysqld/mysqld.pid",
            "character_set_server": "utf8mb4",
            "collation_server": "utf8mb4_unicode_ci",
            "max_connections": 151,
            "max_allowed_packet": 67108864,
            "innodb_buffer_pool_size": 134217728,
            "innodb_log_file_size": 50331648,
            "query_cache_size": 0,
            "query_cache_type": "OFF",
            "log_error": "/var/log/mysql/error.log",
            "slow_query_log": "OFF",
            "slow_query_log_file": "/var/lib/mysql/slow.log",
            "general_log": "OFF",
            "general_log_file": "/var/lib/mysql/general.log",
            "secure_file_priv": "/var/lib/mysql-files/",
            "sql_mode": "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
            "time_zone": "SYSTEM",
            "autocommit": 1,
            "wait_timeout": 28800,
            "interactive_timeout": 28800,
        }
        
    def _initialize_system_databases(self):
        """Initialize MySQL system databases"""
        # information_schema (read-only, metadata)
        info_schema = Database("information_schema")
        self.databases["information_schema"] = info_schema
        
        # mysql (system database)
        mysql_db = Database("mysql")
        
        # User table
        user_table = Table("user", comment="MySQL users")
        user_table.add_column(Column("Host", "VARCHAR(255)", primary_key=True))
        user_table.add_column(Column("User", "VARCHAR(32)", primary_key=True))
        user_table.add_column(Column("authentication_string", "TEXT"))
        user_table.add_column(Column("Select_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Insert_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Update_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Delete_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Create_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Drop_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Grant_priv", "ENUM('N','Y')", default="N"))
        user_table.add_column(Column("Super_priv", "ENUM('N','Y')", default="N"))
        mysql_db.add_table(user_table)
        
        # db table
        db_table = Table("db", comment="Database privileges")
        db_table.add_column(Column("Host", "VARCHAR(255)", primary_key=True))
        db_table.add_column(Column("Db", "VARCHAR(64)", primary_key=True))
        db_table.add_column(Column("User", "VARCHAR(32)", primary_key=True))
        db_table.add_column(Column("Select_priv", "ENUM('N','Y')", default="N"))
        db_table.add_column(Column("Insert_priv", "ENUM('N','Y')", default="N"))
        mysql_db.add_table(db_table)
        
        self.databases["mysql"] = mysql_db
        
        # performance_schema
        perf_schema = Database("performance_schema")
        self.databases["performance_schema"] = perf_schema
        
        # sys
        sys_db = Database("sys")
        self.databases["sys"] = sys_db
        
    def _initialize_game_databases(self):
        """Initialize game development databases"""
        
        # nexus_gamedev - Main game development database
        nexus_db = Database("nexus_gamedev")
        
        # Players table
        players = Table("players", comment="Game player accounts")
        players.add_column(Column("player_id", "INT(11)", auto_increment=True, primary_key=True))
        players.add_column(Column("username", "VARCHAR(50)", nullable=False, unique=True))
        players.add_column(Column("email", "VARCHAR(100)", nullable=False))
        players.add_column(Column("password_hash", "VARCHAR(255)", nullable=False))
        players.add_column(Column("level", "INT(11)", default=1))
        players.add_column(Column("experience", "BIGINT(20)", default=0))
        players.add_column(Column("gold", "BIGINT(20)", default=100))
        players.add_column(Column("premium_currency", "INT(11)", default=0))
        players.add_column(Column("is_premium", "TINYINT(1)", default=0))
        players.add_column(Column("is_banned", "TINYINT(1)", default=0))
        players.add_column(Column("last_login", "DATETIME"))
        players.add_column(Column("created_at", "DATETIME", nullable=False))
        players.add_column(Column("updated_at", "DATETIME"))
        players.row_count = 15847
        nexus_db.add_table(players)
        
        # Characters table
        characters = Table("characters", comment="Player characters")
        characters.add_column(Column("character_id", "INT(11)", auto_increment=True, primary_key=True))
        characters.add_column(Column("player_id", "INT(11)", nullable=False))
        characters.add_column(Column("name", "VARCHAR(50)", nullable=False))
        characters.add_column(Column("class", "ENUM('warrior','mage','rogue','healer','archer')"))
        characters.add_column(Column("level", "INT(11)", default=1))
        characters.add_column(Column("health", "INT(11)", default=100))
        characters.add_column(Column("mana", "INT(11)", default=50))
        characters.add_column(Column("strength", "INT(11)", default=10))
        characters.add_column(Column("intelligence", "INT(11)", default=10))
        characters.add_column(Column("agility", "INT(11)", default=10))
        characters.add_column(Column("playtime_seconds", "BIGINT(20)", default=0))
        characters.add_column(Column("created_at", "DATETIME", nullable=False))
        characters.row_count = 28493
        nexus_db.add_table(characters)
        
        # Achievements table
        achievements = Table("achievements", comment="Game achievements")
        achievements.add_column(Column("achievement_id", "INT(11)", auto_increment=True, primary_key=True))
        achievements.add_column(Column("name", "VARCHAR(100)", nullable=False))
        achievements.add_column(Column("description", "TEXT"))
        achievements.add_column(Column("points", "INT(11)", default=10))
        achievements.add_column(Column("category", "VARCHAR(50)"))
        achievements.add_column(Column("icon_url", "VARCHAR(255)"))
        achievements.add_column(Column("is_hidden", "TINYINT(1)", default=0))
        achievements.row_count = 156
        nexus_db.add_table(achievements)
        
        # Player achievements
        player_achievements = Table("player_achievements", comment="Player achievement unlocks")
        player_achievements.add_column(Column("id", "INT(11)", auto_increment=True, primary_key=True))
        player_achievements.add_column(Column("player_id", "INT(11)", nullable=False))
        player_achievements.add_column(Column("achievement_id", "INT(11)", nullable=False))
        player_achievements.add_column(Column("unlocked_at", "DATETIME", nullable=False))
        player_achievements.row_count = 89421
        nexus_db.add_table(player_achievements)
        
        # Inventory table
        inventory = Table("inventory", comment="Player inventory items")
        inventory.add_column(Column("inventory_id", "INT(11)", auto_increment=True, primary_key=True))
        inventory.add_column(Column("player_id", "INT(11)", nullable=False))
        inventory.add_column(Column("item_id", "INT(11)", nullable=False))
        inventory.add_column(Column("quantity", "INT(11)", default=1))
        inventory.add_column(Column("slot", "INT(11)"))
        inventory.add_column(Column("acquired_at", "DATETIME", nullable=False))
        inventory.row_count = 324891
        nexus_db.add_table(inventory)
        
        # Items table
        items = Table("items", comment="Game items catalog")
        items.add_column(Column("item_id", "INT(11)", auto_increment=True, primary_key=True))
        items.add_column(Column("name", "VARCHAR(100)", nullable=False))
        items.add_column(Column("description", "TEXT"))
        items.add_column(Column("type", "ENUM('weapon','armor','consumable','material','quest')"))
        items.add_column(Column("rarity", "ENUM('common','uncommon','rare','epic','legendary')"))
        items.add_column(Column("base_price", "INT(11)", default=0))
        items.add_column(Column("stats", "JSON"))
        items.add_column(Column("icon_url", "VARCHAR(255)"))
        items.row_count = 2847
        nexus_db.add_table(items)
        
        # Sessions table (for security monitoring)
        sessions = Table("sessions", comment="Active game sessions")
        sessions.add_column(Column("session_id", "VARCHAR(64)", primary_key=True))
        sessions.add_column(Column("player_id", "INT(11)", nullable=False))
        sessions.add_column(Column("ip_address", "VARCHAR(45)"))
        sessions.add_column(Column("user_agent", "TEXT"))
        sessions.add_column(Column("started_at", "DATETIME", nullable=False))
        sessions.add_column(Column("last_activity", "DATETIME"))
        sessions.add_column(Column("is_active", "TINYINT(1)", default=1))
        sessions.row_count = 847
        nexus_db.add_table(sessions)
        
        # Transactions table (for payment tracking - juicy target)
        transactions = Table("transactions", comment="Payment transactions")
        transactions.add_column(Column("transaction_id", "VARCHAR(64)", primary_key=True))
        transactions.add_column(Column("player_id", "INT(11)", nullable=False))
        transactions.add_column(Column("amount", "DECIMAL(10,2)", nullable=False))
        transactions.add_column(Column("currency", "VARCHAR(3)", default="USD"))
        transactions.add_column(Column("payment_method", "VARCHAR(50)"))
        transactions.add_column(Column("status", "ENUM('pending','completed','failed','refunded')"))
        transactions.add_column(Column("created_at", "DATETIME", nullable=False))
        transactions.row_count = 45892
        nexus_db.add_table(transactions)
        
        self.databases["nexus_gamedev"] = nexus_db
        
        # player_data - Player statistics and leaderboards
        player_data_db = Database("player_data")
        
        # Leaderboards table
        leaderboards = Table("leaderboards", comment="Game leaderboards")
        leaderboards.add_column(Column("id", "INT(11)", auto_increment=True, primary_key=True))
        leaderboards.add_column(Column("player_id", "INT(11)", nullable=False))
        leaderboards.add_column(Column("leaderboard_type", "VARCHAR(50)", nullable=False))
        leaderboards.add_column(Column("score", "BIGINT(20)", default=0))
        leaderboards.add_column(Column("rank", "INT(11)"))
        leaderboards.add_column(Column("season", "INT(11)", default=1))
        leaderboards.add_column(Column("updated_at", "DATETIME"))
        leaderboards.row_count = 158470
        player_data_db.add_table(leaderboards)
        
        # Match history
        match_history = Table("match_history", comment="PvP match records")
        match_history.add_column(Column("match_id", "VARCHAR(64)", primary_key=True))
        match_history.add_column(Column("player1_id", "INT(11)", nullable=False))
        match_history.add_column(Column("player2_id", "INT(11)", nullable=False))
        match_history.add_column(Column("winner_id", "INT(11)"))
        match_history.add_column(Column("game_mode", "VARCHAR(50)"))
        match_history.add_column(Column("duration_seconds", "INT(11)"))
        match_history.add_column(Column("played_at", "DATETIME", nullable=False))
        match_history.row_count = 892145
        player_data_db.add_table(match_history)
        
        # Player statistics
        player_stats = Table("player_stats", comment="Aggregated player statistics")
        player_stats.add_column(Column("player_id", "INT(11)", primary_key=True))
        player_stats.add_column(Column("total_wins", "INT(11)", default=0))
        player_stats.add_column(Column("total_losses", "INT(11)", default=0))
        player_stats.add_column(Column("total_kills", "INT(11)", default=0))
        player_stats.add_column(Column("total_deaths", "INT(11)", default=0))
        player_stats.add_column(Column("total_playtime", "BIGINT(20)", default=0))
        player_stats.add_column(Column("highest_score", "BIGINT(20)", default=0))
        player_stats.add_column(Column("updated_at", "DATETIME"))
        player_stats.row_count = 15847
        player_data_db.add_table(player_stats)
        
        self.databases["player_data"] = player_data_db
        
        # game_analytics - Analytics data
        analytics_db = Database("game_analytics")
        
        # Events table
        events = Table("events", comment="Game analytics events")
        events.add_column(Column("event_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        events.add_column(Column("event_type", "VARCHAR(100)", nullable=False))
        events.add_column(Column("player_id", "INT(11)"))
        events.add_column(Column("session_id", "VARCHAR(64)"))
        events.add_column(Column("data", "JSON"))
        events.add_column(Column("timestamp", "DATETIME", nullable=False))
        events.row_count = 15892847
        analytics_db.add_table(events)
        
        # Daily metrics
        daily_metrics = Table("daily_metrics", comment="Daily aggregated metrics")
        daily_metrics.add_column(Column("date", "DATE", primary_key=True))
        daily_metrics.add_column(Column("dau", "INT(11)", comment="Daily Active Users"))
        daily_metrics.add_column(Column("new_users", "INT(11)"))
        daily_metrics.add_column(Column("revenue", "DECIMAL(12,2)"))
        daily_metrics.add_column(Column("sessions", "INT(11)"))
        daily_metrics.add_column(Column("avg_session_length", "INT(11)"))
        daily_metrics.row_count = 365
        analytics_db.add_table(daily_metrics)
        
        self.databases["game_analytics"] = analytics_db
        
        # asset_library - Game assets
        assets_db = Database("asset_library")
        
        # Assets table
        assets = Table("assets", comment="Game asset metadata")
        assets.add_column(Column("asset_id", "INT(11)", auto_increment=True, primary_key=True))
        assets.add_column(Column("name", "VARCHAR(255)", nullable=False))
        assets.add_column(Column("type", "ENUM('texture','model','sound','animation','shader')"))
        assets.add_column(Column("file_path", "VARCHAR(500)"))
        assets.add_column(Column("file_size", "BIGINT(20)"))
        assets.add_column(Column("checksum", "VARCHAR(64)"))
        assets.add_column(Column("version", "VARCHAR(20)"))
        assets.add_column(Column("created_by", "VARCHAR(100)"))
        assets.add_column(Column("created_at", "DATETIME", nullable=False))
        assets.row_count = 8924
        assets_db.add_table(assets)
        
        self.databases["asset_library"] = assets_db
        
    def list_databases(self) -> List[str]:
        """List all databases"""
        return list(self.databases.keys())
    
    def get_database(self, name: str) -> Optional[Database]:
        """Get a database by name"""
        return self.databases.get(name.lower())
    
    def has_database(self, name: str) -> bool:
        """Check if database exists"""
        return name.lower() in self.databases
    
    def create_database(self, name: str) -> bool:
        """Create a new database"""
        if name.lower() in self.databases:
            return False
        self.databases[name.lower()] = Database(name)
        return True
    
    def drop_database(self, name: str) -> bool:
        """Drop a database"""
        if name.lower() in self.databases and name.lower() not in ["mysql", "information_schema", "performance_schema", "sys"]:
            del self.databases[name.lower()]
            if self.current_database == name.lower():
                self.current_database = None
            return True
        return False
    
    def use_database(self, name: str) -> bool:
        """Switch to a database"""
        if name.lower() in self.databases:
            self.current_database = name.lower()
            return True
        return False
    
    def get_current_database(self) -> Optional[Database]:
        """Get the currently selected database"""
        if self.current_database:
            return self.databases.get(self.current_database)
        return None
    
    def get_variable(self, name: str) -> Any:
        """Get a MySQL system variable"""
        # Handle @@ prefix
        var_name = name.lstrip("@").lower()
        return self.variables.get(var_name, None)
    
    def set_variable(self, name: str, value: Any):
        """Set a MySQL system variable"""
        var_name = name.lstrip("@").lower()
        self.variables[var_name] = value
        
    def save_state(self, path: str):
        """Save database state to file"""
        state = {
            "databases": {name: db.to_dict() for name, db in self.databases.items()},
            "current_database": self.current_database,
            "variables": self.variables
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
            
    def load_state(self, path: str) -> bool:
        """Load database state from file"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                state = json.load(f)
            
            self.databases = {}
            for name, db_data in state.get("databases", {}).items():
                self.databases[name] = Database.from_dict(db_data)
            
            self.current_database = state.get("current_database")
            self.variables = state.get("variables", {})
            return True
        except Exception as e:
            logger.error(f"Failed to load database state: {e}")
            return False
