#!/usr/bin/env python3
"""
MySQL Virtual Database System for MySQL Honeypot
Provides a realistic MySQL database structure with dynamic data generation and per-user persistence
"""

import datetime
import hashlib
import json
import logging
import os
import random
import re
import string
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# Realistic data pools for generating fake but believable data
FIRST_NAMES = ["Alex", "Sarah", "Mike", "Emma", "Chris", "Lisa", "James", "Anna", "David", "Maria", 
               "Ryan", "Jessica", "Kevin", "Ashley", "Brian", "Nicole", "Jason", "Amanda", "Eric", "Megan",
               "Tyler", "Brittany", "Andrew", "Samantha", "Brandon", "Rachel", "Justin", "Lauren", "Matthew", "Stephanie"]

LAST_NAMES = ["Chen", "Martinez", "Thompson", "Wilson", "Garcia", "Brown", "Davis", "Miller", "Rodriguez", "Anderson",
              "Taylor", "Thomas", "Moore", "Jackson", "Martin", "Lee", "White", "Harris", "Clark", "Lewis",
              "Young", "Walker", "Hall", "Allen", "King", "Wright", "Scott", "Green", "Baker", "Adams"]

GAME_NAMES = ["Shadow", "Dragon", "Storm", "Fire", "Ice", "Thunder", "Phoenix", "Mystic", "Dark", "Light",
              "Cosmic", "Stellar", "Crimson", "Azure", "Golden", "Silver", "Iron", "Crystal", "Nova", "Omega"]

GAME_SUFFIXES = ["Hunter", "Master", "King", "Lord", "Knight", "Wizard", "Warrior", "Slayer", "Champion", "Legend",
                 "Destroyer", "Guardian", "Demon", "Angel", "Beast", "Spirit", "Wolf", "Hawk", "Blade", "Storm"]

ITEM_NAMES = {
    "weapon": ["Excalibur", "Dragonslayer", "Shadowblade", "Frostmourne", "Thunderfury", "Doomhammer", "Warglaive", "Ashbringer", "Gorehowl", "Soulreaper"],
    "armor": ["Dragon Plate", "Shadow Leather", "Mithril Chain", "Crystal Guard", "Phoenix Aegis", "Titan Armor", "Void Cloak", "Storm Shield", "Ice Barrier", "Fire Ward"],
    "consumable": ["Health Potion", "Mana Elixir", "Stamina Tonic", "Strength Buff", "Speed Boost", "Shield Scroll", "Teleport Stone", "Revival Crystal", "Damage Amp", "Defense Boost"],
    "material": ["Dragon Scale", "Phoenix Feather", "Mithril Ore", "Shadow Essence", "Crystal Shard", "Ancient Rune", "Void Fragment", "Storm Dust", "Ice Core", "Fire Stone"],
    "quest": ["Ancient Map", "Royal Decree", "Mysterious Key", "Sealed Letter", "Cursed Artifact", "Sacred Relic", "Lost Tome", "Broken Compass", "Faded Photo", "Cryptic Note"]
}

ACHIEVEMENT_NAMES = [
    ("First Blood", "Defeat your first enemy", 10),
    ("Monster Slayer", "Defeat 100 enemies", 25),
    ("Dragon Hunter", "Defeat the Ancient Dragon", 50),
    ("Treasure Hunter", "Find 50 treasure chests", 30),
    ("Explorer", "Discover all map regions", 40),
    ("Master Crafter", "Craft 100 items", 35),
    ("Social Butterfly", "Add 25 friends", 20),
    ("Battle Master", "Win 500 PvP matches", 75),
    ("Legendary", "Reach max level", 100),
    ("Completionist", "Complete all achievements", 500),
    ("Speed Runner", "Complete the game in under 10 hours", 60),
    ("Fashion Icon", "Collect 50 cosmetic items", 25),
    ("Guild Leader", "Create and lead a guild", 45),
    ("Arena Champion", "Reach top 100 in ranked", 80),
    ("Dungeon Master", "Complete all dungeons on hard mode", 90),
]

EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com", "icloud.com"]

COUNTRIES = ["US", "CA", "GB", "DE", "FR", "JP", "KR", "AU", "BR", "IN", "MX", "RU", "CN", "ES", "IT"]

CHARACTER_CLASSES = ["warrior", "mage", "rogue", "healer", "archer", "paladin", "necromancer", "assassin"]


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
        return self.data_type.lower()
    
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
    """Represents a database table with columns and data"""
    
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
            "data": self._data,
            "auto_increment_counter": self._auto_increment_counter
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
        table._auto_increment_counter = data.get("auto_increment_counter", 1)
        return table
    
    def get_data(self) -> List[Dict[str, Any]]:
        """Get all rows in the table"""
        return self._data
    
    def get_row_count(self) -> int:
        """Get actual row count"""
        return len(self._data) if self._data else self.row_count
    
    def insert_row(self, row: Dict[str, Any]) -> int:
        """Insert a row and return the auto-incremented ID if any"""
        new_row = {}
        auto_id = None
        
        for col in self.columns:
            if col.auto_increment and col.name not in row:
                new_row[col.name] = self._auto_increment_counter
                auto_id = self._auto_increment_counter
                self._auto_increment_counter += 1
            elif col.name in row:
                new_row[col.name] = row[col.name]
            elif col.default is not None:
                new_row[col.name] = col.default
            else:
                new_row[col.name] = None
        
        self._data.append(new_row)
        self.row_count = len(self._data)
        return auto_id or len(self._data)
    
    def update_rows(self, condition: Dict[str, Any], updates: Dict[str, Any]) -> int:
        """Update rows matching condition, return count of updated rows"""
        count = 0
        for row in self._data:
            match = all(row.get(k) == v for k, v in condition.items())
            if match:
                row.update(updates)
                count += 1
        return count
    
    def delete_rows(self, condition: Dict[str, Any]) -> int:
        """Delete rows matching condition, return count of deleted rows"""
        original_count = len(self._data)
        self._data = [row for row in self._data if not all(row.get(k) == v for k, v in condition.items())]
        deleted = original_count - len(self._data)
        self.row_count = len(self._data)
        return deleted
    
    def truncate(self):
        """Remove all data from table"""
        self._data = []
        self.row_count = 0
        # Don't reset auto_increment - MySQL doesn't by default
    
    def generate_create_statement(self, database_name: str) -> str:
        """Generate CREATE TABLE statement"""
        lines = [f"CREATE TABLE `{self.name}` ("]
        
        col_defs = []
        primary_keys = []
        
        for col in self.columns:
            col_def = f"  `{col.name}` {col.data_type.lower()}"
            if not col.nullable:
                col_def += " NOT NULL"
            if col.default is not None:
                if isinstance(col.default, str):
                    col_def += f" DEFAULT '{col.default}'"
                elif col.default is None:
                    col_def += " DEFAULT NULL"
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
    Supports per-user persistence
    """
    
    def __init__(self, username: str = None, sessions_dir: str = None):
        self.databases: Dict[str, Database] = {}
        self.current_database: Optional[str] = None
        self.username = username or "anonymous"
        self.variables: Dict[str, Any] = {}
        
        # Set up persistence directory
        if sessions_dir:
            self.sessions_dir = Path(sessions_dir)
        else:
            # Default to MySQL/sessions/database_states/
            self.sessions_dir = Path(__file__).parent / "sessions" / "database_states"
        
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        
        # Try to load existing state for this user
        if not self._load_state():
            # Initialize with default databases
            self._initialize_system_databases()
            self._initialize_game_databases()
            self._populate_sample_data()
        
        self._initialize_variables()
        
    def _get_state_file_path(self) -> Path:
        """Get the persistence file path for current user"""
        safe_username = re.sub(r'[^\w\-]', '_', self.username)
        return self.sessions_dir / f"{safe_username}_database.json"
        
    def _initialize_variables(self):
        """Initialize MySQL system variables"""
        self.variables = {
            "version": "8.0.32-0ubuntu0.20.04.2",
            "version_comment": "(Ubuntu)",
            "version_compile_os": "Linux",
            "version_compile_machine": "x86_64",
            "hostname": "nexus-db-01",
            "datadir": "/var/lib/mysql/",
            "basedir": "/usr/",
            "tmpdir": "/tmp",
            "port": 3306,
            "socket": "/var/run/mysqld/mysqld.sock",
            "pid_file": "/var/run/mysqld/mysqld.pid",
            "character_set_server": "utf8mb4",
            "character_set_client": "utf8mb4",
            "character_set_connection": "utf8mb4",
            "character_set_results": "utf8mb4",
            "collation_server": "utf8mb4_unicode_ci",
            "collation_connection": "utf8mb4_unicode_ci",
            "max_connections": 151,
            "max_allowed_packet": 67108864,
            "innodb_buffer_pool_size": 134217728,
            "innodb_log_file_size": 50331648,
            "innodb_version": "8.0.32",
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
            "system_time_zone": "UTC",
            "autocommit": 1,
            "wait_timeout": 28800,
            "interactive_timeout": 28800,
            "net_read_timeout": 30,
            "net_write_timeout": 60,
            "have_ssl": "YES",
            "ssl_cipher": "TLS_AES_256_GCM_SHA384",
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
        """Initialize game development databases with full schema"""
        
        # ============ nexus_gamedev - Main game development database ============
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
        players.add_column(Column("country", "VARCHAR(2)"))
        players.add_column(Column("last_login", "DATETIME"))
        players.add_column(Column("created_at", "DATETIME", nullable=False))
        players.add_column(Column("updated_at", "DATETIME"))
        nexus_db.add_table(players)
        
        # Characters table
        characters = Table("characters", comment="Player characters")
        characters.add_column(Column("character_id", "INT(11)", auto_increment=True, primary_key=True))
        characters.add_column(Column("player_id", "INT(11)", nullable=False))
        characters.add_column(Column("name", "VARCHAR(50)", nullable=False))
        characters.add_column(Column("class", "ENUM('warrior','mage','rogue','healer','archer','paladin','necromancer','assassin')"))
        characters.add_column(Column("level", "INT(11)", default=1))
        characters.add_column(Column("health", "INT(11)", default=100))
        characters.add_column(Column("max_health", "INT(11)", default=100))
        characters.add_column(Column("mana", "INT(11)", default=50))
        characters.add_column(Column("max_mana", "INT(11)", default=50))
        characters.add_column(Column("strength", "INT(11)", default=10))
        characters.add_column(Column("intelligence", "INT(11)", default=10))
        characters.add_column(Column("agility", "INT(11)", default=10))
        characters.add_column(Column("defense", "INT(11)", default=10))
        characters.add_column(Column("playtime_seconds", "BIGINT(20)", default=0))
        characters.add_column(Column("current_zone", "VARCHAR(50)"))
        characters.add_column(Column("created_at", "DATETIME", nullable=False))
        nexus_db.add_table(characters)
        
        # Items table
        items = Table("items", comment="Game items catalog")
        items.add_column(Column("item_id", "INT(11)", auto_increment=True, primary_key=True))
        items.add_column(Column("name", "VARCHAR(100)", nullable=False))
        items.add_column(Column("description", "TEXT"))
        items.add_column(Column("type", "ENUM('weapon','armor','consumable','material','quest')"))
        items.add_column(Column("rarity", "ENUM('common','uncommon','rare','epic','legendary')"))
        items.add_column(Column("base_price", "INT(11)", default=0))
        items.add_column(Column("required_level", "INT(11)", default=1))
        items.add_column(Column("stats", "JSON"))
        items.add_column(Column("icon_url", "VARCHAR(255)"))
        items.add_column(Column("created_at", "DATETIME"))
        nexus_db.add_table(items)
        
        # Inventory table
        inventory = Table("inventory", comment="Player inventory items")
        inventory.add_column(Column("inventory_id", "INT(11)", auto_increment=True, primary_key=True))
        inventory.add_column(Column("player_id", "INT(11)", nullable=False))
        inventory.add_column(Column("item_id", "INT(11)", nullable=False))
        inventory.add_column(Column("quantity", "INT(11)", default=1))
        inventory.add_column(Column("slot", "INT(11)"))
        inventory.add_column(Column("equipped", "TINYINT(1)", default=0))
        inventory.add_column(Column("acquired_at", "DATETIME", nullable=False))
        nexus_db.add_table(inventory)
        
        # Achievements table
        achievements = Table("achievements", comment="Game achievements")
        achievements.add_column(Column("achievement_id", "INT(11)", auto_increment=True, primary_key=True))
        achievements.add_column(Column("name", "VARCHAR(100)", nullable=False))
        achievements.add_column(Column("description", "TEXT"))
        achievements.add_column(Column("points", "INT(11)", default=10))
        achievements.add_column(Column("category", "VARCHAR(50)"))
        achievements.add_column(Column("icon_url", "VARCHAR(255)"))
        achievements.add_column(Column("is_hidden", "TINYINT(1)", default=0))
        nexus_db.add_table(achievements)
        
        # Player achievements
        player_achievements = Table("player_achievements", comment="Player achievement unlocks")
        player_achievements.add_column(Column("id", "INT(11)", auto_increment=True, primary_key=True))
        player_achievements.add_column(Column("player_id", "INT(11)", nullable=False))
        player_achievements.add_column(Column("achievement_id", "INT(11)", nullable=False))
        player_achievements.add_column(Column("unlocked_at", "DATETIME", nullable=False))
        nexus_db.add_table(player_achievements)
        
        # Sessions table (juicy for attackers)
        sessions = Table("sessions", comment="Active game sessions")
        sessions.add_column(Column("session_id", "VARCHAR(64)", primary_key=True))
        sessions.add_column(Column("player_id", "INT(11)", nullable=False))
        sessions.add_column(Column("ip_address", "VARCHAR(45)"))
        sessions.add_column(Column("user_agent", "TEXT"))
        sessions.add_column(Column("started_at", "DATETIME", nullable=False))
        sessions.add_column(Column("last_activity", "DATETIME"))
        sessions.add_column(Column("is_active", "TINYINT(1)", default=1))
        nexus_db.add_table(sessions)
        
        # Transactions table (payment data - very juicy)
        transactions = Table("transactions", comment="Payment transactions")
        transactions.add_column(Column("transaction_id", "VARCHAR(64)", primary_key=True))
        transactions.add_column(Column("player_id", "INT(11)", nullable=False))
        transactions.add_column(Column("amount", "DECIMAL(10,2)", nullable=False))
        transactions.add_column(Column("currency", "VARCHAR(3)", default="USD"))
        transactions.add_column(Column("payment_method", "VARCHAR(50)"))
        transactions.add_column(Column("card_last_four", "VARCHAR(4)"))
        transactions.add_column(Column("status", "ENUM('pending','completed','failed','refunded')"))
        transactions.add_column(Column("item_purchased", "VARCHAR(100)"))
        transactions.add_column(Column("created_at", "DATETIME", nullable=False))
        nexus_db.add_table(transactions)
        
        # Guilds table
        guilds = Table("guilds", comment="Player guilds")
        guilds.add_column(Column("guild_id", "INT(11)", auto_increment=True, primary_key=True))
        guilds.add_column(Column("name", "VARCHAR(50)", nullable=False, unique=True))
        guilds.add_column(Column("description", "TEXT"))
        guilds.add_column(Column("leader_id", "INT(11)", nullable=False))
        guilds.add_column(Column("member_count", "INT(11)", default=1))
        guilds.add_column(Column("level", "INT(11)", default=1))
        guilds.add_column(Column("experience", "BIGINT(20)", default=0))
        guilds.add_column(Column("created_at", "DATETIME", nullable=False))
        nexus_db.add_table(guilds)
        
        # Guild members
        guild_members = Table("guild_members", comment="Guild membership")
        guild_members.add_column(Column("id", "INT(11)", auto_increment=True, primary_key=True))
        guild_members.add_column(Column("guild_id", "INT(11)", nullable=False))
        guild_members.add_column(Column("player_id", "INT(11)", nullable=False))
        guild_members.add_column(Column("rank", "ENUM('leader','officer','member')"))
        guild_members.add_column(Column("joined_at", "DATETIME", nullable=False))
        nexus_db.add_table(guild_members)
        
        self.databases["nexus_gamedev"] = nexus_db
        
        # ============ player_data - Player statistics ============
        player_data_db = Database("player_data")
        
        # Leaderboards table
        leaderboards = Table("leaderboards", comment="Game leaderboards")
        leaderboards.add_column(Column("id", "INT(11)", auto_increment=True, primary_key=True))
        leaderboards.add_column(Column("player_id", "INT(11)", nullable=False))
        leaderboards.add_column(Column("player_name", "VARCHAR(50)"))
        leaderboards.add_column(Column("leaderboard_type", "VARCHAR(50)", nullable=False))
        leaderboards.add_column(Column("score", "BIGINT(20)", default=0))
        leaderboards.add_column(Column("rank", "INT(11)"))
        leaderboards.add_column(Column("season", "INT(11)", default=1))
        leaderboards.add_column(Column("updated_at", "DATETIME"))
        player_data_db.add_table(leaderboards)
        
        # Match history
        match_history = Table("match_history", comment="PvP match records")
        match_history.add_column(Column("match_id", "VARCHAR(64)", primary_key=True))
        match_history.add_column(Column("player1_id", "INT(11)", nullable=False))
        match_history.add_column(Column("player1_name", "VARCHAR(50)"))
        match_history.add_column(Column("player2_id", "INT(11)", nullable=False))
        match_history.add_column(Column("player2_name", "VARCHAR(50)"))
        match_history.add_column(Column("winner_id", "INT(11)"))
        match_history.add_column(Column("game_mode", "VARCHAR(50)"))
        match_history.add_column(Column("duration_seconds", "INT(11)"))
        match_history.add_column(Column("played_at", "DATETIME", nullable=False))
        player_data_db.add_table(match_history)
        
        # Player statistics
        player_stats = Table("player_stats", comment="Aggregated player statistics")
        player_stats.add_column(Column("player_id", "INT(11)", primary_key=True))
        player_stats.add_column(Column("player_name", "VARCHAR(50)"))
        player_stats.add_column(Column("total_wins", "INT(11)", default=0))
        player_stats.add_column(Column("total_losses", "INT(11)", default=0))
        player_stats.add_column(Column("total_kills", "INT(11)", default=0))
        player_stats.add_column(Column("total_deaths", "INT(11)", default=0))
        player_stats.add_column(Column("kd_ratio", "DECIMAL(5,2)", default=0.00))
        player_stats.add_column(Column("win_rate", "DECIMAL(5,2)", default=0.00))
        player_stats.add_column(Column("total_playtime", "BIGINT(20)", default=0))
        player_stats.add_column(Column("highest_score", "BIGINT(20)", default=0))
        player_stats.add_column(Column("updated_at", "DATETIME"))
        player_data_db.add_table(player_stats)
        
        self.databases["player_data"] = player_data_db
        
        # ============ game_analytics - Analytics data ============
        analytics_db = Database("game_analytics")
        
        # Events table
        events = Table("events", comment="Game analytics events")
        events.add_column(Column("event_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        events.add_column(Column("event_type", "VARCHAR(100)", nullable=False))
        events.add_column(Column("player_id", "INT(11)"))
        events.add_column(Column("session_id", "VARCHAR(64)"))
        events.add_column(Column("data", "JSON"))
        events.add_column(Column("timestamp", "DATETIME", nullable=False))
        analytics_db.add_table(events)
        
        # Daily metrics
        daily_metrics = Table("daily_metrics", comment="Daily aggregated metrics")
        daily_metrics.add_column(Column("date", "DATE", primary_key=True))
        daily_metrics.add_column(Column("dau", "INT(11)", comment="Daily Active Users"))
        daily_metrics.add_column(Column("new_users", "INT(11)"))
        daily_metrics.add_column(Column("revenue", "DECIMAL(12,2)"))
        daily_metrics.add_column(Column("sessions", "INT(11)"))
        daily_metrics.add_column(Column("avg_session_length", "INT(11)"))
        daily_metrics.add_column(Column("total_matches", "INT(11)"))
        daily_metrics.add_column(Column("items_purchased", "INT(11)"))
        analytics_db.add_table(daily_metrics)
        
        self.databases["game_analytics"] = analytics_db
        
        # ============ asset_library - Game assets ============
        assets_db = Database("asset_library")
        
        # Assets table
        assets = Table("assets", comment="Game asset metadata")
        assets.add_column(Column("asset_id", "INT(11)", auto_increment=True, primary_key=True))
        assets.add_column(Column("name", "VARCHAR(255)", nullable=False))
        assets.add_column(Column("type", "ENUM('texture','model','sound','animation','shader','prefab')"))
        assets.add_column(Column("file_path", "VARCHAR(500)"))
        assets.add_column(Column("file_size", "BIGINT(20)"))
        assets.add_column(Column("checksum", "VARCHAR(64)"))
        assets.add_column(Column("version", "VARCHAR(20)"))
        assets.add_column(Column("created_by", "VARCHAR(100)"))
        assets.add_column(Column("created_at", "DATETIME", nullable=False))
        assets.add_column(Column("updated_at", "DATETIME"))
        assets_db.add_table(assets)
        
        self.databases["asset_library"] = assets_db
        
        # ============ hr_system - Human Resources ============
        hr_db = Database("hr_system")
        
        employees = Table("employees", comment="Employee records")
        employees.add_column(Column("employee_id", "INT(11)", auto_increment=True, primary_key=True))
        employees.add_column(Column("first_name", "VARCHAR(50)", nullable=False))
        employees.add_column(Column("last_name", "VARCHAR(50)", nullable=False))
        employees.add_column(Column("email", "VARCHAR(100)", unique=True))
        employees.add_column(Column("phone", "VARCHAR(20)"))
        employees.add_column(Column("hire_date", "DATE", nullable=False))
        employees.add_column(Column("department_id", "INT(11)"))
        employees.add_column(Column("position_id", "INT(11)"))
        employees.add_column(Column("manager_id", "INT(11)"))
        employees.add_column(Column("salary", "DECIMAL(10,2)"))
        employees.add_column(Column("status", "ENUM('active','inactive','terminated')"))
        hr_db.add_table(employees)
        
        departments = Table("departments", comment="Company departments")
        departments.add_column(Column("department_id", "INT(11)", auto_increment=True, primary_key=True))
        departments.add_column(Column("name", "VARCHAR(100)", nullable=False))
        departments.add_column(Column("manager_id", "INT(11)"))
        departments.add_column(Column("budget", "DECIMAL(15,2)"))
        departments.add_column(Column("location", "VARCHAR(100)"))
        hr_db.add_table(departments)
        
        positions = Table("positions", comment="Job positions")
        positions.add_column(Column("position_id", "INT(11)", auto_increment=True, primary_key=True))
        positions.add_column(Column("title", "VARCHAR(100)", nullable=False))
        positions.add_column(Column("min_salary", "DECIMAL(10,2)"))
        positions.add_column(Column("max_salary", "DECIMAL(10,2)"))
        positions.add_column(Column("department_id", "INT(11)"))
        hr_db.add_table(positions)
        
        salaries = Table("salaries", comment="Salary history")
        salaries.add_column(Column("salary_id", "INT(11)", auto_increment=True, primary_key=True))
        salaries.add_column(Column("employee_id", "INT(11)", nullable=False))
        salaries.add_column(Column("amount", "DECIMAL(10,2)", nullable=False))
        salaries.add_column(Column("effective_date", "DATE", nullable=False))
        salaries.add_column(Column("end_date", "DATE"))
        hr_db.add_table(salaries)
        
        reviews = Table("performance_reviews", comment="Employee reviews")
        reviews.add_column(Column("review_id", "INT(11)", auto_increment=True, primary_key=True))
        reviews.add_column(Column("employee_id", "INT(11)", nullable=False))
        reviews.add_column(Column("reviewer_id", "INT(11)"))
        reviews.add_column(Column("review_date", "DATE", nullable=False))
        reviews.add_column(Column("rating", "INT(11)"))
        reviews.add_column(Column("comments", "TEXT"))
        hr_db.add_table(reviews)
        
        attendance = Table("attendance", comment="Attendance records")
        attendance.add_column(Column("attendance_id", "INT(11)", auto_increment=True, primary_key=True))
        attendance.add_column(Column("employee_id", "INT(11)", nullable=False))
        attendance.add_column(Column("date", "DATE", nullable=False))
        attendance.add_column(Column("check_in", "TIME"))
        attendance.add_column(Column("check_out", "TIME"))
        attendance.add_column(Column("status", "ENUM('present','absent','late','leave')"))
        hr_db.add_table(attendance)
        
        benefits = Table("benefits", comment="Employee benefits")
        benefits.add_column(Column("benefit_id", "INT(11)", auto_increment=True, primary_key=True))
        benefits.add_column(Column("employee_id", "INT(11)", nullable=False))
        benefits.add_column(Column("benefit_type", "VARCHAR(50)"))
        benefits.add_column(Column("provider", "VARCHAR(100)"))
        benefits.add_column(Column("start_date", "DATE"))
        benefits.add_column(Column("cost", "DECIMAL(10,2)"))
        hr_db.add_table(benefits)
        
        training = Table("training", comment="Training records")
        training.add_column(Column("training_id", "INT(11)", auto_increment=True, primary_key=True))
        training.add_column(Column("name", "VARCHAR(200)", nullable=False))
        training.add_column(Column("description", "TEXT"))
        training.add_column(Column("instructor", "VARCHAR(100)"))
        training.add_column(Column("duration_hours", "INT(11)"))
        training.add_column(Column("cost", "DECIMAL(10,2)"))
        hr_db.add_table(training)
        
        candidates = Table("candidates", comment="Job candidates")
        candidates.add_column(Column("candidate_id", "INT(11)", auto_increment=True, primary_key=True))
        candidates.add_column(Column("first_name", "VARCHAR(50)", nullable=False))
        candidates.add_column(Column("last_name", "VARCHAR(50)", nullable=False))
        candidates.add_column(Column("email", "VARCHAR(100)"))
        candidates.add_column(Column("phone", "VARCHAR(20)"))
        candidates.add_column(Column("position_applied", "VARCHAR(100)"))
        candidates.add_column(Column("resume_url", "VARCHAR(500)"))
        candidates.add_column(Column("status", "ENUM('new','screening','interview','offer','hired','rejected')"))
        hr_db.add_table(candidates)
        
        interviews = Table("interviews", comment="Interview schedules")
        interviews.add_column(Column("interview_id", "INT(11)", auto_increment=True, primary_key=True))
        interviews.add_column(Column("candidate_id", "INT(11)", nullable=False))
        interviews.add_column(Column("interviewer_id", "INT(11)"))
        interviews.add_column(Column("scheduled_date", "DATETIME", nullable=False))
        interviews.add_column(Column("type", "ENUM('phone','video','onsite')"))
        interviews.add_column(Column("feedback", "TEXT"))
        interviews.add_column(Column("result", "ENUM('pass','fail','pending')"))
        hr_db.add_table(interviews)
        
        self.databases["hr_system"] = hr_db
        
        # ============ finance_db - Financial Records ============
        finance_db = Database("finance_db")
        
        accounts = Table("accounts", comment="Financial accounts")
        accounts.add_column(Column("account_id", "INT(11)", auto_increment=True, primary_key=True))
        accounts.add_column(Column("account_number", "VARCHAR(50)", unique=True))
        accounts.add_column(Column("account_name", "VARCHAR(100)", nullable=False))
        accounts.add_column(Column("account_type", "ENUM('asset','liability','equity','revenue','expense')"))
        accounts.add_column(Column("balance", "DECIMAL(15,2)", default=0.00))
        accounts.add_column(Column("currency", "VARCHAR(3)", default="USD"))
        finance_db.add_table(accounts)
        
        transactions = Table("transactions", comment="Financial transactions")
        transactions.add_column(Column("transaction_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        transactions.add_column(Column("account_id", "INT(11)", nullable=False))
        transactions.add_column(Column("transaction_type", "ENUM('debit','credit')"))
        transactions.add_column(Column("amount", "DECIMAL(15,2)", nullable=False))
        transactions.add_column(Column("description", "VARCHAR(500)"))
        transactions.add_column(Column("reference_id", "VARCHAR(100)"))
        transactions.add_column(Column("created_at", "DATETIME", nullable=False))
        finance_db.add_table(transactions)
        
        invoices = Table("invoices", comment="Customer invoices")
        invoices.add_column(Column("invoice_id", "INT(11)", auto_increment=True, primary_key=True))
        invoices.add_column(Column("invoice_number", "VARCHAR(50)", unique=True))
        invoices.add_column(Column("customer_id", "INT(11)", nullable=False))
        invoices.add_column(Column("issue_date", "DATE", nullable=False))
        invoices.add_column(Column("due_date", "DATE"))
        invoices.add_column(Column("total_amount", "DECIMAL(15,2)"))
        invoices.add_column(Column("status", "ENUM('draft','sent','paid','overdue','cancelled')"))
        finance_db.add_table(invoices)
        
        payments = Table("payments", comment="Payment records")
        payments.add_column(Column("payment_id", "INT(11)", auto_increment=True, primary_key=True))
        payments.add_column(Column("invoice_id", "INT(11)"))
        payments.add_column(Column("amount", "DECIMAL(15,2)", nullable=False))
        payments.add_column(Column("payment_method", "ENUM('cash','check','credit_card','wire','crypto')"))
        payments.add_column(Column("payment_date", "DATE", nullable=False))
        payments.add_column(Column("transaction_ref", "VARCHAR(100)"))
        finance_db.add_table(payments)
        
        budgets = Table("budgets", comment="Department budgets")
        budgets.add_column(Column("budget_id", "INT(11)", auto_increment=True, primary_key=True))
        budgets.add_column(Column("department", "VARCHAR(100)", nullable=False))
        budgets.add_column(Column("fiscal_year", "INT(4)", nullable=False))
        budgets.add_column(Column("quarter", "INT(1)"))
        budgets.add_column(Column("allocated", "DECIMAL(15,2)"))
        budgets.add_column(Column("spent", "DECIMAL(15,2)"))
        finance_db.add_table(budgets)
        
        expenses = Table("expenses", comment="Expense reports")
        expenses.add_column(Column("expense_id", "INT(11)", auto_increment=True, primary_key=True))
        expenses.add_column(Column("employee_id", "INT(11)", nullable=False))
        expenses.add_column(Column("category", "VARCHAR(50)"))
        expenses.add_column(Column("amount", "DECIMAL(10,2)", nullable=False))
        expenses.add_column(Column("description", "VARCHAR(500)"))
        expenses.add_column(Column("receipt_url", "VARCHAR(500)"))
        expenses.add_column(Column("status", "ENUM('pending','approved','rejected','reimbursed')"))
        expenses.add_column(Column("submitted_at", "DATETIME"))
        finance_db.add_table(expenses)
        
        reports = Table("financial_reports", comment="Financial reports")
        reports.add_column(Column("report_id", "INT(11)", auto_increment=True, primary_key=True))
        reports.add_column(Column("report_type", "VARCHAR(50)", nullable=False))
        reports.add_column(Column("period_start", "DATE"))
        reports.add_column(Column("period_end", "DATE"))
        reports.add_column(Column("generated_at", "DATETIME"))
        reports.add_column(Column("file_path", "VARCHAR(500)"))
        finance_db.add_table(reports)
        
        audits = Table("audits", comment="Audit records")
        audits.add_column(Column("audit_id", "INT(11)", auto_increment=True, primary_key=True))
        audits.add_column(Column("auditor", "VARCHAR(100)"))
        audits.add_column(Column("audit_date", "DATE", nullable=False))
        audits.add_column(Column("scope", "VARCHAR(200)"))
        audits.add_column(Column("findings", "TEXT"))
        audits.add_column(Column("status", "ENUM('scheduled','in_progress','completed','remediation')"))
        finance_db.add_table(audits)
        
        vendors = Table("vendors", comment="Vendor information")
        vendors.add_column(Column("vendor_id", "INT(11)", auto_increment=True, primary_key=True))
        vendors.add_column(Column("name", "VARCHAR(200)", nullable=False))
        vendors.add_column(Column("contact_name", "VARCHAR(100)"))
        vendors.add_column(Column("email", "VARCHAR(100)"))
        vendors.add_column(Column("phone", "VARCHAR(20)"))
        vendors.add_column(Column("address", "TEXT"))
        vendors.add_column(Column("tax_id", "VARCHAR(50)"))
        finance_db.add_table(vendors)
        
        contracts = Table("contracts", comment="Vendor contracts")
        contracts.add_column(Column("contract_id", "INT(11)", auto_increment=True, primary_key=True))
        contracts.add_column(Column("vendor_id", "INT(11)", nullable=False))
        contracts.add_column(Column("contract_number", "VARCHAR(50)"))
        contracts.add_column(Column("start_date", "DATE", nullable=False))
        contracts.add_column(Column("end_date", "DATE"))
        contracts.add_column(Column("value", "DECIMAL(15,2)"))
        contracts.add_column(Column("status", "ENUM('draft','active','expired','terminated')"))
        finance_db.add_table(contracts)
        
        self.databases["finance_db"] = finance_db
        
        # ============ user_auth - Authentication System ============
        auth_db = Database("user_auth")
        
        users = Table("users", comment="User accounts")
        users.add_column(Column("user_id", "INT(11)", auto_increment=True, primary_key=True))
        users.add_column(Column("username", "VARCHAR(50)", unique=True, nullable=False))
        users.add_column(Column("email", "VARCHAR(100)", unique=True, nullable=False))
        users.add_column(Column("password_hash", "VARCHAR(255)", nullable=False))
        users.add_column(Column("salt", "VARCHAR(64)"))
        users.add_column(Column("is_active", "TINYINT(1)", default=1))
        users.add_column(Column("is_verified", "TINYINT(1)", default=0))
        users.add_column(Column("created_at", "DATETIME", nullable=False))
        users.add_column(Column("last_login", "DATETIME"))
        auth_db.add_table(users)
        
        roles = Table("roles", comment="User roles")
        roles.add_column(Column("role_id", "INT(11)", auto_increment=True, primary_key=True))
        roles.add_column(Column("name", "VARCHAR(50)", unique=True, nullable=False))
        roles.add_column(Column("description", "VARCHAR(200)"))
        roles.add_column(Column("priority", "INT(11)", default=0))
        auth_db.add_table(roles)
        
        permissions = Table("permissions", comment="System permissions")
        permissions.add_column(Column("permission_id", "INT(11)", auto_increment=True, primary_key=True))
        permissions.add_column(Column("name", "VARCHAR(100)", unique=True, nullable=False))
        permissions.add_column(Column("resource", "VARCHAR(100)"))
        permissions.add_column(Column("action", "VARCHAR(50)"))
        permissions.add_column(Column("description", "VARCHAR(200)"))
        auth_db.add_table(permissions)
        
        sessions = Table("sessions", comment="User sessions")
        sessions.add_column(Column("session_id", "VARCHAR(128)", primary_key=True))
        sessions.add_column(Column("user_id", "INT(11)", nullable=False))
        sessions.add_column(Column("ip_address", "VARCHAR(45)"))
        sessions.add_column(Column("user_agent", "VARCHAR(500)"))
        sessions.add_column(Column("created_at", "DATETIME", nullable=False))
        sessions.add_column(Column("expires_at", "DATETIME"))
        sessions.add_column(Column("is_active", "TINYINT(1)", default=1))
        auth_db.add_table(sessions)
        
        tokens = Table("tokens", comment="API tokens")
        tokens.add_column(Column("token_id", "INT(11)", auto_increment=True, primary_key=True))
        tokens.add_column(Column("user_id", "INT(11)", nullable=False))
        tokens.add_column(Column("token_hash", "VARCHAR(255)", nullable=False))
        tokens.add_column(Column("token_type", "ENUM('access','refresh','api')"))
        tokens.add_column(Column("expires_at", "DATETIME"))
        tokens.add_column(Column("created_at", "DATETIME", nullable=False))
        tokens.add_column(Column("is_revoked", "TINYINT(1)", default=0))
        auth_db.add_table(tokens)
        
        login_history = Table("login_history", comment="Login attempts")
        login_history.add_column(Column("login_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        login_history.add_column(Column("user_id", "INT(11)"))
        login_history.add_column(Column("username_attempted", "VARCHAR(100)"))
        login_history.add_column(Column("ip_address", "VARCHAR(45)"))
        login_history.add_column(Column("user_agent", "VARCHAR(500)"))
        login_history.add_column(Column("success", "TINYINT(1)"))
        login_history.add_column(Column("failure_reason", "VARCHAR(100)"))
        login_history.add_column(Column("attempted_at", "DATETIME", nullable=False))
        auth_db.add_table(login_history)
        
        password_resets = Table("password_resets", comment="Password reset requests")
        password_resets.add_column(Column("reset_id", "INT(11)", auto_increment=True, primary_key=True))
        password_resets.add_column(Column("user_id", "INT(11)", nullable=False))
        password_resets.add_column(Column("token_hash", "VARCHAR(255)", nullable=False))
        password_resets.add_column(Column("expires_at", "DATETIME", nullable=False))
        password_resets.add_column(Column("used_at", "DATETIME"))
        password_resets.add_column(Column("created_at", "DATETIME", nullable=False))
        auth_db.add_table(password_resets)
        
        oauth_providers = Table("oauth_providers", comment="OAuth provider config")
        oauth_providers.add_column(Column("provider_id", "INT(11)", auto_increment=True, primary_key=True))
        oauth_providers.add_column(Column("name", "VARCHAR(50)", unique=True, nullable=False))
        oauth_providers.add_column(Column("client_id", "VARCHAR(255)"))
        oauth_providers.add_column(Column("client_secret", "VARCHAR(255)"))
        oauth_providers.add_column(Column("callback_url", "VARCHAR(500)"))
        oauth_providers.add_column(Column("is_enabled", "TINYINT(1)", default=1))
        auth_db.add_table(oauth_providers)
        
        mfa_devices = Table("mfa_devices", comment="MFA devices")
        mfa_devices.add_column(Column("device_id", "INT(11)", auto_increment=True, primary_key=True))
        mfa_devices.add_column(Column("user_id", "INT(11)", nullable=False))
        mfa_devices.add_column(Column("device_type", "ENUM('totp','sms','email','hardware')"))
        mfa_devices.add_column(Column("secret_hash", "VARCHAR(255)"))
        mfa_devices.add_column(Column("phone_number", "VARCHAR(20)"))
        mfa_devices.add_column(Column("is_primary", "TINYINT(1)", default=0))
        mfa_devices.add_column(Column("is_verified", "TINYINT(1)", default=0))
        auth_db.add_table(mfa_devices)
        
        api_keys = Table("api_keys", comment="API keys")
        api_keys.add_column(Column("key_id", "INT(11)", auto_increment=True, primary_key=True))
        api_keys.add_column(Column("user_id", "INT(11)", nullable=False))
        api_keys.add_column(Column("key_prefix", "VARCHAR(10)", nullable=False))
        api_keys.add_column(Column("key_hash", "VARCHAR(255)", nullable=False))
        api_keys.add_column(Column("name", "VARCHAR(100)"))
        api_keys.add_column(Column("permissions", "JSON"))
        api_keys.add_column(Column("rate_limit", "INT(11)", default=1000))
        api_keys.add_column(Column("last_used", "DATETIME"))
        api_keys.add_column(Column("expires_at", "DATETIME"))
        api_keys.add_column(Column("is_active", "TINYINT(1)", default=1))
        auth_db.add_table(api_keys)
        
        self.databases["user_auth"] = auth_db
        
        # ============ inventory_mgmt - Inventory Management ============
        inv_db = Database("inventory_mgmt")
        
        products = Table("products", comment="Product catalog")
        products.add_column(Column("product_id", "INT(11)", auto_increment=True, primary_key=True))
        products.add_column(Column("sku", "VARCHAR(50)", unique=True, nullable=False))
        products.add_column(Column("name", "VARCHAR(200)", nullable=False))
        products.add_column(Column("description", "TEXT"))
        products.add_column(Column("category_id", "INT(11)"))
        products.add_column(Column("brand_id", "INT(11)"))
        products.add_column(Column("unit_price", "DECIMAL(10,2)"))
        products.add_column(Column("cost", "DECIMAL(10,2)"))
        products.add_column(Column("weight", "DECIMAL(8,3)"))
        products.add_column(Column("is_active", "TINYINT(1)", default=1))
        inv_db.add_table(products)
        
        warehouses = Table("warehouses", comment="Warehouse locations")
        warehouses.add_column(Column("warehouse_id", "INT(11)", auto_increment=True, primary_key=True))
        warehouses.add_column(Column("name", "VARCHAR(100)", nullable=False))
        warehouses.add_column(Column("code", "VARCHAR(10)", unique=True))
        warehouses.add_column(Column("address", "TEXT"))
        warehouses.add_column(Column("city", "VARCHAR(100)"))
        warehouses.add_column(Column("country", "VARCHAR(50)"))
        warehouses.add_column(Column("capacity", "INT(11)"))
        warehouses.add_column(Column("manager", "VARCHAR(100)"))
        inv_db.add_table(warehouses)
        
        stock = Table("stock", comment="Stock levels")
        stock.add_column(Column("stock_id", "INT(11)", auto_increment=True, primary_key=True))
        stock.add_column(Column("product_id", "INT(11)", nullable=False))
        stock.add_column(Column("warehouse_id", "INT(11)", nullable=False))
        stock.add_column(Column("quantity", "INT(11)", default=0))
        stock.add_column(Column("reserved", "INT(11)", default=0))
        stock.add_column(Column("min_level", "INT(11)"))
        stock.add_column(Column("max_level", "INT(11)"))
        stock.add_column(Column("last_updated", "DATETIME"))
        inv_db.add_table(stock)
        
        orders = Table("orders", comment="Purchase orders")
        orders.add_column(Column("order_id", "INT(11)", auto_increment=True, primary_key=True))
        orders.add_column(Column("order_number", "VARCHAR(50)", unique=True))
        orders.add_column(Column("supplier_id", "INT(11)"))
        orders.add_column(Column("order_date", "DATE", nullable=False))
        orders.add_column(Column("expected_date", "DATE"))
        orders.add_column(Column("total_amount", "DECIMAL(12,2)"))
        orders.add_column(Column("status", "ENUM('draft','pending','approved','shipped','received','cancelled')"))
        inv_db.add_table(orders)
        
        suppliers = Table("suppliers", comment="Supplier information")
        suppliers.add_column(Column("supplier_id", "INT(11)", auto_increment=True, primary_key=True))
        suppliers.add_column(Column("name", "VARCHAR(200)", nullable=False))
        suppliers.add_column(Column("contact_name", "VARCHAR(100)"))
        suppliers.add_column(Column("email", "VARCHAR(100)"))
        suppliers.add_column(Column("phone", "VARCHAR(20)"))
        suppliers.add_column(Column("address", "TEXT"))
        suppliers.add_column(Column("payment_terms", "VARCHAR(50)"))
        suppliers.add_column(Column("rating", "DECIMAL(2,1)"))
        inv_db.add_table(suppliers)
        
        shipments = Table("shipments", comment="Shipment tracking")
        shipments.add_column(Column("shipment_id", "INT(11)", auto_increment=True, primary_key=True))
        shipments.add_column(Column("order_id", "INT(11)"))
        shipments.add_column(Column("tracking_number", "VARCHAR(100)"))
        shipments.add_column(Column("carrier", "VARCHAR(50)"))
        shipments.add_column(Column("shipped_date", "DATETIME"))
        shipments.add_column(Column("delivered_date", "DATETIME"))
        shipments.add_column(Column("status", "ENUM('pending','in_transit','delivered','failed')"))
        inv_db.add_table(shipments)
        
        returns = Table("returns", comment="Return requests")
        returns.add_column(Column("return_id", "INT(11)", auto_increment=True, primary_key=True))
        returns.add_column(Column("order_id", "INT(11)"))
        returns.add_column(Column("product_id", "INT(11)"))
        returns.add_column(Column("quantity", "INT(11)"))
        returns.add_column(Column("reason", "VARCHAR(200)"))
        returns.add_column(Column("status", "ENUM('pending','approved','rejected','completed')"))
        returns.add_column(Column("refund_amount", "DECIMAL(10,2)"))
        inv_db.add_table(returns)
        
        categories = Table("categories", comment="Product categories")
        categories.add_column(Column("category_id", "INT(11)", auto_increment=True, primary_key=True))
        categories.add_column(Column("name", "VARCHAR(100)", nullable=False))
        categories.add_column(Column("parent_id", "INT(11)"))
        categories.add_column(Column("description", "TEXT"))
        categories.add_column(Column("sort_order", "INT(11)", default=0))
        inv_db.add_table(categories)
        
        brands = Table("brands", comment="Product brands")
        brands.add_column(Column("brand_id", "INT(11)", auto_increment=True, primary_key=True))
        brands.add_column(Column("name", "VARCHAR(100)", nullable=False))
        brands.add_column(Column("logo_url", "VARCHAR(500)"))
        brands.add_column(Column("website", "VARCHAR(200)"))
        brands.add_column(Column("is_active", "TINYINT(1)", default=1))
        inv_db.add_table(brands)
        
        price_history = Table("price_history", comment="Price changes")
        price_history.add_column(Column("history_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        price_history.add_column(Column("product_id", "INT(11)", nullable=False))
        price_history.add_column(Column("old_price", "DECIMAL(10,2)"))
        price_history.add_column(Column("new_price", "DECIMAL(10,2)", nullable=False))
        price_history.add_column(Column("changed_by", "VARCHAR(100)"))
        price_history.add_column(Column("changed_at", "DATETIME", nullable=False))
        inv_db.add_table(price_history)
        
        self.databases["inventory_mgmt"] = inv_db
        
        # ============ support_tickets - Customer Support ============
        support_db = Database("support_tickets")
        
        tickets = Table("tickets", comment="Support tickets")
        tickets.add_column(Column("ticket_id", "INT(11)", auto_increment=True, primary_key=True))
        tickets.add_column(Column("ticket_number", "VARCHAR(20)", unique=True))
        tickets.add_column(Column("subject", "VARCHAR(200)", nullable=False))
        tickets.add_column(Column("description", "TEXT"))
        tickets.add_column(Column("customer_id", "INT(11)", nullable=False))
        tickets.add_column(Column("agent_id", "INT(11)"))
        tickets.add_column(Column("category_id", "INT(11)"))
        tickets.add_column(Column("priority", "ENUM('low','medium','high','urgent')"))
        tickets.add_column(Column("status", "ENUM('open','in_progress','waiting','resolved','closed')"))
        tickets.add_column(Column("created_at", "DATETIME", nullable=False))
        tickets.add_column(Column("updated_at", "DATETIME"))
        tickets.add_column(Column("resolved_at", "DATETIME"))
        support_db.add_table(tickets)
        
        agents = Table("agents", comment="Support agents")
        agents.add_column(Column("agent_id", "INT(11)", auto_increment=True, primary_key=True))
        agents.add_column(Column("name", "VARCHAR(100)", nullable=False))
        agents.add_column(Column("email", "VARCHAR(100)", unique=True))
        agents.add_column(Column("department", "VARCHAR(50)"))
        agents.add_column(Column("is_available", "TINYINT(1)", default=1))
        agents.add_column(Column("max_tickets", "INT(11)", default=10))
        support_db.add_table(agents)
        
        responses = Table("responses", comment="Ticket responses")
        responses.add_column(Column("response_id", "INT(11)", auto_increment=True, primary_key=True))
        responses.add_column(Column("ticket_id", "INT(11)", nullable=False))
        responses.add_column(Column("responder_type", "ENUM('agent','customer','system')"))
        responses.add_column(Column("responder_id", "INT(11)"))
        responses.add_column(Column("message", "TEXT", nullable=False))
        responses.add_column(Column("is_internal", "TINYINT(1)", default=0))
        responses.add_column(Column("created_at", "DATETIME", nullable=False))
        support_db.add_table(responses)
        
        ticket_categories = Table("ticket_categories", comment="Ticket categories")
        ticket_categories.add_column(Column("category_id", "INT(11)", auto_increment=True, primary_key=True))
        ticket_categories.add_column(Column("name", "VARCHAR(100)", nullable=False))
        ticket_categories.add_column(Column("description", "VARCHAR(200)"))
        ticket_categories.add_column(Column("default_priority", "ENUM('low','medium','high','urgent')"))
        ticket_categories.add_column(Column("sla_hours", "INT(11)"))
        support_db.add_table(ticket_categories)
        
        sla = Table("sla", comment="SLA definitions")
        sla.add_column(Column("sla_id", "INT(11)", auto_increment=True, primary_key=True))
        sla.add_column(Column("name", "VARCHAR(100)", nullable=False))
        sla.add_column(Column("priority", "ENUM('low','medium','high','urgent')"))
        sla.add_column(Column("response_time_hours", "INT(11)"))
        sla.add_column(Column("resolution_time_hours", "INT(11)"))
        support_db.add_table(sla)
        
        feedback = Table("feedback", comment="Customer feedback")
        feedback.add_column(Column("feedback_id", "INT(11)", auto_increment=True, primary_key=True))
        feedback.add_column(Column("ticket_id", "INT(11)", nullable=False))
        feedback.add_column(Column("rating", "INT(11)"))
        feedback.add_column(Column("comment", "TEXT"))
        feedback.add_column(Column("submitted_at", "DATETIME"))
        support_db.add_table(feedback)
        
        escalations = Table("escalations", comment="Ticket escalations")
        escalations.add_column(Column("escalation_id", "INT(11)", auto_increment=True, primary_key=True))
        escalations.add_column(Column("ticket_id", "INT(11)", nullable=False))
        escalations.add_column(Column("from_agent_id", "INT(11)"))
        escalations.add_column(Column("to_agent_id", "INT(11)"))
        escalations.add_column(Column("reason", "VARCHAR(200)"))
        escalations.add_column(Column("escalated_at", "DATETIME", nullable=False))
        support_db.add_table(escalations)
        
        knowledge_base = Table("knowledge_base", comment="Knowledge articles")
        knowledge_base.add_column(Column("article_id", "INT(11)", auto_increment=True, primary_key=True))
        knowledge_base.add_column(Column("title", "VARCHAR(200)", nullable=False))
        knowledge_base.add_column(Column("content", "TEXT"))
        knowledge_base.add_column(Column("category", "VARCHAR(100)"))
        knowledge_base.add_column(Column("tags", "VARCHAR(500)"))
        knowledge_base.add_column(Column("author_id", "INT(11)"))
        knowledge_base.add_column(Column("views", "INT(11)", default=0))
        knowledge_base.add_column(Column("is_published", "TINYINT(1)", default=0))
        support_db.add_table(knowledge_base)
        
        macros = Table("macros", comment="Response macros")
        macros.add_column(Column("macro_id", "INT(11)", auto_increment=True, primary_key=True))
        macros.add_column(Column("name", "VARCHAR(100)", nullable=False))
        macros.add_column(Column("content", "TEXT", nullable=False))
        macros.add_column(Column("category", "VARCHAR(50)"))
        macros.add_column(Column("usage_count", "INT(11)", default=0))
        support_db.add_table(macros)
        
        attachments = Table("attachments", comment="Ticket attachments")
        attachments.add_column(Column("attachment_id", "INT(11)", auto_increment=True, primary_key=True))
        attachments.add_column(Column("ticket_id", "INT(11)"))
        attachments.add_column(Column("response_id", "INT(11)"))
        attachments.add_column(Column("filename", "VARCHAR(255)", nullable=False))
        attachments.add_column(Column("file_size", "BIGINT(20)"))
        attachments.add_column(Column("mime_type", "VARCHAR(100)"))
        attachments.add_column(Column("storage_path", "VARCHAR(500)"))
        support_db.add_table(attachments)
        
        self.databases["support_tickets"] = support_db
        
        # ============ marketing_db - Marketing ============
        mkt_db = Database("marketing_db")
        
        campaigns = Table("campaigns", comment="Marketing campaigns")
        campaigns.add_column(Column("campaign_id", "INT(11)", auto_increment=True, primary_key=True))
        campaigns.add_column(Column("name", "VARCHAR(200)", nullable=False))
        campaigns.add_column(Column("type", "ENUM('email','social','ads','sms','event')"))
        campaigns.add_column(Column("status", "ENUM('draft','scheduled','active','paused','completed')"))
        campaigns.add_column(Column("budget", "DECIMAL(12,2)"))
        campaigns.add_column(Column("spent", "DECIMAL(12,2)", default=0.00))
        campaigns.add_column(Column("start_date", "DATE"))
        campaigns.add_column(Column("end_date", "DATE"))
        campaigns.add_column(Column("created_by", "VARCHAR(100)"))
        mkt_db.add_table(campaigns)
        
        leads = Table("leads", comment="Sales leads")
        leads.add_column(Column("lead_id", "INT(11)", auto_increment=True, primary_key=True))
        leads.add_column(Column("first_name", "VARCHAR(50)"))
        leads.add_column(Column("last_name", "VARCHAR(50)"))
        leads.add_column(Column("email", "VARCHAR(100)"))
        leads.add_column(Column("phone", "VARCHAR(20)"))
        leads.add_column(Column("company", "VARCHAR(100)"))
        leads.add_column(Column("source", "VARCHAR(50)"))
        leads.add_column(Column("campaign_id", "INT(11)"))
        leads.add_column(Column("status", "ENUM('new','contacted','qualified','converted','lost')"))
        leads.add_column(Column("score", "INT(11)"))
        mkt_db.add_table(leads)
        
        conversions = Table("conversions", comment="Conversion tracking")
        conversions.add_column(Column("conversion_id", "INT(11)", auto_increment=True, primary_key=True))
        conversions.add_column(Column("lead_id", "INT(11)"))
        conversions.add_column(Column("campaign_id", "INT(11)"))
        conversions.add_column(Column("conversion_type", "VARCHAR(50)"))
        conversions.add_column(Column("value", "DECIMAL(12,2)"))
        conversions.add_column(Column("converted_at", "DATETIME", nullable=False))
        mkt_db.add_table(conversions)
        
        emails = Table("emails", comment="Email campaigns")
        emails.add_column(Column("email_id", "INT(11)", auto_increment=True, primary_key=True))
        emails.add_column(Column("campaign_id", "INT(11)"))
        emails.add_column(Column("subject", "VARCHAR(200)", nullable=False))
        emails.add_column(Column("body_html", "TEXT"))
        emails.add_column(Column("body_text", "TEXT"))
        emails.add_column(Column("sent_count", "INT(11)", default=0))
        emails.add_column(Column("open_count", "INT(11)", default=0))
        emails.add_column(Column("click_count", "INT(11)", default=0))
        mkt_db.add_table(emails)
        
        newsletters = Table("newsletters", comment="Newsletter subscribers")
        newsletters.add_column(Column("subscriber_id", "INT(11)", auto_increment=True, primary_key=True))
        newsletters.add_column(Column("email", "VARCHAR(100)", unique=True, nullable=False))
        newsletters.add_column(Column("name", "VARCHAR(100)"))
        newsletters.add_column(Column("is_subscribed", "TINYINT(1)", default=1))
        newsletters.add_column(Column("subscribed_at", "DATETIME"))
        newsletters.add_column(Column("unsubscribed_at", "DATETIME"))
        newsletters.add_column(Column("source", "VARCHAR(50)"))
        mkt_db.add_table(newsletters)
        
        ab_tests = Table("ab_tests", comment="A/B testing")
        ab_tests.add_column(Column("test_id", "INT(11)", auto_increment=True, primary_key=True))
        ab_tests.add_column(Column("name", "VARCHAR(100)", nullable=False))
        ab_tests.add_column(Column("campaign_id", "INT(11)"))
        ab_tests.add_column(Column("variant_a", "TEXT"))
        ab_tests.add_column(Column("variant_b", "TEXT"))
        ab_tests.add_column(Column("metric", "VARCHAR(50)"))
        ab_tests.add_column(Column("winner", "ENUM('a','b','none')"))
        ab_tests.add_column(Column("status", "ENUM('running','completed','cancelled')"))
        mkt_db.add_table(ab_tests)
        
        segments = Table("segments", comment="Customer segments")
        segments.add_column(Column("segment_id", "INT(11)", auto_increment=True, primary_key=True))
        segments.add_column(Column("name", "VARCHAR(100)", nullable=False))
        segments.add_column(Column("description", "TEXT"))
        segments.add_column(Column("criteria", "JSON"))
        segments.add_column(Column("member_count", "INT(11)", default=0))
        segments.add_column(Column("created_at", "DATETIME"))
        mkt_db.add_table(segments)
        
        mkt_analytics = Table("analytics", comment="Marketing analytics")
        mkt_analytics.add_column(Column("analytics_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        mkt_analytics.add_column(Column("campaign_id", "INT(11)"))
        mkt_analytics.add_column(Column("date", "DATE", nullable=False))
        mkt_analytics.add_column(Column("impressions", "INT(11)", default=0))
        mkt_analytics.add_column(Column("clicks", "INT(11)", default=0))
        mkt_analytics.add_column(Column("conversions", "INT(11)", default=0))
        mkt_analytics.add_column(Column("spend", "DECIMAL(10,2)", default=0.00))
        mkt_analytics.add_column(Column("revenue", "DECIMAL(10,2)", default=0.00))
        mkt_db.add_table(mkt_analytics)
        
        social_posts = Table("social_posts", comment="Social media posts")
        social_posts.add_column(Column("post_id", "INT(11)", auto_increment=True, primary_key=True))
        social_posts.add_column(Column("campaign_id", "INT(11)"))
        social_posts.add_column(Column("platform", "ENUM('facebook','twitter','instagram','linkedin','tiktok')"))
        social_posts.add_column(Column("content", "TEXT"))
        social_posts.add_column(Column("media_urls", "JSON"))
        social_posts.add_column(Column("scheduled_at", "DATETIME"))
        social_posts.add_column(Column("posted_at", "DATETIME"))
        social_posts.add_column(Column("engagement", "JSON"))
        mkt_db.add_table(social_posts)
        
        ads = Table("ads", comment="Paid advertisements")
        ads.add_column(Column("ad_id", "INT(11)", auto_increment=True, primary_key=True))
        ads.add_column(Column("campaign_id", "INT(11)"))
        ads.add_column(Column("platform", "VARCHAR(50)"))
        ads.add_column(Column("ad_type", "VARCHAR(50)"))
        ads.add_column(Column("headline", "VARCHAR(200)"))
        ads.add_column(Column("description", "TEXT"))
        ads.add_column(Column("target_audience", "JSON"))
        ads.add_column(Column("daily_budget", "DECIMAL(10,2)"))
        ads.add_column(Column("status", "ENUM('draft','active','paused','ended')"))
        mkt_db.add_table(ads)
        
        self.databases["marketing_db"] = mkt_db
        
        # ============ logs_archive - System Logs ============
        logs_db = Database("logs_archive")
        
        error_logs = Table("error_logs", comment="Application errors")
        error_logs.add_column(Column("log_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        error_logs.add_column(Column("level", "ENUM('debug','info','warning','error','critical')"))
        error_logs.add_column(Column("message", "TEXT"))
        error_logs.add_column(Column("stack_trace", "TEXT"))
        error_logs.add_column(Column("module", "VARCHAR(100)"))
        error_logs.add_column(Column("user_id", "INT(11)"))
        error_logs.add_column(Column("request_id", "VARCHAR(64)"))
        error_logs.add_column(Column("logged_at", "DATETIME", nullable=False))
        logs_db.add_table(error_logs)
        
        access_logs = Table("access_logs", comment="HTTP access logs")
        access_logs.add_column(Column("log_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        access_logs.add_column(Column("ip_address", "VARCHAR(45)"))
        access_logs.add_column(Column("method", "VARCHAR(10)"))
        access_logs.add_column(Column("path", "VARCHAR(500)"))
        access_logs.add_column(Column("status_code", "INT(11)"))
        access_logs.add_column(Column("response_time_ms", "INT(11)"))
        access_logs.add_column(Column("user_agent", "VARCHAR(500)"))
        access_logs.add_column(Column("referer", "VARCHAR(500)"))
        access_logs.add_column(Column("logged_at", "DATETIME", nullable=False))
        logs_db.add_table(access_logs)
        
        audit_logs = Table("audit_logs", comment="Audit trail")
        audit_logs.add_column(Column("audit_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        audit_logs.add_column(Column("user_id", "INT(11)"))
        audit_logs.add_column(Column("action", "VARCHAR(50)", nullable=False))
        audit_logs.add_column(Column("resource_type", "VARCHAR(50)"))
        audit_logs.add_column(Column("resource_id", "VARCHAR(100)"))
        audit_logs.add_column(Column("old_values", "JSON"))
        audit_logs.add_column(Column("new_values", "JSON"))
        audit_logs.add_column(Column("ip_address", "VARCHAR(45)"))
        audit_logs.add_column(Column("logged_at", "DATETIME", nullable=False))
        logs_db.add_table(audit_logs)
        
        security_events = Table("security_events", comment="Security events")
        security_events.add_column(Column("event_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        security_events.add_column(Column("event_type", "VARCHAR(50)", nullable=False))
        security_events.add_column(Column("severity", "ENUM('low','medium','high','critical')"))
        security_events.add_column(Column("source_ip", "VARCHAR(45)"))
        security_events.add_column(Column("target", "VARCHAR(200)"))
        security_events.add_column(Column("details", "JSON"))
        security_events.add_column(Column("action_taken", "VARCHAR(100)"))
        security_events.add_column(Column("logged_at", "DATETIME", nullable=False))
        logs_db.add_table(security_events)
        
        perf_metrics = Table("performance_metrics", comment="Performance metrics")
        perf_metrics.add_column(Column("metric_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        perf_metrics.add_column(Column("metric_name", "VARCHAR(100)", nullable=False))
        perf_metrics.add_column(Column("value", "DECIMAL(15,4)"))
        perf_metrics.add_column(Column("unit", "VARCHAR(20)"))
        perf_metrics.add_column(Column("host", "VARCHAR(100)"))
        perf_metrics.add_column(Column("tags", "JSON"))
        perf_metrics.add_column(Column("recorded_at", "DATETIME", nullable=False))
        logs_db.add_table(perf_metrics)
        
        alerts = Table("alerts", comment="System alerts")
        alerts.add_column(Column("alert_id", "INT(11)", auto_increment=True, primary_key=True))
        alerts.add_column(Column("name", "VARCHAR(100)", nullable=False))
        alerts.add_column(Column("condition", "TEXT"))
        alerts.add_column(Column("severity", "ENUM('info','warning','error','critical')"))
        alerts.add_column(Column("status", "ENUM('active','acknowledged','resolved')"))
        alerts.add_column(Column("triggered_at", "DATETIME"))
        alerts.add_column(Column("resolved_at", "DATETIME"))
        logs_db.add_table(alerts)
        
        notifications = Table("notifications", comment="System notifications")
        notifications.add_column(Column("notification_id", "INT(11)", auto_increment=True, primary_key=True))
        notifications.add_column(Column("alert_id", "INT(11)"))
        notifications.add_column(Column("channel", "ENUM('email','sms','slack','pagerduty')"))
        notifications.add_column(Column("recipient", "VARCHAR(200)"))
        notifications.add_column(Column("sent_at", "DATETIME"))
        notifications.add_column(Column("status", "ENUM('pending','sent','failed')"))
        logs_db.add_table(notifications)
        
        cron_jobs = Table("cron_jobs", comment="Scheduled jobs")
        cron_jobs.add_column(Column("job_id", "INT(11)", auto_increment=True, primary_key=True))
        cron_jobs.add_column(Column("name", "VARCHAR(100)", nullable=False))
        cron_jobs.add_column(Column("schedule", "VARCHAR(50)"))
        cron_jobs.add_column(Column("command", "VARCHAR(500)"))
        cron_jobs.add_column(Column("last_run", "DATETIME"))
        cron_jobs.add_column(Column("next_run", "DATETIME"))
        cron_jobs.add_column(Column("is_enabled", "TINYINT(1)", default=1))
        logs_db.add_table(cron_jobs)
        
        backups = Table("backups", comment="Backup records")
        backups.add_column(Column("backup_id", "INT(11)", auto_increment=True, primary_key=True))
        backups.add_column(Column("backup_type", "ENUM('full','incremental','differential')"))
        backups.add_column(Column("source", "VARCHAR(200)"))
        backups.add_column(Column("destination", "VARCHAR(500)"))
        backups.add_column(Column("size_bytes", "BIGINT(20)"))
        backups.add_column(Column("started_at", "DATETIME"))
        backups.add_column(Column("completed_at", "DATETIME"))
        backups.add_column(Column("status", "ENUM('running','completed','failed')"))
        logs_db.add_table(backups)
        
        health_checks = Table("health_checks", comment="Health check results")
        health_checks.add_column(Column("check_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        health_checks.add_column(Column("service", "VARCHAR(100)", nullable=False))
        health_checks.add_column(Column("endpoint", "VARCHAR(200)"))
        health_checks.add_column(Column("status", "ENUM('healthy','degraded','unhealthy')"))
        health_checks.add_column(Column("response_time_ms", "INT(11)"))
        health_checks.add_column(Column("details", "JSON"))
        health_checks.add_column(Column("checked_at", "DATETIME", nullable=False))
        logs_db.add_table(health_checks)
        
        self.databases["logs_archive"] = logs_db
        
        # ============ api_gateway - API Management ============
        api_db = Database("api_gateway")
        
        endpoints = Table("endpoints", comment="API endpoints")
        endpoints.add_column(Column("endpoint_id", "INT(11)", auto_increment=True, primary_key=True))
        endpoints.add_column(Column("path", "VARCHAR(500)", nullable=False))
        endpoints.add_column(Column("method", "ENUM('GET','POST','PUT','PATCH','DELETE')"))
        endpoints.add_column(Column("version", "VARCHAR(10)"))
        endpoints.add_column(Column("description", "VARCHAR(500)"))
        endpoints.add_column(Column("is_public", "TINYINT(1)", default=0))
        endpoints.add_column(Column("rate_limit", "INT(11)"))
        endpoints.add_column(Column("timeout_ms", "INT(11)", default=30000))
        endpoints.add_column(Column("is_deprecated", "TINYINT(1)", default=0))
        api_db.add_table(endpoints)
        
        rate_limits = Table("rate_limits", comment="Rate limiting rules")
        rate_limits.add_column(Column("limit_id", "INT(11)", auto_increment=True, primary_key=True))
        rate_limits.add_column(Column("name", "VARCHAR(100)", nullable=False))
        rate_limits.add_column(Column("requests_per_second", "INT(11)"))
        rate_limits.add_column(Column("requests_per_minute", "INT(11)"))
        rate_limits.add_column(Column("requests_per_hour", "INT(11)"))
        rate_limits.add_column(Column("burst_size", "INT(11)"))
        rate_limits.add_column(Column("is_active", "TINYINT(1)", default=1))
        api_db.add_table(rate_limits)
        
        api_keys_gw = Table("api_keys", comment="API keys")
        api_keys_gw.add_column(Column("key_id", "INT(11)", auto_increment=True, primary_key=True))
        api_keys_gw.add_column(Column("key_prefix", "VARCHAR(10)", nullable=False))
        api_keys_gw.add_column(Column("key_hash", "VARCHAR(255)", nullable=False))
        api_keys_gw.add_column(Column("owner", "VARCHAR(100)"))
        api_keys_gw.add_column(Column("rate_limit_id", "INT(11)"))
        api_keys_gw.add_column(Column("scopes", "JSON"))
        api_keys_gw.add_column(Column("expires_at", "DATETIME"))
        api_keys_gw.add_column(Column("is_active", "TINYINT(1)", default=1))
        api_db.add_table(api_keys_gw)
        
        usage_stats = Table("usage_stats", comment="API usage statistics")
        usage_stats.add_column(Column("stat_id", "BIGINT(20)", auto_increment=True, primary_key=True))
        usage_stats.add_column(Column("key_id", "INT(11)"))
        usage_stats.add_column(Column("endpoint_id", "INT(11)"))
        usage_stats.add_column(Column("date", "DATE", nullable=False))
        usage_stats.add_column(Column("hour", "INT(2)"))
        usage_stats.add_column(Column("request_count", "INT(11)", default=0))
        usage_stats.add_column(Column("error_count", "INT(11)", default=0))
        usage_stats.add_column(Column("avg_latency_ms", "DECIMAL(10,2)"))
        api_db.add_table(usage_stats)
        
        throttle_rules = Table("throttle_rules", comment="Throttling rules")
        throttle_rules.add_column(Column("rule_id", "INT(11)", auto_increment=True, primary_key=True))
        throttle_rules.add_column(Column("name", "VARCHAR(100)", nullable=False))
        throttle_rules.add_column(Column("condition", "JSON"))
        throttle_rules.add_column(Column("action", "ENUM('delay','reject','queue')"))
        throttle_rules.add_column(Column("delay_ms", "INT(11)"))
        throttle_rules.add_column(Column("priority", "INT(11)", default=0))
        throttle_rules.add_column(Column("is_active", "TINYINT(1)", default=1))
        api_db.add_table(throttle_rules)
        
        domains = Table("domains", comment="API domains")
        domains.add_column(Column("domain_id", "INT(11)", auto_increment=True, primary_key=True))
        domains.add_column(Column("domain", "VARCHAR(200)", unique=True, nullable=False))
        domains.add_column(Column("ssl_enabled", "TINYINT(1)", default=1))
        domains.add_column(Column("ssl_expires_at", "DATE"))
        domains.add_column(Column("is_primary", "TINYINT(1)", default=0))
        domains.add_column(Column("is_active", "TINYINT(1)", default=1))
        api_db.add_table(domains)
        
        certificates = Table("certificates", comment="SSL certificates")
        certificates.add_column(Column("cert_id", "INT(11)", auto_increment=True, primary_key=True))
        certificates.add_column(Column("domain_id", "INT(11)", nullable=False))
        certificates.add_column(Column("issuer", "VARCHAR(200)"))
        certificates.add_column(Column("issued_at", "DATE"))
        certificates.add_column(Column("expires_at", "DATE", nullable=False))
        certificates.add_column(Column("fingerprint", "VARCHAR(100)"))
        certificates.add_column(Column("is_active", "TINYINT(1)", default=1))
        api_db.add_table(certificates)
        
        webhooks = Table("webhooks", comment="Webhook subscriptions")
        webhooks.add_column(Column("webhook_id", "INT(11)", auto_increment=True, primary_key=True))
        webhooks.add_column(Column("url", "VARCHAR(500)", nullable=False))
        webhooks.add_column(Column("events", "JSON"))
        webhooks.add_column(Column("secret_hash", "VARCHAR(255)"))
        webhooks.add_column(Column("retry_count", "INT(11)", default=3))
        webhooks.add_column(Column("timeout_ms", "INT(11)", default=5000))
        webhooks.add_column(Column("is_active", "TINYINT(1)", default=1))
        api_db.add_table(webhooks)
        
        integrations = Table("integrations", comment="Third-party integrations")
        integrations.add_column(Column("integration_id", "INT(11)", auto_increment=True, primary_key=True))
        integrations.add_column(Column("name", "VARCHAR(100)", nullable=False))
        integrations.add_column(Column("type", "VARCHAR(50)"))
        integrations.add_column(Column("config", "JSON"))
        integrations.add_column(Column("credentials", "JSON"))
        integrations.add_column(Column("last_sync", "DATETIME"))
        integrations.add_column(Column("status", "ENUM('active','error','disabled')"))
        api_db.add_table(integrations)
        
        api_versions = Table("versions", comment="API versions")
        api_versions.add_column(Column("version_id", "INT(11)", auto_increment=True, primary_key=True))
        api_versions.add_column(Column("version", "VARCHAR(10)", unique=True, nullable=False))
        api_versions.add_column(Column("release_date", "DATE"))
        api_versions.add_column(Column("deprecation_date", "DATE"))
        api_versions.add_column(Column("sunset_date", "DATE"))
        api_versions.add_column(Column("changelog", "TEXT"))
        api_versions.add_column(Column("is_current", "TINYINT(1)", default=0))
        api_db.add_table(api_versions)
        
        self.databases["api_gateway"] = api_db
        
    def _populate_sample_data(self):
        """Populate tables with realistic sample data"""
        random.seed(42)  # Consistent data generation
        
        nexus_db = self.databases.get("nexus_gamedev")
        if not nexus_db:
            return
        
        # Generate players (50 sample players)
        players_table = nexus_db.get_table("players")
        player_names = []
        for i in range(50):
            fname = random.choice(FIRST_NAMES)
            lname = random.choice(LAST_NAMES)
            username = f"{random.choice(GAME_NAMES)}{random.choice(GAME_SUFFIXES)}{random.randint(1, 999)}"
            email = f"{fname.lower()}.{lname.lower()}{random.randint(1, 99)}@{random.choice(EMAIL_DOMAINS)}"
            
            created = datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 730))
            last_login = created + datetime.timedelta(days=random.randint(0, 365))
            
            level = random.randint(1, 100)
            exp = level * random.randint(1000, 10000)
            
            players_table.insert_row({
                "username": username,
                "email": email,
                "password_hash": hashlib.sha256(f"{username}password".encode()).hexdigest(),
                "level": level,
                "experience": exp,
                "gold": random.randint(100, 1000000),
                "premium_currency": random.randint(0, 5000) if random.random() > 0.7 else 0,
                "is_premium": 1 if random.random() > 0.8 else 0,
                "is_banned": 1 if random.random() > 0.95 else 0,
                "country": random.choice(COUNTRIES),
                "last_login": last_login.strftime("%Y-%m-%d %H:%M:%S"),
                "created_at": created.strftime("%Y-%m-%d %H:%M:%S"),
                "updated_at": last_login.strftime("%Y-%m-%d %H:%M:%S")
            })
            player_names.append(username)
        
        # Generate characters (2-3 per player for first 30 players)
        characters_table = nexus_db.get_table("characters")
        for player_id in range(1, 31):
            num_chars = random.randint(1, 3)
            for _ in range(num_chars):
                char_level = random.randint(1, 80)
                base_hp = 100 + char_level * 10
                base_mana = 50 + char_level * 5
                
                characters_table.insert_row({
                    "player_id": player_id,
                    "name": f"{random.choice(GAME_NAMES)}{random.choice(GAME_SUFFIXES)}",
                    "class": random.choice(CHARACTER_CLASSES),
                    "level": char_level,
                    "health": base_hp,
                    "max_health": base_hp,
                    "mana": base_mana,
                    "max_mana": base_mana,
                    "strength": 10 + char_level + random.randint(0, 20),
                    "intelligence": 10 + char_level + random.randint(0, 20),
                    "agility": 10 + char_level + random.randint(0, 20),
                    "defense": 10 + char_level + random.randint(0, 20),
                    "playtime_seconds": random.randint(3600, 360000),
                    "current_zone": random.choice(["Starter Town", "Dark Forest", "Crystal Cave", "Dragon Peak", "Shadow Valley"]),
                    "created_at": (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d %H:%M:%S")
                })
        
        # Generate items (100 items)
        items_table = nexus_db.get_table("items")
        rarities = ["common", "common", "common", "uncommon", "uncommon", "rare", "epic", "legendary"]
        
        for item_type, item_names in ITEM_NAMES.items():
            for item_name in item_names:
                rarity = random.choice(rarities)
                base_price = {"common": 100, "uncommon": 500, "rare": 2000, "epic": 10000, "legendary": 50000}[rarity]
                
                items_table.insert_row({
                    "name": item_name,
                    "description": f"A {rarity} {item_type}: {item_name}. Highly sought after by adventurers.",
                    "type": item_type,
                    "rarity": rarity,
                    "base_price": base_price + random.randint(0, base_price // 2),
                    "required_level": random.randint(1, 60),
                    "stats": json.dumps({"power": random.randint(10, 100), "durability": random.randint(50, 100)}),
                    "icon_url": f"/assets/items/{item_type}/{item_name.lower().replace(' ', '_')}.png",
                    "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
        
        # Generate achievements
        achievements_table = nexus_db.get_table("achievements")
        categories = ["Combat", "Exploration", "Social", "Collection", "Mastery"]
        for name, desc, points in ACHIEVEMENT_NAMES:
            achievements_table.insert_row({
                "name": name,
                "description": desc,
                "points": points,
                "category": random.choice(categories),
                "icon_url": f"/assets/achievements/{name.lower().replace(' ', '_')}.png",
                "is_hidden": 1 if random.random() > 0.9 else 0
            })
        
        # Generate inventory items for players
        inventory_table = nexus_db.get_table("inventory")
        for player_id in range(1, 31):
            num_items = random.randint(5, 20)
            used_items = set()
            for _ in range(num_items):
                item_id = random.randint(1, 50)
                if item_id not in used_items:
                    used_items.add(item_id)
                    inventory_table.insert_row({
                        "player_id": player_id,
                        "item_id": item_id,
                        "quantity": random.randint(1, 10),
                        "slot": random.randint(1, 50),
                        "equipped": 1 if random.random() > 0.8 else 0,
                        "acquired_at": (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 100))).strftime("%Y-%m-%d %H:%M:%S")
                    })
        
        # Generate player achievements
        player_achievements_table = nexus_db.get_table("player_achievements")
        for player_id in range(1, 31):
            num_achievements = random.randint(1, 10)
            used_achievements = set()
            for _ in range(num_achievements):
                ach_id = random.randint(1, 15)
                if ach_id not in used_achievements:
                    used_achievements.add(ach_id)
                    player_achievements_table.insert_row({
                        "player_id": player_id,
                        "achievement_id": ach_id,
                        "unlocked_at": (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 200))).strftime("%Y-%m-%d %H:%M:%S")
                    })
        
        # Generate transactions (payment data - looks juicy to attackers)
        transactions_table = nexus_db.get_table("transactions")
        payment_methods = ["credit_card", "paypal", "google_pay", "apple_pay", "crypto"]
        purchased_items = ["Premium Pack", "Gold Bundle", "Rare Chest", "Season Pass", "Cosmetic Set", "XP Boost", "VIP Subscription"]
        
        for _ in range(100):
            player_id = random.randint(1, 50)
            amount = random.choice([4.99, 9.99, 19.99, 49.99, 99.99])
            
            transactions_table.insert_row({
                "transaction_id": str(uuid.uuid4()),
                "player_id": player_id,
                "amount": amount,
                "currency": "USD",
                "payment_method": random.choice(payment_methods),
                "card_last_four": f"{random.randint(1000, 9999)}" if random.random() > 0.5 else None,
                "status": random.choice(["completed", "completed", "completed", "pending", "failed"]),
                "item_purchased": random.choice(purchased_items),
                "created_at": (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 180))).strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Generate sessions
        sessions_table = nexus_db.get_table("sessions")
        for i in range(20):
            player_id = random.randint(1, 50)
            sessions_table.insert_row({
                "session_id": hashlib.md5(f"session_{i}_{player_id}".encode()).hexdigest(),
                "player_id": player_id,
                "ip_address": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "user_agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GameClient/2.1.0",
                    "NexusGame/2.1.0 (iOS 17.0)",
                    "NexusGame/2.1.0 (Android 13)",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) GameClient/2.1.0"
                ]),
                "started_at": (datetime.datetime.now() - datetime.timedelta(hours=random.randint(0, 24))).strftime("%Y-%m-%d %H:%M:%S"),
                "last_activity": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "is_active": 1 if random.random() > 0.3 else 0
            })
        
        # Generate guilds
        guilds_table = nexus_db.get_table("guilds")
        guild_names = ["Shadow Legion", "Dragon Slayers", "Crystal Knights", "Phoenix Rising", "Dark Brotherhood",
                       "Storm Riders", "Iron Wolves", "Crimson Guard", "Mystic Order", "Chaos Warriors"]
        for i, guild_name in enumerate(guild_names):
            leader_id = random.randint(1, 30)
            guilds_table.insert_row({
                "name": guild_name,
                "description": f"The mighty {guild_name} guild. Join us for epic adventures!",
                "leader_id": leader_id,
                "member_count": random.randint(5, 100),
                "level": random.randint(1, 25),
                "experience": random.randint(1000, 500000),
                "created_at": (datetime.datetime.now() - datetime.timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d %H:%M:%S")
            })
        
        # Populate player_data database
        player_data_db = self.databases.get("player_data")
        if player_data_db:
            # Leaderboards
            leaderboards_table = player_data_db.get_table("leaderboards")
            lb_types = ["pvp_rating", "pve_score", "gold_collected", "monsters_killed", "achievements"]
            for lb_type in lb_types:
                for rank in range(1, 21):
                    player_id = random.randint(1, 50)
                    leaderboards_table.insert_row({
                        "player_id": player_id,
                        "player_name": player_names[player_id - 1] if player_id <= len(player_names) else f"Player{player_id}",
                        "leaderboard_type": lb_type,
                        "score": random.randint(10000, 1000000) // rank,
                        "rank": rank,
                        "season": 1,
                        "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
            
            # Player stats
            player_stats_table = player_data_db.get_table("player_stats")
            for player_id in range(1, 51):
                wins = random.randint(0, 500)
                losses = random.randint(0, 500)
                kills = random.randint(0, 10000)
                deaths = random.randint(1, 5000)
                
                player_stats_table.insert_row({
                    "player_id": player_id,
                    "player_name": player_names[player_id - 1] if player_id <= len(player_names) else f"Player{player_id}",
                    "total_wins": wins,
                    "total_losses": losses,
                    "total_kills": kills,
                    "total_deaths": deaths,
                    "kd_ratio": round(kills / max(deaths, 1), 2),
                    "win_rate": round(wins / max(wins + losses, 1) * 100, 2),
                    "total_playtime": random.randint(36000, 3600000),
                    "highest_score": random.randint(10000, 500000),
                    "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
            
            # Match history
            match_table = player_data_db.get_table("match_history")
            game_modes = ["ranked", "casual", "tournament", "custom"]
            for _ in range(50):
                p1 = random.randint(1, 50)
                p2 = random.randint(1, 50)
                while p2 == p1:
                    p2 = random.randint(1, 50)
                winner = random.choice([p1, p2])
                
                match_table.insert_row({
                    "match_id": str(uuid.uuid4()),
                    "player1_id": p1,
                    "player1_name": player_names[p1 - 1] if p1 <= len(player_names) else f"Player{p1}",
                    "player2_id": p2,
                    "player2_name": player_names[p2 - 1] if p2 <= len(player_names) else f"Player{p2}",
                    "winner_id": winner,
                    "game_mode": random.choice(game_modes),
                    "duration_seconds": random.randint(60, 1800),
                    "played_at": (datetime.datetime.now() - datetime.timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d %H:%M:%S")
                })
        
        # Populate analytics database
        analytics_db = self.databases.get("game_analytics")
        if analytics_db:
            # Daily metrics for last 30 days
            metrics_table = analytics_db.get_table("daily_metrics")
            for days_ago in range(30):
                date = datetime.date.today() - datetime.timedelta(days=days_ago)
                metrics_table.insert_row({
                    "date": date.strftime("%Y-%m-%d"),
                    "dau": random.randint(5000, 15000),
                    "new_users": random.randint(100, 500),
                    "revenue": round(random.uniform(1000, 10000), 2),
                    "sessions": random.randint(10000, 30000),
                    "avg_session_length": random.randint(900, 3600),
                    "total_matches": random.randint(2000, 8000),
                    "items_purchased": random.randint(500, 2000)
                })
        
        # Save the initial state
        self.save_state()
    
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
        self.save_state()
        return True
    
    def drop_database(self, name: str) -> bool:
        """Drop a database"""
        if name.lower() in self.databases and name.lower() not in ["mysql", "information_schema", "performance_schema", "sys"]:
            del self.databases[name.lower()]
            if self.current_database == name.lower():
                self.current_database = None
            self.save_state()
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
        var_name = name.lstrip("@").lower()
        return self.variables.get(var_name, None)
    
    def set_variable(self, name: str, value: Any):
        """Set a MySQL system variable"""
        var_name = name.lstrip("@").lower()
        self.variables[var_name] = value
        
    def save_state(self):
        """Save database state to file for persistence"""
        try:
            state = {
                "username": self.username,
                "current_database": self.current_database,
                "databases": {},
                "saved_at": datetime.datetime.now().isoformat()
            }
            
            # Only save user-created/modified databases (not system ones)
            user_dbs = ["nexus_gamedev", "player_data", "game_analytics", "asset_library"]
            for db_name in user_dbs:
                if db_name in self.databases:
                    state["databases"][db_name] = self.databases[db_name].to_dict()
            
            # Also save any user-created databases
            for db_name, db in self.databases.items():
                if db_name not in ["mysql", "information_schema", "performance_schema", "sys"] and db_name not in state["databases"]:
                    state["databases"][db_name] = db.to_dict()
            
            state_file = self._get_state_file_path()
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, default=str)
            
            logger.debug(f"Saved database state for user {self.username} to {state_file}")
            
        except Exception as e:
            logger.error(f"Failed to save database state: {e}")
            
    def _load_state(self) -> bool:
        """Load database state from file"""
        try:
            state_file = self._get_state_file_path()
            if not state_file.exists():
                return False
            
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
            
            # Initialize system databases first
            self._initialize_system_databases()
            
            # Load saved databases
            for db_name, db_data in state.get("databases", {}).items():
                self.databases[db_name] = Database.from_dict(db_data)
            
            self.current_database = state.get("current_database")
            
            logger.info(f"Loaded database state for user {self.username} from {state_file}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to load database state: {e}")
            return False
