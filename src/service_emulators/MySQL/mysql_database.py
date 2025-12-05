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
