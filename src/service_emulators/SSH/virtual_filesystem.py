#!/usr/bin/env python3
"""
Virtual Filesystem for SSH Honeypot
Provides a realistic Ubuntu 20.04 LTS filesystem structure with game development content
"""

import datetime
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json


class FileNode:
    """Represents a file or directory in the virtual filesystem"""
    
    def __init__(
        self,
        name: str,
        is_dir: bool = False,
        content: str = "",
        permissions: str = "644",
        owner: str = "root",
        group: str = "root",
        size: Optional[int] = None,
        modified: Optional[datetime.datetime] = None
    ):
        self.name = name
        self.is_dir = is_dir
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.group = group
        self.size = size if size is not None else len(content)
        self.modified = modified or datetime.datetime.now()
        self.children: Dict[str, FileNode] = {} if is_dir else None
        
    def add_child(self, child: 'FileNode') -> None:
        """Add a child node (only for directories)"""
        if self.is_dir:
            self.children[child.name] = child
            
    def get_child(self, name: str) -> Optional['FileNode']:
        """Get a child node by name"""
        if self.is_dir and self.children:
            return self.children.get(name)
        return None
    
    def list_children(self) -> List[str]:
        """List all child names"""
        if self.is_dir and self.children:
            return sorted(self.children.keys())
        return []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize node to dictionary"""
        data = {
            "name": self.name,
            "is_dir": self.is_dir,
            "content": self.content,
            "permissions": self.permissions,
            "owner": self.owner,
            "group": self.group,
            "size": self.size,
            "modified": self.modified.isoformat()
        }
        
        if self.is_dir and self.children:
            data["children"] = {name: child.to_dict() for name, child in self.children.items()}
            
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileNode':
        """Create node from dictionary"""
        node = cls(
            name=data["name"],
            is_dir=data["is_dir"],
            content=data.get("content", ""),
            permissions=data.get("permissions", "644"),
            owner=data.get("owner", "root"),
            group=data.get("group", "root"),
            size=data.get("size"),
            modified=datetime.datetime.fromisoformat(data["modified"]) if data.get("modified") else None
        )
        
        if node.is_dir and "children" in data:
            for child_name, child_data in data["children"].items():
                child_node = cls.from_dict(child_data)
                node.add_child(child_node)
                
        return node


class VirtualFilesystem:
    """
    Virtual filesystem mimicking Ubuntu 20.04 LTS for game development server
    Based on NexusGames Studio environment from prompt.txt
    """
    
    def __init__(self):
        self.root = FileNode("/", is_dir=True, permissions="755")
        self._initialize_filesystem()

        self.installed_packages = {
            "nginx": "1.18.0-0ubuntu1",
            "mysql-server": "8.0.23-0ubuntu0.20.04.1",
            "openssh-server": "1:8.2p1-4ubuntu0.3",
            "vim": "2:8.1.2269-1ubuntu5",
            "git": "1:2.25.1-1ubuntu3"
        }

    def install_package(self, package_name: str, version: str = "1.0.0"):
        self.installed_packages[package_name] = version
        
    def is_installed(self, package_name: str) -> bool:
        return package_name in self.installed_packages

    def serialize(self) -> Dict[str, Any]:
        """Serialize filesystem to dictionary"""
        return self.root.to_dict()

    def deserialize(self, data: Dict[str, Any]):
        """Restore filesystem from dictionary"""
        self.root = FileNode.from_dict(data)

    def save_state(self, path: str) -> bool:
        """Save filesystem state to JSON file"""
        try:
            data = self.serialize()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving filesystem state: {e}")
            return False

    def load_state(self, path: str) -> bool:
        """Load filesystem state from JSON file"""
        if not os.path.exists(path):
            return False
            
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            self.deserialize(data)
            return True
        except Exception as e:
            print(f"Error loading filesystem state: {e}")
            return False
        
    def _initialize_filesystem(self):
        """Initialize the complete Ubuntu filesystem structure"""
        # Create standard Linux directories
        self._create_standard_directories()
        
        # Populate /etc with configuration files
        self._populate_etc()
        
        # Populate /home with user directories
        self._populate_home()
        
        # Populate /opt/games with game projects
        self._populate_game_projects()
        
        # Populate /var with logs and builds
        self._populate_var()
        
        # Populate /srv with assets
        self._populate_srv()
        
        # Populate /backup with backups (misconfigured permissions)
        self._populate_backup()
        
        # Populate /tmp
        self._populate_tmp()
        
    def _create_standard_directories(self):
        """Create standard Linux directory structure"""
        standard_dirs = [
            ("bin", "755", "root", "root"),
            ("boot", "755", "root", "root"),
            ("dev", "755", "root", "root"),
            ("etc", "755", "root", "root"),
            ("home", "755", "root", "root"),
            ("lib", "755", "root", "root"),
            ("lib64", "755", "root", "root"),
            ("media", "755", "root", "root"),
            ("mnt", "755", "root", "root"),
            ("opt", "755", "root", "root"),
            ("proc", "555", "root", "root"),
            ("root", "700", "root", "root"),
            ("run", "755", "root", "root"),
            ("sbin", "755", "root", "root"),
            ("srv", "755", "root", "root"),
            ("sys", "555", "root", "root"),
            ("tmp", "1777", "root", "root"),
            ("usr", "755", "root", "root"),
            ("var", "755", "root", "root"),
            ("backup", "755", "root", "root"),  # Misconfigured backup directory
        ]
        
        for dir_name, perms, owner, group in standard_dirs:
            node = FileNode(dir_name, is_dir=True, permissions=perms, owner=owner, group=group)
            self.root.add_child(node)
            
        # Create usr subdirectories
        usr = self.root.get_child("usr")
        for subdir in ["bin", "lib", "local", "share", "src"]:
            usr.add_child(FileNode(subdir, is_dir=True, permissions="755"))
            
        # Create var subdirectories
        var = self.root.get_child("var")
        for subdir in ["log", "tmp", "cache", "lib", "builds"]:
            var.add_child(FileNode(subdir, is_dir=True, permissions="755"))
            
    def _populate_etc(self):
        """Populate /etc with configuration files"""
        etc = self.root.get_child("etc")
        
        # /etc/passwd
        passwd_content = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alex.chen:x:1001:1001:Alex Chen,,,:/home/alex.chen:/bin/bash
sarah.martinez:x:1002:1002:Sarah Martinez,,,:/home/sarah.martinez:/bin/bash
mike.thompson:x:1003:1003:Mike Thompson,,,:/home/mike.thompson:/bin/bash
dev-intern:x:1004:1004:Dev Intern,,,:/home/dev-intern:/bin/bash
jenkins:x:1005:1005:Jenkins CI,,,:/home/jenkins:/bin/bash
guest:x:1006:1006:Guest User,,,:/home/guest:/bin/bash
"""
        etc.add_child(FileNode("passwd", content=passwd_content, permissions="644"))
        
        # /etc/shadow (restricted)
        shadow_content = """root:$6$rounds=656000$...:18900:0:99999:7:::
alex.chen:$6$rounds=656000$...:18900:0:99999:7:::
sarah.martinez:$6$rounds=656000$...:18900:0:99999:7:::
"""
        etc.add_child(FileNode("shadow", content=shadow_content, permissions="000", owner="root", group="shadow"))
        
        # /etc/hostname
        etc.add_child(FileNode("hostname", content="corp-srv-01\n", permissions="644"))
        
        # /etc/hosts
        hosts_content = """127.0.0.1       localhost
127.0.1.1       corp-srv-01
10.0.0.1        db-server.internal
10.0.0.2        build-server.internal
10.0.0.3        asset-server.internal

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"""
        etc.add_child(FileNode("hosts", content=hosts_content, permissions="644"))
        
        # /etc/secrets (misconfigured - should be 600 but is 644)
        secrets_dir = FileNode("secrets", is_dir=True, permissions="644")  # Intentional misconfiguration
        
        # Database credentials
        db_config = """[database]
host=db-server.internal
port=5432
username=nexus_admin
password=N3xus!G@m3s2024!DB
database=nexus_production

[redis]
host=localhost
port=6379
password=R3d1s!C@ch3#2024
"""
        secrets_dir.add_child(FileNode("db_config.ini", content=db_config, permissions="644"))
        
        # API keys
        api_keys = """# NexusGames API Keys
STEAM_API_KEY=ABCD1234-5678-90EF-GHIJ-KLMNOPQRSTUV
EPIC_API_KEY=epic_live_1234567890abcdefghijklmnop
UNITY_LICENSE_KEY=UL-1234567890-ABCD-EFGH-IJKL-MNOP
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51234567890abcdefghijklmnopqrstuvwxyz
"""
        secrets_dir.add_child(FileNode("api_keys.env", content=api_keys, permissions="644"))
        
        etc.add_child(secrets_dir)
        
        # /etc/os-release
        os_release = """NAME="Ubuntu"
VERSION="20.04.3 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.3 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
"""
        etc.add_child(FileNode("os-release", content=os_release, permissions="644"))
        
    def _populate_home(self):
        """Populate /home with user directories"""
        home = self.root.get_child("home")
        
        users = [
            ("alex.chen", "1001", "1001"),
            ("sarah.martinez", "1002", "1002"),
            ("mike.thompson", "1003", "1003"),
            ("dev-intern", "1004", "1004"),
            ("jenkins", "1005", "1005"),
            ("guest", "1006", "1006"),
        ]
        
        for username, uid, gid in users:
            user_dir = FileNode(username, is_dir=True, permissions="755", owner=username, group=username)
            
            # Add .bashrc
            bashrc = f"""# ~/.bashrc for {username}
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/games
export EDITOR=vim
export PS1='\\u@\\h:\\w\\$ '

alias ll='ls -la'
alias gs='git status'
alias gp='git pull'
"""
            user_dir.add_child(FileNode(".bashrc", content=bashrc, permissions="644", owner=username, group=username))
            
            # Add .bash_history with realistic commands
            if username == "alex.chen":
                history = """cd /opt/games/Stellar-Conquest
git pull origin main
./build.sh
cd /opt/games/Project-Phoenix
ls -la
cat README.md
vim src/main.cpp
git commit -am "Fixed memory leak in renderer"
git push
sudo systemctl restart nginx
"""
                user_dir.add_child(FileNode(".bash_history", content=history, permissions="600", owner=username, group=username))
            
            # Add Documents directory with personal files
            docs_dir = FileNode("Documents", is_dir=True, permissions="755", owner=username, group=username)
            if username == "alex.chen":
                resume = """ALEX CHEN
Senior Game Developer
alex.chen@nexusgames.com

EXPERIENCE:
- NexusGames Studio (2020-Present): Lead Developer on Stellar Conquest
- Previous Company (2018-2020): Unity Developer

SKILLS: C++, C#, Unity, Unreal Engine, Python
"""
                docs_dir.add_child(FileNode("resume.txt", content=resume, permissions="644", owner=username, group=username))
            
            user_dir.add_child(docs_dir)
            home.add_child(user_dir)
            
    def _populate_game_projects(self):
        """Populate /opt/games with game development projects"""
        opt = self.root.get_child("opt")
        games_dir = FileNode("games", is_dir=True, permissions="755", owner="root", group="developers")
        
        projects = [
            ("Stellar-Conquest", "Space strategy game - CONFIDENTIAL"),
            ("Mystic-Realms", "Fantasy RPG - In Production"),
            ("Racing-Thunder", "Mobile racing game - Beta"),
            ("Project-Phoenix", "Unannounced AAA title - TOP SECRET"),
        ]
        
        for project_name, description in projects:
            project_dir = FileNode(project_name, is_dir=True, permissions="755", owner="root", group="developers")
            
            # README.md
            readme = f"""# {project_name}

{description}

## Build Instructions
```bash
./build.sh
```

## Team
- Lead: Alex Chen
- Art: Sarah Martinez  
- Programming: Mike Thompson

## Status
Active development - Q2 2024 release target
"""
            project_dir.add_child(FileNode("README.md", content=readme, permissions="644"))
            
            # Source directory
            src_dir = FileNode("src", is_dir=True, permissions="755")
            
            # Sample source files
            main_cpp = """#include <iostream>
#include "game_engine.h"

int main() {
    GameEngine engine;
    engine.initialize();
    engine.run();
    return 0;
}
"""
            src_dir.add_child(FileNode("main.cpp", content=main_cpp, permissions="644"))
            
            game_engine_h = """#ifndef GAME_ENGINE_H
#define GAME_ENGINE_H

class GameEngine {
public:
    void initialize();
    void run();
    void shutdown();
private:
    // Implementation details
};

#endif
"""
            src_dir.add_child(FileNode("game_engine.h", content=game_engine_h, permissions="644"))
            
            project_dir.add_child(src_dir)
            
            # Build script
            build_script = """#!/bin/bash
echo "Building {project_name}..."
mkdir -p build
cd build
cmake ..
make -j4
echo "Build complete!"
"""
            project_dir.add_child(FileNode("build.sh", content=build_script, permissions="755"))
            
            games_dir.add_child(project_dir)
            
        opt.add_child(games_dir)
        
    def _populate_var(self):
        """Populate /var with logs and build artifacts"""
        var = self.root.get_child("var")
        
        # /var/log
        log_dir = var.get_child("log")
        
        # auth.log
        auth_log = """Dec  2 10:23:15 corp-srv-01 sshd[1234]: Accepted password for alex.chen from 192.168.1.100 port 52341 ssh2
Dec  2 10:45:32 corp-srv-01 sshd[1245]: Failed password for invalid user admin from 203.0.113.42 port 48291 ssh2
Dec  2 11:12:08 corp-srv-01 sudo: alex.chen : TTY=pts/0 ; PWD=/home/alex.chen ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Dec  2 12:03:45 corp-srv-01 sshd[1256]: Accepted password for jenkins from 10.0.0.2 port 41234 ssh2
"""
        log_dir.add_child(FileNode("auth.log", content=auth_log, permissions="640", owner="root", group="adm"))
        
        # syslog
        syslog = """Dec  2 10:00:01 corp-srv-01 CRON[1123]: (root) CMD (/usr/local/bin/backup.sh)
Dec  2 10:15:23 corp-srv-01 systemd[1]: Started Daily apt download activities.
Dec  2 11:30:45 corp-srv-01 kernel: [12345.678901] Out of memory: Kill process 5678 (chrome) score 890 or sacrifice child
"""
        log_dir.add_child(FileNode("syslog", content=syslog, permissions="640", owner="root", group="adm"))
        
        # /var/builds
        builds_dir = var.get_child("builds")
        builds_dir.add_child(FileNode("stellar-conquest-v1.2.3.tar.gz", content="[Binary build artifact]", permissions="644", size=15728640))
        builds_dir.add_child(FileNode("mystic-realms-latest.zip", content="[Binary build artifact]", permissions="644", size=28934567))
        
    def _populate_srv(self):
        """Populate /srv with game assets"""
        srv = self.root.get_child("srv")
        
        assets_dir = FileNode("assets", is_dir=True, permissions="755")
        
        # Textures
        textures_dir = FileNode("textures", is_dir=True, permissions="755")
        textures_dir.add_child(FileNode("spaceship_diffuse.png", content="[PNG image data]", permissions="644", size=2048576))
        textures_dir.add_child(FileNode("terrain_normal.png", content="[PNG image data]", permissions="644", size=4096000))
        assets_dir.add_child(textures_dir)
        
        # Models
        models_dir = FileNode("models", is_dir=True, permissions="755")
        models_dir.add_child(FileNode("character_rig.fbx", content="[FBX model data]", permissions="644", size=8192000))
        assets_dir.add_child(models_dir)
        
        # Audio
        audio_dir = FileNode("audio", is_dir=True, permissions="755")
        audio_dir.add_child(FileNode("background_music.mp3", content="[MP3 audio data]", permissions="644", size=5242880))
        assets_dir.add_child(audio_dir)
        
        srv.add_child(assets_dir)
        
    def _populate_backup(self):
        """Populate /backup with database backups (world-readable - misconfiguration)"""
        backup = self.root.get_child("backup")
        
        # Database backup with sensitive data (misconfigured permissions)
        db_backup = """-- NexusGames Production Database Backup
-- Date: 2024-12-01

INSERT INTO users VALUES (1, 'alex.chen@nexusgames.com', '$2b$12$...');
INSERT INTO financial_data VALUES (1, 'Q3 Revenue', 2300000.00);
INSERT INTO salaries VALUES (1, 'alex.chen', 125000.00);
"""
        backup.add_child(FileNode("db_backup_2024-12-01.sql", content=db_backup, permissions="644"))  # Should be 600!
        
        # Project snapshots
        backup.add_child(FileNode("project-phoenix-snapshot.tar.gz", content="[Compressed backup]", permissions="644", size=52428800))
        
    def _populate_tmp(self):
        """Populate /tmp with temporary files"""
        tmp = self.root.get_child("tmp")
        
        uploads_dir = FileNode("uploads", is_dir=True, permissions="777")
        tmp.add_child(uploads_dir)
        
    def resolve_path(self, path: str, current_dir: str = "/") -> Optional[str]:
        """
        Resolve a path (relative or absolute) to an absolute path
        
        Args:
            path: Path to resolve
            current_dir: Current working directory
            
        Returns:
            Absolute path or None if invalid
        """
        if not path:
            return current_dir
            
        # Handle special cases
        if path == "~":
            return "/home/guest"  # Default user
        if path.startswith("~/"):
            return "/home/guest/" + path[2:]
            
        # Handle absolute paths
        if path.startswith("/"):
            abs_path = path
        else:
            # Relative path
            if current_dir.endswith("/"):
                abs_path = current_dir + path
            else:
                abs_path = current_dir + "/" + path
                
        # Normalize path (handle .. and .)
        parts = []
        for part in abs_path.split("/"):
            if part == "" or part == ".":
                continue
            elif part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
                
        return "/" + "/".join(parts) if parts else "/"
        
    def _get_node(self, path: str) -> Optional[FileNode]:
        """Get a node by absolute path"""
        if path == "/":
            return self.root
            
        parts = [p for p in path.split("/") if p]
        current = self.root
        
        for part in parts:
            if not current or not current.is_dir:
                return None
            current = current.get_child(part)
            
        return current
        
    def exists(self, path: str, current_dir: str = "/") -> bool:
        """Check if a path exists"""
        abs_path = self.resolve_path(path, current_dir)
        return self._get_node(abs_path) is not None
        
    def is_directory(self, path: str, current_dir: str = "/") -> bool:
        """Check if path is a directory"""
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        return node is not None and node.is_dir
        
    def is_file(self, path: str, current_dir: str = "/") -> bool:
        """Check if path is a file"""
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        return node is not None and not node.is_dir
        
    def list_directory(self, path: str, current_dir: str = "/") -> Optional[List[Dict[str, Any]]]:
        """
        List directory contents with metadata
        
        Returns:
            List of dicts with file info, or None if not a directory
        """
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        
        if not node or not node.is_dir:
            return None
            
        result = []
        for child_name in node.list_children():
            child = node.get_child(child_name)
            result.append({
                "name": child.name,
                "is_dir": child.is_dir,
                "permissions": child.permissions,
                "owner": child.owner,
                "group": child.group,
                "size": child.size,
                "modified": child.modified,
            })
            
        return result
        
    def read_file(self, path: str, current_dir: str = "/") -> Optional[str]:
        """Read file contents"""
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        
        if not node or node.is_dir:
            return None
            
        # Check permissions (simplified - just check if readable)
        if node.permissions[0] == "0":
            return None  # No read permission
            
        return node.content
        
    def write_file(self, path: str, content: str, current_dir: str = "/") -> bool:
        """Write content to a file (create if doesn't exist)"""
        abs_path = self.resolve_path(path, current_dir)
        
        # Get parent directory
        parent_path = "/".join(abs_path.split("/")[:-1]) or "/"
        filename = abs_path.split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or not parent.is_dir:
            return False
            
        # Check if file exists
        existing = parent.get_child(filename)
        if existing:
            if existing.is_dir:
                return False
            existing.content = content
            existing.size = len(content)
            existing.modified = datetime.datetime.now()
        else:
            # Create new file
            new_file = FileNode(filename, content=content, permissions="644")
            parent.add_child(new_file)
            
        return True
        
    def create_directory(self, path: str, current_dir: str = "/") -> bool:
        """Create a directory"""
        abs_path = self.resolve_path(path, current_dir)
        
        # Get parent directory
        parent_path = "/".join(abs_path.split("/")[:-1]) or "/"
        dirname = abs_path.split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or not parent.is_dir:
            return False
            
        # Check if already exists
        if parent.get_child(dirname):
            return False
            
        new_dir = FileNode(dirname, is_dir=True, permissions="755")
        parent.add_child(new_dir)
        return True
        
    def delete(self, path: str, current_dir: str = "/") -> bool:
        """Delete a file or empty directory"""
        abs_path = self.resolve_path(path, current_dir)
        
        if abs_path == "/":
            return False  # Can't delete root
            
        parent_path = "/".join(abs_path.split("/")[:-1]) or "/"
        filename = abs_path.split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or not parent.is_dir:
            return False
            
        node = parent.get_child(filename)
        if not node:
            return False
            
        # Don't delete non-empty directories
        if node.is_dir and node.children:
            return False
            
        del parent.children[filename]
        return True
        
    def get_file_info(self, path: str, current_dir: str = "/") -> Optional[Dict[str, Any]]:
        """Get detailed file information"""
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        
        if not node:
            return None
            
        return {
            "name": node.name,
            "path": abs_path,
            "is_dir": node.is_dir,
            "permissions": node.permissions,
            "owner": node.owner,
            "group": node.group,
            "size": node.size,
            "modified": node.modified,
        }
