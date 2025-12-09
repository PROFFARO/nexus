#!/usr/bin/env python3
"""
Virtual Filesystem for FTP Honeypot
Provides a realistic Ubuntu 20.04 LTS filesystem structure for FTP server emulation
Adapted from SSH honeypot VirtualFilesystem with FTP-specific customizations
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import random
import datetime
import hashlib


class FileNode:
    """Represents a file or directory in the virtual filesystem"""
    
    def __init__(
        self,
        name: str,
        is_dir: bool = False,
        content: str = "",
        permissions: str = "644",
        owner: str = "ftp",
        group: str = "ftp",
        size: Optional[int] = None,
        modified: Optional[datetime.datetime] = None
    ):
        self.name = name
        self.is_dir = is_dir
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.group = group
        self.size = size if size is not None else len(content.encode('utf-8') if isinstance(content, str) else content)
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
            owner=data.get("owner", "ftp"),
            group=data.get("group", "ftp"),
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
    Virtual filesystem mimicking Ubuntu 22.04 LTS for FTP honeypot
    Provides persistent, in-memory filesystem with dynamic content generation
    """
    
    def __init__(self, username: str = "ftp"):
        self.root = FileNode("/", is_dir=True, permissions="755", owner="root", group="root")
        self.current_user = username
        self._server_start_time = datetime.datetime.now() - datetime.timedelta(days=random.randint(30, 180))
        self._initialize_filesystem()

        self.installed_packages = {
            "vsftpd": "3.0.5-0ubuntu1",
            "nginx": "1.24.0-1ubuntu1",
            "mysql-server": "8.0.35-0ubuntu0.22.04.1",
            "openssh-server": "1:9.0p1-1ubuntu8.5",
            "python3": "3.10.12-1~22.04.2",
            "git": "1:2.34.1-1ubuntu1.10",
        }

    # ========== Dynamic Content Generators ==========
    
    def _generate_timestamp(self, days_ago_max: int = 30) -> datetime.datetime:
        """Generate a realistic recent timestamp"""
        days_ago = random.randint(0, days_ago_max)
        hours_ago = random.randint(0, 23)
        return datetime.datetime.now() - datetime.timedelta(days=days_ago, hours=hours_ago)
    
    def _generate_build_log(self, project_name: str, build_num: int) -> str:
        """Generate realistic CI/CD build log"""
        start_time = self._generate_timestamp(7)
        commit_hash = hashlib.sha1(f"{project_name}{build_num}".encode()).hexdigest()[:8]
        
        log_lines = [
            f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] === NexusGames CI/CD Pipeline v3.2.1 ===",
            f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] Build #{build_num} for {project_name}",
            f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] Branch: main | Commit: {commit_hash}",
            f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] Triggered by: GitHub webhook (push)",
            "",
            f"[{(start_time + datetime.timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')}] === STAGE: Checkout ===",
            f"Cloning into '/var/jenkins/workspace/{project_name}'...",
            f"HEAD is now at {commit_hash} feat: update game engine",
            "",
            f"[{(start_time + datetime.timedelta(seconds=8)).strftime('%Y-%m-%d %H:%M:%S')}] === STAGE: Dependencies ===",
            "Installing npm packages...",
            "added 1247 packages in 42.3s",
            "",
            f"[{(start_time + datetime.timedelta(seconds=55)).strftime('%Y-%m-%d %H:%M:%S')}] === STAGE: Build ===",
            "Running webpack production build...",
            "asset main.js 2.4 MiB [emitted] [minimized]",
            "asset styles.css 156 KiB [emitted]",
            f"webpack compiled successfully in {random.randint(15000, 45000)}ms",
            "",
            f"[{(start_time + datetime.timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S')}] === STAGE: Test ===",
            f"Running {random.randint(150, 400)} tests...",
            f"Tests: {random.randint(145, 395)} passed, {random.randint(0, 5)} skipped",
            "Coverage: 78.4%",
            "",
            f"[{(start_time + datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')}] === STAGE: Package ===",
            f"Creating artifact: {project_name.lower()}-build-{build_num}.zip",
            f"Artifact size: {random.randint(50, 500)} MB",
            "",
            f"[{(start_time + datetime.timedelta(minutes=6)).strftime('%Y-%m-%d %H:%M:%S')}] BUILD SUCCESS",
            f"Total time: {random.randint(300, 600)} seconds",
        ]
        return "\n".join(log_lines)

    def _generate_access_log(self, num_entries: int = 50) -> str:
        """Generate realistic nginx/apache access log"""
        ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "192.168.5.42", "10.10.10.15"]
        paths = ["/api/v1/users", "/assets/game.js", "/login", "/dashboard", "/api/v1/scores"]
        codes = [200, 200, 200, 200, 304, 404, 500]
        
        lines = []
        for i in range(num_entries):
            ts = self._generate_timestamp(3)
            ip = random.choice(ips)
            path = random.choice(paths)
            code = random.choice(codes)
            size = random.randint(200, 50000)
            lines.append(f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {code} {size}')
        return "\n".join(lines)

    def _generate_auth_log(self, num_entries: int = 30) -> str:
        """Generate realistic auth.log entries"""
        users = ["admin", "nexus", "dev", "root", "backup"]
        results = ["success", "success", "success", "failure"]
        
        lines = []
        for i in range(num_entries):
            ts = self._generate_timestamp(5)
            user = random.choice(users)
            result = random.choice(results)
            lines.append(f'{ts.strftime("%b %d %H:%M:%S")} ftp-srv-prod-01 vsftpd: pam_unix(vsftpd:auth): authentication {result}; user={user}')
        return "\n".join(sorted(lines))


    def set_user(self, username: str):
        """Set the current user context"""
        self.current_user = username

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
        """Initialize the complete Ubuntu filesystem structure for FTP"""
        # Create standard Linux directories
        self._create_standard_directories()
        
        # Populate /etc with configuration files
        self._populate_etc()
        
        # Populate /home with user directories
        self._populate_home()
        
        # Populate /var/ftp with FTP public files
        self._populate_ftp_root()
        
        # Populate /opt with game projects
        self._populate_game_projects()
        
        # Populate /var with logs and builds
        self._populate_var()
        
        # Populate /tmp
        self._populate_tmp()
        
        # Populate depot with CI/CD artifacts
        self._populate_depot()
        
        # Populate database files (honeypot bait)
        self._populate_database_files()

        
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
        ]
        
        for dir_name, perms, owner, group in standard_dirs:
            node = FileNode(dir_name, is_dir=True, permissions=perms, owner=owner, group=group)
            self.root.add_child(node)
            
        # Create usr subdirectories
        usr = self.root.get_child("usr")
        for subdir in ["bin", "lib", "local", "share", "src"]:
            usr.add_child(FileNode(subdir, is_dir=True, permissions="755", owner="root", group="root"))
            
        # Create var subdirectories
        var = self.root.get_child("var")
        for subdir in ["log", "tmp", "cache", "lib", "ftp", "www"]:
            var.add_child(FileNode(subdir, is_dir=True, permissions="755", owner="root", group="root"))

    def _populate_etc(self):
        """Populate /etc with realistic configuration files"""
        etc = self.root.get_child("etc")
        
        # /etc/vsftpd.conf
        vsftpd_conf = """# vsftpd configuration - NexusGames Studio FTP Server
# Standalone mode
listen=YES
listen_ipv6=NO

# Security settings
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_std_format=YES

# Chroot settings
chroot_local_user=YES
chroot_list_enable=NO
allow_writeable_chroot=YES

# Passive mode settings
pasv_enable=YES
pasv_min_port=50000
pasv_max_port=50100

# Security restrictions
ascii_upload_enable=YES
ascii_download_enable=YES
ftpd_banner=Welcome to NexusGames Studio FTP Server
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
"""
        etc.add_child(FileNode("vsftpd.conf", content=vsftpd_conf, permissions="644", owner="root", group="root"))
        
        # /etc/passwd (simplified FTP-relevant entries)
        passwd_content = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ftp:x:21:21::/var/ftp:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
admin:x:1001:1001:FTP Administrator,,,:/home/admin:/bin/bash
upload:x:1002:1002:Upload User,,,:/home/upload:/bin/bash
backup:x:1003:1003:Backup User,,,:/home/backup:/bin/bash
nexus:x:1004:1004:NexusGames User,,,:/home/nexus:/bin/bash
dev:x:1005:1005:Developer,,,:/home/dev:/bin/bash
"""
        etc.add_child(FileNode("passwd", content=passwd_content, permissions="644", owner="root", group="root"))
        
        # /etc/group
        group_content = """root:x:0:
ftp:x:21:
www-data:x:33:
nogroup:x:65534:
admin:x:1001:
upload:x:1002:
backup:x:1003:
nexus:x:1004:
dev:x:1005:
"""
        etc.add_child(FileNode("group", content=group_content, permissions="644", owner="root", group="root"))
        
        # /etc/hostname
        etc.add_child(FileNode("hostname", content="ftp-srv-prod-01\n", permissions="644", owner="root", group="root"))
        
        # /etc/os-release
        os_release = """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy
"""
        etc.add_child(FileNode("os-release", content=os_release, permissions="644", owner="root", group="root"))
        
        # /etc/motd
        motd_content = """
╔══════════════════════════════════════════════════════════════╗
║           NEXUSGAMES STUDIO - FTP FILE SERVER                ║
║                   ftp-srv-prod-01                            ║
╚══════════════════════════════════════════════════════════════╝

⚠️  WARNING: Authorized access only
📊 All file transfers are monitored and logged
🔒 Unauthorized access is strictly prohibited

For support: admin@nexusgames.local
"""
        etc.add_child(FileNode("motd", content=motd_content, permissions="644", owner="root", group="root"))
        
        # /etc/hosts
        hosts_content = """127.0.0.1       localhost
127.0.1.1       ftp-srv-prod-01
192.168.10.5    db-prod-cluster.internal.nexusgames.local db-prod
192.168.10.10   redis-prod.internal.nexusgames.local redis
192.168.10.15   api-gateway.internal.nexusgames.local api
10.0.0.100      git.nexusgames.local git
10.0.0.101      jenkins.nexusgames.local ci
"""
        etc.add_child(FileNode("hosts", content=hosts_content, permissions="644", owner="root", group="root"))
        
        # Create /etc/nginx directory
        nginx_dir = FileNode("nginx", is_dir=True, permissions="755", owner="root", group="root")
        nginx_conf = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""
        nginx_dir.add_child(FileNode("nginx.conf", content=nginx_conf, permissions="644", owner="root", group="root"))
        
        sites_available = FileNode("sites-available", is_dir=True, permissions="755", owner="root", group="root")
        game_api_site = """server {
    listen 443 ssl http2;
    server_name api.nexusgames.local;
    
    ssl_certificate /etc/ssl/certs/nexusgames.crt;
    ssl_certificate_key /etc/ssl/private/nexusgames.key;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /api/v1 {
        proxy_pass http://127.0.0.1:8080;
        limit_req zone=api_limit burst=20 nodelay;
    }
}
"""
        sites_available.add_child(FileNode("game-api", content=game_api_site, permissions="644", owner="root", group="root"))
        nginx_dir.add_child(sites_available)
        etc.add_child(nginx_dir)
        
        # Create /etc/mysql directory
        mysql_dir = FileNode("mysql", is_dir=True, permissions="755", owner="root", group="root")
        mysql_conf = """[mysqld]
user            = mysql
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
datadir         = /var/lib/mysql

bind-address    = 0.0.0.0
max_connections = 500
innodb_buffer_pool_size = 4G
innodb_log_file_size = 256M

slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

[client]
port            = 3306
socket          = /var/run/mysqld/mysqld.sock
"""
        mysql_dir.add_child(FileNode("my.cnf", content=mysql_conf, permissions="644", owner="root", group="root"))
        etc.add_child(mysql_dir)
        
        # /etc/crontab
        crontab_content = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
0 3     * * *   backup  /opt/scripts/backup_db.sh >> /var/log/backup.log 2>&1
0 4     * * 0   root    /opt/scripts/cleanup_temp.sh
*/5 *   * * *   jenkins /opt/scripts/check_builds.sh
"""
        etc.add_child(FileNode("crontab", content=crontab_content, permissions="644", owner="root", group="root"))


    def _populate_home(self):
        """Populate /home with user directories"""
        home = self.root.get_child("home")
        
        users = [
            ("admin", "1001", "1001"),
            ("upload", "1002", "1002"),
            ("backup", "1003", "1003"),
            ("nexus", "1004", "1004"),
            ("dev", "1005", "1005"),
            ("ftp", "21", "21"),
        ]
        
        for username, uid, gid in users:
            user_dir = FileNode(username, is_dir=True, permissions="755", owner=username, group=username)
            
            # Add common directories
            for subdir in ["uploads", "downloads", "backups"]:
                user_dir.add_child(FileNode(subdir, is_dir=True, permissions="755", owner=username, group=username))
            
            # Add .bashrc
            bashrc = f"""# ~/.bashrc for {username}
export PATH=/usr/local/bin:/usr/bin:/bin
export PS1='\\u@\\h:\\w\\$ '
alias ll='ls -la'
"""
            user_dir.add_child(FileNode(".bashrc", content=bashrc, permissions="644", owner=username, group=username))
            
            home.add_child(user_dir)

    def _populate_ftp_root(self):
        """Populate /var/ftp with FTP public files"""
        var = self.root.get_child("var")
        ftp = var.get_child("ftp")
        
        # Create pub directory
        pub = FileNode("pub", is_dir=True, permissions="755", owner="ftp", group="ftp")
        
        # Add welcome message
        welcome = """
* NEXUSGAMES STUDIO - INTERNAL NETWORK
* ASSET MANAGEMENT GATEWAY
********************************************************************************
* WARNING: RESTRICTED ACCESS SYSTEM
* This system is for the use of authorized NexusGames personnel only.
* Activities on this server are monitored, recorded, and audited.
* Unauthorized access is a violation of the Computer Fraud and Abuse Act
* and applicable international laws.
********************************************************************************

[ SYSTEM NOTICE ]
> Server Version: NGS-FTPd v4.2.1 (Build 2024-11-RC)
> Maint Window:   Sundays 02:00 - 04:00 UTC
> Encryption:     TLS 1.2 Required for Uploads

[ DIRECTORY INDEX & POLICIES ]

1. /pub (PUBLIC)
   -----------------------------------------------------------------------------
   Contains press kits, whitepapers, and public demo builds.
   [RWX] - Guest Access Allowed

2. /depot (INTERNAL - TEAM A)
   -----------------------------------------------------------------------------
   Daily build artifacts, CI/CD logs, and debug symbols.
   [R-X] - Developers & QA Only. No external distribution.

3. /assets (INTERNAL - ART DEPT)
   -----------------------------------------------------------------------------
   Raw texture files (.psd, .tiff), model source files, and audio stems.
   [R--] - Read-only. Use the checkout system for modifications.

4. /legacy (ARCHIVE)
   -----------------------------------------------------------------------------
   Deprecated project files and pre-2023 backups.
   [---] - Restricted. Contact SysAdmin for retrieval.

[ SUPPORT ]
> If you have lost your credentials or require write access to /depot,
> please submit a ticket to IT-OPS via the Intranet or contact:
> admin.sysops@nexusgames.local
"""
        pub.add_child(FileNode("README.txt", content=welcome, permissions="644", owner="ftp", group="ftp"))
        
        # Create builds directory
        builds = FileNode("builds", is_dir=True, permissions="755", owner="ftp", group="ftp")
        builds.add_child(FileNode("StellarConquest_v1.2.3.zip", content="[Binary Game Build]", 
                                   permissions="644", owner="ftp", group="ftp", size=524288000))
        builds.add_child(FileNode("MysticRealms_v0.9.1_beta.zip", content="[Binary Game Build]", 
                                   permissions="644", owner="ftp", group="ftp", size=312500000))
        builds.add_child(FileNode("RacingThunder_v2.0.0_release.zip", content="[Binary Game Build]", 
                                   permissions="644", owner="ftp", group="ftp", size=156250000))
        pub.add_child(builds)
        
        # Create assets directory
        assets = FileNode("assets", is_dir=True, permissions="755", owner="ftp", group="ftp")
        
        textures = FileNode("textures", is_dir=True, permissions="755", owner="ftp", group="ftp")
        textures.add_child(FileNode("environment_pack_v3.zip", content="[Texture Pack]", 
                                     permissions="644", owner="ftp", group="ftp", size=2147483648))
        textures.add_child(FileNode("character_textures.zip", content="[Texture Pack]", 
                                     permissions="644", owner="ftp", group="ftp", size=1073741824))
        assets.add_child(textures)
        
        models = FileNode("models", is_dir=True, permissions="755", owner="ftp", group="ftp")
        models.add_child(FileNode("vehicles_collection.fbx", content="[3D Models]", 
                                   permissions="644", owner="ftp", group="ftp", size=536870912))
        models.add_child(FileNode("characters_rigged.blend", content="[Blender File]", 
                                   permissions="644", owner="ftp", group="ftp", size=268435456))
        assets.add_child(models)
        
        audio = FileNode("audio", is_dir=True, permissions="755", owner="ftp", group="ftp")
        audio.add_child(FileNode("soundtrack_master.wav", content="[Audio File]", 
                                  permissions="644", owner="ftp", group="ftp", size=134217728))
        audio.add_child(FileNode("sfx_pack_v2.zip", content="[Sound Effects]", 
                                  permissions="644", owner="ftp", group="ftp", size=67108864))
        assets.add_child(audio)
        
        pub.add_child(assets)
        
        # Create documentation directory
        docs = FileNode("documentation", is_dir=True, permissions="755", owner="ftp", group="ftp")
        docs.add_child(FileNode("API_Reference_v3.pdf", content="[PDF Document]", 
                                 permissions="644", owner="ftp", group="ftp", size=4194304))
        docs.add_child(FileNode("Engine_Manual.pdf", content="[PDF Document]", 
                                 permissions="644", owner="ftp", group="ftp", size=8388608))
        docs.add_child(FileNode("Asset_Pipeline_Guide.md", content="""# Asset Pipeline Guide

## Overview
This document describes the asset import pipeline for NexusGames projects.

## Supported Formats
- 3D Models: FBX, GLTF, OBJ
- Textures: PNG, TGA, PSD
- Audio: WAV, OGG, MP3

## Import Process
1. Place assets in /incoming directory
2. Run asset_import.py script
3. Verify in engine editor
""", permissions="644", owner="ftp", group="ftp"))
        pub.add_child(docs)
        
        # Create backups directory (intentionally readable - honeypot trap)
        backups = FileNode("backups", is_dir=True, permissions="755", owner="ftp", group="ftp")
        backups.add_child(FileNode("db_backup_20241201.sql.gz", content="[Database Backup]", 
                                    permissions="644", owner="ftp", group="ftp", size=16777216))
        backups.add_child(FileNode("config_backup_20241201.tar.gz", content="[Config Backup]", 
                                    permissions="644", owner="ftp", group="ftp", size=1048576))
        pub.add_child(backups)
        
        # Create incoming/uploads directory
        incoming = FileNode("incoming", is_dir=True, permissions="777", owner="ftp", group="ftp")
        incoming.add_child(FileNode(".gitkeep", content="", permissions="644", owner="ftp", group="ftp"))
        pub.add_child(incoming)
        
        ftp.add_child(pub)

    def _populate_game_projects(self):
        """Populate /opt with game development projects"""
        opt = self.root.get_child("opt")
        games_dir = FileNode("games", is_dir=True, permissions="755", owner="root", group="developers")
        
        projects = [
            ("Stellar-Conquest", "Space strategy game - Production"),
            ("Mystic-Realms", "Fantasy RPG - Beta"),
            ("Racing-Thunder", "Mobile racing game - Release"),
            ("Project-Phoenix", "Unannounced AAA title - CONFIDENTIAL"),
        ]
        
        for project_name, description in projects:
            project_dir = FileNode(project_name, is_dir=True, permissions="755", owner="nexus", group="developers")
            
            # README.md
            readme = f"""# {project_name}

{description}

## Build Instructions
```bash
./build.sh
```

## Team
- Lead Developer: Alex Chen
- Art Director: Sarah Martinez  
- Engine Programmer: Mike Thompson

## Status
Active development - Q1 2025 release target
"""
            project_dir.add_child(FileNode("README.md", content=readme, permissions="644", owner="nexus", group="developers"))
            
            # Source directory
            src_dir = FileNode("src", is_dir=True, permissions="755", owner="nexus", group="developers")
            src_dir.add_child(FileNode("main.cpp", content="// Main entry point\n#include \"engine.h\"\n", 
                                        permissions="644", owner="nexus", group="developers"))
            project_dir.add_child(src_dir)
            
            # Assets directory
            assets_dir = FileNode("assets", is_dir=True, permissions="755", owner="nexus", group="developers")
            project_dir.add_child(assets_dir)
            
            # Build script
            build_script = f"""#!/bin/bash
echo "Building {project_name}..."
mkdir -p build
cd build
cmake ..
make -j4
echo "Build complete!"
"""
            project_dir.add_child(FileNode("build.sh", content=build_script, permissions="755", owner="nexus", group="developers"))
            
            games_dir.add_child(project_dir)
            
        opt.add_child(games_dir)

    def _populate_var(self):
        """Populate /var with logs and system files"""
        var = self.root.get_child("var")
        
        # /var/log
        log_dir = var.get_child("log")
        if not log_dir:
            log_dir = FileNode("log", is_dir=True, permissions="755", owner="root", group="root")
            var.add_child(log_dir)
        
        # vsftpd.log
        vsftpd_log = """Mon Dec  2 10:23:15 2024 [pid 1234] CONNECT: Client "192.168.1.100"
Mon Dec  2 10:23:16 2024 [pid 1234] [admin] OK LOGIN: Client "192.168.1.100"
Mon Dec  2 10:23:45 2024 [pid 1234] [admin] OK DOWNLOAD: Client "192.168.1.100", "/pub/builds/StellarConquest_v1.2.3.zip"
Mon Dec  2 11:05:22 2024 [pid 1245] CONNECT: Client "10.0.0.50"
Mon Dec  2 11:05:23 2024 [pid 1245] [nexus] OK LOGIN: Client "10.0.0.50"
Mon Dec  2 11:06:01 2024 [pid 1245] [nexus] OK UPLOAD: Client "10.0.0.50", "/pub/incoming/new_assets.zip"
"""
        log_dir.add_child(FileNode("vsftpd.log", content=vsftpd_log, permissions="640", owner="root", group="adm"))
        
        # auth.log
        auth_log = """Dec  2 10:23:15 ftp-srv-prod-01 vsftpd: pam_unix(vsftpd:auth): authentication success; user=admin
Dec  2 10:45:32 ftp-srv-prod-01 vsftpd: pam_unix(vsftpd:auth): authentication failure; user=root
Dec  2 11:05:22 ftp-srv-prod-01 vsftpd: pam_unix(vsftpd:auth): authentication success; user=nexus
"""
        log_dir.add_child(FileNode("auth.log", content=auth_log, permissions="640", owner="root", group="adm"))

    def _populate_tmp(self):
        """Populate /tmp with temporary files"""
        tmp = self.root.get_child("tmp")
        tmp.add_child(FileNode(".X0-lock", content="1234\n", permissions="644", owner="root", group="root"))

    # ========== Path Resolution and Navigation ==========
    
    def resolve_path(self, path: str, current_dir: str = "/") -> str:
        """
        Resolve a path (relative or absolute) to an absolute path
        
        Args:
            path: Path to resolve
            current_dir: Current working directory
            
        Returns:
            Absolute path
        """
        if not path:
            return current_dir
            
        # Handle absolute paths
        if path.startswith("/"):
            abs_path = path
        else:
            # Relative path - join with current directory
            if current_dir.endswith("/"):
                abs_path = current_dir + path
            else:
                abs_path = current_dir + "/" + path
        
        # Normalize the path - handle '..' and '.'
        parts = []
        for part in abs_path.split("/"):
            if part == "." or part == "":
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
            
        return node.content
        
    def read_file_bytes(self, path: str, current_dir: str = "/") -> Optional[bytes]:
        """Read file contents as bytes"""
        content = self.read_file(path, current_dir)
        if content is None:
            return None
        return content.encode('utf-8') if isinstance(content, str) else content
        
    def write_file(self, path: str, content: str, current_dir: str = "/", 
                   owner: str = None, group: str = None) -> bool:
        """Write content to a file (create if doesn't exist)"""
        abs_path = self.resolve_path(path, current_dir)
        
        # Get parent directory
        parent_path = "/".join(abs_path.split("/")[:-1]) or "/"
        filename = abs_path.split("/")[-1]
        
        parent = self._get_node(parent_path)
        if not parent or not parent.is_dir:
            return False
            
        # Use current user if owner not specified
        if owner is None:
            owner = self.current_user
        if group is None:
            group = self.current_user
            
        # Check if file exists
        existing = parent.get_child(filename)
        if existing:
            if existing.is_dir:
                return False
            existing.content = content
            existing.size = len(content.encode('utf-8') if isinstance(content, str) else content)
            existing.modified = datetime.datetime.now()
        else:
            # Create new file
            new_file = FileNode(filename, content=content, permissions="644", owner=owner, group=group)
            parent.add_child(new_file)
            
        return True
        
    def create_directory(self, path: str, current_dir: str = "/", 
                         owner: str = None, group: str = None) -> bool:
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
            
        # Use current user if owner not specified
        if owner is None:
            owner = self.current_user
        if group is None:
            group = self.current_user
            
        new_dir = FileNode(dirname, is_dir=True, permissions="755", owner=owner, group=group)
        parent.add_child(new_dir)
        return True

    def create_directory_recursive(self, path: str, current_dir: str = "/",
                                    owner: str = None, group: str = None) -> bool:
        """Create a directory and any necessary parent directories"""
        abs_path = self.resolve_path(path, current_dir)
        
        parts = [p for p in abs_path.split("/") if p]
        current_path = ""
        
        for part in parts:
            current_path += "/" + part
            if not self.exists(current_path, "/"):
                if not self.create_directory(current_path, "/", owner, group):
                    return False
                    
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

    def delete_recursive(self, path: str, current_dir: str = "/") -> bool:
        """Delete a file or directory recursively"""
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
            
        del parent.children[filename]
        return True

    def rename(self, old_path: str, new_path: str, current_dir: str = "/") -> bool:
        """Rename/move a file or directory"""
        old_abs = self.resolve_path(old_path, current_dir)
        new_abs = self.resolve_path(new_path, current_dir)
        
        if old_abs == "/" or new_abs == "/":
            return False
            
        # Get the node to rename
        old_parent_path = "/".join(old_abs.split("/")[:-1]) or "/"
        old_name = old_abs.split("/")[-1]
        
        old_parent = self._get_node(old_parent_path)
        if not old_parent or not old_parent.is_dir:
            return False
            
        node = old_parent.get_child(old_name)
        if not node:
            return False
            
        # Get new parent
        new_parent_path = "/".join(new_abs.split("/")[:-1]) or "/"
        new_name = new_abs.split("/")[-1]
        
        new_parent = self._get_node(new_parent_path)
        if not new_parent or not new_parent.is_dir:
            return False
            
        # Check if destination already exists
        if new_parent.get_child(new_name):
            return False
            
        # Perform the rename
        del old_parent.children[old_name]
        node.name = new_name
        new_parent.add_child(node)
        
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

    def get_file_size(self, path: str, current_dir: str = "/") -> Optional[int]:
        """Get file size in bytes"""
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        
        if not node or node.is_dir:
            return None
            
        return node.size

    def get_modification_time(self, path: str, current_dir: str = "/") -> Optional[datetime.datetime]:
        """Get file modification time"""
        abs_path = self.resolve_path(path, current_dir)
        node = self._get_node(abs_path)
        
        if not node:
            return None
            
        return node.modified

    def format_unix_listing(self, entries: List[Dict[str, Any]]) -> str:
        """Format directory listing in Unix ls -l format"""
        lines = []
        for entry in entries:
            # Format permissions
            if entry["is_dir"]:
                perms = "d"
            else:
                perms = "-"
            
            # Parse numeric permissions (e.g., "755") to rwx format
            perm_str = entry["permissions"]
            if len(perm_str) == 3:
                for digit in perm_str:
                    d = int(digit)
                    perms += "r" if d & 4 else "-"
                    perms += "w" if d & 2 else "-"
                    perms += "x" if d & 1 else "-"
            else:
                perms += "rwxr-xr-x"  # Default
            
            # Format size
            size = entry["size"]
            
            # Format modification time
            mod_time = entry["modified"]
            if isinstance(mod_time, datetime.datetime):
                time_str = mod_time.strftime("%b %d %H:%M")
            else:
                time_str = "Jan  1 00:00"
            
            # Format the line
            line = f"{perms}    1 {entry['owner']:<8} {entry['group']:<8} {size:>10} {time_str} {entry['name']}"
            lines.append(line)
            
        return "\r\n".join(lines)

    def get_current_state_summary(self, current_dir: str = "/") -> Dict[str, Any]:
        """Get a summary of the current filesystem state for LLM context injection"""
        entries = self.list_directory(current_dir, "/")
        
        files = []
        dirs = []
        
        if entries:
            for entry in entries:
                if entry["is_dir"]:
                    dirs.append(entry["name"])
                else:
                    files.append(entry["name"])
        
        return {
            "current_directory": current_dir,
            "directories": dirs,
            "files": files,
            "total_items": len(files) + len(dirs),
        }

    def _populate_depot(self):
        """Populate /var/ftp/pub/depot with CI/CD build artifacts"""
        var = self.root.get_child("var")
        ftp = var.get_child("ftp")
        pub = ftp.get_child("pub")
        
        depot = FileNode("depot", is_dir=True, permissions="755", owner="jenkins", group="developers")
        
        # Build logs
        logs_dir = FileNode("logs", is_dir=True, permissions="755", owner="jenkins", group="developers")
        for i in range(5):
            build_num = 1000 + i
            log_content = self._generate_build_log("StellarConquest", build_num)
            logs_dir.add_child(FileNode(
                f"build_{build_num}.log", content=log_content,
                permissions="644", owner="jenkins", group="developers",
                modified=self._generate_timestamp(7)
            ))
        depot.add_child(logs_dir)
        
        # Debug symbols
        symbols_dir = FileNode("symbols", is_dir=True, permissions="755", owner="jenkins", group="developers")
        for project in ["StellarConquest", "MysticRealms", "RacingThunder"]:
            symbols_dir.add_child(FileNode(
                f"{project.lower()}_debug.pdb", content="[Debug Symbols Binary]",
                permissions="644", owner="jenkins", group="developers",
                size=random.randint(50000000, 150000000)
            ))
        depot.add_child(symbols_dir)
        
        # Artifacts
        artifacts_dir = FileNode("artifacts", is_dir=True, permissions="755", owner="jenkins", group="developers")
        for i in range(3):
            date_str = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y%m%d")
            artifacts_dir.add_child(FileNode(
                f"stellar_conquest_{date_str}.tar.gz", content="[Build Artifact]",
                permissions="644", owner="jenkins", group="developers",
                size=random.randint(200000000, 500000000)
            ))
        depot.add_child(artifacts_dir)
        
        pub.add_child(depot)

    def _populate_database_files(self):
        """Populate honeypot bait database files"""
        var = self.root.get_child("var")
        ftp = var.get_child("ftp")
        pub = ftp.get_child("pub")
        backups = pub.get_child("backups")
        
        # SQL dump with schema
        sql_content = f"""-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)
-- Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
-- Server version: 8.0.35-0ubuntu0.22.04.1

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for users
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `api_key` varchar(64) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=1001 DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Records of users (SAMPLE - First 10)
-- ----------------------------
INSERT INTO `users` VALUES (1, 'admin', 'admin@nexusgames.local', '$2b$12$K8GpZkE...', 'ngk_prod_a8f3c2d1...', '2023-01-15 10:00:00');
INSERT INTO `users` VALUES (2, 'dev_alex', 'alex.chen@nexusgames.local', '$2b$12$Jd9xKl...', 'ngk_dev_b7e4f1c2...', '2023-02-20 14:30:00');

-- ----------------------------
-- Table structure for game_scores
-- ----------------------------
DROP TABLE IF EXISTS `game_scores`;
CREATE TABLE `game_scores` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `game_id` varchar(32) NOT NULL,
  `score` int NOT NULL,
  `level` int DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_game` (`user_id`, `game_id`)
) ENGINE=InnoDB AUTO_INCREMENT=500001 DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;
"""
        backups.add_child(FileNode(
            "nexusgames_prod_full.sql", content=sql_content,
            permissions="640", owner="backup", group="backup",
            modified=self._generate_timestamp(2)
        ))
        
        # Config backup with credentials (bait)
        config_yaml = f"""# NexusGames Production Configuration
# WARNING: Contains sensitive credentials - DO NOT DISTRIBUTE

server:
  hostname: game-api-prod-01.nexusgames.local
  port: 8443
  ssl_enabled: true

database:
  host: db-prod-cluster.internal.nexusgames.local
  port: 3306
  name: nexusgames_production
  username: ng_app_service
  password: "Pr0dDB#2024!SecurePass"
  pool_size: 50

redis:
  host: redis-prod.internal.nexusgames.local
  port: 6379
  password: "R3d1s#Pr0d2024"

aws:
  region: us-east-1
  access_key_id: AKIA3EXAMPLE7ACCESS
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  s3_bucket: nexusgames-prod-assets

stripe:
  secret_key: sk_live_51ABC...EXAMPLE
  webhook_secret: whsec_EXAMPLE...

jwt:
  secret: "super_secret_jwt_key_2024_production"
  expiry_hours: 24
"""
        backups.add_child(FileNode(
            "app_config_prod.yml", content=config_yaml,
            permissions="600", owner="root", group="root",
            modified=self._generate_timestamp(5)
        ))
        
        # SSH keys (bait)
        ssh_dir = FileNode(".ssh_backup", is_dir=True, permissions="700", owner="backup", group="backup")
        ssh_dir.add_child(FileNode(
            "id_rsa", content="""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA0X1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
[REDACTED - Full key removed for security]
-----END OPENSSH PRIVATE KEY-----""",
            permissions="600", owner="backup", group="backup"
        ))
        ssh_dir.add_child(FileNode(
            "authorized_keys", content="""ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... admin@nexusgames.local
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... jenkins@build-server
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... deploy@prod-server
""",
            permissions="644", owner="backup", group="backup"
        ))
        backups.add_child(ssh_dir)

    def get_user_state_path(self, base_dir: str, username: str) -> str:
        """Get the state file path for a specific user"""
        import os
        user_dir = os.path.join(base_dir, username)
        os.makedirs(user_dir, exist_ok=True)
        return os.path.join(user_dir, "filesystem_state.json")

