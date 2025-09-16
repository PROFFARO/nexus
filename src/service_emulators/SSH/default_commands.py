#!/usr/bin/env python3
"""
Default command implementations for SSH honeypot
Provides realistic command responses for common Linux commands
"""

import os
import time
import random
import datetime
from typing import Dict, List, Any

class DefaultCommands:
    """Implements default command responses for the SSH honeypot"""
    
    def __init__(self, username: str = "user", hostname: str = "corp-srv-prod-01"):
        self.username = username
        self.hostname = hostname
        self.current_dir = "/home/" + username
        self.processes = self._generate_processes()
        self.network_connections = self._generate_network_connections()
        self.file_system = self._generate_file_system()
        
    def execute_command(self, command: str) -> str:
        """Execute a command and return realistic output"""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return ""
            
        cmd = cmd_parts[0].lower()
        args = cmd_parts[1:] if len(cmd_parts) > 1 else []
        
        # Command mapping
        command_map = {
            'ls': self._cmd_ls,
            'dir': self._cmd_ls,
            'pwd': self._cmd_pwd,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'uname': self._cmd_uname,
            'hostname': self._cmd_hostname,
            'uptime': self._cmd_uptime,
            'ps': self._cmd_ps,
            'top': self._cmd_top,
            'netstat': self._cmd_netstat,
            'ss': self._cmd_ss,
            'ifconfig': self._cmd_ifconfig,
            'ip': self._cmd_ip,
            'df': self._cmd_df,
            'free': self._cmd_free,
            'cat': self._cmd_cat,
            'head': self._cmd_head,
            'tail': self._cmd_tail,
            'grep': self._cmd_grep,
            'find': self._cmd_find,
            'which': self._cmd_which,
            'whereis': self._cmd_whereis,
            'history': self._cmd_history,
            'env': self._cmd_env,
            'mount': self._cmd_mount,
            'lsblk': self._cmd_lsblk,
            'systemctl': self._cmd_systemctl,
            'service': self._cmd_service,
            'crontab': self._cmd_crontab,
            'w': self._cmd_w,
            'who': self._cmd_who,
            'last': self._cmd_last,
            'date': self._cmd_date,
            'cal': self._cmd_cal,
            'help': self._cmd_help,
            'man': self._cmd_man
        }
        
        if cmd in command_map:
            try:
                return command_map[cmd](args)
            except Exception as e:
                return f"bash: {cmd}: command error: {str(e)}"
        else:
            return f"bash: {cmd}: command not found"
    
    def _cmd_ls(self, args: List[str]) -> str:
        """List directory contents"""
        show_all = '-a' in args or '--all' in args
        long_format = '-l' in args or '--long' in args
        
        files = [
            {'name': '.', 'type': 'd', 'perms': 'drwxr-xr-x', 'size': 4096, 'owner': self.username, 'group': self.username},
            {'name': '..', 'type': 'd', 'perms': 'drwxr-xr-x', 'size': 4096, 'owner': 'root', 'group': 'root'},
            {'name': 'Documents', 'type': 'd', 'perms': 'drwxr-xr-x', 'size': 4096, 'owner': self.username, 'group': self.username},
            {'name': 'Downloads', 'type': 'd', 'perms': 'drwxr-xr-x', 'size': 4096, 'owner': self.username, 'group': self.username},
            {'name': 'config.txt', 'type': '-', 'perms': '-rw-r--r--', 'size': 1024, 'owner': self.username, 'group': self.username},
            {'name': 'backup.sh', 'type': '-', 'perms': '-rwxr-xr-x', 'size': 2048, 'owner': self.username, 'group': self.username},
            {'name': '.bashrc', 'type': '-', 'perms': '-rw-r--r--', 'size': 3526, 'owner': self.username, 'group': self.username},
            {'name': '.bash_history', 'type': '-', 'perms': '-rw-------', 'size': 15234, 'owner': self.username, 'group': self.username},
            {'name': '.ssh', 'type': 'd', 'perms': 'drwx------', 'size': 4096, 'owner': self.username, 'group': self.username}
        ]
        
        if not show_all:
            files = [f for f in files if not f['name'].startswith('.')]
        
        if long_format:
            result = f"total {sum(f['size'] for f in files) // 1024}\n"
            for f in files:
                date_str = datetime.datetime.now().strftime("%b %d %H:%M")
                result += f"{f['perms']} 1 {f['owner']} {f['group']} {f['size']:>8} {date_str} {f['name']}\n"
            return result.rstrip()
        else:
            return "  ".join(f['name'] for f in files)
    
    def _cmd_pwd(self, args: List[str]) -> str:
        """Print working directory"""
        return self.current_dir
    
    def _cmd_whoami(self, args: List[str]) -> str:
        """Print current username"""
        return self.username
    
    def _cmd_id(self, args: List[str]) -> str:
        """Print user and group IDs"""
        uid = 1000 if self.username != 'root' else 0
        gid = 1000 if self.username != 'root' else 0
        groups = "1000(user)" if self.username != 'root' else "0(root)"
        return f"uid={uid}({self.username}) gid={gid}({self.username}) groups={groups}"
    
    def _cmd_uname(self, args: List[str]) -> str:
        """Print system information"""
        if '-a' in args or '--all' in args:
            return f"Linux {self.hostname} 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux"
        elif '-r' in args:
            return "5.10.0-21-amd64"
        elif '-n' in args:
            return self.hostname
        elif '-m' in args:
            return "x86_64"
        elif '-s' in args:
            return "Linux"
        else:
            return "Linux"
    
    def _cmd_hostname(self, args: List[str]) -> str:
        """Print hostname"""
        return self.hostname
    
    def _cmd_uptime(self, args: List[str]) -> str:
        """Print system uptime"""
        uptime_days = random.randint(1, 365)
        uptime_hours = random.randint(0, 23)
        uptime_mins = random.randint(0, 59)
        load_avg = f"{random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}"
        users = random.randint(1, 5)
        
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        return f" {current_time} up {uptime_days} days, {uptime_hours}:{uptime_mins:02d}, {users} users, load average: {load_avg}"
    
    def _cmd_ps(self, args: List[str]) -> str:
        """Show running processes"""
        if 'aux' in ' '.join(args) or '-ef' in args:
            header = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
            result = [header]
            for proc in self.processes[:20]:  # Show first 20 processes
                result.append(f"{proc['user']:<10} {proc['pid']:>5} {proc['cpu']:>4.1f} {proc['mem']:>4.1f} {proc['vsz']:>7} {proc['rss']:>5} {proc['tty']:<8} {proc['stat']:<4} {proc['start']:<5} {proc['time']:<7} {proc['command']}")
            return "\n".join(result)
        else:
            header = "  PID TTY          TIME CMD"
            result = [header]
            for proc in self.processes[:10]:
                result.append(f"{proc['pid']:>5} {proc['tty']:<12} {proc['time']:<8} {proc['command'].split()[0]}")
            return "\n".join(result)
    
    def _cmd_top(self, args: List[str]) -> str:
        """Show top processes"""
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        uptime_str = f"up {random.randint(1, 100)} days"
        users = random.randint(1, 5)
        load_avg = f"{random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}"
        
        tasks_total = len(self.processes)
        tasks_running = random.randint(1, 5)
        tasks_sleeping = tasks_total - tasks_running
        
        cpu_us = random.uniform(5, 25)
        cpu_sy = random.uniform(1, 10)
        cpu_id = 100 - cpu_us - cpu_sy
        
        mem_total = random.randint(8000000, 32000000)  # 8-32GB in KB
        mem_free = random.randint(1000000, mem_total // 2)
        mem_used = mem_total - mem_free
        
        result = f"""top - {current_time} {uptime_str}, {users} users, load average: {load_avg}
Tasks: {tasks_total} total, {tasks_running} running, {tasks_sleeping} sleeping, 0 stopped, 0 zombie
%Cpu(s): {cpu_us:4.1f} us, {cpu_sy:4.1f} sy, 0.0 ni, {cpu_id:4.1f} id, 0.0 wa, 0.0 hi, 0.0 si, 0.0 st
MiB Mem : {mem_total//1024:8.1f} total, {mem_free//1024:8.1f} free, {mem_used//1024:8.1f} used, 0.0 buff/cache
MiB Swap: 0.0 total, 0.0 free, 0.0 used. {mem_free//1024:8.1f} avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"""
        
        for proc in self.processes[:15]:
            result += f"\n{proc['pid']:>5} {proc['user']:<8} {20:>3} {0:>3} {proc['vsz']:>7} {proc['rss']:>6} {proc['rss']//2:>6} {proc['stat'][0]} {proc['cpu']:>5.1f} {proc['mem']:>5.1f} {proc['time']:>9} {proc['command']}"
        
        return result
    
    def _cmd_netstat(self, args: List[str]) -> str:
        """Show network connections"""
        if '-an' in ' '.join(args) or '-a' in args:
            header = "Active Internet connections (servers and established)"
            result = [header, "Proto Recv-Q Send-Q Local Address           Foreign Address         State"]
            
            for conn in self.network_connections:
                result.append(f"{conn['proto']:<5} {conn['recv_q']:>6} {conn['send_q']:>6} {conn['local']:<23} {conn['foreign']:<23} {conn['state']}")
            
            return "\n".join(result)
        else:
            return "Active Internet connections (w/o servers)"
    
    def _cmd_ss(self, args: List[str]) -> str:
        """Show socket statistics"""
        if '-tulpn' in ' '.join(args) or '-a' in args:
            header = "Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port"
            result = [header]
            
            for conn in self.network_connections[:10]:
                local_addr = conn['local'].replace(':', ' ')
                foreign_addr = conn['foreign'].replace(':', ' ')
                result.append(f"{conn['proto'].lower():<6} {conn['state']:<10} {conn['recv_q']:>6} {conn['send_q']:>6} {local_addr:<31} {foreign_addr}")
            
            return "\n".join(result)
        else:
            return "State      Recv-Q Send-Q Local Address:Port                 Peer Address:Port"
    
    def _cmd_ifconfig(self, args: List[str]) -> str:
        """Show network interface configuration"""
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.100.50  netmask 255.255.255.0  broadcast 10.10.100.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
        RX packets 1234567  bytes 987654321 (941.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 654321  bytes 123456789 (117.7 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 12345  bytes 1234567 (1.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12345  bytes 1234567 (1.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"""
    
    def _cmd_ip(self, args: List[str]) -> str:
        """Show IP configuration"""
        if 'addr' in args or 'address' in args:
            return """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:4e:66:a1 brd ff:ff:ff:ff:ff:ff
    inet 10.10.100.50/24 brd 10.10.100.255 scope global dynamic eth0
       valid_lft 86394sec preferred_lft 86394sec
    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link 
       valid_lft forever preferred_lft forever"""
        elif 'route' in args:
            return """default via 10.10.100.1 dev eth0 proto dhcp metric 100 
10.10.100.0/24 dev eth0 proto kernel scope link src 10.10.100.50 metric 100"""
        else:
            return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"
    
    def _cmd_df(self, args: List[str]) -> str:
        """Show disk space usage"""
        if '-h' in args:
            return """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G  8.5G   11G  45% /
/dev/sda2       100G   45G   50G  48% /home
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           2.0G  8.8M  2.0G   1% /run
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup"""
        else:
            return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       20971520 8912896  11534336  45% /
/dev/sda2      104857600 47185920  52428800  48% /home
tmpfs            2097152        0   2097152   0% /dev/shm
tmpfs            2097152     9011   2088141   1% /run
tmpfs            2097152        0   2097152   0% /sys/fs/cgroup"""
    
    def _cmd_free(self, args: List[str]) -> str:
        """Show memory usage"""
        if '-h' in args:
            return """              total        used        free      shared  buff/cache   available
Mem:           16Gi       4.2Gi       8.1Gi       256Mi       3.7Gi        11Gi
Swap:         2.0Gi          0B       2.0Gi"""
        else:
            return """              total        used        free      shared  buff/cache   available
Mem:       16777216     4398046     8388608      262144     3932160    11534336
Swap:       2097152           0     2097152"""
    
    def _cmd_cat(self, args: List[str]) -> str:
        """Display file contents"""
        if not args:
            return "cat: missing file operand"
        
        filename = args[0]
        
        # Simulate common files
        file_contents = {
            '/etc/passwd': """root:x:0:0:root:/root:/bin/bash
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
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
user:x:1000:1000:User,,,:/home/user:/bin/bash""",
            
            '/etc/shadow': "cat: /etc/shadow: Permission denied",
            
            '/etc/hosts': """127.0.0.1	localhost
127.0.1.1	corp-srv-prod-01.nexus.local	corp-srv-prod-01
10.10.100.1	gateway.nexus.local
10.10.100.10	dc01.nexus.local
10.10.100.20	mail.nexus.local
10.10.100.30	web.nexus.local

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters""",
            
            'config.txt': """# Application Configuration
server.host=10.10.100.50
server.port=8080
database.url=jdbc:mysql://10.10.100.40:3306/appdb
database.username=appuser
database.password=SecureP@ssw0rd123
api.key=ak_live_1234567890abcdef
encryption.key=AES256_KEY_HERE
debug.enabled=false""",
            
            '.bashrc': """# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi"""
        }
        
        if filename in file_contents:
            return file_contents[filename]
        else:
            return f"cat: {filename}: No such file or directory"
    
    def _cmd_head(self, args: List[str]) -> str:
        """Show first lines of file"""
        if not args:
            return "head: missing file operand"
        return "head: showing first 10 lines of file (simulated)"
    
    def _cmd_tail(self, args: List[str]) -> str:
        """Show last lines of file"""
        if not args:
            return "tail: missing file operand"
        return "tail: showing last 10 lines of file (simulated)"
    
    def _cmd_grep(self, args: List[str]) -> str:
        """Search text patterns"""
        if len(args) < 2:
            return "grep: missing pattern or file"
        return f"grep: searching for '{args[0]}' (simulated)"
    
    def _cmd_find(self, args: List[str]) -> str:
        """Find files and directories"""
        return """./Documents
./Documents/report.pdf
./Documents/notes.txt
./Downloads
./Downloads/script.sh
./config.txt
./backup.sh"""
    
    def _cmd_which(self, args: List[str]) -> str:
        """Locate command"""
        if not args:
            return "which: missing argument"
        
        common_paths = {
            'bash': '/bin/bash',
            'ls': '/bin/ls',
            'cat': '/bin/cat',
            'grep': '/bin/grep',
            'find': '/usr/bin/find',
            'python': '/usr/bin/python3',
            'python3': '/usr/bin/python3',
            'perl': '/usr/bin/perl',
            'ruby': '/usr/bin/ruby',
            'php': '/usr/bin/php',
            'java': '/usr/bin/java',
            'gcc': '/usr/bin/gcc',
            'make': '/usr/bin/make',
            'wget': '/usr/bin/wget',
            'curl': '/usr/bin/curl',
            'ssh': '/usr/bin/ssh',
            'scp': '/usr/bin/scp',
            'nc': '/bin/nc',
            'netcat': '/bin/nc'
        }
        
        cmd = args[0]
        return common_paths.get(cmd, f"which: no {cmd} in (/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games)")
    
    def _cmd_whereis(self, args: List[str]) -> str:
        """Locate binary, source, and manual page files"""
        if not args:
            return "whereis: missing argument"
        
        cmd = args[0]
        return f"{cmd}: /usr/bin/{cmd} /usr/share/man/man1/{cmd}.1.gz"
    
    def _cmd_history(self, args: List[str]) -> str:
        """Show command history"""
        history_commands = [
            "ls -la",
            "cd Documents",
            "cat config.txt",
            "ps aux",
            "netstat -an",
            "whoami",
            "id",
            "uname -a",
            "df -h",
            "free -h",
            "top",
            "history"
        ]
        
        result = []
        for i, cmd in enumerate(history_commands, 1):
            result.append(f"  {i:3d}  {cmd}")
        
        return "\n".join(result)
    
    def _cmd_env(self, args: List[str]) -> str:
        """Show environment variables"""
        env_vars = {
            'USER': self.username,
            'HOME': f'/home/{self.username}',
            'SHELL': '/bin/bash',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games',
            'PWD': self.current_dir,
            'LANG': 'en_US.UTF-8',
            'TERM': 'xterm-256color',
            'SSH_CLIENT': '192.168.1.100 54321 22',
            'SSH_CONNECTION': '192.168.1.100 54321 10.10.100.50 22',
            'SSH_TTY': '/dev/pts/0',
            'HOSTNAME': self.hostname,
            'HISTSIZE': '1000',
            'HISTFILESIZE': '2000'
        }
        
        return "\n".join(f"{k}={v}" for k, v in env_vars.items())
    
    def _cmd_mount(self, args: List[str]) -> str:
        """Show mounted filesystems"""
        return """/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
/dev/sda2 on /home type ext4 (rw,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=409600k,mode=755)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)"""
    
    def _cmd_lsblk(self, args: List[str]) -> str:
        """List block devices"""
        return """NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0  120G  0 disk 
├─sda1   8:1    0   20G  0 part /
└─sda2   8:2    0  100G  0 part /home
sr0     11:0    1 1024M  0 rom"""
    
    def _cmd_systemctl(self, args: List[str]) -> str:
        """Control systemd services"""
        if 'status' in args:
            return """● ssh.service - OpenBSD Secure Shell server
   Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)
   Active: active (running) since Mon 2024-01-15 10:30:45 UTC; 2h 15min ago
     Docs: man:sshd(8)
           man:sshd_config(5)
  Process: 1234 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
 Main PID: 1235 (sshd)
    Tasks: 1 (limit: 4915)
   Memory: 2.8M
   CGroup: /system.slice/ssh.service
           └─1235 /usr/sbin/sshd -D"""
        elif 'list-units' in args:
            return """UNIT                               LOAD   ACTIVE SUB       DESCRIPTION
ssh.service                        loaded active running   OpenBSD Secure Shell server
systemd-networkd.service           loaded active running   Network Service
systemd-resolved.service           loaded active running   Network Name Resolution
cron.service                       loaded active running   Regular background program processing daemon
rsyslog.service                    loaded active running   System Logging Service"""
        else:
            return "systemctl: missing command"
    
    def _cmd_service(self, args: List[str]) -> str:
        """Control system services"""
        if '--status-all' in args:
            return """[ + ]  cron
[ + ]  networking
[ + ]  rsyslog
[ + ]  ssh
[ - ]  apache2
[ - ]  mysql"""
        else:
            return "service: missing arguments"
    
    def _cmd_crontab(self, args: List[str]) -> str:
        """Show/edit cron jobs"""
        if '-l' in args:
            return """# Edit this file to introduce tasks to be run by cron.
# 
# m h  dom mon dow   command
0 2 * * * /home/user/backup.sh
*/15 * * * * /usr/bin/system_check.sh
0 0 * * 0 /usr/bin/weekly_cleanup.sh"""
        else:
            return "crontab: usage error"
    
    def _cmd_w(self, args: List[str]) -> str:
        """Show who is logged on"""
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        return f""" {current_time} up 15 days,  3:45,  2 users,  load average: 0.15, 0.25, 0.30
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{self.username}     pts/0    192.168.1.100    14:23    0.00s  0.05s  0.01s w
admin    pts/1    10.10.50.100     13:45    1:30   0.10s  0.02s -bash"""
    
    def _cmd_who(self, args: List[str]) -> str:
        """Show who is logged on"""
        return f"""{self.username}     pts/0        2024-01-15 14:23 (192.168.1.100)
admin    pts/1        2024-01-15 13:45 (10.10.50.100)"""
    
    def _cmd_last(self, args: List[str]) -> str:
        """Show last logins"""
        return f"""{self.username}     pts/0        192.168.1.100    Mon Jan 15 14:23   still logged in
admin    pts/1        10.10.50.100     Mon Jan 15 13:45   still logged in
{self.username}     pts/0        192.168.1.50     Mon Jan 15 09:15 - 12:30  (03:15)
root     tty1                          Sun Jan 14 18:00 - 18:05  (00:05)
reboot   system boot  5.10.0-21-amd64  Sun Jan 14 17:58   still running

wtmp begins Sun Jan 14 17:58:42 2024"""
    
    def _cmd_date(self, args: List[str]) -> str:
        """Show current date and time"""
        return datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
    
    def _cmd_cal(self, args: List[str]) -> str:
        """Show calendar"""
        import calendar
        now = datetime.datetime.now()
        return calendar.month(now.year, now.month)
    
    def _cmd_help(self, args: List[str]) -> str:
        """Show help information"""
        return """GNU bash, version 5.1.4(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type `help' to see this list.
Type `help name' to find out more about the function `name'.
Use `info bash' to find out more about the shell in general.

 alias [-p] [name[=value] ... ]
 bg [job_spec ...]
 bind [-lpsvPSVX] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command] [keyseq:readline-function or readline-command]
 break [n]
 builtin [shell-builtin [arg ...]]
 caller [expr]
 case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac
 cd [-L|[-P [-e]] [-@]] [dir]
 command [-pVv] command [arg ...]
 compgen [-abcdefgjksuv] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [word]
 complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P prefix] [-S suffix] [name ...]
 compopt [-o|+o option] [-DE] [name ...]
 continue [n]
 declare [-aAfFgilnrtux] [-p] [name[=value] ...]
 dirs [-clpv] [+N] [-N]
 disown [-h] [-ar] [jobspec ... | pid ...]
 echo [-neE] [arg ...]
 enable [-a] [-dnps] [-f filename] [name ...]
 eval [arg ...]
 exec [-cl] [-a name] [command [arguments ...]] [redirection ...]
 exit [n]
 export [-fn] [name[=value] ...] or export -p
 false
 fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]
 fg [job_spec]
 for NAME [in WORDS ... ] ; do COMMANDS; done
 for (( exp1; exp2; exp3 )); do COMMANDS; done
 function name { COMMANDS ; } or name () { COMMANDS ; }
 getopts optstring name [arg]
 hash [-lr] [-p pathname] [-dt] [name ...]
 help [-dms] [pattern ...]
 history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]
 if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi
 jobs [-lnprs] [jobspec ...] or jobs -x command [args]
 kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]
 let arg [arg ...]
 local [option] name[=value] ...
 logout [n]
 mapfile [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]
 popd [-n] [+N | -N]
 printf [-v var] format [arguments]
 pushd [-n] [+N | -N | dir]
 pwd [-LP]
 read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]
 readarray [-d delim] [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]
 readonly [-aAf] [name[=value] ...] or readonly -p
 return [n]
 select NAME [in WORDS ... ;] do COMMANDS; done
 set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]
 shift [n]
 shopt [-pqsu] [-o] [optname ...]
 source filename [arguments]
 suspend [-f]
 test [expr]
 time [-p] pipeline
 times
 trap [-lp] [[arg] signal_spec ...]
 true
 type [-afptP] name [name ...]
 typeset [-aAfFgilnrtux] [-p] name[=value] ...
 ulimit [-SHabcdefiklmnpqrstuvxPT] [limit]
 umask [-p] [-S] [mode]
 unalias [-a] name [name ...]
 unset [-f] [-v] [-n] [name ...]
 until COMMANDS; do COMMANDS; done
 variables - Names and meanings of some shell variables
 wait [-fn] [id ...]
 while COMMANDS; do COMMANDS; done
 { COMMANDS ; }"""
    
    def _cmd_man(self, args: List[str]) -> str:
        """Show manual pages"""
        if not args:
            return "What manual page do you want?"
        
        cmd = args[0]
        return f"""NAME
       {cmd} - {cmd} command

SYNOPSIS
       {cmd} [OPTION]... [FILE]...

DESCRIPTION
       Manual page for {cmd} command.
       
       This is a simulated manual page in the honeypot environment.
       For detailed information, consult the actual system documentation.

OPTIONS
       -h, --help
              display this help and exit

       -v, --version
              output version information and exit

EXAMPLES
       {cmd} file.txt
              Process file.txt

SEE ALSO
       Full documentation at: <https://www.gnu.org/software/coreutils/>

AUTHOR
       Written by various authors.

COPYRIGHT
       Copyright © 2024 Free Software Foundation, Inc.
       License GPLv3+: GNU GPL version 3 or later.
       This is free software: you are free to change and redistribute it.
       There is NO WARRANTY, to the extent permitted by law."""
    
    def _generate_processes(self) -> List[Dict[str, Any]]:
        """Generate realistic process list"""
        processes = [
            {'pid': 1, 'user': 'root', 'cpu': 0.0, 'mem': 0.1, 'vsz': 225280, 'rss': 9472, 'tty': '?', 'stat': 'Ss', 'start': '17:58', 'time': '0:01', 'command': '/sbin/init'},
            {'pid': 2, 'user': 'root', 'cpu': 0.0, 'mem': 0.0, 'vsz': 0, 'rss': 0, 'tty': '?', 'stat': 'S', 'start': '17:58', 'time': '0:00', 'command': '[kthreadd]'},
            {'pid': 3, 'user': 'root', 'cpu': 0.0, 'mem': 0.0, 'vsz': 0, 'rss': 0, 'tty': '?', 'stat': 'I<', 'start': '17:58', 'time': '0:00', 'command': '[rcu_gp]'},
            {'pid': 4, 'user': 'root', 'cpu': 0.0, 'mem': 0.0, 'vsz': 0, 'rss': 0, 'tty': '?', 'stat': 'I<', 'start': '17:58', 'time': '0:00', 'command': '[rcu_par_gp]'},
            {'pid': 123, 'user': 'root', 'cpu': 0.1, 'mem': 0.2, 'vsz': 65536, 'rss': 3072, 'tty': '?', 'stat': 'Ss', 'start': '17:59', 'time': '0:00', 'command': '/usr/sbin/sshd -D'},
            {'pid': 456, 'user': 'root', 'cpu': 0.0, 'mem': 0.1, 'vsz': 28672, 'rss': 2048, 'tty': '?', 'stat': 'Ss', 'start': '18:00', 'time': '0:00', 'command': '/usr/sbin/cron -f'},
            {'pid': 789, 'user': 'syslog', 'cpu': 0.0, 'mem': 0.1, 'vsz': 224256, 'rss': 4096, 'tty': '?', 'stat': 'Ssl', 'start': '18:00', 'time': '0:00', 'command': '/usr/sbin/rsyslogd -n'},
            {'pid': 1001, 'user': 'www-data', 'cpu': 0.2, 'mem': 1.5, 'vsz': 524288, 'rss': 24576, 'tty': '?', 'stat': 'S', 'start': '18:01', 'time': '0:02', 'command': '/usr/sbin/apache2 -DFOREGROUND'},
            {'pid': 1234, 'user': self.username, 'cpu': 0.1, 'mem': 0.3, 'vsz': 21504, 'rss': 5120, 'tty': 'pts/0', 'stat': 'Ss', 'start': '14:23', 'time': '0:00', 'command': '-bash'},
            {'pid': 1235, 'user': 'root', 'cpu': 0.0, 'mem': 0.1, 'vsz': 65536, 'rss': 2048, 'tty': '?', 'stat': 'S', 'start': '14:23', 'time': '0:00', 'command': 'sshd: user [priv]'},
            {'pid': 1236, 'user': self.username, 'cpu': 0.0, 'mem': 0.1, 'vsz': 65536, 'rss': 1024, 'tty': '?', 'stat': 'S', 'start': '14:23', 'time': '0:00', 'command': 'sshd: user@pts/0'},
            {'pid': 2001, 'user': 'mysql', 'cpu': 1.2, 'mem': 5.8, 'vsz': 1048576, 'rss': 98304, 'tty': '?', 'stat': 'Ssl', 'start': '18:00', 'time': '0:15', 'command': '/usr/sbin/mysqld'},
            {'pid': 2002, 'user': 'redis', 'cpu': 0.3, 'mem': 0.8, 'vsz': 65536, 'rss': 12288, 'tty': '?', 'stat': 'Ssl', 'start': '18:00', 'time': '0:03', 'command': '/usr/bin/redis-server 127.0.0.1:6379'},
            {'pid': 2003, 'user': 'postgres', 'cpu': 0.5, 'mem': 2.1, 'vsz': 262144, 'rss': 32768, 'tty': '?', 'stat': 'S', 'start': '18:00', 'time': '0:05', 'command': 'postgres: main'},
            {'pid': 3001, 'user': 'root', 'cpu': 0.0, 'mem': 0.1, 'vsz': 16384, 'rss': 1024, 'tty': '?', 'stat': 'S', 'start': '18:30', 'time': '0:00', 'command': '/usr/bin/system_monitor.sh'},
            {'pid': 3002, 'user': 'backup', 'cpu': 0.1, 'mem': 0.2, 'vsz': 32768, 'rss': 2048, 'tty': '?', 'stat': 'S', 'start': '02:00', 'time': '0:01', 'command': '/usr/bin/backup_daemon'},
            {'pid': 4001, 'user': 'nagios', 'cpu': 0.2, 'mem': 0.5, 'vsz': 49152, 'rss': 8192, 'tty': '?', 'stat': 'S', 'start': '18:00', 'time': '0:02', 'command': '/usr/sbin/nagios -d /etc/nagios/nagios.cfg'},
            {'pid': 4002, 'user': 'zabbix', 'cpu': 0.1, 'mem': 0.3, 'vsz': 32768, 'rss': 4096, 'tty': '?', 'stat': 'S', 'start': '18:00', 'time': '0:01', 'command': '/usr/sbin/zabbix_agentd -c /etc/zabbix/zabbix_agentd.conf'},
            {'pid': 5001, 'user': 'elastic', 'cpu': 2.1, 'mem': 8.5, 'vsz': 2097152, 'rss': 131072, 'tty': '?', 'stat': 'Sl', 'start': '18:00', 'time': '0:25', 'command': '/usr/share/elasticsearch/bin/elasticsearch'},
            {'pid': 5002, 'user': 'kibana', 'cpu': 0.8, 'mem': 3.2, 'vsz': 1048576, 'rss': 49152, 'tty': '?', 'stat': 'Sl', 'start': '18:01', 'time': '0:08', 'command': '/usr/share/kibana/bin/kibana'}
        ]
        
        # Add some random processes
        for i in range(20):
            pid = random.randint(5000, 9999)
            processes.append({
                'pid': pid,
                'user': random.choice(['root', self.username, 'www-data', 'daemon']),
                'cpu': round(random.uniform(0.0, 5.0), 1),
                'mem': round(random.uniform(0.1, 2.0), 1),
                'vsz': random.randint(16384, 524288),
                'rss': random.randint(1024, 32768),
                'tty': random.choice(['?', 'pts/0', 'pts/1', 'tty1']),
                'stat': random.choice(['S', 'Ss', 'R', 'I', 'Z']),
                'start': f"{random.randint(10, 23):02d}:{random.randint(0, 59):02d}",
                'time': f"0:{random.randint(0, 59):02d}",
                'command': random.choice([
                    '[kworker/0:1]', '[migration/0]', '[ksoftirqd/0]',
                    '/usr/bin/python3 /usr/local/bin/monitor.py',
                    '/bin/bash /usr/local/bin/cleanup.sh',
                    'sleep 3600'
                ])
            })
        
        return processes
    
    def _generate_network_connections(self) -> List[Dict[str, str]]:
        """Generate realistic network connections"""
        connections = [
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '0.0.0.0:22', 'foreign': '0.0.0.0:*', 'state': 'LISTEN'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '127.0.0.1:3306', 'foreign': '0.0.0.0:*', 'state': 'LISTEN'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '0.0.0.0:80', 'foreign': '0.0.0.0:*', 'state': 'LISTEN'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '0.0.0.0:443', 'foreign': '0.0.0.0:*', 'state': 'LISTEN'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '127.0.0.1:6379', 'foreign': '0.0.0.0:*', 'state': 'LISTEN'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '127.0.0.1:5432', 'foreign': '0.0.0.0:*', 'state': 'LISTEN'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '10.10.100.50:22', 'foreign': '192.168.1.100:54321', 'state': 'ESTABLISHED'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '10.10.100.50:443', 'foreign': '203.0.113.45:12345', 'state': 'ESTABLISHED'},
            {'proto': 'tcp', 'recv_q': 0, 'send_q': 0, 'local': '10.10.100.50:80', 'foreign': '198.51.100.23:56789', 'state': 'TIME_WAIT'},
            {'proto': 'udp', 'recv_q': 0, 'send_q': 0, 'local': '0.0.0.0:68', 'foreign': '0.0.0.0:*', 'state': ''},
            {'proto': 'udp', 'recv_q': 0, 'send_q': 0, 'local': '127.0.0.1:53', 'foreign': '0.0.0.0:*', 'state': ''},
            {'proto': 'udp', 'recv_q': 0, 'send_q': 0, 'local': '0.0.0.0:161', 'foreign': '0.0.0.0:*', 'state': ''},
            {'proto': 'tcp6', 'recv_q': 0, 'send_q': 0, 'local': ':::22', 'foreign': ':::*', 'state': 'LISTEN'},
            {'proto': 'tcp6', 'recv_q': 0, 'send_q': 0, 'local': ':::80', 'foreign': ':::*', 'state': 'LISTEN'},
            {'proto': 'tcp6', 'recv_q': 0, 'send_q': 0, 'local': ':::443', 'foreign': ':::*', 'state': 'LISTEN'}
        ]
        
        return connections
    
    def _generate_file_system(self) -> Dict[str, Any]:
        """Generate realistic file system structure"""
        return {
            '/': {'type': 'directory', 'size': 4096, 'permissions': 'drwxr-xr-x'},
            '/home': {'type': 'directory', 'size': 4096, 'permissions': 'drwxr-xr-x'},
            '/etc': {'type': 'directory', 'size': 4096, 'permissions': 'drwxr-xr-x'},
            '/var': {'type': 'directory', 'size': 4096, 'permissions': 'drwxr-xr-x'},
            '/usr': {'type': 'directory', 'size': 4096, 'permissions': 'drwxr-xr-x'},
            '/tmp': {'type': 'directory', 'size': 4096, 'permissions': 'drwxrwxrwt'}
        }