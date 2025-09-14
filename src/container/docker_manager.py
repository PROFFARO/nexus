"""
Docker Manager - Container orchestration for honeypot services
"""

import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any


class DockerManager:
    """
    Manages Docker containers for honeypot service isolation
    Provides containerization and orchestration capabilities
    """
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.containers = {}
        self.networks = {}
        self.volumes = {}
        self.initialized = False
        
        # Container configurations
        self.container_configs = {
            "ssh": {
                "image": "nexus/ssh-honeypot:latest",
                "ports": {"22/tcp": 22},
                "environment": {
                    "SERVICE_TYPE": "ssh",
                    "LOG_LEVEL": "INFO"
                },
                "volumes": {
                    "ssh_logs": "/var/log/honeypot",
                    "ssh_data": "/var/lib/honeypot"
                }
            },
            "ftp": {
                "image": "nexus/ftp-honeypot:latest", 
                "ports": {"21/tcp": 21},
                "environment": {
                    "SERVICE_TYPE": "ftp",
                    "LOG_LEVEL": "INFO"
                },
                "volumes": {
                    "ftp_logs": "/var/log/honeypot",
                    "ftp_data": "/var/lib/honeypot"
                }
            },
            "mysql": {
                "image": "nexus/mysql-honeypot:latest",
                "ports": {"3306/tcp": 3306},
                "environment": {
                    "SERVICE_TYPE": "mysql",
                    "LOG_LEVEL": "INFO"
                },
                "volumes": {
                    "mysql_logs": "/var/log/honeypot",
                    "mysql_data": "/var/lib/honeypot"
                }
            },
            "smb": {
                "image": "nexus/smb-honeypot:latest",
                "ports": {"445/tcp": 445},
                "environment": {
                    "SERVICE_TYPE": "smb",
                    "LOG_LEVEL": "INFO"
                },
                "volumes": {
                    "smb_logs": "/var/log/honeypot",
                    "smb_data": "/var/lib/honeypot"
                }
            },
            "rdp": {
                "image": "nexus/rdp-honeypot:latest",
                "ports": {"3389/tcp": 3389},
                "environment": {
                    "SERVICE_TYPE": "rdp",
                    "LOG_LEVEL": "INFO"
                },
                "volumes": {
                    "rdp_logs": "/var/log/honeypot",
                    "rdp_data": "/var/lib/honeypot"
                }
            }
        }
    
    def is_enabled(self) -> bool:
        """Check if Docker manager is enabled"""
        return self.enabled
    
    def initialize(self):
        """Initialize Docker manager"""
        if not self.enabled or self.initialized:
            return
        
        try:
            # Check Docker availability
            if not self._check_docker_availability():
                print(f"[{datetime.now()}] Docker not available, disabling container support")
                self.enabled = False
                return
            
            # Create honeypot network
            self._create_honeypot_network()
            
            # Create volumes
            self._create_volumes()
            
            # Build honeypot images if needed
            self._ensure_honeypot_images()
            
            self.initialized = True
            print(f"[{datetime.now()}] Docker Manager initialized")
            
        except Exception as e:
            print(f"[{datetime.now()}] Docker Manager initialization failed: {e}")
            self.enabled = False
    
    def _check_docker_availability(self) -> bool:
        """Check if Docker is available and running"""
        try:
            result = subprocess.run(
                ["docker", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _create_honeypot_network(self):
        """Create isolated network for honeypot containers"""
        network_name = "nexus-honeypot-network"
        
        try:
            # Check if network exists
            result = subprocess.run(
                ["docker", "network", "ls", "--filter", f"name={network_name}", "--format", "{{.Name}}"],
                capture_output=True,
                text=True
            )
            
            if network_name not in result.stdout:
                # Create network
                subprocess.run([
                    "docker", "network", "create",
                    "--driver", "bridge",
                    "--subnet", "172.20.0.0/16",
                    "--ip-range", "172.20.1.0/24",
                    network_name
                ], check=True)
                
                print(f"[{datetime.now()}] Created honeypot network: {network_name}")
            
            self.networks["honeypot"] = network_name
            
        except subprocess.CalledProcessError as e:
            print(f"[{datetime.now()}] Failed to create network: {e}")
    
    def _create_volumes(self):
        """Create Docker volumes for persistent storage"""
        volume_names = [
            "nexus-logs", "nexus-data", "nexus-config",
            "ssh-logs", "ftp-logs", "mysql-logs", "smb-logs", "rdp-logs"
        ]
        
        for volume_name in volume_names:
            try:
                # Check if volume exists
                result = subprocess.run(
                    ["docker", "volume", "ls", "--filter", f"name={volume_name}", "--format", "{{.Name}}"],
                    capture_output=True,
                    text=True
                )
                
                if volume_name not in result.stdout:
                    # Create volume
                    subprocess.run([
                        "docker", "volume", "create", volume_name
                    ], check=True)
                
                self.volumes[volume_name] = volume_name
                
            except subprocess.CalledProcessError as e:
                print(f"[{datetime.now()}] Failed to create volume {volume_name}: {e}")
    
    def _ensure_honeypot_images(self):
        """Ensure honeypot Docker images are available"""
        # For now, we'll create simple Dockerfiles
        # In production, these would be pre-built images
        
        for service, config in self.container_configs.items():
            image_name = config["image"]
            
            try:
                # Check if image exists
                result = subprocess.run(
                    ["docker", "images", "--filter", f"reference={image_name}", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True,
                    text=True
                )
                
                if image_name not in result.stdout:
                    # Build image
                    self._build_honeypot_image(service, image_name)
                
            except subprocess.CalledProcessError as e:
                print(f"[{datetime.now()}] Failed to check image {image_name}: {e}")
    
    def _build_honeypot_image(self, service: str, image_name: str):
        """Build honeypot Docker image"""
        dockerfile_content = self._generate_dockerfile(service)
        
        # Create temporary directory for build context
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as temp_dir:
            dockerfile_path = os.path.join(temp_dir, "Dockerfile")
            
            with open(dockerfile_path, "w") as f:
                f.write(dockerfile_content)
            
            try:
                subprocess.run([
                    "docker", "build",
                    "-t", image_name,
                    temp_dir
                ], check=True, capture_output=True)
                
                print(f"[{datetime.now()}] Built honeypot image: {image_name}")
                
            except subprocess.CalledProcessError as e:
                print(f"[{datetime.now()}] Failed to build image {image_name}: {e}")
    
    def _generate_dockerfile(self, service: str) -> str:
        """Generate Dockerfile for honeypot service"""
        base_dockerfile = f"""
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    net-tools \\
    procps \\
    && rm -rf /var/lib/apt/lists/*

# Create honeypot user
RUN useradd -m -s /bin/bash honeypot

# Create directories
RUN mkdir -p /var/log/honeypot /var/lib/honeypot /opt/honeypot
RUN chown -R honeypot:honeypot /var/log/honeypot /var/lib/honeypot /opt/honeypot

# Copy honeypot code
COPY . /opt/honeypot/

# Install Python dependencies
WORKDIR /opt/honeypot
RUN pip install --no-cache-dir -r requirements.txt || echo "No requirements.txt found"

# Set environment variables
ENV SERVICE_TYPE={service}
ENV PYTHONPATH=/opt/honeypot

# Switch to honeypot user
USER honeypot

# Expose service port
"""
        
        # Add service-specific configurations
        if service == "ssh":
            base_dockerfile += """
EXPOSE 22
CMD ["python", "-m", "service_emulator.ssh_emulator"]
"""
        elif service == "ftp":
            base_dockerfile += """
EXPOSE 21
CMD ["python", "-m", "service_emulator.ftp_emulator"]
"""
        elif service == "mysql":
            base_dockerfile += """
EXPOSE 3306
CMD ["python", "-m", "service_emulator.mysql_emulator"]
"""
        elif service == "smb":
            base_dockerfile += """
EXPOSE 445
CMD ["python", "-m", "service_emulator.smb_emulator"]
"""
        elif service == "rdp":
            base_dockerfile += """
EXPOSE 3389
CMD ["python", "-m", "service_emulator.rdp_emulator"]
"""
        
        return base_dockerfile
    
    def setup_containers(self):
        """Setup all honeypot containers"""
        if not self.enabled or not self.initialized:
            return
        
        for service, config in self.container_configs.items():
            try:
                container_id = self._create_container(service, config)
                if container_id:
                    self.containers[service] = container_id
                    print(f"[{datetime.now()}] Created container for {service}: {container_id[:12]}")
            
            except Exception as e:
                print(f"[{datetime.now()}] Failed to create container for {service}: {e}")
    
    def _create_container(self, service: str, config: Dict[str, Any]) -> Optional[str]:
        """Create individual container"""
        container_name = f"nexus-{service}-honeypot"
        
        # Build docker run command
        cmd = [
            "docker", "run", "-d",
            "--name", container_name,
            "--network", self.networks.get("honeypot", "bridge"),
            "--restart", "unless-stopped"
        ]
        
        # Add port mappings
        for container_port, host_port in config.get("ports", {}).items():
            cmd.extend(["-p", f"{host_port}:{container_port}"])
        
        # Add environment variables
        for env_key, env_value in config.get("environment", {}).items():
            cmd.extend(["-e", f"{env_key}={env_value}"])
        
        # Add volume mounts
        for volume_name, mount_point in config.get("volumes", {}).items():
            if volume_name in self.volumes:
                cmd.extend(["-v", f"{self.volumes[volume_name]}:{mount_point}"])
        
        # Add image name
        cmd.append(config["image"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        
        except subprocess.CalledProcessError as e:
            print(f"[{datetime.now()}] Container creation failed: {e.stderr}")
            return None
    
    def start_container(self, service: str) -> bool:
        """Start specific container"""
        if service not in self.containers:
            return False
        
        container_id = self.containers[service]
        
        try:
            subprocess.run([
                "docker", "start", container_id
            ], check=True, capture_output=True)
            
            print(f"[{datetime.now()}] Started container for {service}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[{datetime.now()}] Failed to start container for {service}: {e}")
            return False
    
    def stop_container(self, service: str) -> bool:
        """Stop specific container"""
        if service not in self.containers:
            return False
        
        container_id = self.containers[service]
        
        try:
            subprocess.run([
                "docker", "stop", container_id
            ], check=True, capture_output=True)
            
            print(f"[{datetime.now()}] Stopped container for {service}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[{datetime.now()}] Failed to stop container for {service}: {e}")
            return False
    
    def get_container_logs(self, service: str, lines: int = 100) -> str:
        """Get container logs"""
        if service not in self.containers:
            return ""
        
        container_id = self.containers[service]
        
        try:
            result = subprocess.run([
                "docker", "logs", "--tail", str(lines), container_id
            ], capture_output=True, text=True, check=True)
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            print(f"[{datetime.now()}] Failed to get logs for {service}: {e}")
            return ""
    
    def get_container_stats(self, service: str) -> Dict[str, Any]:
        """Get container resource statistics"""
        if service not in self.containers:
            return {}
        
        container_id = self.containers[service]
        
        try:
            result = subprocess.run([
                "docker", "stats", "--no-stream", "--format", 
                "{{json .}}", container_id
            ], capture_output=True, text=True, check=True)
            
            return json.loads(result.stdout)
            
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"[{datetime.now()}] Failed to get stats for {service}: {e}")
            return {}
    
    def cleanup_containers(self):
        """Clean up all containers"""
        if not self.enabled:
            return
        
        for service, container_id in self.containers.items():
            try:
                # Stop container
                subprocess.run([
                    "docker", "stop", container_id
                ], capture_output=True, timeout=30)
                
                # Remove container
                subprocess.run([
                    "docker", "rm", container_id
                ], capture_output=True)
                
                print(f"[{datetime.now()}] Cleaned up container for {service}")
                
            except Exception as e:
                print(f"[{datetime.now()}] Failed to cleanup container for {service}: {e}")
        
        self.containers.clear()
    
    def get_status(self) -> Dict[str, Any]:
        """Get Docker manager status"""
        if not self.enabled:
            return {"enabled": False}
        
        container_status = {}
        for service, container_id in self.containers.items():
            try:
                result = subprocess.run([
                    "docker", "inspect", "--format", "{{.State.Status}}", container_id
                ], capture_output=True, text=True, check=True)
                
                container_status[service] = result.stdout.strip()
                
            except subprocess.CalledProcessError:
                container_status[service] = "unknown"
        
        return {
            "enabled": self.enabled,
            "initialized": self.initialized,
            "containers": container_status,
            "networks": list(self.networks.keys()),
            "volumes": list(self.volumes.keys())
        }
    
    def execute_in_container(self, service: str, command: List[str]) -> str:
        """Execute command in container"""
        if service not in self.containers:
            return ""
        
        container_id = self.containers[service]
        
        try:
            cmd = ["docker", "exec", container_id] + command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            print(f"[{datetime.now()}] Failed to execute command in {service}: {e}")
            return ""