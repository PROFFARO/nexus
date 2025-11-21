#!/usr/bin/env python3
"""
SMB LLM Integration - AI-powered file system and response generation
Provides dynamic file system generation, file content creation, and adaptive command responses
"""

import json
import logging
import datetime
import hashlib
import random
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.chat_history import InMemoryChatMessageHistory

logger = logging.getLogger('smb_llm')


class LLMFileSystemGenerator:
    """Generate realistic SMB file system using LLM"""
    
    def __init__(self, llm_chain, config: Dict[str, Any]):
        self.llm_chain = llm_chain
        self.config = config
        self.cache_enabled = config['filesystem'].getboolean('cache_filesystem', True)
        self.cache = {} if self.cache_enabled else None
    
    def generate_shares(self, username: str, access_level: str = 'user') -> List[Dict[str, Any]]:
        """Generate list of SMB shares based on user access level"""
        cache_key = f"shares_{username}_{access_level}"
        
        if self.cache_enabled and cache_key in self.cache:
            return self.cache[cache_key]
        
        prompt = f"""Generate a realistic list of SMB shares for user '{username}' with access level '{access_level}'.

Access levels:
- guest: Public shares only (Public$, Downloads$, Documentation$)
- user: Standard user shares (GameProjects$, Art$, Scripts$, Documentation$, Tools$)
- developer: Developer shares (GameProjects$, Art$, Scripts$, Builds$, DevTools$, SDKs$)
- admin: All shares including administrative (IT$, Security$, Backups$, HR$, Finance$, C$, ADMIN$)

Return ONLY a JSON array of share objects with this exact format:
[
  {{"name": "ShareName$", "type": "disk", "comment": "Brief description", "permissions": "read" or "readwrite"}},
  ...
]

Generate 5-15 shares appropriate for the access level. Be realistic and consistent with a game development company."""

        try:
            response = self.llm_chain.invoke({"input": prompt})
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # Extract JSON from response
            shares = self._extract_json_from_response(response_text)
            
            if not isinstance(shares, list):
                shares = self._get_default_shares(access_level)
            
            if self.cache_enabled:
                self.cache[cache_key] = shares
            
            return shares
            
        except Exception as e:
            logger.error(f"Failed to generate shares with LLM: {e}")
            return self._get_default_shares(access_level)
    
    def generate_directory_listing(self, share: str, path: str, username: str,
                                   context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate directory listing for a given path"""
        cache_key = f"dir_{share}_{path}_{username}"
        
        if self.cache_enabled and cache_key in self.cache:
            return self.cache[cache_key]
        
        prompt = f"""Generate a realistic directory listing for SMB share '{share}' at path '{path}' for user '{username}'.

Context:
- Share: {share}
- Current path: {path}
- User: {username}
- Company: NexusGames Studio (game development)

Generate 5-20 files and directories appropriate for this location. Include:
- Subdirectories (if at root or shallow depth)
- Files with realistic extensions (.cs, .cpp, .unreal, .unity, .blend, .fbx, .png, .wav, .json, .xml, .md, etc.)
- Realistic file sizes (source: 1-100KB, assets: 100KB-10MB, builds: 10MB-500MB)
- Recent timestamps for active projects, older for archives
- Hidden files if appropriate (.git, .svn, .gitignore, etc.)

Return ONLY a JSON array of file/directory objects with this exact format:
[
  {{
    "name": "filename.ext",
    "type": "file" or "directory",
    "size": 12345,
    "modified": "2024-11-20T10:30:00Z",
    "attributes": "readonly" or "hidden" or "archive" or "normal"
  }},
  ...
]

Be realistic and contextually appropriate for a game development company."""

        try:
            response = self.llm_chain.invoke({"input": prompt})
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # Extract JSON from response
            listing = self._extract_json_from_response(response_text)
            
            if not isinstance(listing, list):
                listing = self._get_default_directory_listing(share, path)
            
            if self.cache_enabled:
                self.cache[cache_key] = listing
            
            return listing
            
        except Exception as e:
            logger.error(f"Failed to generate directory listing with LLM: {e}")
            return self._get_default_directory_listing(share, path)
    
    def generate_file_metadata(self, filename: str, share: str, path: str,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata for a specific file"""
        # Determine file type and generate appropriate metadata
        ext = Path(filename).suffix.lower()
        
        # Estimate file size based on extension
        size_ranges = {
            '.txt': (100, 10000),
            '.md': (500, 50000),
            '.json': (100, 100000),
            '.xml': (200, 50000),
            '.ini': (100, 5000),
            '.cs': (500, 50000),
            '.cpp': (1000, 100000),
            '.h': (200, 20000),
            '.py': (500, 50000),
            '.js': (500, 50000),
            '.png': (10000, 5000000),
            '.jpg': (50000, 2000000),
            '.wav': (100000, 10000000),
            '.mp3': (500000, 10000000),
            '.fbx': (100000, 50000000),
            '.blend': (500000, 100000000),
            '.unreal': (1000000, 500000000),
            '.unity': (500000, 100000000),
            '.exe': (1000000, 100000000),
            '.dll': (50000, 10000000),
        }
        
        size_range = size_ranges.get(ext, (1000, 100000))
        size = random.randint(*size_range)
        
        # Generate timestamp (recent for active files, older for archives)
        days_ago = random.randint(1, 365)
        modified = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
        
        return {
            'name': filename,
            'type': 'file',
            'size': size,
            'modified': modified.isoformat(),
            'attributes': 'archive',
            'share': share,
            'path': path
        }
    
    def _extract_json_from_response(self, response: str) -> Any:
        """Extract JSON from LLM response"""
        # Try to find JSON in the response
        import re
        
        # Look for JSON array or object
        json_match = re.search(r'(\[.*\]|\{.*\})', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try parsing the entire response
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return None
    
    def _get_default_shares(self, access_level: str) -> List[Dict[str, Any]]:
        """Get default shares when LLM fails"""
        all_shares = [
            {"name": "Public$", "type": "disk", "comment": "Public files", "permissions": "read"},
            {"name": "Downloads$", "type": "disk", "comment": "Download area", "permissions": "read"},
            {"name": "Documentation$", "type": "disk", "comment": "Documentation", "permissions": "read"},
            {"name": "GameProjects$", "type": "disk", "comment": "Game projects", "permissions": "readwrite"},
            {"name": "Art$", "type": "disk", "comment": "Art assets", "permissions": "readwrite"},
            {"name": "Scripts$", "type": "disk", "comment": "Game scripts", "permissions": "readwrite"},
            {"name": "Builds$", "type": "disk", "comment": "Game builds", "permissions": "read"},
            {"name": "DevTools$", "type": "disk", "comment": "Development tools", "permissions": "read"},
            {"name": "IT$", "type": "disk", "comment": "IT resources", "permissions": "readwrite"},
            {"name": "Security$", "type": "disk", "comment": "Security files", "permissions": "readwrite"},
            {"name": "Backups$", "type": "disk", "comment": "Backup files", "permissions": "read"},
            {"name": "C$", "type": "disk", "comment": "Default share", "permissions": "readwrite"},
            {"name": "ADMIN$", "type": "disk", "comment": "Remote Admin", "permissions": "readwrite"},
            {"name": "IPC$", "type": "ipc", "comment": "Remote IPC", "permissions": "readwrite"},
        ]
        
        if access_level == 'guest':
            return all_shares[:3]
        elif access_level == 'user':
            return all_shares[:8]
        elif access_level == 'developer':
            return all_shares[:10]
        else:  # admin
            return all_shares
    
    def _get_default_directory_listing(self, share: str, path: str) -> List[Dict[str, Any]]:
        """Get default directory listing when LLM fails"""
        # Generate some basic files/directories based on share name
        if 'GameProjects' in share:
            return [
                {"name": "CyberRealm2025", "type": "directory", "size": 0, "modified": "2024-11-15T10:00:00Z", "attributes": "normal"},
                {"name": "FantasyQuest", "type": "directory", "size": 0, "modified": "2024-11-10T14:30:00Z", "attributes": "normal"},
                {"name": "SpaceOdyssey", "type": "directory", "size": 0, "modified": "2024-11-05T09:15:00Z", "attributes": "normal"},
                {"name": "README.md", "type": "file", "size": 2048, "modified": "2024-11-01T11:00:00Z", "attributes": "archive"},
            ]
        elif 'Art' in share:
            return [
                {"name": "Concepts", "type": "directory", "size": 0, "modified": "2024-11-12T10:00:00Z", "attributes": "normal"},
                {"name": "Textures", "type": "directory", "size": 0, "modified": "2024-11-14T14:30:00Z", "attributes": "normal"},
                {"name": "Models", "type": "directory", "size": 0, "modified": "2024-11-16T09:15:00Z", "attributes": "normal"},
                {"name": "Animations", "type": "directory", "size": 0, "modified": "2024-11-10T11:00:00Z", "attributes": "normal"},
            ]
        else:
            return [
                {"name": "Documents", "type": "directory", "size": 0, "modified": "2024-11-01T10:00:00Z", "attributes": "normal"},
                {"name": "README.txt", "type": "file", "size": 1024, "modified": "2024-10-15T14:30:00Z", "attributes": "archive"},
            ]


class LLMFileContentGenerator:
    """Generate file content on-demand using LLM"""
    
    def __init__(self, llm_chain, config: Dict[str, Any]):
        self.llm_chain = llm_chain
        self.config = config
        self.max_file_size = config['filesystem'].getint('max_file_size', 10485760)
        self.timeout = config['filesystem'].getint('file_gen_timeout', 30)
    
    def generate_content(self, filename: str, file_type: str, share: str,
                        path: str, context: Dict[str, Any]) -> bytes:
        """Generate file content based on filename and context"""
        ext = Path(filename).suffix.lower()
        
        # For binary files, generate fake binary content
        if ext in ['.exe', '.dll', '.so', '.dylib', '.bin']:
            return self._generate_binary_content(filename, ext)
        
        # For image files, generate fake image headers
        if ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
            return self._generate_image_content(filename, ext)
        
        # For audio files, generate fake audio headers
        if ext in ['.wav', '.mp3', '.ogg', '.flac']:
            return self._generate_audio_content(filename, ext)
        
        # For text-based files, use LLM to generate content
        if ext in ['.txt', '.md', '.json', '.xml', '.ini', '.cfg', '.conf',
                   '.cs', '.cpp', '.h', '.py', '.js', '.html', '.css', '.sql']:
            return self._generate_text_content(filename, ext, share, path, context)
        
        # Default: generate generic text content
        return self._generate_generic_content(filename)
    
    def _generate_text_content(self, filename: str, ext: str, share: str,
                              path: str, context: Dict[str, Any]) -> bytes:
        """Generate text file content using LLM"""
        prompt = f"""Generate realistic content for a file in a game development company's SMB share.

File details:
- Filename: {filename}
- Extension: {ext}
- Share: {share}
- Path: {path}
- Company: NexusGames Studio

Generate appropriate content for this file type:
- For source code (.cs, .cpp, .py, .js): Generate realistic but non-functional game code snippets
- For config files (.json, .xml, .ini): Include believable but fake configuration with honeytokens
- For documentation (.md, .txt): Create realistic game design docs, meeting notes, or technical documentation
- For data files: Generate appropriate structured data

Include honeytokens (fake credentials, API keys, internal URLs) for tracking if appropriate.

Keep content under 2000 characters. Return ONLY the file content, no explanations."""

        try:
            response = self.llm_chain.invoke({"input": prompt})
            content = response.content if hasattr(response, 'content') else str(response)
            
            # Ensure content is not too large
            if len(content) > self.max_file_size:
                content = content[:self.max_file_size]
            
            return content.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to generate file content with LLM: {e}")
            return self._generate_generic_content(filename)
    
    def _generate_binary_content(self, filename: str, ext: str) -> bytes:
        """Generate fake binary file content"""
        if ext == '.exe':
            # Fake Windows PE header
            content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            content += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
            content += b"PE\x00\x00L\x01\x03\x00"
            content += f"NexusGames Studio - {filename}".encode()
            content += b"\x00" * 1000
        elif ext == '.dll':
            # Fake DLL header
            content = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
            content += f"NexusGames DLL - {filename}".encode()
            content += b"\x00" * 500
        else:
            content = f"Binary file: {filename}\n".encode()
            content += b"\x00" * 1000
        
        return content
    
    def _generate_image_content(self, filename: str, ext: str) -> bytes:
        """Generate fake image file headers"""
        if ext == '.png':
            # PNG header
            content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00"
            content += f"NexusGames Image - {filename}".encode()
        elif ext in ['.jpg', '.jpeg']:
            # JPEG header
            content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            content += f"NexusGames JPEG - {filename}".encode()
        else:
            content = f"Image file: {filename}\n".encode()
        
        return content + b"\x00" * 1000
    
    def _generate_audio_content(self, filename: str, ext: str) -> bytes:
        """Generate fake audio file headers"""
        if ext == '.wav':
            # WAV header
            content = b"RIFF\x24\x08\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x02\x00"
            content += f"NexusGames Audio - {filename}".encode()
        elif ext == '.mp3':
            # MP3 header
            content = b"\xff\xfb\x90\x00ID3\x03\x00\x00\x00\x00\x00"
            content += f"NexusGames MP3 - {filename}".encode()
        else:
            content = f"Audio file: {filename}\n".encode()
        
        return content + b"\x00" * 5000
    
    def _generate_generic_content(self, filename: str) -> bytes:
        """Generate generic file content"""
        content = f"""NexusGames Studio File: {filename}
Created: {datetime.datetime.now(datetime.timezone.utc).isoformat()}
This is a honeypot simulation file.

File contains sensitive game development information.
Access restricted to authorized personnel only.

Internal API Key: ng_api_key_2024_{hashlib.md5(filename.encode()).hexdigest()[:16]}
Database: nexusgames-prod.internal:3306
Admin Portal: https://admin.nexusgames.internal
"""
        return content.encode('utf-8')


class LLMCommandResponseGenerator:
    """Generate adaptive SMB command responses using LLM"""
    
    def __init__(self, llm_with_history, config: Dict[str, Any]):
        self.llm_with_history = llm_with_history
        self.config = config
    
    def generate_response(self, command: str, command_type: str, context: Dict[str, Any],
                         session_id: str) -> str:
        """Generate adaptive response to SMB command"""
        prompt = f"""You are responding to an SMB command from an attacker.

Command type: {command_type}
Command details: {command}
User: {context.get('username', 'unknown')}
Share: {context.get('share', 'unknown')}
Path: {context.get('path', '/')}

Context:
- Attacker sophistication: {context.get('sophistication', 'unknown')}
- Attack types detected: {context.get('attack_types', [])}
- Session commands: {context.get('command_count', 0)}

Generate an appropriate SMB protocol response. Be realistic and maintain the illusion of a legitimate server.
Adapt your response based on the attacker's sophistication level.

Return ONLY the response message, no explanations."""

        try:
            response = self.llm_with_history.invoke(
                {"input": prompt},
                config={"configurable": {"session_id": session_id}}
            )
            return response.content if hasattr(response, 'content') else str(response)
            
        except Exception as e:
            logger.error(f"Failed to generate command response with LLM: {e}")
            return "Operation completed successfully."
