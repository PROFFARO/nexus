#!/usr/bin/env python3
"""
Interactive text editors for SSH honeypot
Provides fully functional vim and nano editors
"""

import asyncio
import asyncssh
from typing import Optional, List
import datetime


class InteractiveVim:
    """Fully functional vim editor simulation"""
    
    def __init__(self, process: asyncssh.SSHServerProcess, filename: str, virtual_fs, current_dir: str):
        self.process = process
        self.filename = filename
        self.virtual_fs = virtual_fs
        self.current_dir = current_dir
        
        # Load file content
        content = virtual_fs.read_file(filename, current_dir)
        if content is None:
            self.lines = [""]
            self.is_new = True
            self.modified = False
        else:
            self.lines = content.split('\n')
            self.is_new = False
            self.modified = False
        
        self.cursor_line = 0
        self.cursor_col = 0
        self.mode = "NORMAL"  # NORMAL, INSERT, VISUAL, COMMAND
        self.command_buffer = ""
        self.message = ""
        self.quit_requested = False
    
    async def run(self):
        """Main editor loop"""
        # Enable raw mode
        self.process.channel.set_line_mode(False)
        self.process.channel.set_echo(False)
        
        # Initial draw
        await self.draw_screen()
        
        try:
            buffer = ""
            while not self.quit_requested:
                # Read one character at a time
                char = await self.process.stdin.read(1)
                if not char:
                    break
                
                buffer += char
                
                # Handle escape sequences
                if buffer == '\x1b':
                    # Wait for more characters
                    await asyncio.sleep(0.01)
                    continue
                elif buffer.startswith('\x1b['):
                    # Arrow keys and other escape sequences
                    if len(buffer) >= 3:
                        await self.handle_escape_sequence(buffer)
                        buffer = ""
                    continue
                elif buffer.startswith('\x1b'):
                    # ESC key
                    if self.mode == "INSERT":
                        self.mode = "NORMAL"
                        self.message = ""
                        await self.draw_screen()
                    buffer = ""
                    continue
                
                # Handle regular characters
                await self.handle_input(buffer)
                buffer = ""
        
        except Exception as e:
            pass
        finally:
            # Restore terminal mode
            self.process.channel.set_line_mode(True)
            self.process.channel.set_echo(True)
            await self.clear_screen()
    
    async def handle_input(self, char: str):
        """Handle keyboard input based on current mode"""
        if self.mode == "NORMAL":
            await self.handle_normal_mode(char)
        elif self.mode == "INSERT":
            await self.handle_insert_mode(char)
        elif self.mode == "COMMAND":
            await self.handle_command_mode(char)
    
    async def handle_normal_mode(self, char: str):
        """Handle normal mode commands"""
        if char == 'i':
            self.mode = "INSERT"
            self.message = "-- INSERT --"
            await self.draw_screen()
        elif char == 'a':
            self.mode = "INSERT"
            self.cursor_col = min(self.cursor_col + 1, len(self.lines[self.cursor_line]))
            self.message = "-- INSERT --"
            await self.draw_screen()
        elif char == 'o':
            # Open new line below
            self.cursor_line += 1
            self.lines.insert(self.cursor_line, "")
            self.cursor_col = 0
            self.mode = "INSERT"
            self.modified = True
            self.message = "-- INSERT --"
            await self.draw_screen()
        elif char == 'O':
            # Open new line above
            self.lines.insert(self.cursor_line, "")
            self.cursor_col = 0
            self.mode = "INSERT"
            self.modified = True
            self.message = "-- INSERT --"
            await self.draw_screen()
        elif char == 'x':
            # Delete character
            if self.cursor_line < len(self.lines):
                line = self.lines[self.cursor_line]
                if self.cursor_col < len(line):
                    self.lines[self.cursor_line] = line[:self.cursor_col] + line[self.cursor_col + 1:]
                    self.modified = True
                    await self.draw_screen()
        elif char == 'dd':
            # Delete line
            if len(self.lines) > 1:
                del self.lines[self.cursor_line]
                self.cursor_line = min(self.cursor_line, len(self.lines) - 1)
            else:
                self.lines = [""]
            self.modified = True
            await self.draw_screen()
        elif char == ':':
            self.mode = "COMMAND"
            self.command_buffer = ""
            await self.draw_screen()
        elif char == 'h':
            # Move left
            self.cursor_col = max(0, self.cursor_col - 1)
            await self.draw_screen()
        elif char == 'l':
            # Move right
            self.cursor_col = min(len(self.lines[self.cursor_line]), self.cursor_col + 1)
            await self.draw_screen()
        elif char == 'j':
            # Move down
            self.cursor_line = min(len(self.lines) - 1, self.cursor_line + 1)
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))
            await self.draw_screen()
        elif char == 'k':
            # Move up
            self.cursor_line = max(0, self.cursor_line - 1)
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))
            await self.draw_screen()
    
    async def handle_insert_mode(self, char: str):
        """Handle insert mode input"""
        if char == '\r' or char == '\n':
            # Enter - split line
            line = self.lines[self.cursor_line]
            self.lines[self.cursor_line] = line[:self.cursor_col]
            self.lines.insert(self.cursor_line + 1, line[self.cursor_col:])
            self.cursor_line += 1
            self.cursor_col = 0
            self.modified = True
            await self.draw_screen()
        elif char == '\x7f' or char == '\x08':  # Backspace
            if self.cursor_col > 0:
                line = self.lines[self.cursor_line]
                self.lines[self.cursor_line] = line[:self.cursor_col - 1] + line[self.cursor_col:]
                self.cursor_col -= 1
                self.modified = True
                await self.draw_screen()
            elif self.cursor_line > 0:
                # Join with previous line
                prev_line = self.lines[self.cursor_line - 1]
                curr_line = self.lines[self.cursor_line]
                self.lines[self.cursor_line - 1] = prev_line + curr_line
                del self.lines[self.cursor_line]
                self.cursor_line -= 1
                self.cursor_col = len(prev_line)
                self.modified = True
                await self.draw_screen()
        elif ord(char) >= 32 and ord(char) < 127:  # Printable characters
            line = self.lines[self.cursor_line]
            self.lines[self.cursor_line] = line[:self.cursor_col] + char + line[self.cursor_col:]
            self.cursor_col += 1
            self.modified = True
            await self.draw_screen()
    
    async def handle_command_mode(self, char: str):
        """Handle command mode input"""
        if char == '\r' or char == '\n':
            # Execute command
            await self.execute_command(self.command_buffer)
            self.mode = "NORMAL"
            self.command_buffer = ""
            await self.draw_screen()
        elif char == '\x7f' or char == '\x08':  # Backspace
            if self.command_buffer:
                self.command_buffer = self.command_buffer[:-1]
                await self.draw_screen()
            else:
                self.mode = "NORMAL"
                await self.draw_screen()
        elif ord(char) >= 32 and ord(char) < 127:
            self.command_buffer += char
            await self.draw_screen()
    
    async def handle_escape_sequence(self, seq: str):
        """Handle arrow keys and other escape sequences"""
        if seq == '\x1b[A':  # Up arrow
            self.cursor_line = max(0, self.cursor_line - 1)
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))
            await self.draw_screen()
        elif seq == '\x1b[B':  # Down arrow
            self.cursor_line = min(len(self.lines) - 1, self.cursor_line + 1)
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))
            await self.draw_screen()
        elif seq == '\x1b[C':  # Right arrow
            self.cursor_col = min(len(self.lines[self.cursor_line]), self.cursor_col + 1)
            await self.draw_screen()
        elif seq == '\x1b[D':  # Left arrow
            self.cursor_col = max(0, self.cursor_col - 1)
            await self.draw_screen()
    
    async def execute_command(self, cmd: str):
        """Execute vim command"""
        if cmd == 'q':
            if self.modified:
                self.message = "No write since last change (add ! to override)"
            else:
                self.quit_requested = True
        elif cmd == 'q!':
            self.quit_requested = True
        elif cmd == 'w':
            await self.save_file()
        elif cmd == 'wq' or cmd == 'x':
            await self.save_file()
            self.quit_requested = True
        else:
            self.message = f"Not an editor command: {cmd}"
    
    async def save_file(self):
        """Save file to virtual filesystem"""
        content = '\n'.join(self.lines)
        self.virtual_fs.write_file(self.filename, content, self.current_dir)
        self.modified = False
        line_count = len(self.lines)
        char_count = len(content)
        self.message = f'"{self.filename}" {line_count}L, {char_count}C written'
    
    async def draw_screen(self):
        """Draw the vim interface"""
        # Clear screen and move to home
        self.process.stdout.write('\x1b[2J\x1b[H')
        
        # Get terminal size (default to 24x80)
        term_height = 24
        term_width = 80
        
        # Draw lines
        display_start = max(0, self.cursor_line - term_height + 5)
        for i in range(term_height - 2):
            line_num = display_start + i
            if line_num < len(self.lines):
                line = self.lines[line_num]
                # Truncate if too long
                if len(line) > term_width:
                    line = line[:term_width]
                self.process.stdout.write(line + '\r\n')
            else:
                self.process.stdout.write('~\r\n')
        
        # Status line
        status = f'"{self.filename}" '
        if self.is_new:
            status += "[New File] "
        if self.modified:
            status += "[Modified] "
        status += f'{len(self.lines)}L, {sum(len(l) for l in self.lines)}C'
        
        self.process.stdout.write('\x1b[7m')  # Reverse video
        self.process.stdout.write(status.ljust(term_width))
        self.process.stdout.write('\x1b[0m\r\n')  # Reset
        
        # Command/message line
        if self.mode == "COMMAND":
            self.process.stdout.write(f':{self.command_buffer}')
        elif self.message:
            self.process.stdout.write(self.message)
        
        # Move cursor to correct position
        screen_line = self.cursor_line - display_start + 1
        self.process.stdout.write(f'\x1b[{screen_line};{self.cursor_col + 1}H')
    
    async def clear_screen(self):
        """Clear screen and reset"""
        self.process.stdout.write('\x1b[2J\x1b[H')


class InteractiveNano:
    """Fully functional nano editor simulation"""
    
    def __init__(self, process: asyncssh.SSHServerProcess, filename: str, virtual_fs, current_dir: str):
        self.process = process
        self.filename = filename
        self.virtual_fs = virtual_fs
        self.current_dir = current_dir
        
        # Load file content
        content = virtual_fs.read_file(filename, current_dir)
        if content is None:
            self.lines = [""]
            self.is_new = True
            self.modified = False
        else:
            self.lines = content.split('\n')
            self.is_new = False
            self.modified = False
        
        self.cursor_line = 0
        self.cursor_col = 0
        self.quit_requested = False
    
    async def run(self):
        """Main editor loop"""
        # Enable raw mode
        self.process.channel.set_line_mode(False)
        self.process.channel.set_echo(False)
        
        # Initial draw
        await self.draw_screen()
        
        try:
            buffer = ""
            while not self.quit_requested:
                char = await self.process.stdin.read(1)
                if not char:
                    break
                
                buffer += char
                
                # Handle escape sequences
                if buffer == '\x1b':
                    await asyncio.sleep(0.01)
                    continue
                elif buffer.startswith('\x1b['):
                    if len(buffer) >= 3:
                        await self.handle_escape_sequence(buffer)
                        buffer = ""
                    continue
                
                # Handle control characters
                if buffer.startswith('\x'):
                    await self.handle_control(buffer)
                    buffer = ""
                    continue
                
                # Handle regular input
                await self.handle_input(buffer)
                buffer = ""
        
                if len(buffer) >= 3:
                    await self.handle_escape_sequence(buffer)
                    buffer = ""
                    continue
                
                # Handle control characters
                if buffer.startswith('\x'):
                    await self.handle_control(buffer)
                    buffer = ""
                    continue
                
                # Handle regular input
                await self.handle_input(buffer)
                buffer = ""
        
        except Exception as e:
            pass
        finally:
            self.process.channel.set_line_mode(True)
            self.process.channel.set_echo(True)
            await self.clear_screen()
    
    async def handle_input(self, char: str):
        """Handle keyboard input"""
        if char == '\r' or char == '\n':
            # Enter - split line
            line = self.lines[self.cursor_line]
            self.lines[self.cursor_line] = line[:self.cursor_col]
            self.lines.insert(self.cursor_line + 1, line[self.cursor_col:])
            self.cursor_line += 1
            self.cursor_col = 0
            self.modified = True
            await self.draw_screen()
        elif char == '\x7f' or char == '\x08':  # Backspace
            if self.cursor_col > 0:
                line = self.lines[self.cursor_line]
                self.lines[self.cursor_line] = line[:self.cursor_col - 1] + line[self.cursor_col:]
                self.cursor_col -= 1
                self.modified = True
                await self.draw_screen()
        elif ord(char) >= 32 and ord(char) < 127:
            line = self.lines[self.cursor_line]
            self.lines[self.cursor_line] = line[:self.cursor_col] + char + line[self.cursor_col:]
            self.cursor_col += 1
            self.modified = True
            await self.draw_screen()
    
    async def handle_control(self, char: str):
        """Handle Ctrl+ commands"""
        if char == '\x18':  # Ctrl+X - Exit
            if self.modified:
                # Ask to save
                await self.save_file()
            self.quit_requested = True
        elif char == '\x0f':  # Ctrl+O - Write Out
            await self.save_file()
            await self.draw_screen()
    
    async def handle_escape_sequence(self, seq: str):
        """Handle arrow keys"""
        if seq == '\x1b[A':  # Up
            self.cursor_line = max(0, self.cursor_line - 1)
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))
            await self.draw_screen()
        elif seq == '\x1b[B':  # Down
            self.cursor_line = min(len(self.lines) - 1, self.cursor_line + 1)
            self.cursor_col = min(self.cursor_col, len(self.lines[self.cursor_line]))
            await self.draw_screen()
        elif seq == '\x1b[C':  # Right
            self.cursor_col = min(len(self.lines[self.cursor_line]), self.cursor_col + 1)
            await self.draw_screen()
        elif seq == '\x1b[D':  # Left
            self.cursor_col = max(0, self.cursor_col - 1)
            await self.draw_screen()
    
    async def save_file(self):
        """Save file"""
        content = '\n'.join(self.lines)
        self.virtual_fs.write_file(self.filename, content, self.current_dir)
        self.modified = False
    
    async def draw_screen(self):
        """Draw nano interface"""
        self.process.stdout.write('\x1b[2J\x1b[H')
        
        term_height = 24
        term_width = 80
        
        # Header
        header = f'  GNU nano 4.8{self.filename.center(term_width - 20)}'
        if self.modified:
            header += "Modified"
        self.process.stdout.write('\x1b[7m' + header.ljust(term_width) + '\x1b[0m\r\n')
        
        # Content
        for i in range(term_height - 4):
            if i < len(self.lines):
                line = self.lines[i]
                if len(line) > term_width:
                    line = line[:term_width]
                self.process.stdout.write(line + '\r\n')
            else:
                self.process.stdout.write('\r\n')
        
        # Help bar
        self.process.stdout.write('\x1b[7m')
        self.process.stdout.write('^G Get Help  ^O Write Out ^X Exit      ^J Justify   ^W Where Is'.ljust(term_width))
        self.process.stdout.write('\x1b[0m\r\n')
        self.process.stdout.write('\x1b[7m')
        self.process.stdout.write('^K Cut Text  ^U Paste     ^\\ Replace   ^T To Spell  ^C Cur Pos'.ljust(term_width))
        self.process.stdout.write('\x1b[0m')
        
        # Position cursor
        self.process.stdout.write(f'\x1b[{self.cursor_line + 2};{self.cursor_col + 1}H')
    
    async def clear_screen(self):
        """Clear screen"""
        self.process.stdout.write('\x1b[2J\x1b[H')