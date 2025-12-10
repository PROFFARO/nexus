import asyncio
import json
import logging
import os
from pathlib import Path
from typing import AsyncGenerator, List, Callable, Awaitable

logger = logging.getLogger(__name__)

class LogWatcher:
    def __init__(self, log_files: List[Path]):
        self.log_files = log_files
        self._running = False
        # Store file objects and current positions
        self._files = {}
        
    async def watch(self) -> AsyncGenerator[dict, None]:
        """Watch log files for new lines and yield parsed JSON objects."""
        self._running = True
        
        # Open all files and seek to end
        for log_file in self.log_files:
            if not log_file.exists():
                logger.warning(f"Log file not found: {log_file}")
                continue
            
            try:
                f = open(log_file, "r", encoding="utf-8")
                # Seek to near end to read recent history (approx last 100-200 lines)
                f.seek(0, os.SEEK_END)
                size = f.tell()
                # Read last 50KB to be safe (ssh logs are small)
                f.seek(max(0, size - 51200), os.SEEK_SET)
                
                # If we didn't start at 0, skip the first partial line
                if f.tell() > 0:
                    f.readline()
                
                # Read remaining lines to catch up with history and populate buffer
                current_lines = f.readlines()
                for line in current_lines:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            yield data
                        except json.JSONDecodeError:
                            pass
                        except Exception as e:
                            logger.error(f"Error processing historical line in {log_file}: {e}")

                self._files[str(log_file)] = f
            except Exception as e:
                logger.error(f"Error opening log file {log_file}: {e}")

        logger.info(f"Started watching {len(self._files)} log files")

        while self._running:
            data_found = False
            for file_path, f in self._files.items():
                line = f.readline()
                if line:
                    data_found = True
                    try:
                        # Attempt to parse JSON
                        if line.strip():
                            data = json.loads(line)
                            yield data
                    except json.JSONDecodeError:
                        # Check if it's a partially written line or just plain text
                        logger.debug(f"Could not parse line in {file_path}: {line[:50]}...")
                        pass
                    except Exception as e:
                        logger.error(f"Error processing line in {file_path}: {e}")
            
            if not data_found:
                await asyncio.sleep(0.5) # Wait a bit before checking again

    def stop(self):
        self._running = False
        for f in self._files.values():
            try:
                f.close()
            except:
                pass
        self._files = {}
