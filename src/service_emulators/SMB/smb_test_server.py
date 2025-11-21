#!/usr/bin/env python3
"""
NEXUS SMB Honeypot - Simplified Test Version
Basic SMB server for testing with minimal dependencies
"""

import asyncio
import socket
import struct
import logging
from pathlib import Path

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('smb_test')

class SimpleSMBServer:
    """Simplified SMB server for testing"""
    
    def __init__(self, port=4445):
        self.port = port
        self.server_name = "NEXUS-FS-01"
        logger.info(f"Initializing SMB server on port {port}")
    
    async def handle_connection(self, reader, writer):
        """Handle SMB connection"""
        peername = writer.get_extra_info('peername')
        src_ip, src_port = peername[:2] if peername else ('-', '-')
        
        logger.info(f"✓ Connection from {src_ip}:{src_port}")
        
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=60)
                    if not data:
                        break
                    
                    # Log received data
                    logger.debug(f"Received {len(data)} bytes from {src_ip}")
                    
                    # Simple response - just acknowledge
                    response = b"SMB Honeypot Active\r\n"
                    writer.write(response)
                    await writer.drain()
                    
                except asyncio.TimeoutError:
                    logger.info(f"Timeout from {src_ip}")
                    break
                except Exception as e:
                    logger.error(f"Error: {e}")
                    break
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info(f"✗ Connection closed {src_ip}:{src_port}")
    
    async def start(self):
        """Start the SMB server"""
        server = await asyncio.start_server(
            self.handle_connection,
            '0.0.0.0',
            self.port
        )
        
        addr = server.sockets[0].getsockname()
        logger.info(f'SMB Honeypot serving on {addr}')
        print(f'✓ SMB Honeypot started on port {self.port}')
        print(f'✓ Server: {self.server_name}')
        print(f'✓ Press Ctrl+C to stop')
        
        async with server:
            await server.serve_forever()

async def main():
    """Main entry point"""
    server = SimpleSMBServer(port=4445)
    await server.start()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n✓ Shutting down SMB Honeypot...')
