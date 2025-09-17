#!/usr/bin/env python3
"""
Simple FTP client test for the honeypot
"""

import socket
import time

def test_ftp_honeypot():
    """Test basic FTP honeypot functionality"""
    
    try:
        # Connect to FTP honeypot
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 2121))
        
        # Receive welcome message
        response = sock.recv(1024).decode()
        print(f"Welcome: {response.strip()}")
        
        # Send USER command
        sock.send(b"USER admin\r\n")
        response = sock.recv(1024).decode()
        print(f"USER response: {response.strip()}")
        
        # Send PASS command
        sock.send(b"PASS admin\r\n")
        response = sock.recv(1024).decode()
        print(f"PASS response: {response.strip()}")
        
        # Send SYST command
        sock.send(b"SYST\r\n")
        response = sock.recv(1024).decode()
        print(f"SYST response: {response.strip()}")
        
        # Send PWD command
        sock.send(b"PWD\r\n")
        response = sock.recv(1024).decode()
        print(f"PWD response: {response.strip()}")
        
        # Send LIST command
        sock.send(b"LIST\r\n")
        response = sock.recv(1024).decode()
        print(f"LIST response: {response.strip()}")
        
        # Send QUIT command
        sock.send(b"QUIT\r\n")
        response = sock.recv(1024).decode()
        print(f"QUIT response: {response.strip()}")
        
        sock.close()
        print("FTP test completed successfully!")
        
    except Exception as e:
        print(f"FTP test failed: {e}")

if __name__ == "__main__":
    print("Testing FTP honeypot...")
    test_ftp_honeypot()