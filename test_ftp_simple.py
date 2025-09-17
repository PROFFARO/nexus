#!/usr/bin/env python3

import socket
import time

def test_ftp_basic():
    """Test basic FTP connection and commands"""
    try:
        print("Connecting to FTP server...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 2121))
        
        # Read welcome message
        response = sock.recv(1024).decode()
        print(f"Server: {response.strip()}")
        
        # Send USER command
        print("Sending USER command...")
        sock.send(b"USER admin\r\n")
        response = sock.recv(1024).decode()
        print(f"Server: {response.strip()}")
        
        # Send PASS command
        print("Sending PASS command...")
        sock.send(b"PASS admin\r\n")
        response = sock.recv(1024).decode()
        print(f"Server: {response.strip()}")
        
        # Send PWD command
        print("Sending PWD command...")
        sock.send(b"PWD\r\n")
        response = sock.recv(1024).decode()
        print(f"Server: {response.strip()}")
        
        # Send LIST command
        print("Sending LIST command...")
        sock.send(b"LIST\r\n")
        response = sock.recv(1024).decode()
        print(f"Server: {response.strip()}")
        
        # Send QUIT command
        print("Sending QUIT command...")
        sock.send(b"QUIT\r\n")
        response = sock.recv(1024).decode()
        print(f"Server: {response.strip()}")
        
        sock.close()
        print("Test completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ftp_basic()