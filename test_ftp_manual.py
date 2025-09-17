#!/usr/bin/env python3

import socket
import time

def manual_ftp_test():
    """Manual FTP test to see exactly what's happening"""
    try:
        print("Connecting to FTP server...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', 2121))
        
        # Read welcome message
        response = sock.recv(1024).decode()
        print(f"1. Welcome: {response.strip()}")
        
        # Send OPTS command (like Windows FTP client does)
        print("2. Sending OPTS UTF8 ON...")
        sock.send(b"OPTS UTF8 ON\r\n")
        response = sock.recv(1024).decode()
        print(f"   Response: {response.strip()}")
        
        # Send USER command
        print("3. Sending USER admin...")
        sock.send(b"USER admin\r\n")
        response = sock.recv(1024).decode()
        print(f"   Response: {response.strip()}")
        
        # Send PASS command
        print("4. Sending PASS admin...")
        sock.send(b"PASS admin\r\n")
        response = sock.recv(1024).decode()
        print(f"   Response: {response.strip()}")
        
        # Send PWD command
        print("5. Sending PWD...")
        sock.send(b"PWD\r\n")
        response = sock.recv(1024).decode()
        print(f"   Response: {response.strip()}")
        
        # Send QUIT command
        print("6. Sending QUIT...")
        sock.send(b"QUIT\r\n")
        response = sock.recv(1024).decode()
        print(f"   Response: {response.strip()}")
        
        sock.close()
        print("Test completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    manual_ftp_test()