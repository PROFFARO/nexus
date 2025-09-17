#!/usr/bin/env python3

import ftplib
import sys

def test_ftp_connection():
    try:
        print("Connecting to FTP server...")
        ftp = ftplib.FTP()
        ftp.set_debuglevel(2)  # Enable debug output
        ftp.connect('localhost', 2121)
        print("Connected successfully!")
        
        print("Attempting to login...")
        ftp.login('anonymous', 'test@example.com')
        print("Login successful!")
        
        print("Getting current directory...")
        pwd = ftp.pwd()
        print(f"Current directory: {pwd}")
        
        print("Listing directory...")
        files = ftp.nlst()
        print(f"Files: {files}")
        
        ftp.quit()
        print("Connection closed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ftp_connection()