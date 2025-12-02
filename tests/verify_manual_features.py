#!/usr/bin/env python3
"""
Verification script for manually implemented SSH honeypot features.
Run this script after applying the changes from manual_implementation_guide.md.
"""

import asyncio
import asyncssh
import sys
import time

async def run_test(name, command, expected_pattern):
    print(f"Testing {name}...", end=" ", flush=True)
    try:
        async with asyncssh.connect("localhost", port=8022, username="guest", password="password", known_hosts=None) as conn:
            result = await conn.run(command)
            output = result.stdout
            
            if expected_pattern in output:
                print("✅ PASS")
                return True
            else:
                print("❌ FAIL")
                print(f"  Command: {command}")
                print(f"  Expected: {expected_pattern}")
                print(f"  Actual: {output.strip()}")
                return False
    except Exception as e:
        print("❌ ERROR")
        print(f"  Connection failed: {e}")
        return False

async def main():
    print("=== Verifying Manual Implementation ===\n")
    
    # 1. Test Sudo
    # Expecting the password prompt or execution if we implemented the "always accept" logic
    # The guide implemented a check for user accounts. "guest" is usually not in the list unless added.
    # But the guide said: if username not in user_accounts... return "... not in the sudoers file"
    # So we expect failure for guest, or success if we add guest.
    # Let's test the negative case first which confirms the logic is active.
    await run_test("Sudo (Guest)", "sudo id", "not in the sudoers file")
    
    # 2. Test Package Management
    # Test apt update
    await run_test("APT Update", "apt update", "Hit:1 http://archive.ubuntu.com/ubuntu")
    
    # Test apt install
    await run_test("APT Install", "apt install nginx", "Setting up nginx")
    
    # Test dpkg -l
    await run_test("DPKG List", "dpkg -l", "nginx")
    
    # 3. Test File Operations
    # Test wget
    await run_test("Wget", "wget http://example.com/test.txt -O test_download.txt && cat test_download.txt", "Downloaded from")
    
    # Test tar creation
    await run_test("Tar Create", "touch f1 f2 && tar -czf archive.tar.gz f1 f2 && ls archive.tar.gz", "archive.tar.gz")
    
    # 4. Test Cron
    # Test crontab -l (should be empty initially)
    await run_test("Crontab List", "crontab -l", "no crontab for guest")
    
    # Test crontab -e (should install default)
    await run_test("Crontab Edit", "crontab -e", "installing new crontab")
    
    print("\n=== Verification Complete ===")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (OSError, ConnectionRefusedError):
        print("\n❌ Could not connect to SSH server. Make sure it is running on port 8022.")
        sys.exit(1)
