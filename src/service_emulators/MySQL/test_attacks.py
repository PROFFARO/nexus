#!/usr/bin/env python3
"""
MySQL Honeypot Attack Testing Suite
Tests various attack patterns and exploits against the honeypot
"""

import socket
import struct
import time
import json
from typing import Tuple

class MySQLAttackTester:
    """Test MySQL honeypot with various attack patterns"""
    
    def __init__(self, host: str = "localhost", port: int = 3326):
        self.host = host
        self.port = port
        self.socket = None
        self.results = []
    
    def connect(self) -> bool:
        """Connect to MySQL server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            print(f"✅ Connected to {self.host}:{self.port}")
            
            # Read greeting packet
            greeting = self.socket.recv(1024)
            if greeting:
                print(f"📡 Received greeting ({len(greeting)} bytes)")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            self.socket.close()
            self.socket = None
    
    def send_query(self, query: str) -> str:
        """Send a query and receive response"""
        try:
            # Build MySQL query packet
            query_bytes = query.encode('utf-8')
            packet = struct.pack('<I', len(query_bytes) + 1)[:-1]  # Length (3 bytes)
            packet += bytes([0x00])  # Sequence
            packet += bytes([0x03])  # Query command
            packet += query_bytes
            
            self.socket.send(packet)
            print(f"📤 Sent: {query[:60]}{'...' if len(query) > 60 else ''}")
            
            # Read response
            response = self.socket.recv(4096)
            response_str = response.decode('utf-8', errors='ignore')
            print(f"📥 Received: {response_str[:100]}{'...' if len(response_str) > 100 else ''}")
            
            return response_str
        except Exception as e:
            print(f"⚠️  Error: {e}")
            return ""
    
    def test_reconnaissance(self):
        """Test reconnaissance attacks"""
        print("\n" + "="*60)
        print("🔍 RECONNAISSANCE ATTACKS")
        print("="*60)
        
        tests = [
            ("SHOW DATABASES", "Database enumeration"),
            ("SELECT @@version", "Version detection"),
            ("SELECT USER()", "Current user"),
            ("SELECT DATABASE()", "Current database"),
            ("SHOW TABLES", "List tables without database"),
            ("USE nexus_gamedev", "Database selection"),
            ("SHOW TABLES FROM nexus_gamedev", "List tables in database"),
        ]
        
        for query, description in tests:
            print(f"\n🎯 {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_sql_injection(self):
        """Test SQL injection patterns"""
        print("\n" + "="*60)
        print("💉 SQL INJECTION ATTACKS")
        print("="*60)
        
        tests = [
            ("SELECT * FROM users WHERE id = '1' OR '1'='1'", "Classic OR 1=1"),
            ("UNION SELECT user(), database(), version()", "UNION SELECT"),
            ("'; DROP TABLE users; --", "Drop table injection"),
            ("admin' OR '1'='1", "Login bypass"),
            ("1' AND 1=1 UNION SELECT NULL,NULL,NULL--", "UNION with NULLs"),
        ]
        
        for query, description in tests:
            print(f"\n💉 {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_privilege_escalation(self):
        """Test privilege escalation attempts"""
        print("\n" + "="*60)
        print("⬆️  PRIVILEGE ESCALATION ATTACKS")
        print("="*60)
        
        tests = [
            ("GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'", "Create super user"),
            ("ALTER USER root IDENTIFIED BY 'newpass'", "Modify root password"),
            ("CREATE USER attacker IDENTIFIED BY 'pass123'", "Create new user"),
            ("SET GLOBAL log_bin_trust_function_creators=1", "Modify globals"),
            ("FLUSH PRIVILEGES", "Flush privileges"),
        ]
        
        for query, description in tests:
            print(f"\n⬆️  {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_data_exfiltration(self):
        """Test data exfiltration attempts"""
        print("\n" + "="*60)
        print("📤 DATA EXFILTRATION ATTACKS")
        print("="*60)
        
        tests = [
            ("SELECT * FROM information_schema.tables", "Extract schema info"),
            ("SELECT * FROM information_schema.schemata", "Extract database info"),
            ("SELECT * FROM mysql.user", "Extract users"),
            ("SELECT * FROM nexus_gamedev.players LIMIT 100", "Extract player data"),
            ("SELECT LOAD_FILE('/etc/passwd')", "File read attempt"),
        ]
        
        for query, description in tests:
            print(f"\n📤 {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_command_injection(self):
        """Test OS command injection attempts"""
        print("\n" + "="*60)
        print("🔴 OS COMMAND INJECTION ATTACKS")
        print("="*60)
        
        tests = [
            ("INTO OUTFILE '/tmp/shell.php'", "Write shell file"),
            ("INTO DUMPFILE '/var/www/html/shell.php'", "Dump shell"),
            ("SELECT @@version_compile_os", "OS detection"),
            ("SHOW VARIABLES LIKE '%datadir%'", "Data directory"),
        ]
        
        for query, description in tests:
            print(f"\n🔴 {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_error_based_attacks(self):
        """Test error-based attack detection"""
        print("\n" + "="*60)
        print("❌ ERROR-BASED ATTACKS")
        print("="*60)
        
        tests = [
            ("SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),0x3a,database())FROM information_schema.tables GROUP BY 1)x", "Error-based extraction"),
            ("SELECT EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))", "EXTRACTVALUE error"),
            ("SELECT UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)", "UPDATEXML error"),
            ("SELECT (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())", "Subquery extraction"),
        ]
        
        for query, description in tests:
            print(f"\n❌ {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_time_based_blind(self):
        """Test time-based blind SQL injection"""
        print("\n" + "="*60)
        print("⏱️  TIME-BASED BLIND ATTACKS")
        print("="*60)
        
        tests = [
            ("SELECT * FROM players WHERE id = 1 AND SLEEP(5)", "Sleep injection"),
            ("SELECT IF(1=1,SLEEP(3),0)", "Conditional sleep"),
            ("SELECT * FROM players WHERE 1=1 AND (SELECT COUNT(*) FROM information_schema.tables) > 0", "Blind boolean"),
        ]
        
        for query, description in tests:
            print(f"\n⏱️  {description}")
            start = time.time()
            self.send_query(query)
            elapsed = time.time() - start
            print(f"⏲️  Response time: {elapsed:.2f}s")
            time.sleep(0.5)
    
    def test_stacked_queries(self):
        """Test stacked query injection"""
        print("\n" + "="*60)
        print("📚 STACKED QUERY ATTACKS")
        print("="*60)
        
        tests = [
            ("SELECT 1; DROP DATABASE test", "Stacked drop"),
            ("SELECT 1; INSERT INTO users VALUES ('hacker','pass')", "Stacked insert"),
            ("SELECT 1; UPDATE users SET password='hacked'", "Stacked update"),
        ]
        
        for query, description in tests:
            print(f"\n📚 {description}")
            self.send_query(query)
            time.sleep(0.5)
    
    def test_brute_force(self):
        """Test authentication attempts"""
        print("\n" + "="*60)
        print("🔐 AUTHENTICATION ATTACKS")
        print("="*60)
        
        # Reconnect for each auth test
        common_users = ["root", "admin", "developer", "test", "guest"]
        common_passes = ["password", "123456", "admin", "root", "*", ""]
        
        print("\n🔐 Brute force attempts:")
        for user in common_users[:3]:  # Test first 3 users
            for password in common_passes[:2]:  # Test first 2 passwords
                try:
                    self.disconnect()
                    time.sleep(0.1)
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.settimeout(2)
                    self.socket.connect((self.host, self.port))
                    greeting = self.socket.recv(1024)
                    
                    print(f"  🔑 Attempt: {user}:{password[:3]}{'*' if len(password) > 3 else ''}")
                    time.sleep(0.2)
                except Exception as e:
                    print(f"  ❌ Connection failed")
    
    def test_fuzzing(self):
        """Test fuzzing with random/malformed data"""
        print("\n" + "="*60)
        print("🎲 FUZZING ATTACKS")
        print("="*60)
        
        fuzzing_payloads = [
            ("a" * 1000, "Long string"),
            ("'; SELECT * FROM 1234567890; --", "Large number access"),
            ("\\x00\\x01\\x02\\xFF", "Binary data"),
            ("admin'/**/OR/**/1=1", "Comment-based bypass"),
            ("admin' /*!50000UNION*/ SELECT NULL", "Version-specific syntax"),
        ]
        
        for payload, description in fuzzing_payloads:
            print(f"\n🎲 {description}")
            try:
                self.send_query(payload[:100])
            except:
                print(f"  ⚠️  Fuzzing payload caused exception")
            time.sleep(0.3)
    
    def run_all_tests(self):
        """Run all attack tests"""
        if not self.connect():
            print("❌ Cannot connect to server")
            return
        
        try:
            self.test_reconnaissance()
            time.sleep(1)
            
            self.test_sql_injection()
            time.sleep(1)
            
            self.test_privilege_escalation()
            time.sleep(1)
            
            self.test_data_exfiltration()
            time.sleep(1)
            
            self.test_command_injection()
            time.sleep(1)
            
            self.test_error_based_attacks()
            time.sleep(1)
            
            self.test_time_based_blind()
            time.sleep(1)
            
            self.test_stacked_queries()
            time.sleep(1)
            
            self.test_brute_force()
            time.sleep(1)
            
            self.test_fuzzing()
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Testing interrupted by user")
        finally:
            self.disconnect()
            print("\n" + "="*60)
            print("✅ ATTACK TESTING COMPLETE")
            print("="*60)


def main():
    """Main entry point"""
    print("\n" + "="*60)
    print("🎯 MySQL HONEYPOT ATTACK TESTING SUITE")
    print("="*60)
    print("Testing: localhost:3326")
    print("Objective: Assess attack detection capabilities")
    print("="*60)
    
    tester = MySQLAttackTester(host="localhost", port=3326)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
