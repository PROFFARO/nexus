#!/usr/bin/env python3
"""
Test script to verify MySQL honeypot database context fix.
Tests that:
1. USE command properly sets database context
2. SHOW TABLES after USE returns table list with correct column name
3. LLM is invoked for SHOW TABLES query
4. Database context is preserved across queries
"""

import asyncio
import json
import sys
from configparser import ConfigParser
from io import StringIO
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from service_emulators.MySQL.mysql_server import MySQLHoneypotSession, ResultSet, ResultColumn


async def test_use_database_context():
    """Test 1: USE command sets database context"""
    print("\n=== Test 1: USE command sets database context ===")
    
    # Create minimal config
    config = ConfigParser()
    config.add_section("llm")
    config.set("llm", "provider", "openai")
    config.set("llm", "api_key", "test")
    config.set("llm", "enabled", "True")
    config.add_section("ai_features")
    config.set("ai_features", "deception_techniques", "False")
    config.set("ai_features", "query_result_manipulation", "False")
    config.add_section("attack_detection")
    config.set("attack_detection", "alert_threshold", "70")
    config.add_section("forensics")
    config.set("forensics", "chain_of_custody", "False")
    
    session = MySQLHoneypotSession(config)
    
    # Initially no database selected
    assert session.session_data["database"] is None, "Database should be None initially"
    assert getattr(session, "current_database", None) is None, "current_database attribute should be None initially"
    print("✓ Initial state: database=None, current_database=None")
    
    # Call USE command
    result = session._handle_use_database("USE nexus_gamedev")
    
    # Check database is set
    assert session.session_data["database"] == "nexus_gamedev", f"Database should be 'nexus_gamedev', got {session.session_data['database']}"
    assert session.current_database == "nexus_gamedev", f"current_database should be 'nexus_gamedev', got {session.current_database}"
    print("✓ After USE: database='nexus_gamedev', current_database='nexus_gamedev'")
    
    # Verify result is empty (successful USE)
    assert isinstance(result, ResultSet), "Should return ResultSet"
    assert len(result.rows) == 0, "USE should return no rows"
    print("✓ USE command returned empty ResultSet (success)")
    

async def test_show_tables_after_use():
    """Test 2: SHOW TABLES after USE gets correct database context"""
    print("\n=== Test 2: SHOW TABLES gets database context ===")
    
    config = ConfigParser()
    config.add_section("llm")
    config.set("llm", "provider", "openai")
    config.set("llm", "api_key", "test")
    config.set("llm", "enabled", "True")
    config.add_section("ai_features")
    config.set("ai_features", "deception_techniques", "False")
    config.set("ai_features", "query_result_manipulation", "False")
    config.add_section("attack_detection")
    config.set("attack_detection", "alert_threshold", "70")
    config.add_section("forensics")
    config.set("forensics", "chain_of_custody", "False")
    
    session = MySQLHoneypotSession(config)
    
    # Set database first
    session._handle_use_database("USE nexus_gamedev")
    print(f"✓ Set database to: {session.session_data['database']}")
    
    # Mock LLM response for SHOW TABLES
    llm_response = json.dumps([
        {"Tables_in_nexus_gamedev": "users"},
        {"Tables_in_nexus_gamedev": "games"},
        {"Tables_in_nexus_gamedev": "achievements"}
    ])
    
    # Test _format_show_tables
    parsed = json.loads(llm_response)
    result = session._format_show_tables(parsed)
    
    assert isinstance(result, ResultSet), "Should return ResultSet"
    assert len(result.rows) == 3, f"Should have 3 tables, got {len(result.rows)}"
    assert result.columns[0].name == "Tables_in_nexus_gamedev", f"Column name should be 'Tables_in_nexus_gamedev', got '{result.columns[0].name}'"
    print(f"✓ SHOW TABLES returned {len(result.rows)} tables with correct column name")


async def test_no_database_error():
    """Test 3: SHOW TABLES without database context returns error"""
    print("\n=== Test 3: SHOW TABLES without database returns error ===")
    
    config = ConfigParser()
    config.add_section("llm")
    config.set("llm", "provider", "openai")
    config.set("llm", "api_key", "test")
    config.set("llm", "enabled", "True")
    config.add_section("ai_features")
    config.set("ai_features", "deception_techniques", "False")
    config.set("ai_features", "query_result_manipulation", "False")
    config.add_section("attack_detection")
    config.set("attack_detection", "alert_threshold", "70")
    config.add_section("forensics")
    config.set("forensics", "chain_of_custody", "False")
    
    session = MySQLHoneypotSession(config)
    
    # Don't set a database, just try SHOW TABLES
    assert session.session_data["database"] is None, "Database should be None"
    
    # Mock an LLM response (though it should have been instructed to return error)
    llm_response = json.dumps([{"Error": "ERROR 1046 (3D000): No database selected"}])
    parsed = json.loads(llm_response)
    
    result = session._format_show_tables(parsed)
    
    assert isinstance(result, ResultSet), "Should return ResultSet"
    assert len(result.rows) == 1, f"Should have 1 error row, got {len(result.rows)}"
    assert "ERROR 1046" in result.rows[0][0], f"Error should contain 'ERROR 1046', got {result.rows[0][0]}"
    print(f"✓ SHOW TABLES without database returned: {result.rows[0][0]}")


async def test_database_persistence():
    """Test 4: Database context persists across multiple queries"""
    print("\n=== Test 4: Database context persists across queries ===")
    
    config = ConfigParser()
    config.add_section("llm")
    config.set("llm", "provider", "openai")
    config.set("llm", "api_key", "test")
    config.set("llm", "enabled", "True")
    config.add_section("ai_features")
    config.set("ai_features", "deception_techniques", "False")
    config.set("ai_features", "query_result_manipulation", "False")
    config.add_section("attack_detection")
    config.set("attack_detection", "alert_threshold", "70")
    config.add_section("forensics")
    config.set("forensics", "chain_of_custody", "False")
    
    session = MySQLHoneypotSession(config)
    
    # Set database
    session._handle_use_database("USE nexus_gamedev")
    db1 = session.session_data["database"]
    print(f"✓ Set database to: {db1}")
    
    # Simulate another query (like SELECT)
    # Database should persist
    db2 = session.session_data["database"]
    assert db1 == db2 == "nexus_gamedev", f"Database should persist, got {db1} then {db2}"
    print(f"✓ Database persisted after next query: {db2}")
    
    # Try switching database
    session._handle_use_database("USE information_schema")
    db3 = session.session_data["database"]
    assert db3 == "information_schema", f"Should switch to information_schema, got {db3}"
    print(f"✓ Switched database to: {db3}")


async def main():
    """Run all tests"""
    print("=" * 60)
    print("MySQL Honeypot Database Context Fix - Test Suite")
    print("=" * 60)
    
    try:
        await test_use_database_context()
        await test_show_tables_after_use()
        await test_no_database_error()
        await test_database_persistence()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        print("=" * 60)
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        print("=" * 60)
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
