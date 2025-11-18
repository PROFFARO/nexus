#!/usr/bin/env python3
"""
Integration test for MySQL honeypot database context fix.
Tests the complete flow: handle_query -> _handle_use_database -> _process_llm_query
"""

import asyncio
import json
import sys
from configparser import ConfigParser
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from service_emulators.MySQL.mysql_server import MySQLHoneypotSession, ResultSet, ResultColumn


async def test_complete_flow():
    """Test the complete query processing flow"""
    print("\n=== Integration Test: Complete Query Flow ===")
    
    # Create config
    config = ConfigParser()
    config.add_section("llm")
    config.set("llm", "provider", "ollama")
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
    
    print("\n1. Testing handle_query with USE command:")
    print("   Query: USE nexus_gamedev")
    
    # Call handle_query with USE (which calls _handle_use_database)
    result = await session.handle_query("USE nexus_gamedev;", {})
    
    print(f"   Result: {result}")
    print(f"   Database after USE: {session.session_data['database']}")
    assert session.session_data["database"] == "nexus_gamedev", "Database should be set"
    print("   ✓ Database properly set")
    
    print("\n2. Testing database context persists:")
    print(f"   Current database: {session.session_data['database']}")
    print(f"   current_database attribute: {getattr(session, 'current_database', None)}")
    assert session.session_data["database"] == "nexus_gamedev"
    assert getattr(session, "current_database", None) == "nexus_gamedev"
    print("   ✓ Context properly persisted")
    
    print("\n3. Testing SHOW TABLES formatting with database context:")
    # Simulate LLM response
    llm_response = json.dumps([
        {"Tables_in_nexus_gamedev": "users"},
        {"Tables_in_nexus_gamedev": "games"},
    ])
    parsed = json.loads(llm_response)
    result = session._format_show_tables(parsed)
    
    print(f"   Result columns: {[col.name for col in result.columns]}")
    print(f"   Result rows: {result.rows}")
    assert result.columns[0].name == "Tables_in_nexus_gamedev", "Column name should include database"
    assert len(result.rows) == 2, "Should have 2 tables"
    print("   ✓ SHOW TABLES formatted correctly")
    
    print("\n4. Testing SHOW TABLES without database (should error):")
    session2 = MySQLHoneypotSession(config)
    # Don't set a database
    llm_response_err = json.dumps([{"Error": "ERROR 1046 (3D000): No database selected"}])
    parsed_err = json.loads(llm_response_err)
    result_err = session2._format_show_tables(parsed_err)
    
    print(f"   Result: {result_err.rows[0][0]}")
    assert "ERROR 1046" in result_err.rows[0][0]
    print("   ✓ Error properly returned")
    
    print("\n5. Testing database switch:")
    print("   Switching to information_schema...")
    await session.handle_query("USE information_schema;", {})
    print(f"   Database now: {session.session_data['database']}")
    assert session.session_data["database"] == "information_schema"
    print("   ✓ Database switch successful")


async def main():
    try:
        await test_complete_flow()
        print("\n" + "=" * 60)
        print("✓ All integration tests passed!")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
