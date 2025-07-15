#!/usr/bin/env python3
"""
Debug script to analyze authentication flow and identify keychain session persistence issues
"""

import os
import sys
import time
import json
import keyring
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.enhanced_auth import EnhancedAuthManager


def debug_keychain_operations():
    """Debug keychain operations step by step"""
    print("🔍 Debugging Keychain Operations")
    print("=" * 50)
    
    # Check keychain access
    service_name = "PassGen"
    session_key = "session_token" 
    master_key = "master_password_encrypted"
    
    print(f"Service Name: {service_name}")
    print(f"Session Key: {session_key}")
    print(f"Master Key: {master_key}")
    print()
    
    # 1. Check existing session data
    print("1. Checking existing session data...")
    try:
        session_data = keyring.get_password(service_name, session_key)
        if session_data:
            print(f"✅ Found session data: {session_data}")
            try:
                session_info = json.loads(session_data)
                print(f"   Token: {session_info.get('token', 'N/A')}")
                print(f"   Created: {datetime.fromtimestamp(session_info.get('created_at', 0))}")
                print(f"   Password Hash: {session_info.get('password_hash', 'N/A')[:16]}...")
                
                # Check if expired
                if time.time() - session_info.get('created_at', 0) < 300:  # 5 min default
                    print(f"   Status: ✅ Valid (not expired)")
                else:
                    print(f"   Status: ❌ Expired")
            except json.JSONDecodeError as e:
                print(f"   ❌ Invalid JSON: {e}")
        else:
            print("❌ No session data found")
    except Exception as e:
        print(f"❌ Error reading session: {e}")
    print()
    
    # 2. Check master password
    print("2. Checking stored master password...")
    try:
        master_password = keyring.get_password(service_name, master_key)
        if master_password:
            print(f"✅ Found master password (length: {len(master_password)})")
        else:
            print("❌ No master password found")
    except Exception as e:
        print(f"❌ Error reading master password: {e}")
    print()
    
    # 3. Test writing and reading session data
    print("3. Testing session data write/read...")
    test_session = {
        'token': 'test_token_123',
        'created_at': time.time(),
        'password_hash': 'test_hash_456'
    }
    
    try:
        # Write test session
        keyring.set_password(service_name, f"{session_key}_test", json.dumps(test_session))
        print("✅ Successfully wrote test session")
        
        # Read test session
        read_data = keyring.get_password(service_name, f"{session_key}_test")
        if read_data:
            read_session = json.loads(read_data)
            print(f"✅ Successfully read test session: {read_session}")
            
            # Clean up
            keyring.delete_password(service_name, f"{session_key}_test")
            print("✅ Cleaned up test session")
        else:
            print("❌ Failed to read test session")
            
    except Exception as e:
        print(f"❌ Error in session test: {e}")
    print()


def debug_auth_flow():
    """Debug the complete authentication flow"""
    print("🔍 Debugging Authentication Flow")
    print("=" * 50)
    
    auth_manager = EnhancedAuthManager()
    
    # 1. Check session validity
    print("1. Checking current session validity...")
    is_valid = auth_manager._is_session_valid()
    print(f"   Session valid: {is_valid}")
    print(f"   Cached password: {'✅' if auth_manager.cached_password else '❌'}")
    print(f"   Session start time: {auth_manager.session_start_time}")
    print(f"   Session timeout: {auth_manager.session_timeout}")
    print()
    
    # 2. Try keychain session recovery
    print("2. Testing keychain session recovery...")
    keychain_result = auth_manager._try_keychain_session()
    print(f"   Success: {keychain_result.success}")
    print(f"   Method: {keychain_result.method}")
    print(f"   Error: {keychain_result.error_message}")
    if keychain_result.success:
        print(f"   Password length: {len(keychain_result.password) if keychain_result.password else 0}")
        print(f"   Session token: {keychain_result.session_token}")
    print()
    
    # 3. Check storage verification
    print("3. Testing password verification with storage...")
    try:
        from core.storage import SecureStorage
        storage = SecureStorage()
        print(f"   Storage initialized: {storage.is_initialized()}")
        
        # Try with cached password if available
        if auth_manager.cached_password:
            is_valid_password = auth_manager._verify_password_with_database(auth_manager.cached_password)
            print(f"   Cached password valid: {is_valid_password}")
        
        # Try with keychain password if available  
        keychain_password = auth_manager._get_password_from_keychain()
        if keychain_password:
            print(f"   Keychain password length: {len(keychain_password)}")
            is_valid_keychain = auth_manager._verify_password_with_database(keychain_password)
            print(f"   Keychain password valid: {is_valid_keychain}")
        else:
            print("   No keychain password found")
            
    except Exception as e:
        print(f"   ❌ Storage verification error: {e}")
    print()


def debug_session_persistence():
    """Test session persistence across 'processes' (instances)"""
    print("🔍 Testing Session Persistence Across Instances")
    print("=" * 50)
    
    # Create first instance and authenticate
    print("Creating first auth manager instance...")
    auth1 = EnhancedAuthManager()
    
    # Simulate successful authentication by manually setting session
    print("Simulating successful authentication...")
    test_password = "test_password_123"
    auth1._start_session(test_password)
    
    print(f"Session started at: {datetime.fromtimestamp(auth1.session_start_time)}")
    print(f"Session token: {auth1.session_token}")
    print(f"Cached password: {'✅' if auth1.cached_password else '❌'}")
    print()
    
    # Create second instance (simulating new process)
    print("Creating second auth manager instance (simulating new process)...")
    auth2 = EnhancedAuthManager()
    
    print(f"Second instance - Session start time: {auth2.session_start_time}")
    print(f"Second instance - Session token: {auth2.session_token}")
    print(f"Second instance - Cached password: {'✅' if auth2.cached_password else '❌'}")
    print()
    
    # Try to recover session in second instance
    print("Attempting session recovery in second instance...")
    result = auth2._try_keychain_session()
    print(f"Recovery result - Success: {result.success}")
    print(f"Recovery result - Method: {result.method}")
    print(f"Recovery result - Error: {result.error_message}")
    
    if result.success:
        print(f"Recovered password length: {len(result.password) if result.password else 0}")
        print(f"Recovered session token: {result.session_token}")
        print("✅ Session persistence working!")
    else:
        print("❌ Session persistence failed!")
    print()


def main():
    """Main debug function"""
    print("🚀 PassGen Authentication Debug Tool")
    print("=" * 50)
    print()
    
    # Run all debug tests
    debug_keychain_operations()
    print("\n" + "=" * 50 + "\n")
    
    debug_auth_flow()
    print("\n" + "=" * 50 + "\n")
    
    debug_session_persistence()
    
    print("\n" + "=" * 50)
    print("🏁 Debug Complete")


if __name__ == "__main__":
    main()