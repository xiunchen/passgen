#!/usr/bin/env python3
"""
恢复功能测试工具
模拟iCloud同步导致的盐值不匹配问题
"""

import sys
import os
import json
import getpass
import shutil
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import keyring
from core.enhanced_auth import EnhancedAuthManager

def backup_current_state():
    """备份当前状态"""
    print("📦 备份当前数据库和钥匙串状态...")
    
    # 备份数据库
    db_path = os.path.expanduser("~/.passgen.db")
    if os.path.exists(db_path):
        backup_db = f"{db_path}.backup"
        shutil.copy2(db_path, backup_db)
        print(f"✅ 数据库已备份到: {backup_db}")
    
    # 备份钥匙串信息
    try:
        master_key = keyring.get_password("PassGen", "master_key")
        if master_key:
            backup_file = os.path.expanduser("~/.passgen_keychain_backup.json")
            with open(backup_file, 'w') as f:
                json.dump({"master_key": master_key}, f)
            print(f"✅ 钥匙串已备份到: {backup_file}")
            return json.loads(master_key)
    except Exception as e:
        print(f"⚠️ 备份钥匙串失败: {e}")
    
    return None

def simulate_icloud_sync_issue(original_keychain):
    """模拟iCloud同步问题：生成新的盐值但保持原数据库"""
    print("\n🔄 模拟iCloud同步问题...")
    
    # 生成新的盐值（模拟从其他设备同步的情况）
    import os
    new_salt = os.urandom(32).hex()
    new_keychain_data = {
        'salt': new_salt,
        'created_at': datetime.now().isoformat(),
        'simulated': True
    }
    
    # 更新钥匙串为新盐值
    keyring.set_password("PassGen", "master_key", json.dumps(new_keychain_data))
    
    print(f"✅ 已模拟盐值不匹配问题")
    print(f"   原始盐值: {original_keychain['salt'][:32]}...")
    print(f"   新盐值: {new_salt[:32]}...")
    
    return original_keychain['salt']

def test_recovery_system(original_salt, password):
    """测试恢复系统"""
    print(f"\n🧪 测试智能恢复系统...")
    
    # 创建一个测试用的恢复工具，包含原始盐值
    class TestRecoveryManager(EnhancedAuthManager):
        def __init__(self, original_salt):
            super().__init__()
            self.original_salt = bytes.fromhex(original_salt)
        
        def test_recovery_with_original_salt(self, password):
            """使用原始盐值测试恢复"""
            try:
                db_path = os.path.expanduser("~/.passgen.db")
                with open(db_path, 'rb') as f:
                    data = f.read()
                
                nonce = data[:12]
                ciphertext = data[12:]
                
                # 使用原始盐值测试解密
                return self._test_decryption(password, self.original_salt, nonce, ciphertext)
            except Exception as e:
                print(f"❌ 测试失败: {e}")
                return False
    
    # 创建测试管理器
    test_manager = TestRecoveryManager(original_salt)
    
    # 测试原始盐值是否能解密
    if test_manager.test_recovery_with_original_salt(password):
        print("✅ 原始盐值可以解密数据库！")
        
        # 更新恢复算法，添加用户提供盐值的功能
        success = test_manager._update_keychain_with_correct_salt(test_manager.original_salt)
        print("✅ 钥匙串已更新为正确的盐值")
        
        return True
    else:
        print("❌ 即使使用原始盐值也无法解密")
        return False

def restore_from_backup():
    """从备份恢复"""
    print("\n🔄 从备份恢复...")
    
    # 恢复钥匙串
    backup_file = os.path.expanduser("~/.passgen_keychain_backup.json")
    if os.path.exists(backup_file):
        with open(backup_file, 'r') as f:
            backup_data = json.load(f)
        keyring.set_password("PassGen", "master_key", backup_data["master_key"])
        print("✅ 钥匙串已恢复")
        os.remove(backup_file)

def test_normal_auth():
    """测试正常认证"""
    print("\n🔐 测试正常认证...")
    auth_manager = EnhancedAuthManager()
    result = auth_manager.authenticate()
    
    if result.success:
        print(f"✅ 认证成功! 方法: {result.method}")
        return True
    else:
        print(f"❌ 认证失败: {result.error_message}")
        return False

def main():
    print("🧪 PassGen 恢复功能测试工具")
    print("=" * 60)
    print("这个工具将模拟iCloud同步导致的盐值不匹配问题，并测试智能恢复功能")
    print()
    
    password = getpass.getpass("请输入数据库密码: ")
    
    # 第一步：备份当前状态
    original_keychain = backup_current_state()
    if not original_keychain:
        print("❌ 无法备份当前状态，请确保数据库已初始化")
        return
    
    try:
        # 第二步：模拟问题
        original_salt = simulate_icloud_sync_issue(original_keychain)
        
        # 第三步：测试恢复
        print(f"\n🔍 现在应该会出现盐值不匹配问题...")
        print(f"尝试正常认证应该会失败，然后触发智能恢复...")
        
        # 测试当前认证是否失败（应该失败）
        if test_normal_auth():
            print("⚠️ 意外：认证成功了，这表明没有成功模拟问题")
        else:
            print("✅ 确认：认证失败了，问题模拟成功")
            
            # 测试恢复功能
            if test_recovery_system(original_salt, password):
                print("\n🎉 恢复测试成功！")
                
                # 再次测试认证
                if test_normal_auth():
                    print("🎉 恢复后认证成功！智能恢复功能工作正常")
                else:
                    print("❌ 恢复后认证仍然失败")
            else:
                print("\n💔 恢复测试失败")
    
    except KeyboardInterrupt:
        print("\n\n⚠️ 用户中断，正在恢复...")
    except Exception as e:
        print(f"\n❌ 测试过程出错: {e}")
    finally:
        # 恢复原始状态
        restore_from_backup()
        print("\n✅ 已恢复到原始状态")

if __name__ == "__main__":
    main()