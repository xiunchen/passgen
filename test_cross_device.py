#!/usr/bin/env python3
"""
跨设备恢复测试工具
模拟你的使用场景：设备A创建数据库 → 复制文件到设备B → 在设备B上恢复
"""

import sys
import os
import getpass
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.storage import SecureStorage
from core.enhanced_auth import EnhancedAuthManager
import keyring


def simulate_device_a():
    """模拟设备A：创建数据库并添加一些密码"""
    print("📱 模拟设备A：创建原始数据库")
    print("=" * 50)
    
    # 临时存储路径（模拟设备A）
    temp_dir = tempfile.mkdtemp(prefix="passgen_device_a_")
    device_a_db = Path(temp_dir) / "passgen.db"
    
    print(f"设备A数据库路径: {device_a_db}")
    
    # 创建存储管理器
    storage = SecureStorage(str(device_a_db))
    
    # 初始化数据库
    password = getpass.getpass("请设置设备A的主密码: ")
    
    if not storage.initialize(password):
        print("❌ 设备A初始化失败")
        return None, None
    
    print("✅ 设备A数据库初始化成功")
    
    # 添加一些测试数据
    print("\n📝 添加测试密码...")
    storage.add_password("github.com", "test123", password, username="user1", notes="开发账号")
    storage.add_password("gmail.com", "email456", password, username="user@email.com")
    storage.add_password("company.com", "work789", password, username="employee")
    
    print("✅ 已添加3个测试密码")
    
    # 验证数据
    passwords = storage.list_all_passwords(password)
    print(f"📊 数据库包含 {len(passwords)} 个密码条目")
    
    return str(device_a_db), password


def simulate_device_b(backup_file_path, original_password):
    """模拟设备B：复制文件后进行恢复"""
    print("\n📱 模拟设备B：复制文件并恢复")
    print("=" * 50)
    
    # 备份当前的数据库和Keychain（如果存在）
    home_db = Path.home() / ".passgen.db"
    backup_db = None
    if home_db.exists():
        backup_db = home_db.with_suffix(".db.backup")
        shutil.copy2(home_db, backup_db)
        print(f"📦 已备份现有数据库到: {backup_db}")
    
    backup_keychain = None
    try:
        keychain_data = keyring.get_password("PassGen", "master_key")
        if keychain_data:
            backup_keychain = keychain_data
            keyring.delete_password("PassGen", "master_key")
            print("📦 已备份并清除Keychain数据")
    except:
        pass
    
    try:
        # 复制文件到设备B
        print(f"\n📂 复制文件: {backup_file_path} → {home_db}")
        shutil.copy2(backup_file_path, home_db)
        
        print("🔧 模拟设备B初始化（生成新的Keychain数据）...")
        # 在设备B上，用户会执行 passgen init，这会生成新的Keychain数据
        storage_b = SecureStorage()
        new_password = getpass.getpass("设备B上设置的新密码: ")
        
        # 这会创建新的Keychain数据，但数据库文件是旧的
        storage_b.initialize(new_password)
        
        print("✅ 设备B初始化完成（但数据库文件会被覆盖）")
        
        # 现在恢复原始文件
        print("📂 恢复原始数据库文件...")
        shutil.copy2(backup_file_path, home_db)
        
        print("\n🔐 现在尝试访问数据库...")
        print("   这应该会检测到是备份文件并提示输入原始密码")
        
        # 测试认证流程
        auth_manager = EnhancedAuthManager()
        
        print("\n🧪 测试1: 尝试使用新密码（应该失败）")
        result1 = auth_manager._verify_password_with_database(new_password)
        print(f"新密码验证结果: {result1}")
        
        print("\n🧪 测试2: 检测备份文件")
        is_backup = auth_manager._detect_backup_file()
        print(f"备份文件检测结果: {is_backup}")
        
        print("\n🧪 测试3: 使用原始密码验证")
        result3 = auth_manager._verify_password_with_database(original_password)
        print(f"原始密码验证结果: {result3}")
        
        if result3:
            print("✅ 原始密码验证成功！")
            
            # 尝试读取数据
            storage_b = SecureStorage()
            passwords = storage_b.list_all_passwords(original_password)
            print(f"📊 成功读取 {len(passwords)} 个密码条目:")
            for p in passwords:
                print(f"   - {p.site} ({p.username})")
            
            print("\n🎉 跨设备恢复测试成功！")
            return True
        else:
            print("❌ 原始密码验证失败")
            return False
            
    except Exception as e:
        print(f"❌ 测试过程出错: {e}")
        return False
        
    finally:
        # 恢复备份
        if backup_db and backup_db.exists():
            shutil.copy2(backup_db, home_db)
            backup_db.unlink()
            print("🔄 已恢复原始数据库")
        
        if backup_keychain:
            keyring.set_password("PassGen", "master_key", backup_keychain)
            print("🔄 已恢复原始Keychain数据")


def test_new_format():
    """测试新文件格式的特性"""
    print("\n🔬 测试新文件格式特性")
    print("=" * 50)
    
    # 创建临时数据库
    temp_dir = tempfile.mkdtemp(prefix="passgen_format_test_")
    test_db = Path(temp_dir) / "test.db"
    
    storage = SecureStorage(str(test_db))
    password = "test123"
    
    # 初始化
    if not storage.initialize(password):
        print("❌ 格式测试初始化失败")
        return False
    
    print("✅ 数据库初始化成功")
    
    # 测试快速密码验证（无需解密整个文件）
    print("\n🧪 测试快速密码验证...")
    
    # 正确密码
    result1 = storage.verify_master_password(password)
    print(f"正确密码验证: {result1}")
    
    # 错误密码
    result2 = storage.verify_master_password("wrong")
    print(f"错误密码验证: {result2}")
    
    # 检查文件格式
    with open(test_db, 'rb') as f:
        header = f.read(4)
        print(f"文件头标识: {header}")
        
    if header == b"PGv2":
        print("✅ 文件格式正确")
    else:
        print("❌ 文件格式错误")
        return False
    
    # 添加数据并测试
    storage.add_password("test.com", "password123", password)
    passwords = storage.list_all_passwords(password)
    print(f"✅ 成功添加并读取密码，共 {len(passwords)} 条")
    
    # 清理
    shutil.rmtree(temp_dir)
    
    return True


def main():
    print("🧪 PassGen 跨设备恢复功能测试")
    print("=" * 60)
    print("此测试模拟以下场景：")
    print("1. 在设备A上创建数据库")
    print("2. 复制数据库文件到设备B")  
    print("3. 在设备B上初始化PassGen")
    print("4. 用备份文件替换新数据库")
    print("5. 测试自动检测和密码验证")
    print()
    
    # 测试新文件格式
    if not test_new_format():
        print("❌ 新文件格式测试失败")
        return
    
    # 模拟设备A
    device_a_db, original_password = simulate_device_a()
    if not device_a_db:
        print("❌ 设备A模拟失败")
        return
    
    # 模拟设备B
    success = simulate_device_b(device_a_db, original_password)
    
    # 清理设备A的临时文件
    try:
        os.remove(device_a_db)
        os.rmdir(os.path.dirname(device_a_db))
    except:
        pass
    
    if success:
        print("\n🎉 所有测试通过！跨设备恢复功能工作正常")
    else:
        print("\n💔 测试失败，需要进一步调试")


if __name__ == "__main__":
    main()