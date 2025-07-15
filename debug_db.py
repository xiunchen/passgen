#!/usr/bin/env python3
"""
数据库调试工具
"""

import sys
import os
import json
import getpass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import keyring

def analyze_database():
    """分析数据库文件结构"""
    db_path = os.path.expanduser("~/.passgen.db")
    
    print("🔍 数据库文件分析")
    print("=" * 50)
    
    with open(db_path, 'rb') as f:
        data = f.read()
    
    print(f"📊 文件大小: {len(data)} 字节")
    print(f"📊 文件路径: {db_path}")
    
    if os.path.islink(db_path):
        real_path = os.readlink(db_path)
        print(f"🔗 软链接目标: {real_path}")
    
    print(f"\n📖 文件内容分析:")
    print(f"前12字节 (nonce): {data[:12].hex()}")
    print(f"第13-44字节:     {data[12:44].hex()}")
    print(f"第45-76字节:     {data[44:76].hex()}")
    print(f"最后32字节:      {data[-32:].hex()}")
    
    return data

def test_current_keychain():
    """测试当前钥匙串中的信息"""
    print("\n🔑 钥匙串信息分析")
    print("=" * 50)
    
    try:
        master_key = keyring.get_password("PassGen", "master_key")
        if master_key:
            key_info = json.loads(master_key)
            print("✅ 找到 master_key:")
            print(f"   盐值: {key_info['salt'][:32]}...")
            print(f"   创建时间: {key_info['created_at']}")
            if 'recovered' in key_info:
                print(f"   恢复标记: {key_info['recovered']}")
            return bytes.fromhex(key_info['salt'])
        else:
            print("❌ 未找到 master_key")
            return None
    except Exception as e:
        print(f"❌ 读取 master_key 失败: {e}")
        return None

def test_decryption_with_salt(password, salt, nonce, ciphertext):
    """测试解密"""
    try:
        # 派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # 尝试解密
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # 尝试解析JSON
        data = json.loads(plaintext.decode())
        
        print("✅ 解密成功！")
        print(f"📊 数据结构: {list(data.keys())}")
        if 'passwords' in data:
            print(f"📊 密码条目数: {len(data['passwords'])}")
        if 'version' in data:
            print(f"📊 数据版本: {data['version']}")
        
        return True, data
        
    except Exception as e:
        print(f"❌ 解密失败: {e}")
        return False, None

def comprehensive_test(password):
    """综合测试"""
    print(f"\n🧪 综合解密测试")
    print("=" * 50)
    
    # 分析数据库
    data = analyze_database()
    nonce = data[:12]
    ciphertext = data[12:]
    
    # 测试当前钥匙串盐值
    current_salt = test_current_keychain()
    if current_salt:
        print(f"\n测试1: 使用当前钥匙串盐值 ({len(current_salt)} 字节)")
        success, result = test_decryption_with_salt(password, current_salt, nonce, ciphertext)
        if success:
            return True
    
    # 测试从文件中提取的候选盐值
    candidate_salts = []
    if len(data) >= 44:
        candidate_salts = [
            data[:32],       # 前32字节
            data[12:44],     # nonce后32字节  
            ciphertext[:32] if len(ciphertext) >= 32 else None,  # 密文前32字节
        ]
    
    candidate_salts = [s for s in candidate_salts if s is not None]
    
    for i, salt in enumerate(candidate_salts):
        print(f"\n测试{i+2}: 候选盐值 {i+1} ({len(salt)} 字节)")
        print(f"盐值: {salt.hex()[:32]}...")
        success, result = test_decryption_with_salt(password, salt, nonce, ciphertext)
        if success:
            return True
    
    # 测试特殊情况
    import hashlib
    special_salts = [
        b"",  # 空盐值
        password.encode(),  # 密码作为盐值
        b"PassGen",  # 固定字符串
        hashlib.sha256(password.encode()).digest(),  # 密码SHA256
        hashlib.sha256(b"PassGen" + password.encode()).digest(),  # PassGen+密码
    ]
    
    for i, salt in enumerate(special_salts):
        print(f"\n测试{len(candidate_salts)+i+2}: 特殊盐值 {i+1} ({len(salt)} 字节)")
        if len(salt) <= 32:
            print(f"盐值: {salt.hex()}")
        else:
            print(f"盐值: {salt.hex()[:32]}...")
        success, result = test_decryption_with_salt(password, salt, nonce, ciphertext)
        if success:
            return True
    
    print("\n❌ 所有测试都失败了")
    return False

def main():
    print("🔍 PassGen 数据库深度分析工具")
    print("=" * 60)
    
    password = getpass.getpass("请输入数据库密码: ")
    
    if comprehensive_test(password):
        print("\n🎉 找到了正确的解密方法！")
    else:
        print("\n💔 无法解密数据库，可能原因:")
        print("  1. 密码不正确")
        print("  2. 数据库文件损坏")  
        print("  3. 加密格式不同")
        print("  4. 需要其他参数（迭代次数、算法等）")

if __name__ == "__main__":
    main()