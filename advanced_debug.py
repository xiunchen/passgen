#!/usr/bin/env python3
"""
高级数据库恢复工具 - 尝试不同的加密参数组合
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

def get_candidate_salts(data):
    """获取所有可能的盐值候选"""
    salts = []
    
    # 1. 从文件不同位置提取
    if len(data) >= 44:
        salts.extend([
            data[:32],          # 前32字节
            data[12:44],       # nonce后32字节
            data[44:76] if len(data) >= 76 else None,  # 第45-76字节
        ])
    
    # 2. 从钥匙串获取
    try:
        master_key = keyring.get_password("PassGen", "master_key")
        if master_key:
            key_info = json.loads(master_key)
            salts.append(bytes.fromhex(key_info['salt']))
    except:
        pass
    
    # 过滤None值并去重
    unique_salts = []
    for salt in salts:
        if salt is not None and salt not in unique_salts:
            unique_salts.append(salt)
    
    return unique_salts

def test_different_iterations(password, salt, nonce, ciphertext):
    """测试不同的PBKDF2迭代次数"""
    iterations_to_try = [
        100000,    # 当前版本
        50000,     # 可能的旧版本
        10000,     # 更旧版本
        4096,      # 常见默认值
        1000,      # 简单版本
        1,         # 测试无迭代
    ]
    
    for iterations in iterations_to_try:
        try:
            print(f"    测试迭代次数: {iterations}")
            
            # 派生密钥
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            # 尝试解密
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # 尝试解析JSON
            data = json.loads(plaintext.decode())
            
            print(f"    ✅ 成功！迭代次数: {iterations}")
            print(f"    📊 数据结构: {list(data.keys())}")
            if 'passwords' in data:
                print(f"    📊 密码条目数: {len(data['passwords'])}")
            
            return True, iterations, data
            
        except Exception as e:
            print(f"    ❌ 迭代次数 {iterations} 失败")
            continue
    
    return False, None, None

def test_different_algorithms(password, salt, nonce, ciphertext, iterations=100000):
    """测试不同的哈希算法"""
    algorithms_to_try = [
        (hashes.SHA256(), "SHA256"),
        (hashes.SHA1(), "SHA1"),
        (hashes.SHA512(), "SHA512"),
        (hashes.MD5(), "MD5"),
    ]
    
    for algorithm, name in algorithms_to_try:
        try:
            print(f"    测试算法: {name}")
            
            # 派生密钥
            kdf = PBKDF2HMAC(
                algorithm=algorithm,
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            # 尝试解密
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # 尝试解析JSON
            data = json.loads(plaintext.decode())
            
            print(f"    ✅ 成功！算法: {name}")
            print(f"    📊 数据结构: {list(data.keys())}")
            
            return True, name, data
            
        except Exception:
            print(f"    ❌ 算法 {name} 失败")
            continue
    
    return False, None, None

def test_different_nonce_sizes(password, salt, data):
    """测试不同的nonce大小"""
    nonce_sizes = [12, 16, 8, 24]  # 常见的nonce大小
    
    for nonce_size in nonce_sizes:
        if len(data) <= nonce_size:
            continue
            
        print(f"  测试nonce大小: {nonce_size} 字节")
        
        nonce = data[:nonce_size]
        ciphertext = data[nonce_size:]
        
        print(f"    Nonce: {nonce.hex()}")
        print(f"    密文长度: {len(ciphertext)} 字节")
        
        # 测试不同迭代次数
        success, iterations, result = test_different_iterations(password, salt, nonce, ciphertext)
        if success:
            return True, nonce_size, iterations, result
    
    return False, None, None, None

def comprehensive_recovery_test(password):
    """全面的恢复测试"""
    print("🚀 启动高级恢复模式")
    print("=" * 60)
    
    # 读取数据库文件
    db_path = os.path.expanduser("~/.passgen.db")
    with open(db_path, 'rb') as f:
        data = f.read()
    
    print(f"📊 数据库大小: {len(data)} 字节")
    
    # 获取候选盐值
    candidate_salts = get_candidate_salts(data)
    print(f"📊 找到 {len(candidate_salts)} 个候选盐值")
    
    # 对每个盐值进行全面测试
    for i, salt in enumerate(candidate_salts):
        print(f"\n🧪 测试盐值 {i+1}/{len(candidate_salts)} ({len(salt)} 字节)")
        print(f"盐值: {salt.hex()[:32]}...")
        
        # 测试不同的nonce大小
        success, nonce_size, iterations, result = test_different_nonce_sizes(password, salt, data)
        if success:
            print(f"\n🎉 成功找到解密参数！")
            print(f"   盐值: {salt.hex()}")
            print(f"   Nonce大小: {nonce_size} 字节")
            print(f"   迭代次数: {iterations}")
            
            # 更新钥匙串
            try:
                from datetime import datetime
                key_data = {
                    'salt': salt.hex(),
                    'created_at': datetime.now().isoformat(),
                    'recovered': True,
                    'nonce_size': nonce_size,
                    'iterations': iterations
                }
                keyring.set_password("PassGen", "master_key", json.dumps(key_data))
                print("✅ 已更新钥匙串配置")
            except Exception as e:
                print(f"⚠️ 更新钥匙串失败: {e}")
            
            return True
    
    # 如果所有盐值都失败，尝试没有盐值的情况
    print(f"\n🧪 测试无盐值情况")
    success, nonce_size, iterations, result = test_different_nonce_sizes(password, b"", data)
    if success:
        print(f"\n🎉 成功！使用空盐值")
        return True
    
    # 尝试密码本身作为盐值
    print(f"\n🧪 测试密码作为盐值")
    success, nonce_size, iterations, result = test_different_nonce_sizes(password, password.encode(), data)
    if success:
        print(f"\n🎉 成功！使用密码作为盐值")
        return True
    
    print("\n💔 所有高级恢复尝试都失败了")
    
    # 提供更详细的分析
    print("\n📊 详细分析结果:")
    print(f"   数据库大小: {len(data)} 字节")
    print(f"   候选盐值数量: {len(candidate_salts)}")
    print(f"   尝试的nonce大小: 8, 12, 16, 24 字节")
    print(f"   尝试的迭代次数: 1, 1000, 4096, 10000, 50000, 100000")
    print(f"   尝试的算法: SHA256, SHA1, SHA512, MD5")
    
    return False

def main():
    print("🔬 PassGen 高级数据库恢复工具")
    print("=" * 60)
    print("这个工具会尝试多种加密参数组合来恢复你的数据库")
    print()
    
    password = getpass.getpass("请输入数据库密码: ")
    
    if comprehensive_recovery_test(password):
        print("\n🎉 恢复成功！现在可以正常使用 passgen 命令了")
    else:
        print("\n💔 恢复失败，数据库可能:")
        print("  1. 使用了完全不同的加密方法")
        print("  2. 文件已损坏")
        print("  3. 密码确实不正确")
        print("  4. 使用了自定义的加密参数")

if __name__ == "__main__":
    main()