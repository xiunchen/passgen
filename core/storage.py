"""
加密存储模块
提供安全的密码存储和检索功能
支持自包含的数据库文件格式，可跨设备恢复
"""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import keyring


@dataclass
class PasswordEntry:
    """密码条目"""
    id: str
    site: str
    password: str
    created_at: str
    updated_at: str
    tags: List[str] = None
    notes: str = ""
    username: str = ""
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class SecureStorage:
    """
    安全存储管理器
    
    文件格式 v2:
    [4字节: "PGv2"] + [32字节: 验证盐值] + [32字节: 验证哈希] + 
    [32字节: 加密盐值] + [12字节: nonce] + [密文]
    
    特点:
    - 密码验证无需解密整个文件
    - 文件完全自包含，支持跨设备恢复
    - 双重盐值设计，提高安全性
    """
    
    SERVICE_NAME = "PassGen"
    MASTER_KEY_NAME = "master_key"
    
    # 文件格式标识
    FILE_VERSION = b"PGv2"
    VERSION_SIZE = 4
    
    # 加密参数
    VERIFY_SALT_SIZE = 32
    VERIFY_HASH_SIZE = 32
    ENCRYPT_SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32
    
    # 文件头总大小
    HEADER_SIZE = VERSION_SIZE + VERIFY_SALT_SIZE + VERIFY_HASH_SIZE + ENCRYPT_SALT_SIZE + NONCE_SIZE
    
    def __init__(self, storage_path: str = None):
        """
        初始化存储管理器
        
        Args:
            storage_path: 存储文件路径，默认为用户主目录下的.passgen.db
        """
        if storage_path is None:
            home = Path.home()
            storage_path = home / ".passgen.db"
        
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 设置文件权限（仅用户可读写）
        if self.storage_path.exists():
            os.chmod(self.storage_path, 0o600)
    
    def initialize(self, master_password: str) -> bool:
        """
        初始化存储（设置主密码）
        
        Args:
            master_password: 主密码
            
        Returns:
            初始化是否成功
        """
        try:
            # 生成两个不同的盐值
            verify_salt = os.urandom(self.VERIFY_SALT_SIZE)
            encrypt_salt = os.urandom(self.ENCRYPT_SALT_SIZE)
            
            # 生成密码验证哈希
            verify_hash = self._generate_verification_hash(master_password, verify_salt)
            
            # 生成随机nonce
            nonce = os.urandom(self.NONCE_SIZE)
            
            # 创建空的数据库内容
            empty_data = {
                "version": "2.0",
                "passwords": [],
                "created_at": datetime.now().isoformat()
            }
            
            # 加密数据
            key = self._derive_key(master_password, encrypt_salt)
            plaintext = json.dumps(empty_data, ensure_ascii=False, indent=2).encode()
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # 保存文件
            with open(self.storage_path, 'wb') as f:
                f.write(self.FILE_VERSION)
                f.write(verify_salt)
                f.write(verify_hash)
                f.write(encrypt_salt)
                f.write(nonce)
                f.write(ciphertext)
            
            # 设置文件权限
            os.chmod(self.storage_path, 0o600)
            
            # 同步盐值信息到Keychain（用于Touch ID集成）
            self._sync_to_keychain(verify_salt, encrypt_salt)
            
            return True
            
        except Exception as e:
            print(f"初始化失败: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """检查是否已初始化"""
        if not self.storage_path.exists():
            return False
        
        try:
            with open(self.storage_path, 'rb') as f:
                version = f.read(self.VERSION_SIZE)
                return version == self.FILE_VERSION
        except:
            return False
    
    def verify_master_password(self, master_password: str) -> bool:
        """
        验证主密码（无需解密整个文件）
        
        Args:
            master_password: 主密码
            
        Returns:
            验证是否成功
        """
        if not self.is_initialized():
            return False
        
        try:
            with open(self.storage_path, 'rb') as f:
                # 读取文件头
                f.read(self.VERSION_SIZE)  # 跳过版本
                verify_salt = f.read(self.VERIFY_SALT_SIZE)
                stored_hash = f.read(self.VERIFY_HASH_SIZE)
            
            # 计算验证哈希
            computed_hash = self._generate_verification_hash(master_password, verify_salt)
            
            # 比较哈希
            return computed_hash == stored_hash
            
        except:
            return False
    
    def add_password(self, site: str, password: str, master_password: str,
                    username: str = "", notes: str = "", tags: List[str] = None) -> str:
        """
        添加密码
        
        Args:
            site: 网站或应用名称
            password: 密码
            master_password: 主密码
            username: 用户名
            notes: 备注
            tags: 标签列表
            
        Returns:
            新添加条目的ID
            
        Raises:
            ValueError: 当输入无效时
        """
        # 输入验证
        if not site or not site.strip():
            raise ValueError("网站/应用名称不能为空")
        if not password:
            raise ValueError("密码不能为空")
        if len(password) < 1:
            raise ValueError("密码长度至少为1位")
        if len(site.strip()) > 200:
            raise ValueError("网站/应用名称不能超过200个字符")
        if len(notes) > 1000:
            raise ValueError("备注不能超过1000个字符")
            
        data = self._load_encrypted_data(master_password)
        
        entry_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        entry = PasswordEntry(
            id=entry_id,
            site=site,
            password=password,
            created_at=now,
            updated_at=now,
            username=username,
            notes=notes,
            tags=tags or []
        )
        
        data['passwords'].append(asdict(entry))
        self._save_encrypted_data(data, master_password)
        
        return entry_id
    
    def get_password(self, entry_id: str, master_password: str) -> Optional[PasswordEntry]:
        """
        获取密码条目
        
        Args:
            entry_id: 条目ID
            master_password: 主密码
            
        Returns:
            密码条目，如果不存在则返回None
        """
        data = self._load_encrypted_data(master_password)
        
        for entry_data in data['passwords']:
            if entry_data['id'] == entry_id:
                return PasswordEntry(**entry_data)
        
        return None
    
    def update_password(self, entry_id: str, master_password: str, **kwargs) -> bool:
        """
        更新密码条目
        
        Args:
            entry_id: 条目ID
            master_password: 主密码
            **kwargs: 要更新的字段
            
        Returns:
            更新是否成功
        """
        data = self._load_encrypted_data(master_password)
        
        for entry_data in data['passwords']:
            if entry_data['id'] == entry_id:
                # 更新字段
                for key, value in kwargs.items():
                    if key in entry_data:
                        entry_data[key] = value
                
                # 更新时间
                entry_data['updated_at'] = datetime.now().isoformat()
                
                self._save_encrypted_data(data, master_password)
                return True
        
        return False
    
    def delete_password(self, entry_id: str, master_password: str) -> bool:
        """
        删除密码条目
        
        Args:
            entry_id: 条目ID
            master_password: 主密码
            
        Returns:
            删除是否成功
        """
        data = self._load_encrypted_data(master_password)
        
        original_count = len(data['passwords'])
        data['passwords'] = [
            entry for entry in data['passwords'] 
            if entry['id'] != entry_id
        ]
        
        if len(data['passwords']) < original_count:
            self._save_encrypted_data(data, master_password)
            return True
        
        return False
    
    def search_passwords(self, query: str, master_password: str) -> List[PasswordEntry]:
        """
        搜索密码条目
        
        Args:
            query: 搜索关键词
            master_password: 主密码
            
        Returns:
            匹配的密码条目列表
        """
        data = self._load_encrypted_data(master_password)
        results = []
        
        query_lower = query.lower()
        
        for entry_data in data['passwords']:
            # 搜索网站名、用户名、备注和标签
            searchable_text = ' '.join([
                entry_data.get('site', ''),
                entry_data.get('username', ''),
                entry_data.get('notes', ''),
                ' '.join(entry_data.get('tags', []))
            ]).lower()
            
            if query_lower in searchable_text:
                results.append(PasswordEntry(**entry_data))
        
        # 按更新时间排序（最新的在前）
        results.sort(key=lambda x: x.updated_at, reverse=True)
        
        return results
    
    def list_all_passwords(self, master_password: str) -> List[PasswordEntry]:
        """
        获取所有密码条目
        
        Args:
            master_password: 主密码
            
        Returns:
            所有密码条目列表
        """
        data = self._load_encrypted_data(master_password)
        
        entries = [PasswordEntry(**entry_data) for entry_data in data['passwords']]
        # 按更新时间排序（最新的在前）
        entries.sort(key=lambda x: x.updated_at, reverse=True)
        
        return entries
    
    def export_data(self, master_password: str) -> Dict[str, Any]:
        """
        导出所有数据（用于备份）
        
        Args:
            master_password: 主密码
            
        Returns:
            包含所有数据的字典
        """
        return self._load_encrypted_data(master_password)
    
    def import_data(self, data: Dict[str, Any], master_password: str) -> bool:
        """
        导入数据（用于恢复备份）
        
        Args:
            data: 要导入的数据
            master_password: 主密码
            
        Returns:
            导入是否成功
        """
        try:
            # 验证数据格式
            if 'passwords' not in data or not isinstance(data['passwords'], list):
                return False
            
            self._save_encrypted_data(data, master_password)
            return True
        except:
            return False
    
    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        更改主密码
        
        Args:
            current_password: 当前密码
            new_password: 新密码
            
        Returns:
            更改是否成功
        """
        try:
            # 1. 验证当前密码
            if not self.verify_master_password(current_password):
                return False
            
            # 2. 读取所有数据
            data = self._load_encrypted_data(current_password)
            
            # 3. 生成新的盐值和验证哈希
            new_verify_salt = os.urandom(self.VERIFY_SALT_SIZE)
            new_encrypt_salt = os.urandom(self.ENCRYPT_SALT_SIZE)
            new_verify_hash = self._generate_verification_hash(new_password, new_verify_salt)
            
            # 4. 生成新的nonce
            new_nonce = os.urandom(self.NONCE_SIZE)
            
            # 5. 用新密码加密数据
            new_key = self._derive_key(new_password, new_encrypt_salt)
            plaintext = json.dumps(data, ensure_ascii=False, indent=2).encode()
            aesgcm = AESGCM(new_key)
            new_ciphertext = aesgcm.encrypt(new_nonce, plaintext, None)
            
            # 6. 保存新的加密文件
            with open(self.storage_path, 'wb') as f:
                f.write(self.FILE_VERSION)
                f.write(new_verify_salt)
                f.write(new_verify_hash)
                f.write(new_encrypt_salt)
                f.write(new_nonce)
                f.write(new_ciphertext)
            
            # 7. 设置文件权限
            os.chmod(self.storage_path, 0o600)
            
            # 8. 同步新的盐值到Keychain
            self._sync_to_keychain(new_verify_salt, new_encrypt_salt)
            
            return True
            
        except Exception as e:
            print(f"更改主密码失败: {e}")
            return False
    
    def recover_from_file(self, file_path: str, password: str) -> bool:
        """
        从备份文件恢复（支持跨设备恢复）
        
        Args:
            file_path: 备份文件路径
            password: 备份文件的密码
            
        Returns:
            恢复是否成功
        """
        try:
            # 读取备份文件
            with open(file_path, 'rb') as f:
                backup_data = f.read()
            
            # 验证文件格式
            if len(backup_data) < self.HEADER_SIZE:
                return False
            
            if backup_data[:self.VERSION_SIZE] != self.FILE_VERSION:
                return False
            
            # 验证密码
            verify_salt = backup_data[self.VERSION_SIZE:self.VERSION_SIZE + self.VERIFY_SALT_SIZE]
            stored_hash = backup_data[self.VERSION_SIZE + self.VERIFY_SALT_SIZE:
                                    self.VERSION_SIZE + self.VERIFY_SALT_SIZE + self.VERIFY_HASH_SIZE]
            
            computed_hash = self._generate_verification_hash(password, verify_salt)
            if computed_hash != stored_hash:
                return False
            
            # 密码正确，复制文件
            with open(self.storage_path, 'wb') as f:
                f.write(backup_data)
            
            os.chmod(self.storage_path, 0o600)
            
            # 同步盐值到Keychain
            encrypt_salt = backup_data[self.VERSION_SIZE + self.VERIFY_SALT_SIZE + self.VERIFY_HASH_SIZE:
                                      self.VERSION_SIZE + self.VERIFY_SALT_SIZE + self.VERIFY_HASH_SIZE + self.ENCRYPT_SALT_SIZE]
            self._sync_to_keychain(verify_salt, encrypt_salt)
            
            return True
            
        except Exception as e:
            print(f"恢复失败: {e}")
            return False
    
    def _generate_verification_hash(self, password: str, salt: bytes) -> bytes:
        """生成密码验证哈希"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.VERIFY_HASH_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """从密码派生加密密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _load_encrypted_data(self, master_password: str) -> Dict[str, Any]:
        """加载并解密数据"""
        if not self.storage_path.exists():
            raise FileNotFoundError("数据库文件不存在，请先运行 'passgen init' 进行初始化")
        
        with open(self.storage_path, 'rb') as f:
            # 读取文件头
            version = f.read(self.VERSION_SIZE)
            if version != self.FILE_VERSION:
                raise ValueError("不支持的文件格式版本")
            
            verify_salt = f.read(self.VERIFY_SALT_SIZE)
            stored_hash = f.read(self.VERIFY_HASH_SIZE)
            encrypt_salt = f.read(self.ENCRYPT_SALT_SIZE)
            nonce = f.read(self.NONCE_SIZE)
            ciphertext = f.read()
        
        # 验证密码
        computed_hash = self._generate_verification_hash(master_password, verify_salt)
        if computed_hash != stored_hash:
            raise ValueError("密码错误")
        
        # 解密数据
        key = self._derive_key(master_password, encrypt_salt)
        aesgcm = AESGCM(key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())
        except Exception as e:
            raise ValueError("解密失败") from e
    
    def _save_encrypted_data(self, data: Dict[str, Any], master_password: str):
        """加密并保存数据"""
        # 读取现有文件的盐值信息
        with open(self.storage_path, 'rb') as f:
            f.read(self.VERSION_SIZE)
            verify_salt = f.read(self.VERIFY_SALT_SIZE)
            stored_hash = f.read(self.VERIFY_HASH_SIZE)
            encrypt_salt = f.read(self.ENCRYPT_SALT_SIZE)
        
        # 生成新的nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # 加密数据
        key = self._derive_key(master_password, encrypt_salt)
        plaintext = json.dumps(data, ensure_ascii=False, indent=2).encode()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # 保存到文件
        with open(self.storage_path, 'wb') as f:
            f.write(self.FILE_VERSION)
            f.write(verify_salt)
            f.write(stored_hash)
            f.write(encrypt_salt)
            f.write(nonce)
            f.write(ciphertext)
        
        # 设置文件权限
        os.chmod(self.storage_path, 0o600)
    
    def _sync_to_keychain(self, verify_salt: bytes, encrypt_salt: bytes):
        """同步盐值信息到Keychain（用于Touch ID集成）"""
        try:
            key_data = {
                'encrypt_salt': encrypt_salt.hex(),
                'verify_salt': verify_salt.hex(),
                'created_at': datetime.now().isoformat(),
                'format_version': 'v2'
            }
            
            keyring.set_password(
                self.SERVICE_NAME,
                self.MASTER_KEY_NAME,
                json.dumps(key_data)
            )
        except Exception as e:
            # Keychain同步失败不影响主要功能
            print(f"⚠️ Keychain同步失败: {e}")