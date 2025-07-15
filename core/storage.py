"""
加密存储模块
提供安全的密码存储和检索功能
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
    """安全存储管理器"""
    
    SERVICE_NAME = "PassGen"
    MASTER_KEY_NAME = "master_key"
    SALT_SIZE = 32
    KEY_SIZE = 32
    NONCE_SIZE = 12
    
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
            # 生成盐值
            salt = os.urandom(self.SALT_SIZE)
            
            # 将盐值和主密码哈希存储到 Keychain
            key_data = {
                'salt': salt.hex(),
                'created_at': datetime.now().isoformat()
            }
            
            keyring.set_password(
                self.SERVICE_NAME, 
                self.MASTER_KEY_NAME, 
                json.dumps(key_data)
            )
            
            # 创建空的数据库文件
            empty_data = {
                "version": "1.0",
                "passwords": [],
                "created_at": datetime.now().isoformat()
            }
            
            self._save_encrypted_data(empty_data, master_password)
            return True
            
        except Exception as e:
            print(f"初始化失败: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """检查是否已初始化"""
        try:
            key_data = keyring.get_password(self.SERVICE_NAME, self.MASTER_KEY_NAME)
            return key_data is not None and self.storage_path.exists()
        except:
            return False
    
    def verify_master_password(self, master_password: str) -> bool:
        """
        验证主密码
        
        Args:
            master_password: 主密码
            
        Returns:
            验证是否成功
        """
        try:
            self._load_encrypted_data(master_password)
            return True
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
    
    def _get_master_key_data(self) -> Dict[str, str]:
        """从Keychain获取主密钥数据"""
        key_data_str = keyring.get_password(self.SERVICE_NAME, self.MASTER_KEY_NAME)
        if not key_data_str:
            raise ValueError("未找到主密钥数据，请先初始化")
        
        return json.loads(key_data_str)
    
    def _load_encrypted_data(self, master_password: str) -> Dict[str, Any]:
        """加载并解密数据"""
        if not self.storage_path.exists():
            raise FileNotFoundError("存储文件不存在")
        
        # 获取盐值
        key_data = self._get_master_key_data()
        salt = bytes.fromhex(key_data['salt'])
        
        # 派生密钥
        key = self._derive_key(master_password, salt)
        
        # 读取加密数据
        with open(self.storage_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 分离nonce和密文
        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]
        
        # 解密
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode())
        except Exception as e:
            raise ValueError("解密失败，密码可能不正确") from e
    
    def _save_encrypted_data(self, data: Dict[str, Any], master_password: str):
        """加密并保存数据"""
        # 获取盐值
        key_data = self._get_master_key_data()
        salt = bytes.fromhex(key_data['salt'])
        
        # 派生密钥
        key = self._derive_key(master_password, salt)
        
        # 序列化数据
        plaintext = json.dumps(data, ensure_ascii=False, indent=2).encode()
        
        # 生成随机nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # 加密
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # 保存到文件
        with open(self.storage_path, 'wb') as f:
            f.write(nonce + ciphertext)
        
        # 设置文件权限
        os.chmod(self.storage_path, 0o600)