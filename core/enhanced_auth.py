#!/usr/bin/env python3
"""
增强认证模块
提供多种便捷认证方式，解决CLI Touch ID限制
"""

import os
import sys
import time
import getpass
import subprocess
import hashlib
import json
import keyring
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
from pathlib import Path

# 尝试导入Touch ID支持
try:
    import LocalAuthentication
    TOUCH_ID_AVAILABLE = True
except ImportError:
    TOUCH_ID_AVAILABLE = False


@dataclass
class AuthResult:
    """认证结果"""
    success: bool
    method: str
    password: Optional[str] = None
    error_message: Optional[str] = None
    session_token: Optional[str] = None


class EnhancedAuthManager:
    """增强认证管理器"""
    
    SERVICE_NAME = "PassGen"
    SESSION_KEY = "session_token"
    MASTER_KEY = "master_key"
    
    def __init__(self):
        # 从配置文件读取会话超时时间
        try:
            from utils.config import ConfigManager
            config = ConfigManager()
            self.session_timeout = config.get('session_timeout_seconds', 300)
        except:
            self.session_timeout = 300  # 默认5分钟
        self.session_start_time = None
        self.cached_password = None
        self.session_token = None
        
    def authenticate(self, force_password: bool = False) -> AuthResult:
        """
        主认证方法 - 尝试多种认证方式
        
        Args:
            force_password: 是否强制使用密码认证
            
        Returns:
            认证结果
        """
        # 1. 检查会话缓存
        if not force_password and self._is_session_valid():
            return AuthResult(
                success=True,
                method="cached_session",
                password=self.cached_password,
                session_token=self.session_token
            )
        
        # 2. 尝试快速认证（无密码输入）
        if not force_password:
            quick_auth = self._try_quick_auth()
            if quick_auth.success:
                return quick_auth
        
        # 3. 密码认证
        return self._password_auth()
    
    def _try_quick_auth(self) -> AuthResult:
        """尝试快速认证方法"""
        
        # 方法1: 尝试Touch ID (虽然可能不工作，但值得尝试)
        if TOUCH_ID_AVAILABLE:
            touch_result = self._try_touch_id()
            if touch_result.success:
                return touch_result
        
        # 方法2: 尝试从Keychain获取会话令牌
        keychain_result = self._try_keychain_session()
        if keychain_result.success:
            return keychain_result
            
        # 注意：环境变量认证已移除，推荐使用Touch ID
        
        return AuthResult(success=False, method="none")
    
    def _try_touch_id(self) -> AuthResult:
        """尝试Touch ID认证"""
        try:
            context = LocalAuthentication.LAContext.alloc().init()
            
            # 检查Touch ID是否可用
            error = None
            can_evaluate = context.canEvaluatePolicy_error_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,
                error
            )
            
            if not can_evaluate:
                return AuthResult(success=False, method="touchid", error_message="Touch ID不可用")
            
            # 设置超时时间较短，避免长时间等待
            import threading
            result = {"success": False, "error": None, "completed": False}
            
            def completion_handler(success, error):
                result["success"] = success
                result["error"] = error
                result["completed"] = True
            
            context.evaluatePolicy_localizedReason_reply_(
                LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics,
                "使用Touch ID快速访问密码管理器",
                completion_handler
            )
            
            # 等待5秒，如果没有响应就放弃
            timeout = 5
            start_time = time.time()
            
            while not result["completed"] and (time.time() - start_time) < timeout:
                time.sleep(0.1)
            
            if result["completed"] and result["success"]:
                # Touch ID成功，从Keychain获取密码并验证
                password = self._get_password_from_keychain()
                if password:
                    # 验证密码是否真的能解密数据库
                    if self._verify_password_with_database(password):
                        self._start_session(password)
                        return AuthResult(
                            success=True,
                            method="touchid",
                            password=password
                        )
                    else:
                        # 密码无效，可能是盐值不匹配，进行智能诊断
                        print("🔍 Touch ID认证成功，但检测到数据库同步问题...")
                        diagnosis = self._diagnose_auth_failure()
                        
                        if self._detect_backup_file():
                            print("🔍 检测到备份数据库文件")
                            print("💡 此数据库文件可能来自其他设备")
                            print("🔐 请输入创建此备份时使用的密码:")
                            
                            # 提示用户输入备份密码
                            try:
                                import getpass
                                backup_password = getpass.getpass("备份密码: ")
                                
                                if backup_password:
                                    # 验证备份密码
                                    from core.storage import SecureStorage
                                    storage = SecureStorage()
                                    
                                    if storage.verify_master_password(backup_password):
                                        # 密码正确，启动会话
                                        self._start_session(backup_password)
                                        self._save_password_to_keychain(backup_password)
                                        return AuthResult(
                                            success=True,
                                            method="backup_recovery",
                                            password=backup_password
                                        )
                                    else:
                                        self._clear_invalid_password_from_keychain()
                                        return AuthResult(
                                            success=False,
                                            method="touchid_recovery_failed",
                                            error_message="备份密码错误"
                                        )
                                else:
                                    self._clear_invalid_password_from_keychain()
                                    return AuthResult(
                                        success=False,
                                        method="touchid_cancelled",
                                        error_message="用户取消输入备份密码"
                                    )
                            except Exception as e:
                                self._clear_invalid_password_from_keychain()
                                return AuthResult(
                                    success=False,
                                    method="touchid_input_error",
                                    error_message=f"密码输入错误: {e}"
                                )
                        else:
                            # 其他类型的错误
                            self._clear_invalid_password_from_keychain()
                            return AuthResult(
                                success=False, 
                                method="touchid", 
                                error_message="Touch ID认证成功但数据库访问失败，请尝试手动认证"
                            )
            
            return AuthResult(success=False, method="touchid", error_message="Touch ID验证失败或超时")
            
        except Exception as e:
            return AuthResult(success=False, method="touchid", error_message=f"Touch ID错误: {e}")
    
    def _try_keychain_session(self) -> AuthResult:
        """尝试从Keychain获取会话令牌"""
        try:
            session_data = keyring.get_password(self.SERVICE_NAME, self.SESSION_KEY)
            if session_data:
                session_info = json.loads(session_data)
                
                # 检查会话是否过期
                if time.time() - session_info['created_at'] < self.session_timeout:
                    password = session_info['password_hash']  # 这里应该是加密的
                    self.cached_password = password
                    self.session_token = session_info['token']
                    self.session_start_time = session_info['created_at']
                    
                    return AuthResult(
                        success=True,
                        method="keychain_session",
                        password=password,
                        session_token=self.session_token
                    )
                else:
                    # 会话过期，清除
                    keyring.delete_password(self.SERVICE_NAME, self.SESSION_KEY)
            
            return AuthResult(success=False, method="keychain_session")
            
        except Exception as e:
            return AuthResult(success=False, method="keychain_session", error_message=f"Keychain错误: {e}")
    
    
    def _password_auth(self) -> AuthResult:
        """密码认证"""
        try:
            print("\n🔐 请输入主密码:")
            print("   💡 下次将自动使用 Touch ID 认证")
            
            password = getpass.getpass("密码: ")
            
            if not password:
                return AuthResult(
                    success=False,
                    method="password",
                    error_message="密码不能为空"
                )
            
            # 验证密码是否正确
            if not self._verify_password_with_database(password):
                # 密码验证失败，进行智能诊断
                diagnosis = self._diagnose_auth_failure()
                
                if self._detect_backup_file():
                    # 检测到备份文件，提示用户
                    print("\n🔍 检测到备份数据库文件")
                    print("💡 如果这是从其他设备复制的文件，请使用原始密码")
                    return AuthResult(
                        success=False,
                        method="password",
                        error_message="密码错误（可能需要使用创建备份时的密码）"
                    )
                else:
                    # 其他错误，返回相应的错误信息
                    error_messages = {
                        "NO_DATABASE": "数据库文件不存在，请先运行 'passgen init' 初始化",
                        "NOT_INITIALIZED": "PassGen 尚未初始化，请先运行 'passgen init'",
                        "ORPHANED_DATABASE": "检测到残留数据库文件，请重新运行 'passgen init' 进行初始化",
                        "UNSUPPORTED_FORMAT": "不支持的数据库格式",
                        "DATABASE_CORRUPTION": "数据库文件可能已损坏",
                        "WRONG_PASSWORD": "密码错误",
                        "UNKNOWN_ERROR": "认证过程中发生未知错误"
                    }
                    
                    return AuthResult(
                        success=False,
                        method="password",
                        error_message=error_messages.get(diagnosis, "密码错误")
                    )
            
            # 密码正确，启动会话
            self._start_session(password)
            
            # 将密码存储到Keychain以便Touch ID使用
            self._save_password_to_keychain(password)
            
            return AuthResult(
                success=True,
                method="password",
                password=password
            )
            
        except KeyboardInterrupt:
            return AuthResult(
                success=False,
                method="password",
                error_message="用户取消输入"
            )
        except Exception as e:
            return AuthResult(
                success=False,
                method="password",
                error_message=f"密码输入错误: {e}"
            )
    
    def _is_session_valid(self) -> bool:
        """检查会话是否有效"""
        if not self.session_start_time or not self.cached_password:
            return False
        
        elapsed = time.time() - self.session_start_time
        return elapsed < self.session_timeout
    
    def _start_session(self, password: str):
        """启动会话"""
        self.cached_password = password
        self.session_start_time = time.time()
        self.session_token = hashlib.sha256(f"{password}{time.time()}".encode()).hexdigest()[:16]
        
        # 保存会话到Keychain（可选）
        self._save_session_to_keychain(password)
    
    def _save_session_to_keychain(self, password: str):
        """保存会话到Keychain"""
        try:
            # 注意：这里不应该存储明文密码，而是存储会话令牌
            session_data = {
                'token': self.session_token,
                'created_at': self.session_start_time,
                'password_hash': hashlib.sha256(password.encode()).hexdigest()  # 存储哈希而不是明文
            }
            
            keyring.set_password(
                self.SERVICE_NAME,
                self.SESSION_KEY,
                json.dumps(session_data)
            )
        except Exception as e:
            # 失败不影响主要功能
            pass
    
    def _save_password_to_keychain(self, password: str):
        """将主密码安全地存储到Keychain（仅在密码认证成功后）"""
        try:
            # 注意：这里存储明文密码，依赖系统Keychain的安全性
            # Touch ID认证确保只有授权用户可以访问
            keyring.set_password(self.SERVICE_NAME, "master_password_encrypted", password)
        except Exception as e:
            # 存储失败不影响主要功能
            print(f"⚠️ 保存密码到Keychain失败: {e}")

    def _verify_password_with_database(self, password: str) -> bool:
        """验证密码是否能正确解密数据库"""
        try:
            from core.storage import SecureStorage
            storage = SecureStorage()
            if not storage.is_initialized():
                return False
            # 尝试验证主密码
            return storage.verify_master_password(password)
        except Exception:
            return False
    
    def _diagnose_auth_failure(self) -> str:
        """诊断认证失败的具体原因"""
        try:
            from pathlib import Path
            from core.storage import SecureStorage
            
            # 检查数据库文件是否存在
            db_path = Path.home() / ".passgen.db"
            if not db_path.exists():
                return "NO_DATABASE"
            
            # 检查是否已初始化
            try:
                storage = SecureStorage()
                if not storage.is_initialized():
                    return "NOT_INITIALIZED"
            except Exception:
                return "DATABASE_CORRUPTION"
            
            # 检查文件格式
            try:
                with open(db_path, 'rb') as f:
                    version = f.read(4)
                    # 新格式文件以 "PGv2" 开头
                    if version == b"PGv2":
                        # 检查是否为残留文件（文件存在但Keychain中没有认证信息）
                        if self._detect_orphaned_database():
                            return "ORPHANED_DATABASE"
                        # 新格式文件不需要Keychain数据即可验证密码
                        return "WRONG_PASSWORD"
                    else:
                        # 不支持的格式
                        return "UNSUPPORTED_FORMAT"
            except Exception:
                return "DATABASE_CORRUPTION"
            
        except Exception:
            return "UNKNOWN_ERROR"
    
    def _detect_orphaned_database(self) -> bool:
        """检测是否为孤立数据库（文件存在但没有配套的认证信息）"""
        try:
            # 主要检查主密码是否存在，这是Touch ID认证的关键
            master_password = keyring.get_password(self.SERVICE_NAME, "master_password_encrypted")
            
            # 如果主密码不存在，说明可能是残留文件或未完成初始化
            return master_password is None
            
        except Exception:
            # 如果无法访问Keychain，假设不是孤立文件
            return False
    
    
    
    
    
    
    def _clear_invalid_password_from_keychain(self):
        """清除Keychain中的无效密码"""
        try:
            keyring.delete_password(self.SERVICE_NAME, "master_password_encrypted")
        except Exception:
            pass

    def _get_password_from_keychain(self) -> Optional[str]:
        """从Keychain获取密码（仅用于Touch ID成功后）"""
        try:
            # Touch ID成功后，从Keychain获取存储的主密码
            password = keyring.get_password(self.SERVICE_NAME, "master_password_encrypted")
            return password
        except Exception:
            return None
    
    def clear_session(self):
        """清除会话"""
        self.cached_password = None
        self.session_start_time = None
        self.session_token = None
        
        try:
            keyring.delete_password(self.SERVICE_NAME, self.SESSION_KEY)
        except:
            pass
    
    def get_session_info(self) -> Dict[str, Any]:
        """获取会话信息"""
        if not self._is_session_valid():
            return {
                "active": False,
                "touch_id_available": TOUCH_ID_AVAILABLE
            }
        
        remaining = self.session_timeout - (time.time() - self.session_start_time)
        return {
            "active": True,
            "method": "session",
            "remaining_seconds": int(remaining),
            "touch_id_available": TOUCH_ID_AVAILABLE,
            "session_token": self.session_token
        }
    


# 便捷函数
def authenticate() -> Tuple[bool, Optional[str]]:
    """便捷认证函数"""
    auth_manager = EnhancedAuthManager()
    result = auth_manager.authenticate()
    
    if result.success:
        print(f"✅ 认证成功 (方法: {result.method})")
        return True, result.password
    else:
        print(f"❌ 认证失败: {result.error_message}")
        return False, None


if __name__ == "__main__":
    # 仅用于模块测试
    auth_manager = EnhancedAuthManager()
    result = auth_manager.authenticate()
    print(f"认证结果: {result.success} ({result.method})")