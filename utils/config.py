"""
配置管理模块
管理应用程序的配置文件和设置
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class AppConfig:
    """应用配置"""
    # 密码生成器默认设置
    default_password_length: int = 16
    default_use_uppercase: bool = True
    default_use_lowercase: bool = True
    default_use_digits: bool = True
    default_use_symbols: bool = True
    default_symbols: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # 安全设置
    session_timeout_seconds: int = 300  # 5分钟
    auto_clear_clipboard_seconds: int = 30
    max_auth_attempts: int = 3
    
    # UI设置
    show_password_strength: bool = True
    use_colors: bool = True
    
    # 存储设置
    storage_path: Optional[str] = None
    backup_enabled: bool = True
    backup_count: int = 5


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_path: str = None):
        """
        初始化配置管理器
        
        Args:
            config_path: 配置文件路径，默认为用户主目录下的.passgen_config.json
        """
        if config_path is None:
            home = Path.home()
            config_path = home / ".passgen_config.json"
        
        self.config_path = Path(config_path)
        self.config = AppConfig()
        
        # 加载配置
        self.load_config()
    
    def load_config(self) -> bool:
        """
        从文件加载配置
        
        Returns:
            加载是否成功
        """
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                # 更新配置对象
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                return True
            else:
                # 配置文件不存在，使用默认配置并保存
                self.save_config()
                return True
                
        except Exception as e:
            print(f"⚠️  加载配置文件失败: {e}")
            print("使用默认配置")
            return False
    
    def save_config(self) -> bool:
        """
        保存配置到文件
        
        Returns:
            保存是否成功
        """
        try:
            # 确保目录存在
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 保存配置
            config_dict = asdict(self.config)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, ensure_ascii=False, indent=2)
            
            # 设置文件权限
            os.chmod(self.config_path, 0o600)
            
            return True
            
        except Exception as e:
            print(f"❌ 保存配置文件失败: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值
        
        Args:
            key: 配置键
            default: 默认值
            
        Returns:
            配置值
        """
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any) -> bool:
        """
        设置配置值
        
        Args:
            key: 配置键
            value: 配置值
            
        Returns:
            设置是否成功
        """
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            return self.save_config()
        else:
            print(f"❌ 未知的配置项: {key}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """
        重置为默认配置
        
        Returns:
            重置是否成功
        """
        self.config = AppConfig()
        return self.save_config()
    
    def update_config(self, **kwargs) -> bool:
        """
        批量更新配置
        
        Args:
            **kwargs: 要更新的配置项
            
        Returns:
            更新是否成功
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
            else:
                print(f"❌ 未知的配置项: {key}")
                return False
        
        return self.save_config()
    
    def get_config_dict(self) -> Dict[str, Any]:
        """
        获取配置字典
        
        Returns:
            配置字典
        """
        return asdict(self.config)
    
    def show_config(self):
        """显示当前配置"""
        config_dict = self.get_config_dict()
        
        print("\n📋 当前配置:")
        print("=" * 50)
        
        sections = {
            "密码生成器设置": [
                "default_password_length",
                "default_use_uppercase",
                "default_use_lowercase", 
                "default_use_digits",
                "default_use_symbols"
            ],
            "安全设置": [
                "session_timeout_seconds",
                "auto_clear_clipboard_seconds",
                "max_auth_attempts"
            ],
            "界面设置": [
                "show_password_strength",
                "use_colors"
            ],
            "存储设置": [
                "storage_path",
                "backup_enabled",
                "backup_count"
            ]
        }
        
        for section_name, keys in sections.items():
            print(f"\n🔧 {section_name}:")
            for key in keys:
                if key in config_dict:
                    value = config_dict[key]
                    if key.endswith('_seconds'):
                        if value >= 60:
                            value_str = f"{value} 秒 ({value//60} 分钟)"
                        else:
                            value_str = f"{value} 秒"
                    else:
                        value_str = str(value)
                    
                    print(f"  {key}: {value_str}")
        
        print(f"\n📁 配置文件路径: {self.config_path}")
    
    def validate_config(self) -> bool:
        """
        验证配置有效性
        
        Returns:
            配置是否有效
        """
        try:
            # 检查密码长度
            if self.config.default_password_length <= 0:
                print("❌ 默认密码长度必须大于0")
                return False
            
            # 检查会话超时
            if self.config.session_timeout_seconds < 0:
                print("❌ 会话超时时间不能为负数")
                return False
            
            # 检查剪贴板清除时间
            if self.config.auto_clear_clipboard_seconds < 0:
                print("❌ 剪贴板自动清除时间不能为负数")
                return False
            
            # 检查认证尝试次数
            if self.config.max_auth_attempts <= 0:
                print("❌ 最大认证尝试次数必须大于0")
                return False
            
            
            # 检查备份数量
            if self.config.backup_count < 0:
                print("❌ 备份数量不能为负数")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ 配置验证失败: {e}")
            return False