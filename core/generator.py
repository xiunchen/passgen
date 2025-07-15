"""
密码生成器模块
提供可配置的密码生成功能
"""

import secrets
import string
from dataclasses import dataclass
from typing import Set


@dataclass
class PasswordConfig:
    """密码生成配置"""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    custom_chars: str = ""
    exclude_chars: str = ""
    custom_symbols: str = ""  # 自定义特殊字符集，如果为空则使用默认


class PasswordGenerator:
    """密码生成器"""
    
    DEFAULT_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def __init__(self):
        self.config = PasswordConfig()
    
    def _get_default_symbols(self) -> str:
        """获取默认特殊字符集，优先从配置读取"""
        try:
            import sys
            import os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from utils.config import ConfigManager
            config = ConfigManager()
            return config.get('default_symbols', self.DEFAULT_SYMBOLS)
        except:
            return self.DEFAULT_SYMBOLS
    
    def generate(self, config: PasswordConfig = None) -> str:
        """
        生成密码
        
        Args:
            config: 密码配置，如果为None则使用默认配置
            
        Returns:
            生成的密码
            
        Raises:
            ValueError: 当配置无效时
        """
        if config is None:
            config = self.config
        
        # 输入验证
        if config.length < 4:
            raise ValueError("密码长度至少为4位")
        if config.length > 128:
            raise ValueError("密码长度不能超过128位")
        
        # 确保至少有一种字符类型被启用
        if not any([config.use_uppercase, config.use_lowercase, config.use_digits, config.use_symbols]):
            if not config.custom_chars:
                raise ValueError("必须至少启用一种字符类型或提供自定义字符集")
            
        charset = self._build_charset(config)
        
        if not charset:
            raise ValueError("字符集为空，请检查配置")
            
        # 使用 secrets 模块生成安全的随机密码
        password = ''.join(secrets.choice(charset) for _ in range(config.length))
        
        # 确保密码符合要求（至少包含每种类型的字符）
        if self._needs_strength_check(config):
            password = self._ensure_character_requirements(password, config, charset)
            
        return password
    
    def _build_charset(self, config: PasswordConfig) -> str:
        """构建字符集"""
        charset = ""
        
        if config.custom_chars:
            charset = config.custom_chars
        else:
            if config.use_lowercase:
                charset += string.ascii_lowercase
            if config.use_uppercase:
                charset += string.ascii_uppercase
            if config.use_digits:
                charset += string.digits
            if config.use_symbols:
                if config.custom_symbols:
                    charset += config.custom_symbols
                else:
                    charset += self._get_default_symbols()
        
        # 排除指定字符
        if config.exclude_chars:
            charset = ''.join(c for c in charset if c not in config.exclude_chars)
            
        # 去重
        charset = ''.join(sorted(set(charset)))
        
        return charset
    
    def _needs_strength_check(self, config: PasswordConfig) -> bool:
        """检查是否需要强度验证"""
        # 只有在使用多种字符类型且长度足够时才进行强度检查
        type_count = sum([
            config.use_lowercase,
            config.use_uppercase,
            config.use_digits,
            config.use_symbols
        ])
        return type_count > 1 and config.length >= type_count and not config.custom_chars
    
    def _ensure_character_requirements(self, password: str, config: PasswordConfig, charset: str) -> str:
        """确保密码包含所需的字符类型"""
        required_chars = []
        
        if config.use_lowercase:
            required_chars.append(secrets.choice(string.ascii_lowercase))
        if config.use_uppercase:
            required_chars.append(secrets.choice(string.ascii_uppercase))
        if config.use_digits:
            required_chars.append(secrets.choice(string.digits))
        if config.use_symbols:
            symbols = config.custom_symbols if config.custom_symbols else self._get_default_symbols()
            required_chars.append(secrets.choice(symbols))
        
        if not required_chars:
            return password
            
        # 检查密码是否已经满足要求
        has_requirements = True
        if config.use_lowercase and not any(c in string.ascii_lowercase for c in password):
            has_requirements = False
        if config.use_uppercase and not any(c in string.ascii_uppercase for c in password):
            has_requirements = False
        if config.use_digits and not any(c in string.digits for c in password):
            has_requirements = False
        symbols = config.custom_symbols if config.custom_symbols else self._get_default_symbols()
        if config.use_symbols and not any(c in symbols for c in password):
            has_requirements = False
            
        if has_requirements:
            return password
        
        # 如果不满足要求，替换前几个字符
        password_list = list(password)
        for i, char in enumerate(required_chars):
            if i < len(password_list):
                password_list[i] = char
        
        # 打乱顺序
        for i in range(len(password_list)):
            j = secrets.randbelow(len(password_list))
            password_list[i], password_list[j] = password_list[j], password_list[i]
            
        return ''.join(password_list)
    
    def evaluate_strength(self, password: str) -> dict:
        """
        评估密码强度
        
        Args:
            password: 要评估的密码
            
        Returns:
            包含强度信息的字典
        """
        score = 0
        feedback = []
        
        # 长度评分
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
            feedback.append("建议密码长度至少12位")
        else:
            score += 5
            feedback.append("密码长度太短，建议至少8位")
        
        # 字符类型评分
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        symbols = self._get_default_symbols()
        has_symbol = any(c in symbols for c in password)
        
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        score += char_types * 15
        
        if char_types < 3:
            feedback.append("建议包含至少3种字符类型（大小写、数字、符号）")
        
        # 重复字符检查
        unique_chars = len(set(password))
        if unique_chars / len(password) < 0.7:
            score -= 10
            feedback.append("密码包含过多重复字符")
        
        # 强度等级
        if score >= 80:
            strength = "强"
        elif score >= 60:
            strength = "中等"
        elif score >= 40:
            strength = "弱"
        else:
            strength = "很弱"
        
        return {
            "score": min(score, 100),
            "strength": strength,
            "feedback": feedback,
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "length": len(password),
            "unique_chars": unique_chars
        }