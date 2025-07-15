"""
剪贴板管理模块
提供安全的剪贴板操作功能
"""

import time
import threading
from typing import Optional
import pyperclip


class SecureClipboard:
    """安全剪贴板管理器"""
    
    def __init__(self, auto_clear_seconds: int = None):
        """
        初始化剪贴板管理器
        
        Args:
            auto_clear_seconds: 自动清除剪贴板的秒数，None表示从配置读取，0表示不自动清除
        """
        if auto_clear_seconds is None:
            # 从配置文件读取
            try:
                import sys
                import os
                sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                from utils.config import ConfigManager
                config = ConfigManager()
                self.auto_clear_seconds = config.get('auto_clear_clipboard_seconds', 30)
            except:
                self.auto_clear_seconds = 30  # 默认30秒
        else:
            self.auto_clear_seconds = auto_clear_seconds
        self._clear_timer = None
        self._original_content = None
    
    def copy_password(self, password: str, show_notification: bool = True) -> bool:
        """
        复制密码到剪贴板
        
        Args:
            password: 要复制的密码
            show_notification: 是否显示通知
            
        Returns:
            复制是否成功
        """
        try:
            # 保存原始剪贴板内容
            try:
                self._original_content = pyperclip.paste()
            except:
                self._original_content = None
            
            # 复制密码到剪贴板
            pyperclip.copy(password)
            
            if show_notification:
                if self.auto_clear_seconds > 0:
                    print(f"✅ 密码已复制到剪贴板，将在 {self.auto_clear_seconds} 秒后自动清除")
                else:
                    print("✅ 密码已复制到剪贴板")
            
            # 启动自动清除定时器
            if self.auto_clear_seconds > 0:
                self._start_auto_clear_timer()
            
            return True
            
        except Exception as e:
            if show_notification:
                print(f"❌ 复制失败: {e}")
            return False
    
    def copy_text(self, text: str, description: str = "文本") -> bool:
        """
        复制普通文本到剪贴板
        
        Args:
            text: 要复制的文本
            description: 文本描述
            
        Returns:
            复制是否成功
        """
        try:
            pyperclip.copy(text)
            print(f"✅ {description}已复制到剪贴板")
            return True
        except Exception as e:
            print(f"❌ 复制{description}失败: {e}")
            return False
    
    def clear_clipboard(self, show_notification: bool = True) -> bool:
        """
        清除剪贴板内容
        
        Args:
            show_notification: 是否显示通知
            
        Returns:
            清除是否成功
        """
        try:
            # 清除剪贴板
            pyperclip.copy("")
            
            if show_notification:
                print("🧹 剪贴板已清除")
            
            # 取消自动清除定时器
            self._cancel_auto_clear_timer()
            
            return True
            
        except Exception as e:
            if show_notification:
                print(f"❌ 清除剪贴板失败: {e}")
            return False
    
    def restore_clipboard(self, show_notification: bool = True) -> bool:
        """
        恢复原始剪贴板内容
        
        Args:
            show_notification: 是否显示通知
            
        Returns:
            恢复是否成功
        """
        try:
            if self._original_content is not None:
                pyperclip.copy(self._original_content)
                if show_notification:
                    print("🔄 剪贴板内容已恢复")
            else:
                self.clear_clipboard(show_notification)
            
            # 取消自动清除定时器
            self._cancel_auto_clear_timer()
            
            return True
            
        except Exception as e:
            if show_notification:
                print(f"❌ 恢复剪贴板失败: {e}")
            return False
    
    def get_clipboard_content(self) -> Optional[str]:
        """
        获取当前剪贴板内容
        
        Returns:
            剪贴板内容，失败时返回None
        """
        try:
            return pyperclip.paste()
        except:
            return None
    
    def is_password_in_clipboard(self, password: str) -> bool:
        """
        检查指定密码是否在剪贴板中
        
        Args:
            password: 要检查的密码
            
        Returns:
            密码是否在剪贴板中
        """
        try:
            return pyperclip.paste() == password
        except:
            return False
    
    def _start_auto_clear_timer(self):
        """启动自动清除定时器"""
        # 取消之前的定时器
        self._cancel_auto_clear_timer()
        
        # 启动新的定时器
        self._clear_timer = threading.Timer(
            self.auto_clear_seconds,
            self._auto_clear_callback
        )
        self._clear_timer.daemon = True
        self._clear_timer.start()
    
    def _cancel_auto_clear_timer(self):
        """取消自动清除定时器"""
        if self._clear_timer and self._clear_timer.is_alive():
            self._clear_timer.cancel()
            self._clear_timer = None
    
    def _auto_clear_callback(self):
        """自动清除回调函数"""
        self.restore_clipboard(show_notification=True)
    
    def set_auto_clear_seconds(self, seconds: int):
        """
        设置自动清除秒数
        
        Args:
            seconds: 自动清除秒数，0表示不自动清除
        """
        self.auto_clear_seconds = seconds
    
    def __del__(self):
        """析构函数，确保清理定时器"""
        self._cancel_auto_clear_timer()