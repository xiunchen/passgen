#!/usr/bin/env python3
"""
密码生成器和管理器 - 统一CLI工具
支持Touch ID增强认证
"""

import sys
import os
import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.generator import PasswordGenerator, PasswordConfig
from core.storage import SecureStorage
from core.enhanced_auth import EnhancedAuthManager
from core.clipboard import SecureClipboard
from utils.config import ConfigManager

console = Console()

# 全局认证管理器实例，确保会话状态在多次操作间保持
_auth_manager = None

def get_auth_manager():
    """获取全局认证管理器实例"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = EnhancedAuthManager()
    return _auth_manager

@click.group(invoke_without_command=True)
@click.pass_context
@click.option('-l', '--length', type=int, help='密码长度')
@click.option('--no-uppercase', is_flag=True, help='不包含大写字母')
@click.option('--no-lowercase', is_flag=True, help='不包含小写字母') 
@click.option('--no-digits', is_flag=True, help='不包含数字')
@click.option('--no-symbols', is_flag=True, help='不包含特殊字符')
@click.option('--custom-symbols', type=str, help='自定义特殊字符集 (如: "!@#$")')
@click.option('--exclude', type=str, help='排除的字符 (如: "0oO1lI")')
@click.option('--count', type=int, default=1, help='生成密码数量')
@click.option('--no-save', is_flag=True, help='不保存到数据库，仅显示')
def cli(ctx, length, no_uppercase, no_lowercase, no_digits, no_symbols, custom_symbols, exclude, count, no_save):
    """🔐 PassGen - 密码生成器和管理器

    现代化的密码生成和管理工具，支持 Touch ID 认证、AES-256 加密存储。

    ✨ 主要功能：
    • 🔑 智能密码生成：可自定义长度、字符集的安全密码
    • 💾 加密存储：AES-GCM 加密，PBKDF2 密钥派生
    • 👆 Touch ID 认证：便捷的生物识别认证，自动回退
    • 🔍 智能搜索：支持网站名、用户名、标签、备注搜索
    • 📋 剪贴板集成：自动复制，30秒后安全清除
    • ⚡ 会话管理：5分钟会话缓存，减少重复认证

    🚀 快速开始：

    \b
    passgen init                         # 首次初始化（设置主密码）
    passgen                              # 生成密码并自动复制到剪贴板
    passgen list                         # 查看密码库（Touch ID 认证）

    🔑 密码生成选项：

    \b
    passgen -l 20                        # 生成20位密码
    passgen --count 3                    # 生成3个密码供选择
    passgen --no-symbols                 # 不包含特殊字符
    passgen --custom-symbols "!@#"       # 只使用指定特殊字符
    passgen --exclude "0oO1lI"           # 排除容易混淆的字符
    passgen --no-save                    # 仅显示不保存

    🔍 搜索和复制：

    \b
    passgen search github                # 搜索包含"github"的条目
    passgen search -c github             # 搜索并直接复制
    passgen list -c 3                    # 直接复制第3个条目

    ✏️ 管理操作：

    \b
    passgen add                          # 添加新密码条目
    passgen edit 1                       # 编辑第1个条目
    passgen delete 2                     # 删除第2个条目

    ⚙️ 配置管理：

    \b
    passgen config                       # 查看当前配置
    passgen config --show                # 显示当前配置
    passgen config --reset               # 重置所有配置到默认值
    passgen config --session-timeout 600    # 设置会话超时为10分钟
    passgen config --clipboard-timeout 60   # 设置剪贴板1分钟后清除
    passgen config --password-length 20     # 设置默认密码长度
    passgen config --symbols "!@#$%"        # 设置默认特殊字符集

    📊 状态和系统：

    \b
    passgen status                       # 查看认证状态和会话信息

    🔄 系统重置：

    \b
    passgen reset                        # 完全重置（数据库+钥匙串+配置）
    passgen reset --config-only          # 仅重置配置文件
    passgen reset --force                # 跳过确认直接重置

    💡 小贴士：
    • 首次认证后，在会话超时时间内无需重复 Touch ID 认证
    • 使用序号（1,2,3...）而不是复杂ID来操作密码条目
    • 密码自动复制到剪贴板，并在30秒后自动清除
    • 所有数据使用 AES-256 加密存储

    使用 'passgen <command> --help' 查看特定命令的详细选项。
    """
    if ctx.invoked_subcommand is None:
        # 默认行为：生成密码
        generate_password(length, no_uppercase, no_lowercase, no_digits, no_symbols, custom_symbols, exclude, count, no_save)


def generate_password(length, no_uppercase, no_lowercase, no_digits, no_symbols, custom_symbols, exclude, count, no_save):
    """生成密码的核心逻辑"""
    try:
        # 加载配置
        config_manager = ConfigManager()
        
        # 构建密码生成配置
        password_config = PasswordConfig(
            length=length or config_manager.get('default_password_length'),
            use_uppercase=not no_uppercase and config_manager.get('default_use_uppercase'),
            use_lowercase=not no_lowercase and config_manager.get('default_use_lowercase'),
            use_digits=not no_digits and config_manager.get('default_use_digits'),
            use_symbols=not no_symbols and config_manager.get('default_use_symbols'),
            custom_symbols=custom_symbols or "",
            exclude_chars=exclude or ""
        )
        
        # 创建密码生成器
        generator = PasswordGenerator()
        
        # 生成密码
        passwords = []
        for _ in range(count):
            password = generator.generate(password_config)
            passwords.append(password)
        
        # 显示生成的密码
        if count == 1:
            console.print(f"🔑 生成的密码: [bold green]{passwords[0]}[/bold green]")
            
            # 立即复制到剪贴板
            clipboard = SecureClipboard()
            clipboard.copy_password(passwords[0], show_notification=False)
            console.print("✅ 密码已复制到剪贴板")
            
            # 格式化显示密码强度
            if config_manager.get('show_password_strength'):
                strength = generator.evaluate_strength(passwords[0])
                console.print("\n💪 密码强度分析:")
                console.print(f"  📊 强度等级: [bold]{strength['strength']}[/bold] ({strength['score']}/100)")
                console.print(f"  📏 密码长度: {strength['length']} 位")
                console.print(f"  🔤 唯一字符: {strength['unique_chars']} 个")
                
                # 字符类型分析
                char_types = []
                if strength['has_lowercase']:
                    char_types.append("小写字母")
                if strength['has_uppercase']:
                    char_types.append("大写字母")
                if strength['has_digits']:
                    char_types.append("数字")
                if strength['has_symbols']:
                    char_types.append("特殊字符")
                
                console.print(f"  🎯 字符类型: {', '.join(char_types)}")
                
                # 显示反馈建议
                if strength['feedback']:
                    console.print("  💡 建议:")
                    for feedback in strength['feedback']:
                        console.print(f"    • {feedback}")
        else:
            table = Table(title="生成的密码")
            table.add_column("序号", style="cyan")
            table.add_column("密码", style="green")
            table.add_column("强度", style="yellow")
            
            for i, password in enumerate(passwords, 1):
                strength = generator.evaluate_strength(password)
                table.add_row(str(i), password, strength['strength'])
            
            console.print(table)
            
            # 多个密码时提示用户选择复制
            try:
                choice = Prompt.ask("选择要复制的密码序号", default="1")
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(passwords):
                        clipboard = SecureClipboard()
                        clipboard.copy_password(passwords[idx], show_notification=False)
                        console.print(f"✅ 密码 {idx+1} 已复制到剪贴板")
            except EOFError:
                pass
        
        # 如果不是仅显示模式，询问是否保存
        if not no_save:
            try:
                if count == 1:
                    save = Prompt.ask("是否保存到密码库？", choices=["y", "n"], default="n")
                    if save == "y":
                        save_password(passwords[0])
                else:
                    save = Prompt.ask("是否保存任何密码到密码库？", choices=["y", "n"], default="n")
                    if save == "y":
                        for i, password in enumerate(passwords, 1):
                            save_choice = Prompt.ask(f"保存密码 {i}？", choices=["y", "n"], default="n")
                            if save_choice == "y":
                                save_password(password)
            except (EOFError, KeyboardInterrupt):
                # 非交互环境或用户取消，跳过保存
                pass
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")
        sys.exit(1)

def save_password(password):
    """保存密码到数据库"""
    try:
        # 使用增强认证
        auth_manager = get_auth_manager()
        auth_result = auth_manager.authenticate()
        
        if not auth_result.success:
            console.print(f"❌ 认证失败: {auth_result.error_message}", style="red")
            return
        
        # 创建存储
        storage = SecureStorage()
        
        # 获取网站信息
        site = Prompt.ask("网站/应用名称")
        username = Prompt.ask("用户名（可选）", default="")
        notes = Prompt.ask("备注（可选）", default="")
        
        # 添加密码
        entry_id = storage.add_password(
            site=site,
            password=password,
            master_password=auth_result.password,
            username=username,
            notes=notes
        )
        
        console.print(f"✅ 密码已保存")
        
    except Exception as e:
        console.print(f"❌ 保存失败: {e}", style="red")

@cli.command()
def init():
    """🔧 初始化密码管理器（首次使用必须运行）"""
    try:
        storage = SecureStorage()
        
        if storage.is_initialized():
            console.print("❌ 密码管理器已经初始化", style="red")
            return
        
        console.print("🔧 初始化密码管理器...")
        
        # 设置主密码
        master_password = Prompt.ask("设置主密码", password=True)
        confirm_password = Prompt.ask("确认主密码", password=True)
        
        if master_password != confirm_password:
            console.print("❌ 密码不匹配", style="red")
            return
        
        if storage.initialize(master_password):
            console.print("✅ 密码管理器初始化成功！")
            
            # 保存密码到钥匙串，供 Touch ID 使用
            import keyring
            keyring.set_password("PassGen", "master_password_encrypted", master_password)
            
            console.print("💡 提示：Touch ID 认证已自动启用")
        else:
            console.print("❌ 初始化失败", style="red")
            
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")

@cli.command()
@click.option('-q', '--query', help='搜索关键词')
@click.option('-c', '--copy', type=int, help='直接复制指定序号的密码')
def list(query, copy):
    """📋 列出密码库中的所有条目"""
    try:
        # 使用增强认证
        auth_manager = get_auth_manager()
        auth_result = auth_manager.authenticate()
        
        if not auth_result.success:
            console.print(f"❌ 认证失败: {auth_result.error_message}", style="red")
            return
        
        storage = SecureStorage()
        
        # 如果指定了 copy 参数，直接复制密码
        if copy:
            all_entries = storage.list_all_passwords(auth_result.password)
            
            # 检查序号是否有效
            if 1 <= copy <= len(all_entries):
                selected_entry = all_entries[copy - 1]
                password = storage.get_password(selected_entry.id, auth_result.password)
                if password:
                    clipboard = SecureClipboard()
                    clipboard.copy_password(password.password, show_notification=False)
                    console.print(f"✅ {password.site} 的密码已复制到剪贴板")
                else:
                    console.print("❌ 获取密码失败", style="red")
            else:
                console.print(f"❌ 无效的序号: {copy}。有效范围: 1-{len(all_entries)}", style="red")
            return
        
        # 获取密码列表
        if query:
            entries = storage.search_passwords(query, auth_result.password)
        else:
            entries = storage.list_all_passwords(auth_result.password)
        
        if not entries:
            console.print("📭 没有找到密码条目")
            return
        
        # 创建表格
        table = Table(title="密码条目")
        table.add_column("#", style="dim", width=3)
        table.add_column("网站", style="green")
        table.add_column("用户名", style="yellow")
        table.add_column("更新时间", style="blue")
        table.add_column("标签", style="magenta")
        
        # 显示所有条目
        for idx, entry in enumerate(entries, 1):
            table.add_row(
                str(idx),
                entry.site,
                entry.username or "-",
                entry.updated_at[:10],
                ", ".join(entry.tags) if entry.tags else "-"
            )
        
        console.print(table)
        
        # 显示总记录数
        console.print(f"📊 共 {len(entries)} 条记录")
        
        # 询问是否要选择条目查看详情
        if entries:
            console.print("\n💡 提示：输入序号(#)查看密码并复制，输入 q 退出")
            try:
                choice = Prompt.ask("选择", default="q")
                if choice.lower() != 'q':
                    selected_entry = None
                    
                    # 按序号选择
                    if choice.isdigit():
                        idx = int(choice)
                        if 1 <= idx <= len(entries):
                            selected_entry = entries[idx - 1]
                    
                    if selected_entry:
                        # 显示密码详情
                        password = storage.get_password(selected_entry.id, auth_result.password)
                        if password:
                            console.print(f"\n🔐 {selected_entry.site}")
                            console.print(f"👤 用户名: {selected_entry.username or '-'}")
                            
                            # 复制到剪贴板
                            clipboard = SecureClipboard()
                            clipboard.copy_password(password.password, show_notification=False)
                            console.print("✅ 密码已复制到剪贴板")
                            
                            # 显示其他信息
                            if password.notes:
                                console.print(f"📝 备注: {password.notes}")
                            if password.tags:
                                console.print(f"🏷️  标签: {', '.join(password.tags)}")
                    else:
                        console.print("❌ 未找到匹配的条目", style="red")
            except EOFError:
                pass
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")


@cli.command()
@click.argument('query')
@click.option('-c', '--copy', is_flag=True, help='直接复制第一个搜索结果或选择复制')
def search(query, copy):
    """🔎 搜索密码条目（支持网站名、用户名、标签、备注）"""
    try:
        # 使用增强认证
        auth_manager = get_auth_manager()
        auth_result = auth_manager.authenticate()
        
        if not auth_result.success:
            console.print(f"❌ 认证失败: {auth_result.error_message}", style="red")
            return
        
        storage = SecureStorage()
        entries = storage.search_passwords(query, auth_result.password)
        
        if not entries:
            console.print(f"📭 没有找到包含 '{query}' 的密码条目")
            return
        
        # 如果指定了 copy 参数
        if copy:
            if len(entries) == 1:
                # 只有一个结果，直接复制
                password = storage.get_password(entries[0].id, auth_result.password)
                if password:
                    clipboard = SecureClipboard()
                    clipboard.copy_password(password.password, show_notification=False)
                    console.print(f"✅ {password.site} 的密码已复制到剪贴板")
                    return
            else:
                # 多个结果，显示表格让用户选择
                table = Table(title=f"搜索结果: '{query}'")
                table.add_column("#", style="dim", width=3)
                table.add_column("网站", style="green")
                table.add_column("用户名", style="yellow")
                table.add_column("更新时间", style="blue")
                
                for idx, entry in enumerate(entries, 1):
                    table.add_row(
                        str(idx),
                        entry.site,
                        entry.username or "-",
                        entry.updated_at[:10]
                    )
                
                console.print(table)
                
                # 让用户选择
                try:
                    choice = Prompt.ask("选择序号", default="1")
                    if choice.isdigit():
                        idx = int(choice) - 1
                        if 0 <= idx < len(entries):
                            selected_entry = entries[idx]
                            password = storage.get_password(selected_entry.id, auth_result.password)
                            if password:
                                clipboard = SecureClipboard()
                                clipboard.copy_password(password.password, show_notification=False)
                                console.print(f"✅ {password.site} 的密码已复制到剪贴板")
                                return
                except EOFError:
                    pass
                console.print("❌ 未选择有效的条目", style="red")
                return
        
        # 正常显示搜索结果（不复制）
        table = Table(title=f"搜索结果: '{query}'")
        table.add_column("#", style="dim", width=3)
        table.add_column("网站", style="green")
        table.add_column("用户名", style="yellow")
        table.add_column("更新时间", style="blue")
        
        for idx, entry in enumerate(entries, 1):
            table.add_row(
                str(idx),
                entry.site,
                entry.username or "-",
                entry.updated_at[:10]
            )
        
        console.print(table)
        console.print(f"📊 找到 {len(entries)} 条匹配记录")
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")

@cli.command()
def add():
    """➕ 添加新的密码条目到密码库"""
    try:
        # 使用增强认证（只认证一次）
        auth_manager = get_auth_manager()
        auth_result = auth_manager.authenticate()
        
        if not auth_result.success:
            console.print(f"❌ 认证失败: {auth_result.error_message}", style="red")
            return
        
        storage = SecureStorage()
        
        # 使用循环而不是递归
        while True:
            # 获取密码信息
            try:
                site = Prompt.ask("网站/应用名称")
                username = Prompt.ask("用户名", default="")
            except EOFError:
                console.print("❌ 非交互式环境，请使用命令行参数", style="red")
                return
            
            # 询问密码生成方式
            generate_password = Confirm.ask("自动生成密码？", default=True)
            
            if generate_password:
                # 询问密码生成选项
                length = Prompt.ask("密码长度", default="16")
                use_symbols = Confirm.ask("包含特殊字符？", default=True)
                
                # 生成密码
                config_manager = ConfigManager()
                password_config = PasswordConfig(
                    length=int(length),
                    use_uppercase=config_manager.get('default_use_uppercase'),
                    use_lowercase=config_manager.get('default_use_lowercase'),
                    use_digits=config_manager.get('default_use_digits'),
                    use_symbols=use_symbols
                )
                
                generator = PasswordGenerator()
                password = generator.generate(password_config)
                
                # 显示生成的密码
                console.print(f"🔑 生成的密码: [bold green]{password}[/bold green]")
                
                # 格式化显示密码强度
                strength = generator.evaluate_strength(password)
                console.print(f"💪 强度: [bold]{strength['strength']}[/bold] ({strength['score']}/100)")
                
                # 询问是否要重新生成
                while not Confirm.ask("使用这个密码？", default=True):
                    password = generator.generate(password_config)
                    console.print(f"🔑 生成的密码: [bold green]{password}[/bold green]")
                    strength = generator.evaluate_strength(password)
                    console.print(f"💪 强度: [bold]{strength['strength']}[/bold] ({strength['score']}/100)")
            else:
                # 手动输入密码
                password = Prompt.ask("密码", password=True)
                confirm_password = Prompt.ask("确认密码", password=True)
                
                if password != confirm_password:
                    console.print("❌ 密码不匹配", style="red")
                    continue  # 重新开始这次添加
            
            notes = Prompt.ask("备注", default="")
            tags_input = Prompt.ask("标签 (用逗号分隔)", default="")
            
            tags = [tag.strip() for tag in tags_input.split(",") if tag.strip()]
            
            # 添加密码
            entry_id = storage.add_password(
                site=site,
                password=password,
                master_password=auth_result.password,
                username=username,
                notes=notes,
                tags=tags
            )
            
            console.print(f"✅ 密码条目已添加")
            
            # 询问是否继续添加
            try:
                if not Confirm.ask("是否继续添加其他密码？", default=False):
                    break  # 退出循环
            except (EOFError, KeyboardInterrupt):
                break  # 退出循环
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")

@cli.command()
@click.argument('sequence_number', type=int)
def edit(sequence_number):
    """✏️ 编辑指定序号的密码条目"""
    try:
        # 使用增强认证
        auth_manager = get_auth_manager()
        auth_result = auth_manager.authenticate()
        
        if not auth_result.success:
            console.print(f"❌ 认证失败: {auth_result.error_message}", style="red")
            return
        
        storage = SecureStorage()
        
        # 获取所有条目
        all_entries = storage.list_all_passwords(auth_result.password)
        
        # 检查序号是否有效
        if sequence_number < 1 or sequence_number > len(all_entries):
            console.print(f"❌ 无效的序号: {sequence_number}。有效范围: 1-{len(all_entries)}", style="red")
            return
        
        # 获取现有条目
        entry_to_edit = all_entries[sequence_number - 1]
        existing_entry = storage.get_password(entry_to_edit.id, auth_result.password)
        if not existing_entry:
            console.print(f"❌ 未找到序号为 {sequence_number} 的条目", style="red")
            return
        
        console.print(f"🔧 编辑密码条目: {existing_entry.site}")
        console.print("💡 提示：直接按回车保持原值不变")
        
        # 编辑字段
        try:
            site = Prompt.ask("网站/应用名称", default=existing_entry.site)
            username = Prompt.ask("用户名", default=existing_entry.username or "")
            
            # 询问是否修改密码
            change_password = Confirm.ask("是否修改密码？", default=False)
            
            if change_password:
                # 询问密码生成方式
                generate_password = Confirm.ask("自动生成密码？", default=True)
                
                if generate_password:
                    # 询问密码生成选项
                    length = Prompt.ask("密码长度", default="16")
                    use_symbols = Confirm.ask("包含特殊字符？", default=True)
                    
                    # 生成密码
                    config_manager = ConfigManager()
                    password_config = PasswordConfig(
                        length=int(length),
                        use_uppercase=config_manager.get('default_use_uppercase'),
                        use_lowercase=config_manager.get('default_use_lowercase'),
                        use_digits=config_manager.get('default_use_digits'),
                        use_symbols=use_symbols
                    )
                    
                    generator = PasswordGenerator()
                    password = generator.generate(password_config)
                    
                    # 显示生成的密码
                    console.print(f"🔑 生成的密码: [bold green]{password}[/bold green]")
                    
                    # 格式化显示密码强度
                    strength = generator.evaluate_strength(password)
                    console.print(f"💪 强度: [bold]{strength['strength']}[/bold] ({strength['score']}/100)")
                    
                    # 询问是否要重新生成
                    while not Confirm.ask("使用这个密码？", default=True):
                        password = generator.generate(password_config)
                        console.print(f"🔑 生成的密码: [bold green]{password}[/bold green]")
                        strength = generator.evaluate_strength(password)
                        console.print(f"💪 强度: [bold]{strength['strength']}[/bold] ({strength['score']}/100)")
                else:
                    # 手动输入密码
                    password = Prompt.ask("新密码", password=True)
                    confirm_password = Prompt.ask("确认新密码", password=True)
                    
                    if password != confirm_password:
                        console.print("❌ 密码不匹配", style="red")
                        return
            else:
                password = existing_entry.password
            
            notes = Prompt.ask("备注", default=existing_entry.notes or "")
            tags_str = ", ".join(existing_entry.tags) if existing_entry.tags else ""
            tags_input = Prompt.ask("标签 (用逗号分隔)", default=tags_str)
            
        except EOFError:
            console.print("❌ 非交互式环境，无法编辑", style="red")
            return
        
        tags = [tag.strip() for tag in tags_input.split(",") if tag.strip()]
        
        # 删除旧条目
        storage.delete_password(entry_to_edit.id, auth_result.password)
        
        # 添加新条目
        new_entry_id = storage.add_password(
            site=site,
            password=password,
            master_password=auth_result.password,
            username=username,
            notes=notes,
            tags=tags
        )
        
        console.print(f"✅ 密码条目已更新")
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")

@cli.command()
@click.argument('sequence_number', type=int)
def delete(sequence_number):
    """🗑️ 删除指定序号的密码条目（需要确认）"""
    try:
        # 使用增强认证
        auth_manager = get_auth_manager()
        auth_result = auth_manager.authenticate()
        
        if not auth_result.success:
            console.print(f"❌ 认证失败: {auth_result.error_message}", style="red")
            return
        
        storage = SecureStorage()
        
        # 获取所有条目
        all_entries = storage.list_all_passwords(auth_result.password)
        
        # 检查序号是否有效
        if sequence_number < 1 or sequence_number > len(all_entries):
            console.print(f"❌ 无效的序号: {sequence_number}。有效范围: 1-{len(all_entries)}", style="red")
            return
        
        # 获取要删除的条目
        entry_to_delete = all_entries[sequence_number - 1]
        
        # 确认删除
        if not Confirm.ask(f"确定要删除 '{entry_to_delete.site}' 的密码条目吗？"):
            console.print("❌ 已取消删除")
            return
        
        if storage.delete_password(entry_to_delete.id, auth_result.password):
            console.print(f"✅ 密码条目 '{entry_to_delete.site}' 已删除")
        else:
            console.print(f"❌ 删除失败", style="red")
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")

@cli.command()
def status():
    """📊 显示认证状态和系统信息"""
    try:
        auth_manager = get_auth_manager()
        session_info = auth_manager.get_session_info()
        
        console.print("🔒 认证状态:")
        console.print(f"  Touch ID 可用: {'✅' if session_info['touch_id_available'] else '❌'}")
        console.print(f"  会话活跃: {'✅' if session_info['active'] else '❌'}")
        
        if session_info['active']:
            console.print(f"  剩余时间: {session_info['remaining_seconds']} 秒")
        
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")

@cli.command()
@click.option('--show', is_flag=True, help='显示当前配置')
@click.option('--reset', is_flag=True, help='重置配置到默认值')
@click.option('--session-timeout', type=int, help='设置会话超时时间（秒）')
@click.option('--clipboard-timeout', type=int, help='设置剪贴板自动清除时间（秒）')
@click.option('--password-length', type=int, help='设置默认密码长度')
@click.option('--symbols', type=str, help='设置默认特殊字符集')
def config(show, reset, session_timeout, clipboard_timeout, password_length, symbols):
    """⚙️ 配置管理（显示、修改配置选项）"""
    global _auth_manager
    
    try:
        config_manager = ConfigManager()
        
        if reset:
            if not Confirm.ask("⚠️  确定要重置配置文件到默认值吗？"):
                console.print("❌ 已取消重置")
                return
            
            # 重置配置
            config_manager.reset_to_defaults()
            console.print("✅ 配置文件已重置到默认值")
            
            # 重新加载全局认证管理器以应用新的超时设置
            _auth_manager = None
            
            show = True  # 重置后显示配置
        
        # 更新配置
        updated = False
        if session_timeout is not None:
            if session_timeout >= 0:
                config_manager.set('session_timeout_seconds', session_timeout)
                console.print(f"✅ 会话超时时间已设置为 {session_timeout} 秒")
                # 重新加载全局认证管理器以应用新的超时设置
                _auth_manager = None
                updated = True
            else:
                console.print("❌ 会话超时时间不能为负数", style="red")
                return
        
        if clipboard_timeout is not None:
            if clipboard_timeout >= 0:
                config_manager.set('auto_clear_clipboard_seconds', clipboard_timeout)
                console.print(f"✅ 剪贴板自动清除时间已设置为 {clipboard_timeout} 秒")
                updated = True
            else:
                console.print("❌ 剪贴板超时时间不能为负数", style="red")
                return
        
        if password_length is not None:
            if password_length > 0:
                config_manager.set('default_password_length', password_length)
                console.print(f"✅ 默认密码长度已设置为 {password_length}")
                updated = True
            else:
                console.print("❌ 密码长度必须大于0", style="red")
                return
        
        
        if symbols is not None:
            if len(symbols) > 0:
                config_manager.set('default_symbols', symbols)
                console.print(f"✅ 默认特殊字符集已设置为 '{symbols}'")
                updated = True
            else:
                console.print("❌ 特殊字符集不能为空", style="red")
                return
        
        # 如果没有指定任何选项，或者用户明确要求显示，则显示配置
        if show or (not reset and not updated):
            console.print("\n📋 当前配置：")
            config_dict = config_manager.get_config_dict()
            
            # 按类别组织显示
            security_config = {
                "会话超时时间": f"{config_dict.get('session_timeout_seconds', 300)} 秒 ({config_dict.get('session_timeout_seconds', 300)//60} 分钟)",
                "剪贴板自动清除": f"{config_dict.get('auto_clear_clipboard_seconds', 30)} 秒",
                "最大认证尝试": f"{config_dict.get('max_auth_attempts', 3)} 次"
            }
            
            generator_config = {
                "默认密码长度": f"{config_dict.get('default_password_length', 16)} 位",
                "使用大写字母": "是" if config_dict.get('default_use_uppercase', True) else "否",
                "使用小写字母": "是" if config_dict.get('default_use_lowercase', True) else "否",
                "使用数字": "是" if config_dict.get('default_use_digits', True) else "否",
                "使用特殊字符": "是" if config_dict.get('default_use_symbols', True) else "否",
                "默认特殊字符集": f"'{config_dict.get('default_symbols', '!@#$%^&*()_+-=[]{}|;:,.<>?')}' ({len(config_dict.get('default_symbols', '!@#$%^&*()_+-=[]{}|;:,.<>?'))} 个字符)"
            }
            
            ui_config = {
                "显示密码强度": "是" if config_dict.get('show_password_strength', True) else "否"
            }
            
            console.print("\n🔒 安全设置:")
            for key, value in security_config.items():
                console.print(f"  {key}: {value}")
            
            console.print("\n🔑 密码生成器设置:")
            for key, value in generator_config.items():
                console.print(f"  {key}: {value}")
            
            console.print("\n🎨 界面设置:")
            for key, value in ui_config.items():
                console.print(f"  {key}: {value}")
            
            console.print(f"\n📁 配置文件: {config_manager.config_path}")
        
        if updated:
            console.print("\n💡 提示：配置更改将在下次认证时生效")
            
    except Exception as e:
        console.print(f"❌ 错误: {e}", style="red")


@cli.command()
@click.option('--config-only', is_flag=True, help='仅重置配置文件，不清理数据库和钥匙串')
@click.option('--force', is_flag=True, help='强制重置，不需要确认')
def reset(config_only, force):
    """🔄 完全重置 PassGen（清理数据库、钥匙串、配置文件）"""
    global _auth_manager
    
    try:
        if config_only:
            # 仅重置配置文件
            config_manager = ConfigManager()
            
            if not force:
                if not Confirm.ask("⚠️  确定要重置配置文件到默认值吗？"):
                    console.print("❌ 已取消重置")
                    return
            
            config_manager.reset_to_defaults()
            console.print("✅ 配置文件已重置到默认值")
            
            # 重新加载全局认证管理器
            _auth_manager = None
            return
        
        # 完全重置
        if not force:
            console.print("⚠️  [bold red]警告：此操作将完全清理 PassGen 的所有本地数据！[/bold red]")
            console.print("\n将要清理的内容：")
            console.print("  • 数据库文件 (~/.passgen.db)")
            console.print("  • 钥匙串中的主密码")
            console.print("  • 配置文件 (~/.passgen_config.json)")
            console.print("  • 当前会话状态")
            console.print("\n💡 如果使用 iCloud 同步，原始数据库文件仍在 iCloud 中保留")
            
            if not Confirm.ask("\n确定要继续重置吗？"):
                console.print("❌ 已取消重置")
                return
        
        console.print("🔄 开始重置 PassGen...")
        
        # 1. 清理钥匙串中的密码
        try:
            import subprocess
            result = subprocess.run([
                'security', 'delete-generic-password', 
                '-s', 'PassGen', 
                '-a', 'master_password_encrypted'
            ], capture_output=True, text=True)
            console.print("✅ 已清理钥匙串中的主密码")
        except Exception:
            console.print("ℹ️  钥匙串中无主密码或清理失败（可能已经是空的）")
        
        # 2. 删除数据库文件
        import os
        from pathlib import Path
        
        db_path = Path.home() / ".passgen.db"
        if db_path.exists():
            # 检查是否是软链接
            if db_path.is_symlink():
                console.print(f"ℹ️  检测到软链接: {db_path} -> {db_path.readlink()}")
                console.print("💡 将删除软链接，但保留 iCloud 中的原始文件")
            
            os.remove(db_path)
            console.print("✅ 已删除数据库文件")
        else:
            console.print("ℹ️  数据库文件不存在")
        
        # 3. 重置配置文件
        config_manager = ConfigManager()
        config_manager.reset_to_defaults()
        console.print("✅ 配置文件已重置到默认值")
        
        # 4. 清理全局会话状态
        _auth_manager = None
        console.print("✅ 会话状态已清理")
        
        console.print("\n🎉 PassGen 重置完成！")
        console.print("\n💡 接下来可以：")
        console.print("  • 运行 'passgen init' 重新初始化")
        console.print("  • 或设置 iCloud 同步链接到现有数据库")
        
    except Exception as e:
        console.print(f"❌ 重置过程中出现错误: {e}", style="red")

if __name__ == "__main__":
    cli()