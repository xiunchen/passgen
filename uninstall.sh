#!/bin/bash

# 🔐 PassGen 卸载脚本
# 完全清理 PassGen 相关文件和配置

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 确认卸载
confirm_uninstall() {
    echo "🔐 PassGen 卸载脚本"
    echo "==================="
    echo ""
    log_warning "此操作将完全删除 PassGen 及其所有数据！"
    echo ""
    echo "将要删除的内容："
    echo "• PassGen 程序文件"
    echo "• 虚拟环境 (venv/)"
    echo "• 密码数据库 (~/.passgen.db)"
    echo "• 配置文件 (~/.passgen_config.json)"
    echo "• 钥匙串中的主密码"
    echo "• PATH 环境变量配置"
    echo ""
    
    read -p "确定要继续卸载吗？(y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "取消卸载"
        exit 0
    fi
}

# 使用 PassGen 自带的 reset 功能清理数据
cleanup_passgen_data() {
    log_info "清理 PassGen 数据..."
    
    # 如果可以运行 passgen reset，使用它来清理
    if command -v passgen >/dev/null 2>&1; then
        log_info "使用 passgen reset 清理数据..."
        if passgen reset --force 2>/dev/null; then
            log_success "PassGen 数据清理完成"
            return 0
        else
            log_warning "passgen reset 失败，尝试手动清理..."
        fi
    fi
    
    # 手动清理
    manual_cleanup_data
}

# 手动清理数据
manual_cleanup_data() {
    log_info "手动清理 PassGen 数据..."
    
    # 清理钥匙串
    if command -v security >/dev/null 2>&1; then
        if security delete-generic-password -s "PassGen" -a "master_password_encrypted" 2>/dev/null; then
            log_success "已清理钥匙串中的主密码"
        else
            log_info "钥匙串中无主密码或清理失败"
        fi
    fi
    
    # 清理数据库文件
    if [ -f "$HOME/.passgen.db" ]; then
        if [ -L "$HOME/.passgen.db" ]; then
            log_info "检测到软链接，仅删除链接保留原文件"
            rm "$HOME/.passgen.db"
            log_success "已删除数据库软链接"
        else
            rm "$HOME/.passgen.db"
            log_success "已删除数据库文件"
        fi
    else
        log_info "未找到数据库文件"
    fi
    
    # 清理配置文件
    if [ -f "$HOME/.passgen_config.json" ]; then
        rm "$HOME/.passgen_config.json"
        log_success "已删除配置文件"
    else
        log_info "未找到配置文件"
    fi
}

# 清理 PATH 环境变量
cleanup_path() {
    log_info "清理 PATH 环境变量..."
    
    # 检测 shell 配置文件
    local shell_configs=(
        "$HOME/.zshrc"
        "$HOME/.bash_profile"
        "$HOME/.bashrc"
        "$HOME/.profile"
    )
    
    local cleaned=false
    
    for config in "${shell_configs[@]}"; do
        if [ -f "$config" ]; then
            # 检查是否包含 PassGen 相关配置
            if grep -q "pass-gen/scripts\|PassGen" "$config"; then
                log_info "清理 $config 中的 PassGen 配置..."
                
                # 创建备份
                cp "$config" "${config}.backup"
                
                # 删除包含 PassGen 的行
                grep -v "pass-gen/scripts\|PassGen 密码管理器" "$config" > "${config}.tmp" || true
                mv "${config}.tmp" "$config"
                
                log_success "已清理 $config"
                cleaned=true
            fi
        fi
    done
    
    if [ "$cleaned" = true ]; then
        log_warning "请重启终端以使 PATH 更改生效"
    else
        log_info "未找到 PATH 配置"
    fi
}

# 删除项目文件
cleanup_project() {
    log_info "删除项目文件..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$SCRIPT_DIR"
    
    # 确认我们在正确的目录
    if [ ! -f "$PROJECT_DIR/passgen.py" ]; then
        log_error "未在正确的 PassGen 项目目录中"
        exit 1
    fi
    
    # 记录项目路径，用于最后删除
    echo "$PROJECT_DIR" > /tmp/passgen_project_path
    
    log_success "项目文件将在脚本完成后删除"
}

# 最终清理（删除项目目录）
final_cleanup() {
    if [ -f /tmp/passgen_project_path ]; then
        PROJECT_PATH=$(cat /tmp/passgen_project_path)
        rm /tmp/passgen_project_path
        
        log_info "删除项目目录: $PROJECT_PATH"
        
        # 切换到上级目录
        cd "$(dirname "$PROJECT_PATH")"
        
        # 删除项目目录
        rm -rf "$PROJECT_PATH"
        
        log_success "项目目录已删除"
    fi
}

# 显示完成信息
show_completion() {
    echo ""
    echo "🎉 PassGen 卸载完成！"
    echo ""
    echo "已清理的内容："
    echo "✅ PassGen 程序文件"
    echo "✅ 密码数据库和配置文件"
    echo "✅ 钥匙串中的主密码"
    echo "✅ PATH 环境变量配置"
    echo ""
    echo "⚠️  请重启终端以使环境变量更改生效"
    echo ""
    echo "如果将来需要重新安装 PassGen："
    echo "1. 重新克隆项目: git clone <repository>"
    echo "2. 运行安装脚本: ./install.sh"
    echo ""
}

# 主函数
main() {
    confirm_uninstall
    cleanup_passgen_data
    cleanup_path
    cleanup_project
    show_completion
    
    # 在脚本退出时执行最终清理
    trap final_cleanup EXIT
}

# 运行主函数
main "$@"