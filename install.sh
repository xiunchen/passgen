#!/bin/bash

# 🔐 PassGen 自动安装脚本
# 自动检测环境、安装依赖、设置 PATH

set -e  # 出错时退出

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

# 检测操作系统
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        log_info "检测到 macOS 系统"
    else
        log_error "目前只支持 macOS 系统"
        exit 1
    fi
}

# 检查 Python 3 安装
check_python() {
    log_info "检查 Python 3 环境..."
    
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        log_success "找到 Python 3: $PYTHON_VERSION"
        
        # 检查版本是否 >= 3.8
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
            log_success "Python 版本满足要求 (>= 3.8)"
        else
            log_error "Python 版本过低，需要 Python 3.8 或更高版本"
            log_info "请升级 Python 或安装较新版本"
            exit 1
        fi
    else
        log_error "未找到 Python 3"
        log_info "请先安装 Python 3.8 或更高版本："
        echo ""
        echo "方法1: 使用 Homebrew"
        echo "  brew install python@3.11"
        echo ""
        echo "方法2: 从官网下载"
        echo "  https://www.python.org/downloads/"
        echo ""
        exit 1
    fi
}

# 检查 pip
check_pip() {
    log_info "检查 pip..."
    
    if command -v pip3 >/dev/null 2>&1; then
        log_success "找到 pip3"
    else
        log_error "未找到 pip3"
        log_info "尝试安装 pip..."
        python3 -m ensurepip --upgrade
    fi
}

# 设置虚拟环境
setup_virtualenv() {
    log_info "设置 Python 虚拟环境..."
    
    if [ -d "venv" ]; then
        log_warning "虚拟环境已存在，删除旧环境..."
        rm -rf venv
    fi
    
    python3 -m venv venv
    log_success "创建虚拟环境成功"
    
    # 激活虚拟环境
    source venv/bin/activate
    log_success "激活虚拟环境"
    
    # 升级 pip
    pip install --upgrade pip
    log_success "升级 pip 完成"
}

# 安装依赖
install_dependencies() {
    log_info "安装 Python 依赖包..."
    
    if [ ! -f "requirements.txt" ]; then
        log_error "未找到 requirements.txt 文件"
        exit 1
    fi
    
    pip install -r requirements.txt
    log_success "依赖包安装完成"
}

# 设置可执行权限
setup_permissions() {
    log_info "设置文件权限..."
    
    chmod +x scripts/passgen
    chmod +x passgen.py
    log_success "文件权限设置完成"
}

# 设置 PATH 环境变量
setup_path() {
    log_info "设置环境变量..."
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SCRIPTS_PATH="$SCRIPT_DIR/scripts"
    
    # 检测用户的默认 shell
    USER_SHELL=$(basename "$SHELL")
    
    if [ "$USER_SHELL" = "zsh" ]; then
        SHELL_RC="$HOME/.zshrc"
        SHELL_NAME="zsh"
    elif [ "$USER_SHELL" = "bash" ]; then
        SHELL_RC="$HOME/.bash_profile"
        SHELL_NAME="bash"
    else
        # 对于其他shell，使用通用的配置文件
        SHELL_RC="$HOME/.profile"
        SHELL_NAME="$USER_SHELL"
    fi
    
    # 检查是否已经添加到 PATH
    if echo "$PATH" | grep -q "$SCRIPTS_PATH"; then
        log_success "PassGen 已在 PATH 中"
        return 0
    fi
    
    # 检查配置文件中是否已存在
    if [ -f "$SHELL_RC" ] && grep -q "pass-gen/scripts" "$SHELL_RC"; then
        log_success "PassGen PATH 已在 $SHELL_NAME 配置中"
        return 0
    fi
    
    # 添加到 PATH
    echo "" >> "$SHELL_RC"
    echo "# PassGen 密码管理器" >> "$SHELL_RC"
    echo "export PATH=\"$SCRIPTS_PATH:\$PATH\"" >> "$SHELL_RC"
    
    log_success "已添加 PassGen 到 $SHELL_NAME 配置文件"
    log_warning "请重新启动终端或运行: source $SHELL_RC"
    
    # 临时添加到当前会话
    export PATH="$SCRIPTS_PATH:$PATH"
    log_success "已临时添加到当前会话 PATH"
}

# 测试安装
test_installation() {
    log_info "测试安装..."
    
    # 激活虚拟环境
    source venv/bin/activate
    
    # 测试 Python 模块导入
    if python3 -c "import click, rich, cryptography, keyring; print('所有依赖模块正常')" 2>/dev/null; then
        log_success "Python 依赖测试通过"
    else
        log_error "Python 依赖测试失败"
        exit 1
    fi
    
    # 测试脚本执行
    if python3 passgen.py --help >/dev/null 2>&1; then
        log_success "PassGen 脚本测试通过"
    else
        log_error "PassGen 脚本测试失败"
        exit 1
    fi
    
    # 测试命令行工具（如果在 PATH 中）
    if command -v passgen >/dev/null 2>&1; then
        log_success "passgen 命令可用"
    else
        log_warning "passgen 命令未在 PATH 中，请重启终端"
    fi
}

# 显示完成信息
show_completion() {
    echo ""
    echo "🎉 PassGen 安装完成！"
    echo ""
    echo "📋 接下来的步骤："
    echo ""
    echo "1. 重启终端或运行以下命令："
    echo "   source ~/.zshrc    # 如果使用 zsh"
    echo "   source ~/.bash_profile    # 如果使用 bash"
    echo ""
    echo "2. 初始化 PassGen："
    echo "   passgen init"
    echo ""
    echo "3. 开始使用："
    echo "   passgen --help     # 查看帮助"
    echo "   passgen            # 生成密码"
    echo "   passgen list       # 查看密码库"
    echo ""
    echo "📚 更多信息请查看 README.md"
    echo ""
}

# 主函数
main() {
    echo "🔐 PassGen 自动安装脚本"
    echo "========================="
    echo ""
    
    # 检查是否在项目目录中
    if [ ! -f "passgen.py" ] || [ ! -f "requirements.txt" ]; then
        log_error "请在 PassGen 项目根目录中运行此脚本"
        exit 1
    fi
    
    detect_os
    check_python
    check_pip
    setup_virtualenv
    install_dependencies
    setup_permissions
    setup_path
    test_installation
    show_completion
}

# 错误处理
trap 'log_error "安装过程中出现错误，请检查上面的错误信息"; exit 1' ERR

# 运行主函数
main "$@"