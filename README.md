# 🔐 PassGen - Mac终端密码生成器/管理器

现代化的密码生成和管理工具CLI，支持 Touch ID 生物识别认证。

## ✨ 功能特性

- 🔑 **智能密码生成**：可自定义长度、字符集的安全密码
- 💾 **加密存储**：AES-GCM 加密，PBKDF2 密钥派生
- 👆 **Touch ID 认证**：便捷的生物识别认证，自动回退
- 🔍 **智能搜索**：支持网站名、用户名、标签、备注搜索
- 📋 **剪贴板集成**：自动复制，30秒后安全清除
- ⚡ **会话管理**：5分钟会话缓存，减少重复认证

## 📋 系统要求

- **操作系统**：macOS 10.13+ （Touch ID 功能需要支持 Touch ID 的 Mac）
- **Python**：Python 3.8 或更高版本
- **依赖**：自动安装脚本会检查并安装所需依赖

**如果没有 Python**：
```bash
# 使用 Homebrew 安装（推荐）
brew install python@3.11

# 或从官网下载安装
# https://www.python.org/downloads/
```

## 🚀 快速开始

### 方法1：自动安装（推荐）

```bash
# 克隆项目
git clone <repository-url> pass-gen
cd pass-gen

# 运行自动安装脚本
./install.sh
```

自动安装脚本会：
- 检查 Python 3.8+ 环境
- 自动创建虚拟环境
- 安装所有依赖
- 设置 PATH 环境变量
- 测试安装结果

### 方法2：手动安装

```bash
# 克隆项目
git clone <repository-url> pass-gen
cd pass-gen

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装 Python 依赖
pip install -r requirements.txt

# 设置可执行权限
chmod +x scripts/passgen
chmod +x passgen.py

# 添加到 PATH（可选）
echo 'export PATH="$(pwd)/scripts:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 初始化

```bash
# 初始化密码管理器（首次使用）
passgen init

# 设置主密码，Touch ID 将自动启用
```

### 开始使用

```bash
# 生成密码（默认功能）
passgen

# 查看密码库（首次会要求密码，之后使用 Touch ID）
passgen list

# 搜索密码
passgen search github
```

## 📖 使用指南

### 密码生成

```bash
# 生成默认密码（16位，包含大小写字母、数字、符号）
passgen

# 自定义密码
passgen -l 20                    # 20位密码
passgen --no-symbols             # 不包含符号
passgen --custom-symbols "!@#$"  # 只使用指定的符号
passgen --exclude "0oO1lI"       # 排除容易混淆的字符
passgen --count 3                # 生成3个密码
passgen --no-save               # 只生成不保存

# 查看帮助
passgen --help
```

### 密码管理

```bash
# 初始化（首次使用）
passgen init

# 查看所有密码（支持交互式选择和复制）
passgen list

# 直接复制指定序号的密码
passgen list -c 3

# 搜索密码
passgen search github
passgen search -c github    # 搜索并复制

# 添加新密码（支持自动生成或手动输入）
passgen add

# 编辑密码条目（使用序号）
passgen edit 1

# 删除密码（使用序号）
passgen delete 2

# 查看认证状态
passgen status

# 配置管理
passgen config                      # 查看当前配置
passgen config --session-timeout 600   # 设置会话超时为10分钟
passgen config --clipboard-timeout 60  # 设置剪贴板1分钟后清除
passgen config --password-length 20    # 设置默认密码长度为20
passgen config --symbols "!@#$%"       # 设置默认特殊字符集
passgen config --reset                 # 重置所有配置到默认值

# 系统重置
passgen reset                       # 完全重置（数据库+钥匙串+配置）
passgen reset --config-only         # 仅重置配置文件
passgen reset --force               # 跳过确认直接重置

# 获取帮助
passgen --help                      # 查看详细使用指南和所有命令
passgen <command> --help            # 查看特定命令的详细选项
```

## 🔒 安全特性

- **军用级加密**：AES-256-GCM 对称加密算法
- **密钥派生**：PBKDF2-HMAC-SHA256，100,000次迭代
- **文件权限**：数据库文件权限设为 600（仅用户可读写）
- **Touch ID 集成**：生物识别认证，密码自动保存到系统钥匙串
- **会话管理**：5分钟自动超时，安全内存清理
- **剪贴板安全**：30秒后自动清除敏感数据

## 📁 文件说明

```
pass-gen/
├── install.sh              # 自动安装脚本
├── uninstall.sh            # 卸载脚本
├── passgen.py              # 主程序（统一CLI工具）
├── scripts/passgen         # 启动脚本
├── core/
│   ├── enhanced_auth.py    # Touch ID 增强认证
│   ├── storage.py          # AES 加密存储
│   ├── generator.py        # 密码生成算法
│   └── clipboard.py        # 安全剪贴板管理
├── utils/config.py         # 配置管理
└── requirements.txt        # Python 依赖
```

## 🛠️ 配置和存储

### 存储文件位置

PassGen 使用以下文件存储数据：

```
~/.passgen.db              # 加密的密码数据库（主要文件）
~/.passgen_config.json     # 系统配置文件
系统钥匙串                  # Touch ID 相关的主密码（macOS Keychain）
```

### 配置文件说明

系统配置位于 `~/.passgen_config.json`：

```json
{
  "default_password_length": 16,
  "default_use_uppercase": true,
  "default_use_lowercase": true,
  "default_use_digits": true,
  "default_use_symbols": true,
  "default_symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?",
  "session_timeout_seconds": 300,
  "auto_clear_clipboard_seconds": 30,
  "show_password_strength": true
}
```

### ⚡ 会话管理优化

**版本 2.1 新功能**：优化了 Touch ID 会话管理，解决每次操作都需要认证的问题：

#### 问题修复
- **全局会话实例**：使用单一的认证管理器实例，确保会话状态在多次操作间保持
- **配置化超时**：可通过配置文件自定义会话超时时间
- **智能缓存**：在会话有效期内，后续操作将自动使用缓存的认证信息

#### 配置会话超时
```bash
# 查看当前会话配置
passgen config

# 设置会话超时为10分钟（600秒）
passgen config --session-timeout 600

# 设置会话超时为1小时（3600秒）
passgen config --session-timeout 3600

# 禁用会话缓存（每次都认证）
passgen config --session-timeout 0
```

#### 会话行为说明
1. **首次认证**：使用 Touch ID 或密码进行身份验证
2. **会话缓存**：认证成功后，会话信息缓存在内存中
3. **后续操作**：在会话有效期内，无需重复认证
4. **自动过期**：超过配置的超时时间后，需要重新认证
5. **进程隔离**：每个 CLI 进程独立管理会话（符合安全最佳实践）

#### 查看会话状态
```bash
# 查看当前认证状态和剩余会话时间
passgen status
```

### 📱 iCloud 实时同步设置

如果您希望在多台 Mac 之间同步密码库，可以使用 iCloud Drive：

#### 方法1：移动到 iCloud Drive（推荐）

```bash
# 1. 确保 iCloud Drive 已启用
# 系统偏好设置 → Apple ID → iCloud → iCloud Drive ✓

# 2. 创建 PassGen 专用文件夹
mkdir -p ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen

# 3. 移动现有数据库到 iCloud（如果已存在）
mv ~/.passgen.db ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/

# 4. 创建软链接（使用绝对路径）
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db

# 5. 验证链接
ls -la ~/.passgen.db
# 应该显示: ~/.passgen.db -> ~/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db
```

#### 方法2：从新初始化到 iCloud

```bash
# 1. 删除现有数据库（⚠️ 注意备份）
rm ~/.passgen.db

# 2. 创建 iCloud 文件夹
mkdir -p ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen

# 3. 创建软链接指向 iCloud（使用绝对路径）
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db

# 4. 重新初始化
passgen init
```

#### 验证同步状态

```bash
# 检查文件是否在 iCloud 中
ls -la ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/

# 检查软链接是否正确
readlink ~/.passgen.db

# 查看 iCloud 同步状态（文件名后应该有云朵图标）
open ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/
```

### 🔄 多设备使用详细指南

#### 第二台 Mac 完整设置步骤

**⚠️ 重要警告**：
- `passgen init` 会在 `~/.passgen.db` 创建新的数据库文件
- 创建软链接前**必须先删除**这个文件，否则会有文件名冲突
- 删除的是空的新数据库，不会影响 iCloud 中的原始数据

**重要概念**：
- 📁 **数据库文件**：存储在 iCloud 中，可以在多台设备间共享
- 🔐 **钥匙串和 Touch ID**：每台 Mac 独立，不会同步
- 🔑 **主密码**：所有设备必须使用相同的主密码

**完整设置流程**：

```bash
# 第二台 Mac 上的设置步骤：

# 步骤1：确保 iCloud 同步完成
ls -la "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/"
# 确认能看到 .passgen.db 文件

# 步骤2：创建软链接
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db

# 步骤3：首次认证（设置钥匙串）
passgen list
# 会提示输入主密码（使用与第一台 Mac 相同的密码）
# 输入正确后，主密码会保存到本机钥匙串，Touch ID 自动启用

# 验证设置成功
passgen status  # 查看 Touch ID 状态
```

**如果遇到"存储文件不存在"错误**：

```bash
# 这通常是因为钥匙串中没有主密码记录，解决方法：

# 方法1：运行任何需要认证的命令来触发密码设置
passgen list  # 输入主密码后会自动保存到钥匙串

# 方法2：如果方法1不工作，手动初始化钥匙串
passgen init  # 输入相同的主密码（这会创建一个新的 ~/.passgen.db 文件）
rm ~/.passgen.db  # ⚠️ 重要：删除刚创建的空数据库文件，避免与软链接冲突
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db
```

#### 多设备使用注意事项

1. **Touch ID 独立性**：每台设备的 Touch ID 设置独立，需要在每台 Mac 上分别进行首次密码认证

2. **主密码一致性**：所有设备必须使用相同的主密码，否则无法解密数据库

3. **同步延迟**：iCloud 同步可能有几秒到几分钟的延迟，建议：
   - 添加密码后等待同步完成再在其他设备使用
   - 避免同时在多台设备上修改密码库

4. **网络要求**：需要稳定的网络连接才能正常同步

5. **冲突处理**：如果出现同步冲突，iCloud 会保留多个版本，手动选择需要的版本

### 🔒 安全建议

- **启用高级数据保护**：在 iCloud 设置中启用"高级数据保护"以获得端到端加密
- **定期本地备份**：除了 iCloud 同步，建议定期手动备份到其他位置
- **验证同步**：定期检查各设备上的数据是否一致

```bash
# 手动备份命令
cp ~/.passgen.db ~/Documents/passgen_backup_$(date +%Y%m%d).db
```

## 🔧 故障排除

### Touch ID 不工作

1. **检查系统设置**：系统偏好设置 → 触控 ID 与密码
2. **确认硬件支持**：需要支持 Touch ID 的 Mac
3. **重新认证**：删除旧数据重新初始化

```bash
# 方法1：使用 reset 命令（推荐）
passgen reset  # 完全重置，包括数据库、钥匙串、配置

# 方法2：手动清理（仅限单设备使用）
rm ~/.passgen.db
passgen init

# 如果使用 iCloud 同步，请按照多设备设置指南操作
```

### 依赖问题

```bash
# 使用虚拟环境
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 忘记主密码

⚠️ **重要**：忘记主密码将无法恢复数据，请务必牢记或安全备份。

```bash
# 重新开始（会丢失所有数据）
passgen reset  # 或手动: rm ~/.passgen.db && passgen init
```

### 测试第二台电脑流程

在当前电脑上模拟第二台电脑的设置流程：

```bash
# 1. 完全重置当前环境
passgen reset

# 2. 确认 iCloud 文件存在
ls -la "$HOME/Library/Mobile Documents/com~apple~CloudDocs/important/passgen/.passgen.db"

# 3. 按照第二台 Mac 设置流程
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/important/passgen/.passgen.db" ~/.passgen.db

# 4. 测试访问（输入原来的主密码）
passgen list

# 5. 恢复正常使用
passgen status  # 验证 Touch ID 状态
```

### 完全卸载 PassGen

如果需要完全移除 PassGen：

```bash
# 方法1：使用卸载脚本（推荐）
./uninstall.sh

# 方法2：手动卸载
passgen reset          # 清理所有数据
cd ..                   # 退出项目目录
rm -rf pass-gen         # 删除项目目录
```

卸载脚本会清理：
- PassGen 程序文件
- 密码数据库和配置文件
- 钥匙串中的主密码
- PATH 环境变量配置

### iCloud 同步问题

#### 软链接断开（常见问题）

**问题**：软链接使用相对路径导致"存储文件不存在"错误

**原因**：如果使用相对路径创建软链接（如 `ln -s ./.passgen.db ~/.passgen.db`），当从不同目录运行 passgen 时，相对路径会解析到错误位置，导致软链接断开。

**解决方案**：始终使用绝对路径创建软链接

#### 软链接断开
```bash
# 检查软链接状态
ls -la ~/.passgen.db

# 检查链接是否断开
file ~/.passgen.db
# 如果显示 "broken symbolic link"，说明链接断开

# 修复断开的软链接（删除并重新创建，使用绝对路径）
rm ~/.passgen.db
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db

# 验证修复结果
file ~/.passgen.db
# 应该显示 "data" 而不是 "broken symbolic link"
```

#### 同步冲突
```bash
# 查看是否有冲突文件
ls -la ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/

# 如果有多个版本（如 .passgen.db 和 .passgen (Conflicted copy).db）
# 1. 备份所有版本
cp ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/*.db ~/Documents/

# 2. 选择最新的版本重新链接（使用绝对路径）
rm ~/.passgen.db
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db
```

#### iCloud 未同步
```bash
# 强制 iCloud 同步
killall bird
open ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/

# 检查 iCloud 状态
brctl log --wait --shorten
```

#### 恢复本地副本
```bash
# 如果 iCloud 出现问题，恢复到本地存储
mv ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/.passgen.db ~/.passgen.db
rm ~/.passgen.db  # 删除软链接
mv ~/.passgen.db.backup ~/.passgen.db  # 使用备份
```

## 📊 使用示例

### 基本工作流
```bash
# 日常工作流
passgen init                     # 首次初始化
passgen -l 20                   # 生成20位密码并保存
passgen list                    # Touch ID 认证，查看密码库
passgen search work             # 搜索工作相关密码
passgen search -c work         # 搜索并复制密码

# 高级用法
passgen --count 5 --no-symbols  # 生成5个无符号密码
passgen edit 1                  # 编辑第1个条目
passgen delete 3                # 删除第3个条目
passgen status                  # 查看认证和系统状态
passgen config --session-timeout 600  # 设置会话超时为10分钟
```

### iCloud 同步完整设置流程
```bash
# 1. 初始化系统
passgen init

# 2. 添加一些测试数据
passgen add
passgen -l 16  # 生成并保存密码

# 3. 设置 iCloud 同步
mkdir -p ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen
mv ~/.passgen.db ~/Library/Mobile\ Documents/com~apple~CloudDocs/PassGen/
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db

# 4. 验证同步设置
ls -la ~/.passgen.db
readlink ~/.passgen.db
passgen list  # 确认数据仍然可访问

# 5. 在其他 Mac 上设置
# 重要：每台 Mac 都需要单独设置 Touch ID 和钥匙串，但可以共享同一个数据库文件

# 方法1：直接链接到现有的 iCloud 数据库（推荐）
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db
# 首次使用时会提示"存储文件不存在"，这是正常的，因为钥匙串中还没有主密码

# 方法2：先初始化再替换（如果方法1不行）
passgen init  # 设置主密码（与第一台 Mac 相同的密码）
rm ~/.passgen.db  # ⚠️ 重要：删除 init 创建的空数据库文件
ln -s "$HOME/Library/Mobile Documents/com~apple~CloudDocs/PassGen/.passgen.db" ~/.passgen.db

# 验证设置
passgen list  # 输入主密码，Touch ID 将自动启用
```

## 🔐 认证流程

1. **首次使用**：设置主密码 → 自动保存到钥匙串
2. **后续使用**：Touch ID 认证 → 自动获取主密码 → 解锁数据库
3. **认证失败**：自动回退到密码输入  
4. **会话管理**：配置的超时时间内（默认5分钟）无需重复认证
5. **配置化管理**：可通过 `passgen config` 自定义会话超时时间

## 📝 版本信息

- **当前版本**：2.1
- **Python 要求**：3.8+
- **系统要求**：macOS 10.13+ （Touch ID 功能）
- **许可证**：MIT

### 更新日志

**v2.1 (2024-07-15)**
- ✅ 修复会话管理问题：现在使用全局认证实例，避免每次操作都需要 Touch ID 认证
- ✅ 简化用户界面：移除复杂的 ID 显示，改用简单的序号操作
- ✅ 合并快速复制功能到搜索命令：`passgen search -c` 
- ✅ 新增配置管理命令：`passgen config` 支持动态修改会话超时等设置
- ✅ 改进命令接口：`passgen edit 1`、`passgen delete 2` 等使用序号操作
- ✅ 增强用户体验：更直观的序号系统，减少用户记忆负担
- ✅ 改进 add 命令：成功添加密码后询问是否继续添加，支持批量添加操作
- ✅ 修复 iCloud 同步文档：更正软链接创建方法，使用绝对路径避免链接断开

**v2.0**
- Touch ID 集成和增强认证系统
- AES-256 加密存储
- 智能密码生成器
- 命令行界面统一

---

💡 **提示**：首次密码认证成功后，系统会自动启用 Touch ID，之后只需指纹即可快速访问密码库。