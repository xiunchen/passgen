# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PassGen is a modern password generator and manager CLI tool for macOS that features Touch ID biometric authentication. It provides secure password generation, encrypted storage using AES-256-GCM, and seamless integration with macOS Keychain.

## Essential Commands

### Development Environment
```bash
# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
pip install -r requirements.txt

# Run the application
python3 passgen.py [command] [options]
# OR (if added to PATH)
./scripts/passgen [command] [options]
```

### Installation & Setup
```bash
# Auto-install (recommended for new setups)
./install.sh

# Manual installation
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x scripts/passgen
chmod +x passgen.py

# Initialize password manager (first time use)
./passgen.py init
```

### Testing & Validation
```bash
# Test basic functionality
./passgen.py --help
./passgen.py status

# Test authentication
./passgen.py list

# Test password generation
./passgen.py -l 16 --no-save
```

## Architecture Overview

### Core Components

- **`passgen.py`**: Main CLI entry point using Click framework
  - Implements all user commands and interaction flow
  - Manages global authentication manager instance for session persistence
  - Uses Rich library for enhanced terminal output

- **`core/enhanced_auth.py`**: Authentication and session management
  - Touch ID integration using LocalAuthentication framework
  - macOS Keychain integration for secure password storage
  - Session caching with configurable timeout (default 5 minutes)
  - Automatic fallback to password input when Touch ID fails

- **`core/storage.py`**: Encrypted database operations
  - AES-256-GCM encryption with PBKDF2 key derivation
  - SQLite database with file permissions set to 600
  - Password entry CRUD operations with search capabilities

- **`core/generator.py`**: Password generation engine
  - Configurable character sets and length
  - Password strength evaluation
  - Cryptographically secure random generation

- **`core/clipboard.py`**: Secure clipboard management
  - Automatic password copying with time-based clearing
  - Secure memory handling for sensitive data

- **`utils/config.py`**: Configuration management
  - JSON-based configuration stored in `~/.passgen_config.json`
  - Runtime configuration updates with validation

### Data Flow

1. **Authentication**: User authenticates via Touch ID or password
2. **Session Management**: Successful auth creates cached session (configurable timeout)
3. **Storage Access**: Master password decrypts AES-256 encrypted database
4. **Password Operations**: Generate, store, retrieve, or manage passwords
5. **Clipboard Integration**: Passwords automatically copied with secure cleanup

### Security Architecture

- **Master Password**: Stored in macOS Keychain, never in plaintext
- **Database Encryption**: AES-256-GCM with PBKDF2 (100,000 iterations)
- **File Permissions**: Database file set to 600 (user read/write only)
- **Session Security**: Memory-cached sessions with automatic timeout
- **Clipboard Security**: Automatic clearing after 30 seconds (configurable)

## Key Implementation Details

### Global Authentication Manager
The application uses a singleton pattern for authentication management (lines 26-34 in passgen.py) to maintain session state across CLI invocations within the same process.

### Touch ID Integration
Touch ID is implemented using macOS LocalAuthentication framework with automatic fallback to password authentication. This requires the `pyobjc-framework-LocalAuthentication` dependency.

### Database Storage
- Primary database: `~/.passgen.db` (AES-256-GCM encrypted)
- Configuration: `~/.passgen_config.json`
- iCloud sync support via symbolic links to iCloud Drive

### Command Structure
The CLI uses Click's group structure with the main entry point supporting both direct password generation (default) and subcommands for management operations.

## Common Development Patterns

### Adding New Commands
1. Create function with `@cli.command()` decorator
2. Add authentication using `get_auth_manager().authenticate()`
3. Use Rich console for formatted output
4. Handle errors gracefully with try/catch blocks

### Configuration Changes
1. Update `utils/config.py` with new config keys
2. Add validation in ConfigManager class
3. Update CLI options in relevant commands
4. Reset global auth manager when session timeout changes

### Security Considerations
- Never store passwords in plaintext
- Always use the global auth manager for session handling
- Validate user input before database operations
- Use secure memory clearing for sensitive operations

## Dependencies

Core dependencies include:
- `cryptography>=41.0.0`: Encryption and key derivation
- `keyring>=24.0.0`: macOS Keychain integration
- `click>=8.1.0`: CLI framework
- `rich>=13.0.0`: Terminal formatting
- `pyperclip>=1.8.2`: Clipboard operations
- `pyobjc-framework-LocalAuthentication>=10.0`: Touch ID support (macOS only)

## File Structure Context

```
passgen/
├── passgen.py              # Main CLI application entry point
├── core/                   # Core functionality modules
│   ├── enhanced_auth.py    # Touch ID & session management
│   ├── storage.py          # Encrypted database operations
│   ├── generator.py        # Password generation algorithms
│   └── clipboard.py        # Secure clipboard handling
├── utils/
│   └── config.py          # Configuration management
├── scripts/
│   └── passgen            # Bash launcher script
├── install.sh             # Automated installation script
├── uninstall.sh           # Clean removal script
└── requirements.txt       # Python dependencies
```

The application stores user data in:
- `~/.passgen.db`: Encrypted password database
- `~/.passgen_config.json`: User configuration
- macOS Keychain: Master password for Touch ID