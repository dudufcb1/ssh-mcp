# SSH MCP Server

[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Downloads](https://img.shields.io/npm/dm/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Node Version](https://img.shields.io/node/v/ssh-mcp)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/forks)
[![Build Status](https://github.com/tufantunc/ssh-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/tufantunc/ssh-mcp/actions)
[![GitHub issues](https://img.shields.io/github/issues/tufantunc/ssh-mcp)](https://github.com/tufantunc/ssh-mcp/issues)

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/tufantunc/ssh-mcp)](https://archestra.ai/mcp-catalog/tufantunc__ssh-mcp)

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux and Windows systems, enabling LLMs and other MCP clients to execute shell commands securely via SSH.

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Client Setup](#client-setup)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) SSH MCP Server
- [Configure](#configuration) SSH MCP Server
- [Set up](#client-setup) your MCP Client (e.g. Claude Desktop, Cursor, etc)
- Execute remote shell commands on your Linux or Windows server via natural language

## Features

- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux and Windows systems
- Secure authentication via password or SSH key
- Built with TypeScript and the official MCP SDK
- **Configurable timeout protection** with automatic process abortion
- **Graceful timeout handling** - attempts to kill hanging processes before closing connections
- **🔒 Jail/Sandbox System** - Restrict agent operations to specific directories for enhanced security
- **Path traversal protection** - Automatic blocking of `../` and other directory escape attempts

### Tools

- `ssh-access-default`: Execute a shell command on the default SSH server using hardcoded configuration
  - **Parameters:**
    - `command` (required): Shell command to execute on the remote SSH server
  - **Security:** Automatically validates commands against jail configuration if enabled

- `ssh-access-with-credentials`: Execute a shell command using dynamic credentials
  - **Parameters:**
    - `command` (required): Shell command to execute on the remote SSH server
  - **Security:** Automatically validates commands against jail configuration if enabled
  - **Timeout Configuration:**
    - Timeout is configured via command line argument `--timeout` (in milliseconds)
    - Default timeout: 60000ms (1 minute)
    - When a command times out, the server automatically attempts to abort the running process

- `sftp-list-files`: List files and directories in a remote path using SFTP
  - **Parameters:**
    - `remotePath` (required): Remote directory path to list
  - **Security:** Path is validated against jail configuration if enabled

- `sftp-upload`: Upload a local file to the remote server using SFTP
  - **Parameters:**
    - `localPath` (required): Local file path to upload
    - `remotePath` (required): Remote file path where the file will be saved
    - `mode` (optional): File permissions in octal format (default: '644')
  - **Security:** Remote path is validated against jail configuration if enabled

- `sftp-download`: Download a file from the remote server using SFTP
  - **Parameters:**
    - `remotePath` (required): Remote file path to download
    - `localPath` (optional): Local file path to save the downloaded file
    - `asText` (optional): Return file content as text (default: false)
  - **Security:** Remote path is validated against jail configuration if enabled

- `ssh-configure`: Configure SSH connection parameters for the current session
  - **Parameters:**
    - `host` (required): SSH server hostname or IP address
    - `port` (optional): SSH port (default: 22)
    - `username` (required): SSH username
    - `password` (optional): SSH password
    - `privateKeyPath` (optional): Path to private SSH key file
    - `timeout` (optional): Command execution timeout in milliseconds

- `ssh-status`: Show current SSH connection configuration status and manage sessions
  - **Parameters:**
    - `action` (optional): 'show' displays current config, 'clear' removes temporal config

- `ssh-jail-info`: Show comprehensive information about the Jail/Sandbox system
  - **Parameters:**
    - `section` (optional): 'status', 'config', 'examples', 'troubleshooting', or 'all' (default)
  - **Usage:** Get help on jail configuration and troubleshooting

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tufantunc/ssh-mcp.git
   cd ssh-mcp
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```

## Client Setup

You can configure Claude Desktop to use this MCP Server.

**Required Parameters:**
- `host`: Hostname or IP of the Linux or Windows server
- `user`: SSH username

**Optional Parameters:**
- `port`: SSH port (default: 22)
- `password`: SSH password (or use `key` for key-based auth)
- `key`: Path to private SSH key
- `timeout`: Command execution timeout in milliseconds (default: 60000ms = 1 minute)

### Jail/Sandbox Configuration (Optional but Recommended)

The jail system restricts the agent's operations to a specific directory, preventing accidental or malicious access to other parts of the server.

**Environment Variables:**
- `SSH_JAIL_PATH`: (Required if jail enabled) Absolute path to the jail directory
- `SSH_JAIL_ENABLED`: Set to "true" to enable jail protection
- `SSH_JAIL_STRICT`: Set to "true" to prevent jail from being disabled during session

**Example Configuration with Jail:**

```json
{
    "mcpServers": {
        "ssh-mcp-project-a": {
            "command": "npx",
            "args": [
                "ssh-mcp",
                "-y",
                "--",
                "--host=1.2.3.4",
                "--port=22",
                "--user=username",
                "--password=password",
                "--timeout=30000"
            ],
            "env": {
                "SSH_JAIL_PATH": "/home/user/domains/project-a.com",
                "SSH_JAIL_ENABLED": "true",
                "SSH_JAIL_STRICT": "true"
            }
        }
    }
}
```

**Multiple Projects Example:**

```commandline
{
    "mcpServers": {
        "ssh-mcp": {
            "command": "npx",
            "args": [
                "ssh-mcp",
                "-y",
                "--",
                "--host=1.2.3.4",
                "--port=22",
                "--user=root",
                "--password=pass",
                "--key=path/to/key",
                "--timeout=30000"
            ]
        },
        "ssh-mcp-project-b": {
            "command": "npx",
            "args": [
                "ssh-mcp",
                "-y",
                "--",
                "--host=1.2.3.4",
                "--port=22",
                "--user=username",
                "--password=password"
            ],
            "env": {
                "SSH_JAIL_PATH": "/home/user/domains/project-b.com",
                "SSH_JAIL_ENABLED": "true",
                "SSH_JAIL_STRICT": "true"
            }
        }
    }
}
```

### Security Features

The jail system provides multiple layers of protection:

✅ **Path Validation**: All file operations are validated against the jail path
✅ **Command Wrapping**: SSH commands are automatically prefixed to run within the jail
✅ **Path Traversal Protection**: Attempts to use `../` or access parent directories are blocked
✅ **Security Logging**: All blocked access attempts are logged for audit purposes
✅ **Strict Mode**: When enabled, the jail cannot be disabled during the session

**Example blocked operations:**
- Accessing `/etc/passwd` when jail is `/home/user/project`
- Using `cd ../../` to navigate outside the jail
- SFTP operations outside the configured directory

**Getting Help:**

Use the `ssh-jail-info` tool to get comprehensive information about jail configuration:
```bash
# Show all information
ssh-jail-info()

# Show only current status
ssh-jail-info({ section: "status" })

# Show configuration examples
ssh-jail-info({ section: "examples" })

# Show troubleshooting guide
ssh-jail-info({ section: "troubleshooting" })
```

## Testing

You can use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) for visual debugging of this MCP Server.

```sh
npm run inspect
```

## Disclaimer

SSH MCP Server is provided under the [MIT License](./LICENSE). Use at your own risk. This project is not affiliated with or endorsed by any SSH or MCP provider.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](./CONTRIBUTING.md) for more information.

## Code of Conduct

This project follows a [Code of Conduct](./CODE_OF_CONDUCT.md) to ensure a welcoming environment for everyone.

## Support

If you find SSH MCP Server helpful, consider starring the repository or contributing! Pull requests and feedback are welcome. 