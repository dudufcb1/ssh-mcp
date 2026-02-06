#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient } from 'ssh2';
import type { SFTPWrapper, Stats as SftpStats } from 'ssh2';
import type { Stats as FsStats } from 'node:fs';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import path from 'node:path';
import fg from 'fast-glob';

// Example usage: node build/index.js --host=1.2.3.4 --port=22 --user=root --password=pass --key=path/to/key --timeout=5000
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string> = {};
  for (const arg of args) {
    const match = arg.match(/^--([^=]+)=(.*)$/);
    if (match) {
      config[match[1]] = match[2];
    }
  }
  return config;
}
const argvConfig = parseArgv();

const HOST = argvConfig.host;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : 22;
const USER = argvConfig.user;
const PASSWORD = argvConfig.password;
const KEY = argvConfig.key;
const DEFAULT_TIMEOUT = argvConfig.timeout ? parseInt(argvConfig.timeout) : 600000; // 10 minutes default timeout
const POSIX_PATH = path.posix;

// Jail/Sandbox configuration
const JAIL_PATH = process.env.SSH_JAIL_PATH;
const JAIL_ENABLED = process.env.SSH_JAIL_ENABLED === 'true';
const JAIL_STRICT = process.env.SSH_JAIL_STRICT === 'true';

// Validate jail configuration on startup
if (JAIL_ENABLED && !JAIL_PATH) {
  throw new Error('SSH_JAIL_ENABLED is true but SSH_JAIL_PATH is not set');
}

// Security logging on startup
if (JAIL_ENABLED) {
  console.error(`[SECURITY] SSH MCP Server started with ACTIVE JAIL`);
  console.error(`[SECURITY] Jail Path: ${JAIL_PATH}`);
  console.error(`[SECURITY] Strict Mode: ${JAIL_STRICT ? 'ON' : 'OFF'}`);
}

// Normalize path by removing .. and . components and resolving against jail
function normalizePath(path: string, basePath?: string): string {
  // If path is already absolute, use it; otherwise resolve against base
  let fullPath = path;
  if (!path.startsWith('/') && basePath) {
    fullPath = basePath + '/' + path;
  }
  
  const parts = fullPath.split('/').filter(Boolean);
  const stack: string[] = [];
  
  for (const part of parts) {
    if (part === '..') {
      stack.pop();
    } else if (part !== '.') {
      stack.push(part);
    }
  }
  
  return '/' + stack.join('/');
}

// Validate that a path is within the configured jail
function validatePathInJail(path: string): void {
  if (!JAIL_ENABLED) return;
  
  // Normalize the path against the jail base to handle relative paths
  const normalized = normalizePath(path, JAIL_PATH);
  const jailNormalized = normalizePath(JAIL_PATH!);
  
  // Ensure jail path ends with / for exact prefix matching
  const jailWithSlash = jailNormalized.endsWith('/') ? jailNormalized : jailNormalized + '/';
  const normalizedWithSlash = normalized.endsWith('/') ? normalized : normalized + '/';
  
  // Check if normalized path is exactly the jail or starts with jail/
  if (normalized !== jailNormalized && !normalizedWithSlash.startsWith(jailWithSlash)) {
    console.error(`[SECURITY VIOLATION] Access attempt blocked:`);
    console.error(`  Jail: ${jailNormalized}`);
    console.error(`  Attempted: ${normalized}`);
    
    throw new McpError(
      ErrorCode.InvalidParams,
      `ACCESO DENEGADO\n\n` +
      `Este servidor MCP está restringido a:\n${JAIL_PATH}\n\n` +
      `Path intentado: ${path}\n` +
      `Path normalizado: ${normalized}\n\n` +
      `El agente NO tiene permiso para acceder fuera del jail configurado.`
    );
  }
}

// Escape shell argument for safe inclusion in command
function escapeShellArg(arg: string): string {
  // Replace single quotes with '\'' and wrap in single quotes
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

// Validate SSH commands for dangerous patterns
function validateAndWrapCommand(command: string): string {
  if (!JAIL_ENABLED) return command;
  
  // Block any use of .. in arguments (path traversal attempts)
  // This catches ../,  ..\, and standalone ..
  if (/\.\.(?:[\/\\]|\s|$|;)/.test(command)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Comando bloqueado: Detectado intento de path traversal con '..'`
    );
  }
  
  // Block standalone 'cd ..' command
  if (/(?:^|\s|;)cd\s+\.\.(?:\s|;|$)/.test(command)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Comando bloqueado: Intento de 'cd ..' fuera del jail`
    );
  }
  
  // Block absolute paths that go outside jail (but ignore URLs with ://)
  const absolutePathPattern = /(?:^|\s)(?!https?:\/\/)\/([^\s'"]*)/g;
  let match;
  while ((match = absolutePathPattern.exec(command)) !== null) {
    const absPath = '/' + match[1];
    // If it's an absolute path (not URL), validate it
    if (absPath.length > 1 && !absPath.includes('://')) {
      try {
        validatePathInJail(absPath);
      } catch (err) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Comando bloqueado: Ruta absoluta fuera del jail detectada: ${absPath}`
        );
      }
    }
  }
  
  // Block paths in command-line flags like --config=/etc/file
  const flagPathPattern = /--[a-zA-Z0-9-]+=\/([^\s'"]*)/g;
  while ((match = flagPathPattern.exec(command)) !== null) {
    const absPath = '/' + match[1];
    if (absPath.length > 1) {
      try {
        validatePathInJail(absPath);
      } catch (err) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Comando bloqueado: Ruta en flag fuera del jail: ${absPath}`
        );
      }
    }
  }
  
  // Detect cd commands (both absolute and relative)
  const cdPattern = /cd\s+(['"]?)([^'";\s]+)\1/g;
  while ((match = cdPattern.exec(command)) !== null) {
    const targetPath = match[2];
    
    // Validate the cd target (absolute or relative to jail)
    if (targetPath.startsWith('/')) {
      validatePathInJail(targetPath);
    } else if (targetPath !== '.' && targetPath !== '~') {
      // For relative paths, resolve against jail and validate
      const resolvedPath = normalizePath(targetPath, JAIL_PATH);
      validatePathInJail(resolvedPath);
    }
  }
  
  // Force command to execute within jail with proper escaping
  const escapedJailPath = escapeShellArg(JAIL_PATH!);
  return `cd ${escapedJailPath} && ${command}`;
}

function validateConfig(config: Record<string, string>) {
  const errors = [];
  // Only validate if some connection args were provided (partial config is an error)
  const hasAnyConnectionArg = config.host || config.user || config.password || config.key;

  if (hasAnyConnectionArg) {
    if (!config.host) errors.push('Missing required --host');
    if (!config.user) errors.push('Missing required --user');
    if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
    if (errors.length > 0) {
      throw new Error('Configuration error:\n' + errors.join('\n'));
    }
  }
}

validateConfig(argvConfig);

// Log startup mode
if (HOST && USER) {
  console.error(`[SSH MCP] Started with hardcoded connection: ${USER}@${HOST}:${PORT}`);
} else {
  console.error(`[SSH MCP] Started in dynamic mode - use ssh-configure to set connection`);
}


// Dynamic session storage for temporal connections
interface TemporalSSHConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  timeout?: number;
}

let temporalConfig: TemporalSSHConfig | null = null;

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '1.0.7',
  capabilities: {
    resources: {},
    tools: {},
  },
});

server.tool(
  "ssh-configure",
  "Configure SSH connection parameters for this session. The agent will prompt for connection details.",
  {
    host: z.string().describe("SSH server hostname or IP address"),
    port: z.number().optional().describe("SSH port (default: 22)"),
    username: z.string().describe("SSH username"),
    password: z.string().optional().describe("SSH password (optional if using key)"),
    privateKeyPath: z.string().optional().describe("Path to private SSH key file (optional if using password)"),
    timeout: z.number().optional().describe("Command execution timeout in milliseconds (default: 600000)"),
  },
  async ({ host, port = 22, username, password, privateKeyPath, timeout = 600000 }) => {
    try {
      // Validate required parameters
      if (!host || !username) {
        throw new McpError(ErrorCode.InvalidParams, 'Host and username are required parameters.');
      }

      if (!password && !privateKeyPath) {
        throw new McpError(ErrorCode.InvalidParams, 'Either password or privateKeyPath must be provided.');
      }

      // Prepare temporal configuration
      const config: TemporalSSHConfig = {
        host,
        port,
        username,
        timeout,
      };

      if (password) {
        config.password = password;
      }

      if (privateKeyPath) {
        try {
          const fs = await import('fs/promises');
          config.privateKey = await fs.readFile(privateKeyPath, 'utf8');
        } catch (err: any) {
          throw new McpError(ErrorCode.InternalError, `Failed to read private key file: ${err.message}`);
        }
      }

      // Store temporal configuration for this session
      temporalConfig = config;

      return {
        content: [{
          type: 'text',
          text: `Temporal SSH connection configured successfully!\n\nConnection Details:\n- Host: ${host}:${port}\n- Username: ${username}\n- Auth Method: ${password ? 'Password' : 'Private Key'}\n- Timeout: ${timeout}ms\n\nYou can now use the SSH tools to run commands on this server.`,
        }],
      };
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Failed to configure temporal connection: ${err?.message || err}`);
    }
  }
);

server.tool(
  "ssh-status",
  "Show current SSH connection configuration status and manage sessions.",
  {
    action: z.enum(['show', 'clear']).optional().describe("Action to perform: 'show' displays current config, 'clear' removes temporal config (default: show)"),
  },
  async ({ action = 'show' }) => {
    try {
      if (action === 'clear') {
        if (temporalConfig) {
          temporalConfig = null;
          return {
            content: [{
              type: 'text',
              text: 'Temporal SSH configuration cleared successfully.\n\nThe server will now fall back to hardcoded configuration (if available) for future commands.',
            }],
          };
        } else {
          return {
            content: [{
              type: 'text',
              text: 'No temporal configuration to clear.',
            }],
          };
        }
      }

      // Show current configuration status
      let statusText = '📊 SSH MCP Server Configuration Status\n\n';

      if (temporalConfig) {
        statusText += '🔄 **Active Temporal Configuration:**\n';
        statusText += `- Host: ${temporalConfig.host}:${temporalConfig.port}\n`;
        statusText += `- Username: ${temporalConfig.username}\n`;
        statusText += `- Auth Method: ${temporalConfig.password ? 'Password' : 'Private Key'}\n`;
        statusText += `- Timeout: ${temporalConfig.timeout}ms\n\n`;
        statusText += '✅ Ready to execute commands using temporal configuration.\n';
        statusText += 'Use `ssh-status` with action "clear" to remove temporal config.';
      } else {
        statusText += '⚙️ **Hardcoded Configuration:**\n';
        if (HOST && USER) {
          statusText += `- Host: ${HOST}:${PORT}\n`;
          statusText += `- Username: ${USER}\n`;
          statusText += `- Auth Method: ${PASSWORD ? 'Password' : KEY ? 'Private Key' : 'Not configured'}\n`;
          statusText += `- Timeout: ${DEFAULT_TIMEOUT}ms\n\n`;
          statusText += '✅ Ready to execute commands using hardcoded configuration.\n';
        } else {
          statusText += '❌ No hardcoded configuration available.\n\n';
          statusText += '⚠️ **No SSH configuration set!**\n';
          statusText += 'Please use the `ssh-configure` tool to configure connection parameters before using `exec`.';
        }
      }

      return {
        content: [{
          type: 'text',
          text: statusText,
        }],
      };
    } catch (err: any) {
      throw new McpError(ErrorCode.InternalError, `Failed to get status: ${err?.message || err}`);
    }
  }
);

// SSH access to default/common server
server.tool(
  "ssh-access-default",
  "Execute a shell command on the default SSH server using hardcoded configuration. Use this tool when connecting to your commonly used server that was configured when starting the MCP server.",
  {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
  },
  async ({ command }) => {
    // Sanitize command input
    if (typeof command !== 'string' || !command.trim()) {
      throw new McpError(ErrorCode.InternalError, 'Command must be a non-empty string.');
    }
    
    // Validate and wrap command within jail if enabled
    const safeCommand = validateAndWrapCommand(command);
    
    const sshConfig: any = {
      host: HOST,
      port: PORT,
      username: USER,
    };
    
    try {
      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
      const result = await execSshCommandSimple(sshConfig, safeCommand);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// SSH access with dynamic credentials
server.tool(
  "ssh-access-with-credentials",
  "Execute a shell command on any SSH server using dynamic credentials. Use this tool when you need to connect to servers that are not used frequently and require different credentials to be provided dynamically during the session.",
  {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
  },
  async ({ command }) => {
    // Sanitize command input
    if (typeof command !== 'string' || !command.trim()) {
      throw new McpError(ErrorCode.InternalError, 'Command must be a non-empty string.');
    }
    
    // Validate and wrap command within jail if enabled
    const safeCommand = validateAndWrapCommand(command);

    // Determine which configuration to use - temporal takes priority
    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      // Use temporal configuration
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      // Fall back to hardcoded configuration
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }
      
      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await execSshCommand(sshConfig, safeCommand, timeout);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// Original simple SSH command execution (without timeout)
async function execSshCommandSimple(sshConfig: any, command: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          conn.end();
          return;
        }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, signal: string) => {
          conn.end();
          if (stderr) {
            reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
          } else {
            resolve({
              content: [{
                type: 'text',
                text: stdout,
              }],
            });
          }
        });
        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
    conn.on('error', (err) => {
      reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
    });
    conn.connect(sshConfig);
  });
}

// SFTP List Files Tool
server.tool(
  "sftp-list-files",
  "List files and directories in a remote path using SFTP. Shows detailed information including permissions, size, and modification time.",
  {
    remotePath: z.string().describe("Remote directory path to list (e.g., '/home/user', '/var/www', '.')"),
  },
  async ({ remotePath }) => {
    // Sanitize path input
    if (typeof remotePath !== 'string' || !remotePath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a non-empty string.');
    }
    
    // Validate path is within jail if enabled
    validatePathInJail(remotePath);

    // Determine which configuration to use - temporal takes priority
    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      // Use temporal configuration
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      // Fall back to hardcoded configuration
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }
      
      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await sftpListFiles(sshConfig, remotePath, timeout);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// SFTP Upload File Tool
server.tool(
  "sftp-upload",
  "Upload a local file to the remote server using SFTP. Supports both text and binary files.",
  {
    localPath: z.string().describe("Local file path to upload (e.g., '/home/user/document.txt', './config.json')"),
    remotePath: z.string().describe("Remote file path where the file will be saved (e.g., '/var/www/document.txt', './config.json')"),
    mode: z.string().optional().describe("File permissions in octal format (e.g., '644', '755'). Defaults to '644'"),
  },
  async ({ localPath, remotePath, mode = '644' }) => {
    // Sanitize inputs
    if (typeof localPath !== 'string' || !localPath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Local path must be a non-empty string.');
    }
    if (typeof remotePath !== 'string' || !remotePath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a non-empty string.');
    }
    
    // Validate remote path is within jail if enabled
    validatePathInJail(remotePath);

    // Determine which configuration to use - temporal takes priority
    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      // Use temporal configuration
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      // Fall back to hardcoded configuration
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }
      
      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await sftpUploadFile(sshConfig, localPath, remotePath, mode, timeout);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// SFTP Upload Directory Tool
server.tool(
  "sftp-upload-directory",
  "Upload all files within a local directory to the remote server using SFTP. Supports recursive uploads.",
  {
    localPath: z.string().describe("Local directory path to upload (e.g., './dist', '/home/user/site')"),
    remotePath: z.string().describe("Remote directory path where contents will be uploaded (e.g., '/var/www', './public_html')"),
    recursive: z.boolean().optional().describe("Recursively include subdirectories (default: true)"),
    mode: z.string().optional().describe("Override file permissions in octal format for all uploads (e.g., '644'). Defaults to preserving local permissions"),
  },
  async ({ localPath, remotePath, recursive = true, mode }) => {
    if (typeof localPath !== 'string' || !localPath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Local path must be a non-empty string.');
    }
    if (typeof remotePath !== 'string' || !remotePath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a non-empty string.');
    }

    validatePathInJail(remotePath);

    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }

      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await sftpUploadDirectory(sshConfig, localPath, remotePath, recursive, mode, timeout);
      return result;
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// SFTP Batch Upload Tool
server.tool(
  "sftp-upload-batch",
  "Upload multiple files to the remote server in a single operation. Supports glob patterns for local files.",
  {
    files: z.array(z.object({
      local: z.string().describe("Local file path or glob pattern (e.g., './dist/index.html', './dist/_astro/*')"),
      remote: z.string().describe("Remote file path or target directory when using patterns (e.g., '/var/www/index.html', '/var/www/_astro/')"),
      mode: z.string().optional().describe("Override file permissions in octal format for matching files"),
    })).min(1).describe("List of files or patterns to upload"),
  },
  async ({ files }) => {
    if (!Array.isArray(files) || files.length === 0) {
      throw new McpError(ErrorCode.InvalidParams, 'Provide at least one file mapping.');
    }

    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }

      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await sftpUploadBatch(sshConfig, files, timeout);
      return result;
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// SFTP Sync Tool
server.tool(
  "sftp-sync",
  "Synchronize a local directory with a remote directory. Optionally delete remote files that no longer exist locally.",
  {
    localPath: z.string().describe("Local directory to sync from (e.g., './dist')"),
    remotePath: z.string().describe("Remote directory to sync to (e.g., '/var/www/html')"),
    delete: z.boolean().optional().describe("If true, delete remote files/directories that are missing locally (default: false)"),
  },
  async ({ localPath, remotePath, delete: deleteFlag = false }) => {
    if (typeof localPath !== 'string' || !localPath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Local path must be a non-empty string.');
    }
    if (typeof remotePath !== 'string' || !remotePath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a non-empty string.');
    }

    validatePathInJail(remotePath);

    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }

      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await sftpSyncDirectories(sshConfig, localPath, remotePath, deleteFlag, timeout);
      return result;
    } catch (err: any) {
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// SFTP Download File Tool
server.tool(
  "sftp-download", 
  "Download a file from the remote server using SFTP. Can save to local path or return content as text.",
  {
    remotePath: z.string().describe("Remote file path to download (e.g., '/var/www/config.txt', './document.pdf')"),
    localPath: z.string().optional().describe("Local file path to save the downloaded file. If not provided, file content will be returned as text (only for text files)"),
    asText: z.boolean().optional().describe("If true and no localPath provided, return file content as text. Use only for text files. Defaults to false for binary safety"),
  },
  async ({ remotePath, localPath, asText = false }) => {
    // Sanitize inputs
    if (typeof remotePath !== 'string' || !remotePath.trim()) {
      throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a non-empty string.');
    }
    
    // Validate remote path is within jail if enabled
    validatePathInJail(remotePath);

    // Determine which configuration to use - temporal takes priority
    let sshConfig: any;
    let timeout: number;

    if (temporalConfig) {
      // Use temporal configuration
      sshConfig = {
        host: temporalConfig.host,
        port: temporalConfig.port,
        username: temporalConfig.username,
      };
      timeout = temporalConfig.timeout || 600000;

      if (temporalConfig.password) {
        sshConfig.password = temporalConfig.password;
      } else if (temporalConfig.privateKey) {
        sshConfig.privateKey = temporalConfig.privateKey;
      }
    } else {
      // Fall back to hardcoded configuration
      if (!HOST || !USER) {
        throw new McpError(ErrorCode.InvalidParams, 'No temporal configuration set and missing required hardcoded parameters. Please use ssh-configure tool first to configure connection.');
      }
      
      sshConfig = {
        host: HOST,
        port: PORT,
        username: USER,
      };
      timeout = DEFAULT_TIMEOUT;

      if (PASSWORD) {
        sshConfig.password = PASSWORD;
      } else if (KEY) {
        const fs = await import('fs/promises');
        sshConfig.privateKey = await fs.readFile(KEY, 'utf8');
      }
    }

    try {
      const result = await sftpDownloadFile(sshConfig, remotePath, localPath, asText, timeout);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// Enhanced SSH command execution (with timeout support)
async function execSshCommand(sshConfig: any, command: string, timeout: number = DEFAULT_TIMEOUT): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;
    
    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        // Close connection immediately on timeout
        // Note: We cannot safely kill the remote process without risking injection
        // The timeout itself will cause the SSH session to close
        conn.end();
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${timeout}ms`));
      }
    }, timeout);
    
    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          }
          conn.end();
          return;
        }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            if (stderr) {
              reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
            } else {
              resolve({
                content: [{
                  type: 'text',
                  text: stdout,
                }],
              });
            }
          }
        });
        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
    conn.on('error', (err) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    conn.connect(sshConfig);
  });
}

function normalizeRemoteDirectoryPath(remotePath: string): string {
  const trimmed = remotePath.trim();
  if (!trimmed || trimmed === '.') return '.';
  if (trimmed === '/') return '/';
  const withoutTrailing = trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
  return POSIX_PATH.normalize(withoutTrailing || '.');
}

function normalizeRemoteFilePath(remotePath: string): string {
  const trimmed = remotePath.trim();
  if (!trimmed) {
    throw new McpError(ErrorCode.InvalidParams, 'Remote path must be a non-empty string.');
  }
  return POSIX_PATH.normalize(trimmed);
}

function joinRemotePath(base: string, segment: string): string {
  if (!base || base === '.' || base === './') {
    return POSIX_PATH.normalize(segment);
  }
  return POSIX_PATH.normalize(POSIX_PATH.join(base, segment));
}

function toPosixRelativePath(relative: string): string {
  if (!relative) return relative;
  return relative.split(path.sep).join('/');
}

function isNoSuchFileError(err: any): boolean {
  if (!err) return false;
  if (err.code === 2 || err.code === 'ENOENT') return true;
  const message = String(err.message || '').toLowerCase();
  return message.includes('no such file') || message.includes('does not exist');
}

function parseMode(mode: string | undefined): number | undefined {
  if (mode === undefined) return undefined;
  const trimmed = mode.trim();
  if (!/^[0-7]{3,4}$/.test(trimmed)) {
    throw new McpError(ErrorCode.InvalidParams, `Invalid mode "${mode}". Expected octal string such as 644 or 755.`);
  }
  return parseInt(trimmed, 8);
}

async function withSftpConnection<T>(sshConfig: any, timeout: number, handler: (sftp: SFTPWrapper) => Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let timeoutId: NodeJS.Timeout;
    let finished = false;

    const finalizeSuccess = (result: T) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutId);
      conn.end();
      resolve(result);
    };

    const finalizeError = (error: any) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutId);
      conn.end();
      if (error instanceof McpError) {
        reject(error);
      } else if (error && error.message) {
        reject(new McpError(ErrorCode.InternalError, error.message));
      } else {
        reject(new McpError(ErrorCode.InternalError, 'Unknown SFTP error'));
      }
    };

    timeoutId = setTimeout(() => {
      finalizeError(new McpError(ErrorCode.InternalError, `SFTP operation timed out after ${timeout}ms`));
    }, timeout);

    conn.on('ready', () => {
      conn.sftp(async (err, sftp) => {
        if (err) {
          finalizeError(new McpError(ErrorCode.InternalError, `SFTP session error: ${err.message}`));
          return;
        }

        try {
          const result = await handler(sftp);
          finalizeSuccess(result);
        } catch (handlerErr: any) {
          finalizeError(handlerErr);
        }
      });
    });

    conn.on('error', (err) => {
      finalizeError(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
    });

    conn.connect(sshConfig);
  });
}

function sftpStat(sftp: SFTPWrapper, remotePath: string): Promise<SftpStats> {
  return new Promise((resolve, reject) => {
    sftp.stat(remotePath, (err, stats) => {
      if (err) reject(err);
      else resolve(stats);
    });
  });
}

function sftpLstat(sftp: SFTPWrapper, remotePath: string): Promise<SftpStats> {
  return new Promise((resolve, reject) => {
    sftp.lstat(remotePath, (err, stats) => {
      if (err) reject(err);
      else resolve(stats);
    });
  });
}

function sftpMkdir(sftp: SFTPWrapper, remotePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.mkdir(remotePath, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function sftpUnlink(sftp: SFTPWrapper, remotePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.unlink(remotePath, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function sftpRmdir(sftp: SFTPWrapper, remotePath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    sftp.rmdir(remotePath, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function sftpReaddir(sftp: SFTPWrapper, remotePath: string) {
  return new Promise<{ filename: string; longname: string; attrs: SftpStats; }[]>((resolve, reject) => {
    sftp.readdir(remotePath, (err, list) => {
      if (err) reject(err);
      else resolve(list);
    });
  });
}

function sftpFastPut(sftp: SFTPWrapper, localPath: string, remotePath: string, mode?: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const callback = (err?: Error | null) => {
      if (err) reject(err);
      else resolve();
    };

    if (mode !== undefined) {
      sftp.fastPut(localPath, remotePath, { mode }, callback);
    } else {
      sftp.fastPut(localPath, remotePath, callback);
    }
  });
}

async function ensureRemoteDirectory(sftp: SFTPWrapper, remoteDir: string): Promise<void> {
  const normalized = normalizeRemoteDirectoryPath(remoteDir);
  if (normalized === '.' || normalized === '') return;
  if (normalized === '/') return;

  const parts = normalized.split('/').filter(Boolean);
  let current = normalized.startsWith('/') ? '/' : '';

  for (const part of parts) {
    current = current === '/' ? POSIX_PATH.join(current, part) : (current ? POSIX_PATH.join(current, part) : part);
    validatePathInJail(current);

    try {
      const stats = await sftpStat(sftp, current);
      if (!stats.isDirectory()) {
        throw new McpError(ErrorCode.InternalError, `Remote path ${current} exists and is not a directory.`);
      }
    } catch (err: any) {
      if (isNoSuchFileError(err)) {
        try {
          await sftpMkdir(sftp, current);
        } catch (mkdirErr: any) {
          throw new McpError(
            ErrorCode.InternalError,
            `Failed to create remote directory ${current}: ${mkdirErr?.message || mkdirErr}`
          );
        }
      } else {
        if (err instanceof McpError) throw err;
        throw new McpError(
          ErrorCode.InternalError,
          `Failed to inspect remote path ${current}: ${err?.message || err}`
        );
      }
    }
  }
}

interface LocalFileInfo {
  absolutePath: string;
  relativePath: string;
  stats: FsStats;
}

async function collectLocalFiles(baseDir: string, recursive: boolean): Promise<LocalFileInfo[]> {
  const fs = await import('fs/promises');
  const patterns = recursive ? ['**/*'] : ['*'];
  const entries = await fg(patterns, {
    cwd: baseDir,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
  });

  const result: LocalFileInfo[] = [];
  for (const entry of entries) {
    const relativePosix = toPosixRelativePath(entry);
    const absolutePath = path.resolve(baseDir, entry);
    const stats = await fs.stat(absolutePath);
    result.push({
      absolutePath,
      relativePath: relativePosix,
      stats,
    });
  }
  return result;
}

interface RemoteTreeState {
  files: Map<string, SftpStats>;
  directories: Set<string>;
}

async function collectRemoteTree(sftp: SFTPWrapper, remoteBase: string): Promise<RemoteTreeState> {
  const files = new Map<string, SftpStats>();
  const directories = new Set<string>();
  const normalizedBase = normalizeRemoteDirectoryPath(remoteBase);

  try {
    const baseStats = await sftpLstat(sftp, normalizedBase);
    if (!baseStats.isDirectory()) {
      throw new McpError(ErrorCode.InvalidParams, `Remote path ${normalizedBase} exists and is not a directory.`);
    }
  } catch (err: any) {
    if (isNoSuchFileError(err)) {
      return { files, directories };
    }
    if (err instanceof McpError) throw err;
    throw new McpError(ErrorCode.InternalError, `Failed to inspect remote path ${normalizedBase}: ${err?.message || err}`);
  }

  directories.add('');

  async function traverse(currentRemote: string, relative: string): Promise<void> {
    let list;
    try {
      list = await sftpReaddir(sftp, currentRemote);
    } catch (err: any) {
      if (isNoSuchFileError(err)) return;
      throw new McpError(ErrorCode.InternalError, `Failed to read remote directory ${currentRemote}: ${err?.message || err}`);
    }

    for (const entry of list) {
      const childRemote = joinRemotePath(currentRemote, entry.filename);
      const childRelative = relative ? `${relative}/${entry.filename}` : entry.filename;
      if (entry.attrs.isDirectory()) {
        directories.add(childRelative);
        await traverse(childRemote, childRelative);
      } else {
        files.set(childRelative, entry.attrs);
      }
    }
  }

  await traverse(normalizedBase, '');
  return { files, directories };
}

function buildLocalDirectorySet(localFiles: LocalFileInfo[]): Set<string> {
  const directories = new Set<string>();
  directories.add('');
  for (const file of localFiles) {
    const parts = file.relativePath.split('/').filter(Boolean);
    if (parts.length <= 1) continue;
    let current = '';
    for (let i = 0; i < parts.length - 1; i++) {
      current = current ? `${current}/${parts[i]}` : parts[i];
      directories.add(current);
    }
  }
  return directories;
}

type BatchUploadDescriptor = {
  local: string;
  remote: string;
  mode?: string;
};

// SFTP list files function
async function sftpListFiles(sshConfig: any, remotePath: string, timeout: number = DEFAULT_TIMEOUT): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;
    
    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        conn.end();
        reject(new McpError(ErrorCode.InternalError, `SFTP list operation timed out after ${timeout}ms`));
      }
    }, timeout);
    
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SFTP session error: ${err.message}`));
          }
          conn.end();
          return;
        }
        
        sftp.readdir(remotePath, (err, list) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            
            if (err) {
              reject(new McpError(ErrorCode.InternalError, `SFTP readdir error: ${err.message}`));
            } else {
              // Format the file list for display
              let resultText = `📁 Remote Directory Listing: ${remotePath}\n\n`;
              
              if (list.length === 0) {
                resultText += '(empty directory)\n';
              } else {
                // Sort by type (directories first) then by name
                list.sort((a, b) => {
                  const aIsDir = a.attrs.isDirectory();
                  const bIsDir = b.attrs.isDirectory();
                  if (aIsDir !== bIsDir) return bIsDir ? 1 : -1;
                  return a.filename.localeCompare(b.filename);
                });
                
                for (const item of list) {
                  const isDir = item.attrs.isDirectory();
                  const isLink = item.attrs.isSymbolicLink();
                  const size = item.attrs.size || 0;
                  const mtime = item.attrs.mtime ? new Date(item.attrs.mtime * 1000).toISOString() : 'unknown';
                  const permissions = item.attrs.mode ? '0' + (item.attrs.mode & parseInt('777', 8)).toString(8) : 'unknown';
                  
                  let icon = '📄'; // file
                  if (isDir) icon = '📁'; // directory
                  else if (isLink) icon = '🔗'; // symbolic link
                  
                  resultText += `${icon} ${item.filename.padEnd(30)} ${size.toString().padStart(10)} bytes  ${permissions}  ${mtime}\n`;
                }
              }
              
              resolve({
                content: [{
                  type: 'text',
                  text: resultText,
                }],
              });
            }
          }
        });
      });
    });
    
    conn.on('error', (err) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    
    conn.connect(sshConfig);
  });
}

// SFTP upload file function
async function sftpUploadFile(sshConfig: any, localPath: string, remotePath: string, mode: string, timeout: number = DEFAULT_TIMEOUT): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise(async (resolve, reject) => {
    const conn = new SSHClient();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;
    
    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        conn.end();
        reject(new McpError(ErrorCode.InternalError, `SFTP upload operation timed out after ${timeout}ms`));
      }
    }, timeout);

    try {
      // Check if local file exists and get its stats
      const fs = await import('fs/promises');
      const localStats = await fs.stat(localPath);
      const fileSize = localStats.size;
      
      conn.on('ready', () => {
        conn.sftp((err, sftp) => {
          if (err) {
            if (!isResolved) {
              isResolved = true;
              clearTimeout(timeoutId);
              reject(new McpError(ErrorCode.InternalError, `SFTP session error: ${err.message}`));
            }
            conn.end();
            return;
          }
          
          // Convert mode string to number
          const fileMode = parseInt(mode, 8);
          
          // Use writeFile for simpler implementation
          fs.readFile(localPath).then((data) => {
            sftp.writeFile(remotePath, data, { mode: fileMode }, (err) => {
              if (!isResolved) {
                isResolved = true;
                clearTimeout(timeoutId);
                conn.end();
                
                if (err) {
                  reject(new McpError(ErrorCode.InternalError, `SFTP upload error: ${err.message}`));
                } else {
                  resolve({
                    content: [{
                      type: 'text',
                      text: `✅ File uploaded successfully!\n\nLocal: ${localPath}\nRemote: ${remotePath}\nSize: ${fileSize} bytes\nPermissions: ${mode}\n\nUpload completed.`,
                    }],
                  });
                }
              }
            });
          }).catch((readErr) => {
            if (!isResolved) {
              isResolved = true;
              clearTimeout(timeoutId);
              conn.end();
              reject(new McpError(ErrorCode.InternalError, `Failed to read local file: ${readErr.message}`));
            }
          });
        });
      });
      
      conn.on('error', (err) => {
        if (!isResolved) {
          isResolved = true;
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
        }
      });
      
      conn.connect(sshConfig);
    } catch (fsErr: any) {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `Local file access error: ${fsErr.message}`));
      }
    }
  });
}

async function sftpUploadDirectory(
  sshConfig: any,
  localPath: string,
  remotePath: string,
  recursive: boolean,
  mode: string | undefined,
  timeout: number = DEFAULT_TIMEOUT
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; })[] }> {
  const fs = await import('fs/promises');
  const resolvedLocal = path.resolve(localPath);
  let localStats: FsStats;
  try {
    localStats = await fs.stat(resolvedLocal);
  } catch (err: any) {
    throw new McpError(ErrorCode.InvalidParams, `Local directory not found: ${localPath}`);
  }

  if (!localStats.isDirectory()) {
    throw new McpError(ErrorCode.InvalidParams, `Local path must be a directory: ${localPath}`);
  }

  const remoteBase = normalizeRemoteDirectoryPath(remotePath);
  validatePathInJail(remoteBase);
  const parsedMode = parseMode(mode);
  const localFiles = await collectLocalFiles(resolvedLocal, recursive);

  const transferStats = await withSftpConnection(sshConfig, timeout, async (sftp) => {
    await ensureRemoteDirectory(sftp, remoteBase);
    let uploaded = 0;
    let bytes = 0;

    for (const file of localFiles) {
      const remoteFilePath = joinRemotePath(remoteBase, file.relativePath);
      validatePathInJail(remoteFilePath);
      const remoteDir = POSIX_PATH.dirname(remoteFilePath);
      await ensureRemoteDirectory(sftp, remoteDir);
      const effectiveMode = parsedMode ?? (file.stats.mode & 0o777);
      await sftpFastPut(sftp, file.absolutePath, remoteFilePath, effectiveMode);
      uploaded += 1;
      bytes += file.stats.size;
    }

    return { uploaded, bytes };
  });

  const messageLines = [
    'Directory upload completed.',
    `Local base: ${resolvedLocal}`,
    `Remote base: ${remoteBase}`,
    `Recursive: ${recursive ? 'yes' : 'no'}`,
    `Files found: ${localFiles.length}`,
    `Files uploaded: ${transferStats.uploaded}`,
    `Total bytes transferred: ${transferStats.bytes}`,
    `Mode: ${mode ? mode : 'preserve local permissions'}`,
  ];

  return {
    content: [{
      type: 'text',
      text: messageLines.join('\n'),
    }],
  };
}

async function sftpUploadBatch(
  sshConfig: any,
  descriptors: BatchUploadDescriptor[],
  timeout: number = DEFAULT_TIMEOUT
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; })[] }> {
  const fs = await import('fs/promises');
  const cwd = process.cwd();

  const uploads: { local: string; remote: string; mode: number; size: number; }[] = [];
  const seen = new Map<string, number>();

  for (const descriptor of descriptors) {
    const trimmedLocal = (descriptor.local || '').trim();
    const trimmedRemote = (descriptor.remote || '').trim();

    if (!trimmedLocal) {
      throw new McpError(ErrorCode.InvalidParams, 'Each batch entry must include a local path or pattern.');
    }
    if (!trimmedRemote) {
      throw new McpError(ErrorCode.InvalidParams, 'Each batch entry must include a remote path.');
    }

    const parsedMode = parseMode(descriptor.mode);
    const isPattern = fg.isDynamicPattern(trimmedLocal);

    if (isPattern) {
      const remoteBase = normalizeRemoteDirectoryPath(trimmedRemote);
      validatePathInJail(remoteBase);
      const tasks = fg.generateTasks([trimmedLocal], {
        cwd,
        dot: true,
        followSymbolicLinks: false,
      });

      let matched = 0;

      for (const task of tasks) {
        const basePath = path.resolve(cwd, task.base);
        const matches = await fg(task.patterns, {
          cwd,
          dot: true,
          onlyFiles: true,
          absolute: true,
          followSymbolicLinks: false,
        });

        for (const match of matches) {
          matched += 1;
          const stats = await fs.stat(match);
          const relativeRaw = path.relative(basePath, match);
          const relative = relativeRaw ? toPosixRelativePath(relativeRaw) : path.basename(match);
          const remoteFilePath = joinRemotePath(remoteBase, relative);
          validatePathInJail(remoteFilePath);
          const effectiveMode = parsedMode ?? (stats.mode & 0o777);
          const item = { local: match, remote: remoteFilePath, mode: effectiveMode, size: stats.size };
          if (seen.has(remoteFilePath)) {
            uploads[seen.get(remoteFilePath)!] = item;
          } else {
            seen.set(remoteFilePath, uploads.length);
            uploads.push(item);
          }
        }
      }

      if (matched === 0) {
        throw new McpError(ErrorCode.InvalidParams, `No files matched pattern: ${trimmedLocal}`);
      }
    } else {
      const absoluteLocal = path.resolve(trimmedLocal);
      let stats: FsStats;
      try {
        stats = await fs.stat(absoluteLocal);
      } catch (err: any) {
        throw new McpError(ErrorCode.InvalidParams, `Local file not found: ${trimmedLocal}`);
      }

      if (!stats.isFile()) {
        throw new McpError(ErrorCode.InvalidParams, `Local path must be a file: ${trimmedLocal}`);
      }

      let remoteFilePath: string;
      if (trimmedRemote.endsWith('/')) {
        const remoteBase = normalizeRemoteDirectoryPath(trimmedRemote);
        validatePathInJail(remoteBase);
        remoteFilePath = joinRemotePath(remoteBase, path.basename(absoluteLocal));
      } else {
        remoteFilePath = normalizeRemoteFilePath(trimmedRemote);
        validatePathInJail(remoteFilePath);
      }

      const effectiveMode = parsedMode ?? (stats.mode & 0o777);
      const item = { local: absoluteLocal, remote: remoteFilePath, mode: effectiveMode, size: stats.size };
      if (seen.has(remoteFilePath)) {
        uploads[seen.get(remoteFilePath)!] = item;
      } else {
        seen.set(remoteFilePath, uploads.length);
        uploads.push(item);
      }
    }
  }

  if (uploads.length === 0) {
    throw new McpError(ErrorCode.InvalidParams, 'No files resolved for batch upload.');
  }

  const transferStats = await withSftpConnection(sshConfig, timeout, async (sftp) => {
    let uploaded = 0;
    let bytes = 0;

    for (const item of uploads) {
      const remoteDir = POSIX_PATH.dirname(item.remote);
      await ensureRemoteDirectory(sftp, remoteDir);
      await sftpFastPut(sftp, item.local, item.remote, item.mode);
      uploaded += 1;
      bytes += item.size;
    }

    return { uploaded, bytes };
  });

  const messageLines = [
    'Batch upload completed.',
    `Batch entries: ${descriptors.length}`,
    `Files uploaded: ${transferStats.uploaded}`,
    `Total bytes transferred: ${transferStats.bytes}`,
  ];

  return {
    content: [{
      type: 'text',
      text: messageLines.join('\n'),
    }],
  };
}

async function sftpSyncDirectories(
  sshConfig: any,
  localPath: string,
  remotePath: string,
  deleteRemote: boolean,
  timeout: number = DEFAULT_TIMEOUT
): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; })[] }> {
  const fs = await import('fs/promises');
  const resolvedLocal = path.resolve(localPath);
  let localStats: FsStats;

  try {
    localStats = await fs.stat(resolvedLocal);
  } catch (err: any) {
    throw new McpError(ErrorCode.InvalidParams, `Local directory not found: ${localPath}`);
  }

  if (!localStats.isDirectory()) {
    throw new McpError(ErrorCode.InvalidParams, `Local path must be a directory: ${localPath}`);
  }

  const remoteBase = normalizeRemoteDirectoryPath(remotePath);
  validatePathInJail(remoteBase);

  const localFiles = await collectLocalFiles(resolvedLocal, true);
  const localFileSet = new Set(localFiles.map((file) => file.relativePath));
  const localDirectories = buildLocalDirectorySet(localFiles);

  const syncStats = await withSftpConnection(sshConfig, timeout, async (sftp) => {
    const remoteState = await collectRemoteTree(sftp, remoteBase);
    await ensureRemoteDirectory(sftp, remoteBase);

    let uploaded = 0;
    let skipped = 0;
    let deletedFiles = 0;
    let deletedDirs = 0;
    let uploadedBytes = 0;

    for (const file of localFiles) {
      const remoteFilePath = joinRemotePath(remoteBase, file.relativePath);
      validatePathInJail(remoteFilePath);
      const remoteDir = POSIX_PATH.dirname(remoteFilePath);
      await ensureRemoteDirectory(sftp, remoteDir);
      const remoteStats = remoteState.files.get(file.relativePath);
      const localMode = file.stats.mode & 0o777;
      const localMtimeSeconds = Math.floor(file.stats.mtimeMs / 1000);
      const needsUpload = !remoteStats ||
        remoteStats.size !== file.stats.size ||
        (remoteStats.mtime ?? 0) !== localMtimeSeconds;

      if (needsUpload) {
        await sftpFastPut(sftp, file.absolutePath, remoteFilePath, localMode);
        uploaded += 1;
        uploadedBytes += file.stats.size;
      } else {
        skipped += 1;
      }
    }

    if (deleteRemote) {
      for (const [remoteRelative] of remoteState.files) {
        if (!localFileSet.has(remoteRelative)) {
          const remoteFilePath = joinRemotePath(remoteBase, remoteRelative);
          validatePathInJail(remoteFilePath);
          try {
            await sftpUnlink(sftp, remoteFilePath);
            deletedFiles += 1;
          } catch (err: any) {
            throw new McpError(
              ErrorCode.InternalError,
              `Failed to delete remote file ${remoteFilePath}: ${err?.message || err}`
            );
          }
        }
      }

      const dirsToDelete = Array.from(remoteState.directories)
        .filter((dir) => dir && !localDirectories.has(dir))
        .sort((a, b) => b.split('/').length - a.split('/').length);

      for (const dir of dirsToDelete) {
        const remoteDirPath = joinRemotePath(remoteBase, dir);
        validatePathInJail(remoteDirPath);
        try {
          await sftpRmdir(sftp, remoteDirPath);
          deletedDirs += 1;
        } catch (err: any) {
          throw new McpError(
            ErrorCode.InternalError,
            `Failed to delete remote directory ${remoteDirPath}: ${err?.message || err}`
          );
        }
      }
    }

    return { uploaded, skipped, deletedFiles, deletedDirs, uploadedBytes };
  });

  const messageLines = [
    'Directory sync completed.',
    `Local base: ${resolvedLocal}`,
    `Remote base: ${remoteBase}`,
    `Local files: ${localFiles.length}`,
    `Uploaded: ${syncStats.uploaded}`,
    `Skipped (unchanged): ${syncStats.skipped}`,
    `Bytes uploaded: ${syncStats.uploadedBytes}`,
    deleteRemote ? `Remote files deleted: ${syncStats.deletedFiles}` : 'Remote files deleted: 0 (delete=false)',
    deleteRemote ? `Remote directories deleted: ${syncStats.deletedDirs}` : 'Remote directories deleted: 0 (delete=false)',
  ];

  return {
    content: [{
      type: 'text',
      text: messageLines.join('\n'),
    }],
  };
}

// SFTP download file function
async function sftpDownloadFile(sshConfig: any, remotePath: string, localPath?: string, asText: boolean = false, timeout: number = DEFAULT_TIMEOUT): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;
    
    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        conn.end();
        reject(new McpError(ErrorCode.InternalError, `SFTP download operation timed out after ${timeout}ms`));
      }
    }, timeout);
    
    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SFTP session error: ${err.message}`));
          }
          conn.end();
          return;
        }
        
        sftp.readFile(remotePath, (err, data) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            
            if (err) {
              reject(new McpError(ErrorCode.InternalError, `SFTP download error: ${err.message}`));
            } else {
              if (localPath) {
                // Save to local file
                import('fs/promises').then(fs => {
                  fs.writeFile(localPath, data).then(() => {
                    resolve({
                      content: [{
                        type: 'text',
                        text: `✅ File downloaded successfully!\n\nRemote: ${remotePath}\nLocal: ${localPath}\nSize: ${data.length} bytes\n\nDownload completed.`,
                      }],
                    });
                  }).catch((writeErr) => {
                    reject(new McpError(ErrorCode.InternalError, `Failed to write local file: ${writeErr.message}`));
                  });
                }).catch((importErr) => {
                  reject(new McpError(ErrorCode.InternalError, `Failed to import fs module: ${importErr.message}`));
                });
              } else if (asText) {
                // Return content as text
                try {
                  const textContent = data.toString('utf8');
                  resolve({
                    content: [{
                      type: 'text',
                      text: `📄 File Content: ${remotePath}\nSize: ${data.length} bytes\n\n${'─'.repeat(50)}\n${textContent}\n${'─'.repeat(50)}`,
                    }],
                  });
                } catch (decodeErr) {
                  reject(new McpError(ErrorCode.InternalError, `Failed to decode file as text: file may be binary`));
                }
              } else {
                // Return basic info without content (safe for binary files)
                resolve({
                  content: [{
                    type: 'text',
                    text: `✅ File downloaded to memory!\n\nRemote: ${remotePath}\nSize: ${data.length} bytes\n\n⚠️ File content not displayed (use localPath to save or asText=true for text files)`,
                  }],
                });
              }
            }
          }
        });
      });
    });
    
    conn.on('error', (err) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    
    conn.connect(sshConfig);
  });
}

// Tool to provide information about jail configuration
server.tool(
  "ssh-jail-info",
  "Show comprehensive information about the Jail/Sandbox system configuration, including current status, configuration examples, and troubleshooting guide.",
  {
    section: z.enum(['status', 'config', 'examples', 'troubleshooting', 'all']).optional()
      .describe("Section to display: 'status' (current state), 'config' (how to configure), 'examples' (examples), 'troubleshooting' (problem solving), 'all' (everything). Default: 'all'")
  },
  async ({ section = 'all' }) => {
    let output = '';

    // CURRENT STATUS
    if (section === 'status' || section === 'all') {
      output += `╔════════════════════════════════════════════════════════════╗\n`;
      output += `║           🔒 ESTADO ACTUAL DEL JAIL SYSTEM                ║\n`;
      output += `╚════════════════════════════════════════════════════════════╝\n\n`;
      
      if (JAIL_ENABLED) {
        output += `✅ **JAIL ACTIVO Y OPERANDO**\n\n`;
        output += `📍 **Path del Jail:**\n   ${JAIL_PATH}\n\n`;
        output += `🔐 **Modo:**\n   ${JAIL_STRICT ? 'STRICT (no se puede deshabilitar)' : 'Normal'}\n\n`;
        output += `📊 **Restricciones Activas:**\n`;
        output += `   • ✅ Todas las operaciones SFTP validadas\n`;
        output += `   • ✅ Todos los comandos SSH validados\n`;
        output += `   • ✅ Path traversal bloqueado (../ protegido)\n`;
        output += `   • ✅ Acceso a directorios externos: DENEGADO\n\n`;
        output += `⚠️ **Importante:** Este jail fue configurado al inicio del servidor\n`;
        output += `   y NO puede ser modificado durante esta sesión.\n\n`;
      } else {
        output += `⚠️ **JAIL NO CONFIGURADO**\n\n`;
        output += `El agente tiene acceso SIN RESTRICCIONES al servidor SSH.\n\n`;
        output += `💡 **Recomendación:** Configura un jail para mayor seguridad.\n`;
        output += `   Ver sección 'config' para instrucciones.\n\n`;
      }
    }

    // CONFIGURATION
    if (section === 'config' || section === 'all') {
      output += `\n╔════════════════════════════════════════════════════════════╗\n`;
      output += `║              ⚙️  CÓMO CONFIGURAR EL JAIL                  ║\n`;
      output += `╚════════════════════════════════════════════════════════════╝\n\n`;
      
      output += `**1. Localiza tu archivo de configuración MCP:**\n\n`;
      output += `   Roo/Cline:\n`;
      output += `   ~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json\n\n`;
      output += `   Claude Desktop:\n`;
      output += `   ~/Library/Application Support/Claude/claude_desktop_config.json (Mac)\n`;
      output += `   %APPDATA%/Claude/claude_desktop_config.json (Windows)\n\n`;
      
      output += `**2. Agrega las variables de entorno al servidor SSH:**\n\n`;
      output += `   \`\`\`json\n`;
      output += `   {\n`;
      output += `     "mcpServers": {\n`;
      output += `       "ssh-mcp-NOMBRE-PROYECTO": {\n`;
      output += `         "command": "node",\n`;
      output += `         "args": [\n`;
      output += `           "/ruta/a/ssh-mcp/build/index.js",\n`;
      output += `           "--host=TU_HOST",\n`;
      output += `           "--port=22",\n`;
      output += `           "--user=TU_USUARIO",\n`;
      output += `           "--password=TU_PASSWORD"\n`;
      output += `         ],\n`;
      output += `         "env": {\n`;
      output += `           "SSH_JAIL_PATH": "/ruta/absoluta/al/proyecto",\n`;
      output += `           "SSH_JAIL_ENABLED": "true",\n`;
      output += `           "SSH_JAIL_STRICT": "true"\n`;
      output += `         },\n`;
      output += `         "type": "stdio"\n`;
      output += `       }\n`;
      output += `     }\n`;
      output += `   }\n`;
      output += `   \`\`\`\n\n`;
      
      output += `**3. Variables de entorno disponibles:**\n\n`;
      output += `   • \`SSH_JAIL_PATH\`: (Requerido) Ruta absoluta del directorio jail\n`;
      output += `   • \`SSH_JAIL_ENABLED\`: (Requerido) "true" para activar, "false" para desactivar\n`;
      output += `   • \`SSH_JAIL_STRICT\`: (Opcional) "true" = no se puede deshabilitar durante sesión\n\n`;
    }

    // EXAMPLES
    if (section === 'examples' || section === 'all') {
      output += `\n╔════════════════════════════════════════════════════════════╗\n`;
      output += `║                  📚 EJEMPLOS DE USO                        ║\n`;
      output += `╚════════════════════════════════════════════════════════════╝\n\n`;
      
      output += `**Ejemplo 1: Configuración para múltiples proyectos**\n\n`;
      output += `   \`\`\`json\n`;
      output += `   {\n`;
      output += `     "mcpServers": {\n`;
      output += `       "ssh-mcp-proyecto-a": {\n`;
      output += `         "command": "node",\n`;
      output += `         "args": [...],\n`;
      output += `         "env": {\n`;
      output += `           "SSH_JAIL_PATH": "/home/user/domains/proyecto-a.com",\n`;
      output += `           "SSH_JAIL_ENABLED": "true",\n`;
      output += `           "SSH_JAIL_STRICT": "true"\n`;
      output += `         }\n`;
      output += `       },\n`;
      output += `       "ssh-mcp-proyecto-b": {\n`;
      output += `         "command": "node",\n`;
      output += `         "args": [...],\n`;
      output += `         "env": {\n`;
      output += `           "SSH_JAIL_PATH": "/home/user/domains/proyecto-b.com",\n`;
      output += `           "SSH_JAIL_ENABLED": "true",\n`;
      output += `           "SSH_JAIL_STRICT": "true"\n`;
      output += `         }\n`;
      output += `       }\n`;
      output += `     }\n`;
      output += `   }\n`;
      output += `   \`\`\`\n\n`;
      
      output += `**Ejemplo 2: Configuración típica de Hostinger**\n\n`;
      output += `   \`\`\`json\n`;
      output += `   "ssh-mcp-midnightblue": {\n`;
      output += `     "command": "node",\n`;
      output += `     "args": [\n`;
      output += `       "/media/eduardo/.../ssh-mcp/build/index.js",\n`;
      output += `       "--host=62.72.50.50",\n`;
      output += `       "--port=65002",\n`;
      output += `       "--user=u241574983",\n`;
      output += `       "--password=YOUR_PASSWORD",\n`;
      output += `       "--timeout=30000"\n`;
      output += `     ],\n`;
      output += `     "env": {\n`;
      output += `       "SSH_JAIL_PATH": "/home/u241574983/domains/midnightblue-porpoise-162417.hostingersite.com",\n`;
      output += `       "SSH_JAIL_ENABLED": "true",\n`;
      output += `       "SSH_JAIL_STRICT": "true"\n`;
      output += `     },\n`;
      output += `     "type": "stdio"\n`;
      output += `   }\n`;
      output += `   \`\`\`\n\n`;
      
      output += `**Ejemplo 3: Servidor sin jail (acceso completo)**\n\n`;
      output += `   \`\`\`json\n`;
      output += `   "ssh-mcp-admin": {\n`;
      output += `     "command": "node",\n`;
      output += `     "args": [...],\n`;
      output += `     "env": {\n`;
      output += `       "SSH_JAIL_ENABLED": "false"\n`;
      output += `     }\n`;
      output += `   }\n`;
      output += `   \`\`\`\n\n`;
    }

    // TROUBLESHOOTING
    if (section === 'troubleshooting' || section === 'all') {
      output += `\n╔════════════════════════════════════════════════════════════╗\n`;
      output += `║            🔧 SOLUCIÓN DE PROBLEMAS                        ║\n`;
      output += `╚════════════════════════════════════════════════════════════╝\n\n`;
      
      output += `**Problema 1: "⛔ ACCESO DENEGADO" al intentar una operación**\n\n`;
      output += `   ✅ Solución: Verifica que el path esté dentro del jail configurado.\n`;
      output += `   Usa la tool 'ssh-jail-info' sección 'status' para ver el jail activo.\n\n`;
      
      output += `**Problema 2: Necesito trabajar en otro proyecto**\n\n`;
      output += `   ✅ Solución: Crea una nueva instancia MCP con diferente nombre:\n`;
      output += `      • Agrega "ssh-mcp-OTRO-PROYECTO" a mcp_settings.json\n`;
      output += `      • Configura SSH_JAIL_PATH para el nuevo proyecto\n`;
      output += `      • Reinicia el IDE para cargar la nueva configuración\n\n`;
      
      output += `**Problema 3: El jail no se está aplicando**\n\n`;
      output += `   ✅ Verifica:\n`;
      output += `      1. SSH_JAIL_ENABLED está en "true" (no true sin comillas)\n`;
      output += `      2. SSH_JAIL_PATH es una ruta absoluta que empieza con /\n`;
      output += `      3. Reiniciaste el IDE después de cambiar la configuración\n\n`;
      
      output += `**Problema 4: "Command execution timed out"**\n\n`;
      output += `   ✅ Solución: Aumenta el timeout en los args:\n`;
      output += `      "--timeout=600000" (10 minutos)\n\n`;
      
      output += `**Problema 5: Necesito acceso completo temporalmente**\n\n`;
      output += `   ✅ Solución:\n`;
      output += `      • Crea una instancia "ssh-mcp-admin" sin jail\n`;
      output += `      • Usa esa instancia solo cuando necesites acceso total\n`;
      output += `      • Mantén las instancias con jail para trabajo diario\n\n`;
    }

    // FOOTER
    if (section === 'all') {
      output += `\n╔════════════════════════════════════════════════════════════╗\n`;
      output += `║                    💡 TIPS ÚTILES                          ║\n`;
      output += `╚════════════════════════════════════════════════════════════╝\n\n`;
      
      output += `🔹 Usa nombres descriptivos para cada instancia MCP\n`;
      output += `🔹 El jail protege contra errores accidentales del agente\n`;
      output += `🔹 Puedes tener múltiples instancias corriendo simultáneamente\n`;
      output += `🔹 Los logs de seguridad se muestran en la consola del servidor\n`;
      output += `🔹 Path traversal (../) está bloqueado automáticamente\n\n`;
      
      output += `📖 **Ver secciones específicas:**\n`;
      output += `   • ssh-jail-info({ section: "status" })         - Estado actual\n`;
      output += `   • ssh-jail-info({ section: "config" })         - Cómo configurar\n`;
      output += `   • ssh-jail-info({ section: "examples" })       - Ejemplos\n`;
      output += `   • ssh-jail-info({ section: "troubleshooting" }) - Soluciones\n`;
    }

    return {
      content: [{
        type: 'text',
        text: output
      }]
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
