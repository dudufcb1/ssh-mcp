#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

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
  if (!config.host) errors.push('Missing required --host');
  if (!config.user) errors.push('Missing required --user');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

validateConfig(argvConfig);


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