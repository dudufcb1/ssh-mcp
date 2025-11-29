# SSH MCP Server - Funcionalidades Dinámicas y Sistema de Jail/Sandbox

Este servidor MCP SSH incluye tanto las herramientas originales como las nuevas funcionalidades mejoradas, incluyendo un robusto sistema de Jail/Sandbox para seguridad.

## 🔒 Sistema de Jail/Sandbox (NUEVO)

### ¿Qué es el Sistema de Jail?

El sistema de Jail/Sandbox restringe todas las operaciones del agente MCP a un directorio específico del servidor SSH, previniendo acceso accidental o malicioso a otras partes del sistema.

### Características de Seguridad

✅ **Validación de Paths**: Todos los paths en operaciones SFTP son validados
✅ **Wrapping de Comandos**: Los comandos SSH se ejecutan automáticamente dentro del jail
✅ **Protección Path Traversal**: Bloquea automáticamente `../` y otros intentos de escape
✅ **Logging de Seguridad**: Todos los intentos bloqueados se registran en los logs
✅ **Modo Strict**: Cuando está activado, el jail no puede ser deshabilitado durante la sesión

### Configuración

El jail se configura mediante variables de entorno en tu archivo `mcp_settings.json`:

```json
{
  "mcpServers": {
    "ssh-mcp-proyecto-a": {
      "command": "node",
      "args": [
        "/ruta/a/ssh-mcp/build/index.js",
        "--host=tu-host",
        "--port=22",
        "--user=tu-usuario",
        "--password=tu-password"
      ],
      "env": {
        "SSH_JAIL_PATH": "/home/user/domains/proyecto-a.com",
        "SSH_JAIL_ENABLED": "true",
        "SSH_JAIL_STRICT": "true"
      },
      "type": "stdio"
    }
  }
}
```

### Variables de Entorno

- **`SSH_JAIL_PATH`**: (Requerido si jail está habilitado) Ruta absoluta del directorio jail
- **`SSH_JAIL_ENABLED`**: "true" para activar, "false" para desactivar
- **`SSH_JAIL_STRICT`**: "true" para modo estricto (no se puede deshabilitar durante la sesión)

## Herramientas Disponibles

### 1. `ssh-access-default` (Acceso SSH al Servidor Común)
- **Descripción**: Acceso SSH al servidor por defecto usando configuración hardcodeada
- **Configuración**: Solo via parámetros de línea de comandos (--host, --user, --password, --key)
- **Uso**: Para conectarse al servidor que usas comúnmente y que fue configurado al iniciar el servidor MCP
- **Seguridad**: Si el jail está habilitado, el comando se valida y ejecuta dentro del jail

### 2. `ssh-access-with-credentials` (Acceso SSH con Credenciales Dinámicas)
- **Descripción**: Acceso SSH a cualquier servidor usando credenciales dinámicas
- **Configuración**: Soporta configuración temporal via `ssh-configure` y fallback a hardcodeada
- **Uso**: Para conectarse a servidores que no se usan frecuentemente y requieren credenciales diferentes proporcionadas dinámicamente durante la sesión
- **Timeout**: Timeout configurable (60s por defecto)
- **Seguridad**: Validación automática contra jail si está habilitado
- **Características adicionales**: 
  - Cancelación automática de comandos en timeout
  - Soporte para múltiples métodos de autenticación
  - Gestión avanzada de sesiones

### 3. `ssh-configure` (Configuración Dinámica)
- **Descripción**: Configura conexiones SSH temporales para la sesión actual
- **Parámetros**: host, port, username, password, privateKeyPath, timeout
- **Flexibilidad**: Permite cambiar credenciales sin reiniciar el servidor

### 4. `ssh-status` (Gestión de Estado)
- **Descripción**: Muestra y gestiona el estado de configuración SSH
- **Acciones**: `show` (mostrar estado), `clear` (limpiar configuración temporal)
- **Utilidad**: Debugging y gestión de sesiones

### 5. `sftp-list-files` (Listar Archivos SFTP)
- **Descripción**: Lista archivos y directorios en una ruta remota usando SFTP
- **Parámetros**: remotePath (ruta del directorio remoto)
- **Seguridad**: Path validado contra jail si está habilitado
- **Output**: Información detallada incluyendo permisos, tamaño y fecha de modificación

### 6. `sftp-upload` (Subir Archivo SFTP)
- **Descripción**: Sube un archivo local al servidor remoto usando SFTP
- **Parámetros**: localPath, remotePath, mode (permisos opcionales)
- **Seguridad**: Remote path validado contra jail si está habilitado
- **Soporte**: Archivos de texto y binarios

### 7. `sftp-download` (Descargar Archivo SFTP)
- **Descripción**: Descarga un archivo del servidor remoto usando SFTP
- **Parámetros**: remotePath, localPath (opcional), asText (opcional)
- **Seguridad**: Remote path validado contra jail si está habilitado
- **Opciones**: Guardar en disco o devolver como texto

### 8. `ssh-jail-info` (Información del Sistema de Jail) - NUEVO
- **Descripción**: Muestra información completa sobre la configuración del sistema de Jail/Sandbox
- **Parámetros**: 
  - `section` (opcional): 'status', 'config', 'examples', 'troubleshooting', 'all' (default)
- **Uso**: Obtener ayuda sobre configuración, ejemplos y solución de problemas
- **Secciones**:
  - **status**: Estado actual del jail
  - **config**: Cómo configurar el jail
  - **examples**: Ejemplos de configuración
  - **troubleshooting**: Guía de solución de problemas

## Casos de Uso

### Uso para Múltiples Proyectos con Jail

```json
{
  "mcpServers": {
    "ssh-mcp-midnightblue": {
      "command": "node",
      "args": [...],
      "env": {
        "SSH_JAIL_PATH": "/home/u241574983/domains/midnightblue-porpoise-162417.hostingersite.com",
        "SSH_JAIL_ENABLED": "true",
        "SSH_JAIL_STRICT": "true"
      }
    },
    "ssh-mcp-cetogenicos": {
      "command": "node",
      "args": [...],
      "env": {
        "SSH_JAIL_PATH": "/home/u241574983/domains/cetogenicos.com",
        "SSH_JAIL_ENABLED": "true",
        "SSH_JAIL_STRICT": "true"
      }
    }
  }
}
```

### Uso para Servidor Común sin Jail

```bash
node build/index.js --host=server.com --user=admin --password=secret
# Sin env vars de jail = acceso completo
# Usar herramienta: ssh-access-default
```

### Uso para Servidores Dinámicos

```bash
node build/index.js
# 1. Configurar con ssh-configure para servidor específico
# 2. Usar ssh-access-with-credentials
# 3. Gestionar con ssh-status
```

## Ejemplos de Operaciones Bloqueadas por Jail

Si el jail está configurado en `/home/user/domains/proyecto-a.com`:

❌ **Bloqueado**: `sftp-list-files({ remotePath: "/etc" })`
❌ **Bloqueado**: `ssh-access-with-credentials({ command: "cd /var/www" })`
❌ **Bloqueado**: `sftp-download({ remotePath: "../../passwords.txt" })`
❌ **Bloqueado**: `ssh-access-with-credentials({ command: "cat /etc/passwd" })`

✅ **Permitido**: `sftp-list-files({ remotePath: "/home/user/domains/proyecto-a.com/public_html" })`
✅ **Permitido**: `ssh-access-with-credentials({ command: "ls -la" })` (se ejecuta dentro del jail)
✅ **Permitido**: `sftp-upload({ localPath: "./file.txt", remotePath: "/home/user/domains/proyecto-a.com/file.txt" })`

## Logs de Seguridad

Cuando el jail está activo, todos los intentos bloqueados se registran en stderr:

```
[SECURITY] SSH MCP Server started with ACTIVE JAIL
[SECURITY] Jail Path: /home/user/domains/proyecto-a.com
[SECURITY] Strict Mode: ON
[SECURITY VIOLATION] Access attempt blocked:
  Jail: /home/user/domains/proyecto-a.com
  Attempted: /etc/passwd
```

## Obtener Ayuda

Para obtener información completa sobre el sistema de jail, usa la herramienta:

```bash
# Ver toda la información
ssh-jail-info()

# Ver solo el estado actual
ssh-jail-info({ section: "status" })

# Ver ejemplos de configuración
ssh-jail-info({ section: "examples" })

# Ver guía de solución de problemas
ssh-jail-info({ section: "troubleshooting" })
```

## Coexistencia de Herramientas

- **`ssh-access-default`**: Para tu servidor común configurado al inicio
- **`ssh-access-with-credentials`**: Para servidores ocasionales con credenciales dinámicas
- **`ssh-configure`** y **`ssh-status`**: Gestión dinámica de credenciales
- **`sftp-*`**: Operaciones de transferencia de archivos
- **`ssh-jail-info`**: Información y ayuda sobre el sistema de seguridad

Todas las herramientas pueden usarse en la misma sesión según el servidor al que necesites acceder, y todas respetan las restricciones del jail si está configurado.