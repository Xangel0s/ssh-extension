# MCP SRE DevOps Server

Este es un servidor MCP (Model Context Protocol) escrito en Go. Funciona como un router JSON-RPC a través de `stdio`, permitiendo a modelos de IA (como Claude, etc.) interactuar de manera segura y eficiente con tu homelab o infraestructura.

## 🚀 Características

1. **Diagnóstico SSH Seguro (`execute_ssh_diagnostic`)**:
   - Mantiene un pool de conexiones SSH activas para respuestas inmediatas.
   - **Seguridad SRE:** Filtra estrictamente los comandos para permitir únicamente operaciones de **solo lectura**.
   - Admite encadenamiento por pipelines (`|`) siempre que todos los segmentos sean seguros (ej: `docker ps | grep nginx`).
   - Bloquea accesos directos o indirectos a comandos destructivos (`rm`, `mv`, `sudo`), redirecciones (`>`, `>>`) y sustituciones de comandos.

2. **Monitoreo de Proxmox (`get_proxmox_node_status`)**:
   - Conexión sin estado con la API de Proxmox usando tokens de API (`PVEAPIToken`).
   - Retorna estadísticas en tiempo real del hipervisor (CPU, memoria, disco, uptime, etc.).

3. **Orquestación de Coolify**:
   - Listado de aplicaciones (`list_coolify_applications`).
   - Detalles y estado (`get_coolify_application_status`).
   - Obtención de logs en tiempo real (`get_coolify_application_logs`).

---

## 🛠️ Configuración e Instalación

### 1. Compilación
Asegúrate de tener Go instalado y compila el binario:
```bash
go build -o mcp-sre-server.exe ./cmd/server
```

### 2. Configuración en Clientes MCP (ej. Claude Desktop)
Para integrar este servidor en tu cliente de Claude, añade la configuración en el archivo `claude_desktop_config.json`:

* **Ruta en Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
* **Ruta en macOS/Linux:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Añade el servidor en la sección `mcpServers`:

```json
{
  "mcpServers": {
    "mcp-sre-server": {
      "command": "C:\\Users\\User\\Documents\\sysadmin-extension\\mcp-ssh-go\\mcp-sre-server.exe",
      "env": {
        "PROXMOX_URL": "https://192.168.1.100:8006",
        "PROXMOX_TOKEN_ID": "root@pam!sre-token-name",
        "PROXMOX_TOKEN_VALUE": "tu-token-de-proxmox-uuid",
        "PROXMOX_SKIP_TLS_VERIFY": "true",
        "COOLIFY_URL": "http://192.168.1.150:8000",
        "COOLIFY_TOKEN": "tu-api-token-de-coolify",
        "COOLIFY_SKIP_TLS_VERIFY": "true"
      }
    }
  }
}
```

*Nota: Los valores de Proxmox y Coolify son opcionales. Si no se configuran, las herramientas correspondientes devolverán un error amigable al ejecutarse, pero el servidor iniciará sin problemas y las herramientas SSH seguirán funcionando.*

### 🔌 Extensión de VS Code (Sysadmin Extension)
La extensión integrada en esta carpeta (`sysadmin-extension`) permite gestionar, arrancar y monitorear este servidor MCP directamente desde una barra lateral en el IDE.

* **Independencia del Espacio de Trabajo (Workspace-Agnostic):** La extensión resuelve las rutas de ejecución dinámicamente buscando el ejecutable compilado en su propio directorio de instalación (`c:\Users\User\Documents\sysadmin-extension\mcp-ssh-go`). Esto permite arrancar el servidor MCP sin importar qué carpeta o archivo tengas abierto actualmente en la ventana de VS Code.
* **Sistema de Logs de Depuración:** 
  - `extension-debug.log` (en la raíz de la extensión): Registra la activación, comunicación por mensajes de la UI y eventos del ciclo de vida de la extensión.
  - `mcp-server-debug.log` (en la carpeta `mcp-ssh-go`): Guarda el estado, la salida estándar (stdout/stderr) y códigos de salida detallados del binario Go.

---

## 🔒 Filtro de Seguridad SRE (SSH)

El servidor valida cada comando antes de enviarlo a la máquina remota:
* **Comandos Permitidos:** `df`, `free`, `uptime`, `uname`, `hostname`, `top` (solo lectura), `ps`, `journalctl`, `systemctl`, `smartctl`, `docker`, `cat` (solo archivos de sistema no sensibles), `grep`, `tail`, `head`, `ls`, `ping`, `netstat`, `ss`, `ip`, `ifconfig`, `lsof`.
* **Acciones Bloqueadas en Systemctl:** Solo se permiten subcomandos de consulta: `status`, `is-active`, `is-failed`, `list-units`, `list-sockets`, `list-timers`, `show`. Modificadores como `stop`, `start`, `restart`, `disable` o `enable` están bloqueados.
* **Acciones Bloqueadas en Docker:** Solo lectura: `ps`, `stats`, `logs`, `inspect`, `port`, `version`, `info`. Modificadores como `run`, `rm`, `exec` o `stop` están bloqueados.
* **Archivos Bloqueados en Cat:** Bloquea de forma proactiva la visualización de `/etc/shadow`, `/etc/passwd`, claves SSH (`.ssh`, `id_rsa`) y tokens confidenciales.

---

## 🗺️ Roadmap & Siguientes Pasos

1. **📦 Empaquetado en formato `.vsix`:**
   - Crear un script de empaquetado automático (`vsce package`) para poder instalar la extensión localmente con un clic, sin requerir abrir el modo de desarrollo de VS Code.
2. **⚙️ Configuración Visual de Credenciales:**
   - Crear una pestaña de "Ajustes" en el panel lateral que permita editar las variables de entorno (`.env`) y la configuración de Proxmox/Coolify directamente desde la UI con inputs amigables.
3. **🔔 Notificaciones y Alertas Activas:**
   - Implementar un demonio de fondo en Go que monitorice umbrales críticos de CPU/RAM en Proxmox o estados en Coolify, y envíe notificaciones de advertencia nativas a VS Code cuando algo falle.
4. **🔑 Gestión Segura de Claves (Secret Vault):**
   - Integrar la extensión con el VS Code SecretStorage API para guardar passwords de SSH y API tokens de forma segura en el llavero nativo del sistema operativo (Keychain / Windows Credential Manager).
5. **🛡️ Acciones de Escritura Autorizadas (Aprobación Interactiva):**
   - Habilitar comandos para reiniciar servicios o contenedores, pero solicitando confirmación interactiva en pantalla al usuario mediante diálogos emergentes de VS Code antes de enviarlos por SSH.
