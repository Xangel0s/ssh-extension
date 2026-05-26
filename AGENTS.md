# AGENTS.md

## Información del Proyecto
Este proyecto es una extensión de VS Code llamada **SysAdmin & MCP Manager** integrada con un servidor MCP escrito en Go (**mcp-ssh-go**). Permite interactuar con servidores remotos mediante SSH seguro, monitorear nodos de Proxmox VE y gestionar contenedores y aplicaciones en Coolify de manera segura mediante la interfaz de VS Code.

## Estructura del Proyecto
- `extension.js`: Código fuente principal de la extensión de VS Code. Implementa el sidebar y la comunicación vía JSON-RPC sobre stdio con el servidor en Go.
- `package.json`: Configuración y dependencias de la extensión de VS Code.
- `mcp-ssh-go/`:
  - `cmd/server/main.go`: Punto de entrada del servidor Go MCP.
  - `internal/`:
    - `ssh/`: Control del pool de conexiones SSH y validación de seguridad de comandos de diagnóstico.
    - `proxmox/`: Cliente para interactuar con la API JSON de Proxmox VE.
    - `coolify/`: Cliente para la API REST de Coolify.
    - `tools/`: Registro y manejo de herramientas del servidor MCP.

## Guía de Desarrollo e Instalación

### Requisitos
- Node.js (v16+)
- Go (v1.18+)

### Comandos Comunes
- Instalar dependencias de la extensión: `npm install`
- Compilar el servidor de Go: `go build -o mcp-sre-server.exe ./cmd/server` (ejecutado dentro del directorio `mcp-ssh-go`)
- Ejecutar pruebas unitarias de Go: `go test ./...`

## Convenciones de Código
- **Estilo de Go:** Seguir estándares de Go (`gofmt`, `go vet`).
- **Principios:** Diseñar componentes desacoplados, cohesivos y listos para pruebas (SOLID, DRY, KISS).
- **Manejo de Errores:** Evitar pánicos silenciosos; propagar y registrar adecuadamente los errores con contexto descriptivo.
- **Confirmación de Cambios:** Siempre mostrar una vista previa/diff de los cambios propuestos al usuario antes de aplicarlos.
