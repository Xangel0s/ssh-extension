import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

let serverProcess: cp.ChildProcess | null = null;
let currentRequestId = 1;
const pendingRequests = new Map<number, { resolve: (value: any) => void; reject: (reason: any) => void }>();
let outputChannel: vscode.OutputChannel | null = null;
let activeWebview: vscode.WebviewView | null = null;

function debugLog(msg: string) {
    try {
        const logPath = path.join(__dirname, 'extension-debug.log');
        const time = new Date().toISOString();
        fs.appendFileSync(logPath, `[${time}] ${msg}\n`);
    } catch (e: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Failed to write global debug log: ${e.message}`);
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    debugLog("activate() called");
    // Create the Output Channel named "MCP SRE Audit" to capture stderr logs
    outputChannel = vscode.window.createOutputChannel("MCP SRE Audit");
    context.subscriptions.push(outputChannel);

    outputChannel.appendLine("MCP SRE Audit Log Initialized.");

    // Register Webview View Provider
    const provider = new MCPSidebarProvider(context.extensionUri, context);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider("sysadmin-mcp-manager", provider)
    );

    // Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sysadmin-extension.startServer', () => {
            debugLog("Command startServer triggered");
            provider.startServer();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sysadmin-extension.stopServer', () => {
            debugLog("Command stopServer triggered");
            provider.stopServer();
        })
    );
}

export function deactivate() {
    debugLog("deactivate() called");
    if (serverProcess) {
        serverProcess.kill();
    }
}

class MCPSidebarProvider implements vscode.WebviewViewProvider {
    private readonly _extensionUri: vscode.Uri;
    private readonly _context: vscode.ExtensionContext;

    constructor(extensionUri: vscode.Uri, context: vscode.ExtensionContext) {
        this._extensionUri = extensionUri;
        this._context = context;
    }

    resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        debugLog("resolveWebviewView() called");
        activeWebview = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        // Send current status immediately
        this.updateStatus(serverProcess ? 'Running' : 'Stopped');

        webviewView.webview.onDidReceiveMessage(async (data) => {
            debugLog(`Received message from webview: ${JSON.stringify(data)}`);
            switch (data.type) {
                case 'start':
                    this.startServer();
                    break;
                case 'stop':
                    this.stopServer();
                    break;
                case 'executeTool':
                    this.runTool(data.tool, data.args);
                    break;
                case 'getStatus':
                    this.updateStatus(serverProcess ? 'Running' : 'Stopped');
                    break;
                case 'getSettings': {
                    const config = vscode.workspace.getConfiguration('mcpSreManager');
                    webviewView.webview.postMessage({
                        type: 'settings',
                        config: {
                            sshHost: config.get('sshHost') || '',
                            sshPort: config.get('sshPort') || 22,
                            sshUser: config.get('sshUser') || 'root',
                            proxmoxUrl: config.get('proxmoxUrl') || '',
                            proxmoxTokenId: config.get('proxmoxTokenId') || '',
                            proxmoxSkipTlsVerify: config.get('proxmoxSkipTlsVerify') !== false,
                            coolifyUrl: config.get('coolifyUrl') || '',
                            coolifySkipTlsVerify: config.get('coolifySkipTlsVerify') !== false,
                            monitoringInterval: config.get('monitoringInterval') || '30s',
                            monitoringCpuThreshold: config.get('monitoringCpuThreshold') || 90,
                            monitoringMemThreshold: config.get('monitoringMemThreshold') || 90
                        },
                        secrets: {
                            sshPass: await this._context.secrets.get('sshPass') || '',
                            proxmoxTokenValue: await this._context.secrets.get('proxmoxTokenValue') || '',
                            coolifyToken: await this._context.secrets.get('coolifyToken') || ''
                        }
                    });
                    break;
                }
                case 'saveSettings': {
                    const config = vscode.workspace.getConfiguration('mcpSreManager');
                    await config.update('sshHost', data.config.sshHost, vscode.ConfigurationTarget.Global);
                    await config.update('sshPort', data.config.sshPort, vscode.ConfigurationTarget.Global);
                    await config.update('sshUser', data.config.sshUser, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxUrl', data.config.proxmoxUrl, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxTokenId', data.config.proxmoxTokenId, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxSkipTlsVerify', data.config.proxmoxSkipTlsVerify, vscode.ConfigurationTarget.Global);
                    await config.update('coolifyUrl', data.config.coolifyUrl, vscode.ConfigurationTarget.Global);
                    await config.update('coolifySkipTlsVerify', data.config.coolifySkipTlsVerify, vscode.ConfigurationTarget.Global);
                    await config.update('monitoringInterval', data.config.monitoringInterval, vscode.ConfigurationTarget.Global);
                    await config.update('monitoringCpuThreshold', data.config.monitoringCpuThreshold, vscode.ConfigurationTarget.Global);
                    await config.update('monitoringMemThreshold', data.config.monitoringMemThreshold, vscode.ConfigurationTarget.Global);
                    
                    if (data.secrets.sshPass) {
                        await this._context.secrets.store('sshPass', data.secrets.sshPass);
                    } else {
                        await this._context.secrets.delete('sshPass');
                    }
                    if (data.secrets.proxmoxTokenValue) {
                        await this._context.secrets.store('proxmoxTokenValue', data.secrets.proxmoxTokenValue);
                    } else {
                        await this._context.secrets.delete('proxmoxTokenValue');
                    }
                    if (data.secrets.coolifyToken) {
                        await this._context.secrets.store('coolifyToken', data.secrets.coolifyToken);
                    } else {
                        await this._context.secrets.delete('coolifyToken');
                    }
                    vscode.window.showInformationMessage("Ajustes guardados correctamente.");
                    // Refresh settings in UI
                    webviewView.webview.postMessage({
                        type: 'settings',
                        config: data.config,
                        secrets: data.secrets
                    });
                    break;
                }
                case 'showMessage':
                    if (data.severity === 'warning') {
                        vscode.window.showWarningMessage(data.message);
                    } else if (data.severity === 'error') {
                        vscode.window.showErrorMessage(data.message);
                    } else {
                        vscode.window.showInformationMessage(data.message);
                    }
                    break;
            }
        });
    }

    logToFile(logPath: string, msg: string) {
        debugLog(`logToFile: ${msg}`);
        try {
            const time = new Date().toISOString();
            fs.appendFileSync(logPath, `[${time}] ${msg}\n`);
        } catch (e: any) {
            if (outputChannel) {
                outputChannel.appendLine(`Failed to write debug log file: ${e.message}`);
            }
        }
    }

    async startServer() {
        if (serverProcess) {
            vscode.window.showInformationMessage("MCP Server is already running.");
            return;
        }

        const extensionDir = this._context.extensionUri.fsPath;
        const workspaceFolders = vscode.workspace.workspaceFolders;
        const workspaceRoot = (workspaceFolders && workspaceFolders.length > 0) ? workspaceFolders[0].uri.fsPath : null;
        
        // Robust scanning for compiled binary
        let binPath = "";
        let cwd = "";

        const binarySearchPaths = [
            {
                bin: path.join(extensionDir, 'mcp-ssh-go', 'mcp-sre-server.exe'),
                dir: path.join(extensionDir, 'mcp-ssh-go')
            },
            {
                bin: path.join(extensionDir, 'mcp-sre-server.exe'),
                dir: extensionDir
            }
        ];

        if (workspaceRoot) {
            binarySearchPaths.push({
                bin: path.join(workspaceRoot, 'mcp-ssh-go', 'mcp-sre-server.exe'),
                dir: path.join(workspaceRoot, 'mcp-ssh-go')
            });
            binarySearchPaths.push({
                bin: path.join(workspaceRoot, 'mcp-sre-server.exe'),
                dir: workspaceRoot
            });
        }

        // Search for the first existing compiled binary
        for (const item of binarySearchPaths) {
            if (fs.existsSync(item.bin)) {
                binPath = item.bin;
                cwd = item.dir;
                break;
            }
        }

        const logPath = path.join(cwd || extensionDir, 'mcp-server-debug.log');

        // Clean old log file
        try {
            if (fs.existsSync(logPath)) {
                fs.unlinkSync(logPath);
            }
        } catch (e) {}

        this.logToFile(logPath, `Resolved extensionDir: ${extensionDir}`);
        this.logToFile(logPath, `Resolved workspaceRoot: ${workspaceRoot}`);
        this.logToFile(logPath, `Resolved binPath: ${binPath}`);
        this.logToFile(logPath, `Resolved cwd: ${cwd}`);
        this.logToFile(logPath, `Resolved logPath: ${logPath}`);

        const hasBin = !!binPath;
        let cmd: string, args: string[];
        if (hasBin) {
            cmd = binPath;
            args = [];
            if (outputChannel) {
                outputChannel.appendLine(`Starting server using compiled binary: ${binPath}`);
            }
            this.logToFile(logPath, `Starting using compiled binary: ${binPath}`);
        } else {
            // Find where Go source code is to run 'go run'
            let goSourceDir = "";
            const sourceSearchPaths = [
                path.join(extensionDir, 'mcp-ssh-go'),
                extensionDir
            ];
            if (workspaceRoot) {
                sourceSearchPaths.push(path.join(workspaceRoot, 'mcp-ssh-go'));
                sourceSearchPaths.push(workspaceRoot);
            }

            for (const sPath of sourceSearchPaths) {
                if (fs.existsSync(path.join(sPath, 'cmd', 'server', 'main.go'))) {
                    goSourceDir = sPath;
                    break;
                }
            }

            cwd = goSourceDir || extensionDir;
            cmd = 'go';
            args = ['run', './cmd/server/main.go'];
            if (outputChannel) {
                outputChannel.appendLine(`Starting server in development using 'go run ./cmd/server/main.go' in ${cwd}...`);
            }
            this.logToFile(logPath, `Starting using 'go run ./cmd/server/main.go' in ${cwd}`);
        }

        const config = vscode.workspace.getConfiguration('mcpSreManager');
        const sshPass = await this._context.secrets.get('sshPass') || '';
        const proxmoxTokenValue = await this._context.secrets.get('proxmoxTokenValue') || '';
        const coolifyToken = await this._context.secrets.get('coolifyToken') || '';

        const spawnOptions: cp.SpawnOptions = {
            cwd: cwd,
            env: {
                ...process.env,
                PROXMOX_URL: config.get<string>('proxmoxUrl') || '',
                PROXMOX_TOKEN_ID: config.get<string>('proxmoxTokenId') || '',
                PROXMOX_TOKEN_VALUE: proxmoxTokenValue,
                PROXMOX_SKIP_TLS_VERIFY: String(config.get<boolean>('proxmoxSkipTlsVerify') !== false),
                COOLIFY_URL: config.get<string>('coolifyUrl') || '',
                COOLIFY_TOKEN: coolifyToken,
                COOLIFY_SKIP_TLS_VERIFY: String(config.get<boolean>('coolifySkipTlsVerify') !== false),
                MONITORING_INTERVAL: config.get<string>('monitoringInterval') || '30s',
                MONITORING_CPU_THRESHOLD: String(config.get<number>('monitoringCpuThreshold') || 90),
                MONITORING_MEM_THRESHOLD: String(config.get<number>('monitoringMemThreshold') || 90)
            }
        };

        try {
            const proc = cp.spawn(cmd, args, spawnOptions);
            serverProcess = proc;
            this.updateStatus('Running');
            vscode.window.showInformationMessage("MCP SRE Server started successfully.");

            let buffer = '';
            proc.stdout?.on('data', (data: Buffer | string) => {
                const rawStr = data.toString();
                this.logToFile(logPath, `[Stdout Raw]: ${rawStr}`);
                buffer += rawStr;
                let boundary = buffer.indexOf('\n');
                while (boundary !== -1) {
                    const line = buffer.substring(0, boundary).trim();
                    buffer = buffer.substring(boundary + 1);
                    if (line) {
                        try {
                            const message = JSON.parse(line);
                            this.handleServerMessage(message);
                        } catch (e) {
                            if (outputChannel) {
                                outputChannel.appendLine(`[Server raw stdout]: ${line}`);
                            }
                        }
                    }
                    boundary = buffer.indexOf('\n');
                }
            });

            proc.stderr?.on('data', (data: Buffer | string) => {
                const str = data.toString();
                // Everything on stderr goes to OutputChannel for SRE Audit!
                if (outputChannel) {
                    outputChannel.append(str);
                }
                this.logToFile(logPath, `[Stderr]: ${str}`);
            });

            proc.on('error', (err: any) => {
                if (outputChannel) {
                    outputChannel.appendLine(`[Spawn Error]: ${err.message}`);
                }
                this.logToFile(logPath, `[Spawn Error]: ${err.message}`);
                let msg = `Failed to start MCP server: ${err.message}`;
                if (err.code === 'ENOENT' && cmd === 'go') {
                    msg = "No se pudo iniciar el servidor. No se encontró el ejecutable de Go ni el binario compiled.";
                }
                vscode.window.showErrorMessage(msg);
                this.stopServer();
            });

            proc.on('close', (code) => {
                if (outputChannel) {
                    outputChannel.appendLine(`MCP Server closed with exit code ${code}`);
                }
                this.logToFile(logPath, `MCP Server closed with exit code ${code}`);
                serverProcess = null;
                this.updateStatus('Stopped');
            });
        } catch (e: any) {
            vscode.window.showErrorMessage(`Error spawning server: ${e.message}`);
            this.logToFile(logPath, `Spawn exception: ${e.message}`);
            this.updateStatus('Stopped');
        }
    }

    stopServer() {
        if (!serverProcess) {
            vscode.window.showInformationMessage("MCP Server is not running.");
            return;
        }

        serverProcess.kill();
        serverProcess = null;
        this.updateStatus('Stopped');
        vscode.window.showInformationMessage("MCP SRE Server stopped.");
    }

    updateStatus(status: string) {
        if (activeWebview) {
            activeWebview.webview.postMessage({ type: 'status', value: status });
        }
    }

    async handleServerMessage(message: any) {
        if (message.method !== undefined && message.id !== undefined) {
            // Incoming request from Go server (Interactive command approval)
            if (message.method === 'custom/requestApproval') {
                const command = message.params.command;
                const reqId = message.params.id;
                
                const result = await vscode.window.showWarningMessage(
                    `El servidor MCP solicita ejecutar el comando SSH de ESCRITURA:\n\n"${command}"\n\n¿Deseas autorizar esta acción?`,
                    { modal: true },
                    "Autorizar",
                    "Denegar"
                );
                
                const approved = (result === "Autorizar");
                const response = {
                    jsonrpc: "2.0",
                    method: "custom/approveResponse",
                    params: {
                        id: reqId,
                        approved: approved
                    }
                };
                if (serverProcess && serverProcess.stdin) {
                    serverProcess.stdin.write(JSON.stringify(response) + '\n');
                }
                if (outputChannel) {
                    outputChannel.appendLine(`[Security]: Command approval response sent: id=${reqId}, approved=${approved}`);
                }
            }
        } else if (message.id !== undefined) {
            const pending = pendingRequests.get(message.id);
            if (pending) {
                pendingRequests.delete(message.id);
                if (message.error) {
                    pending.reject(message.error);
                } else {
                    pending.resolve(message.result);
                }
            }
        } else if (message.method !== undefined) {
            // Notification from Go server (Alerts)
            if (message.method === 'notifications/alert') {
                const msg = message.params.message;
                const level = message.params.level || 'info';
                if (level === 'warning') {
                    vscode.window.showWarningMessage(`[MCP Alert]: ${msg}`);
                } else if (level === 'error') {
                    vscode.window.showErrorMessage(`[MCP Alert]: ${msg}`);
                } else {
                    vscode.window.showInformationMessage(`[MCP Alert]: ${msg}`);
                }
            }
        }
    }

    sendJSONRPC(method: string, params = {}) {
        if (!serverProcess || !serverProcess.stdin) {
            return Promise.reject(new Error("Server is not running. Please start the server first."));
        }
        const id = currentRequestId++;
        const request = {
            jsonrpc: "2.0",
            method: method,
            id: id,
            params: params
        };

        return new Promise((resolve, reject) => {
            pendingRequests.set(id, { resolve, reject });
            serverProcess!.stdin!.write(JSON.stringify(request) + '\n');
        });
    }

    async runTool(toolName: string, args: any) {
        if (outputChannel) {
            outputChannel.appendLine(`Invoking tool '${toolName}' with arguments: ${JSON.stringify(args)}`);
        }
        
        try {
            const result = await this.sendJSONRPC("tools/call", {
                name: toolName,
                arguments: args
            });

            if (activeWebview) {
                activeWebview.webview.postMessage({
                    type: 'toolResult',
                    tool: toolName,
                    success: true,
                    result: result
                });
            }
        } catch (err: any) {
            if (outputChannel) {
                outputChannel.appendLine(`Tool call error: ${JSON.stringify(err)}`);
            }
            if (activeWebview) {
                activeWebview.webview.postMessage({
                    type: 'toolResult',
                    tool: toolName,
                    success: false,
                    result: err.message || JSON.stringify(err)
                });
            }
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        return `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Server Manager</title>
    <style>
        body {
            font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif);
            color: var(--vscode-foreground);
            background-color: var(--vscode-sideBar-background);
            padding: 10px;
            box-sizing: border-box;
            margin: 0;
        }

        h2 {
            font-size: 1.1rem;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 6px;
        }

        .status-container {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            margin-bottom: 15px;
            padding: 8px 12px;
            background-color: var(--vscode-editor-background);
            border-radius: 6px;
            border: 1px solid var(--vscode-widget-border, rgba(255, 255, 255, 0.1));
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-Running .status-dot {
            background-color: #3fb950;
            box-shadow: 0 0 8px #3fb950;
        }

        .status-Stopped .status-dot {
            background-color: #f85149;
            box-shadow: 0 0 8px #f85149;
        }

        .btn {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 6px 12px;
            cursor: pointer;
            border-radius: 4px;
            font-weight: 500;
            font-size: 0.85rem;
            width: 100%;
            box-sizing: border-box;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            margin-bottom: 8px;
            transition: background-color 0.2s;
        }

        .btn:hover {
            background-color: var(--vscode-button-hoverBackground);
        }

        .btn-secondary {
            background-color: var(--vscode-button-secondaryBackground, #30363d);
            color: var(--vscode-button-secondaryForeground, #c9d1d9);
        }

        .btn-secondary:hover {
            background-color: var(--vscode-button-secondaryHoverBackground, #383f47);
        }

        .tabs {
            display: flex;
            gap: 2px;
            border-bottom: 1px solid var(--vscode-panel-border);
            margin-bottom: 12px;
        }

        .tab-btn {
            background: none;
            border: none;
            color: var(--vscode-tab-inactiveForeground, #8b949e);
            padding: 6px 10px;
            cursor: pointer;
            font-size: 0.8rem;
            font-weight: 500;
            border-bottom: 2px solid transparent;
        }

        .tab-btn.active {
            color: var(--vscode-tab-activeForeground, #f0f6fc);
            border-bottom: 2px solid var(--vscode-button-background);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .card {
            background-color: var(--vscode-editor-background);
            border: 1px solid var(--vscode-widget-border, rgba(255, 255, 255, 0.05));
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 12px;
        }

        .form-group {
            margin-bottom: 8px;
        }

        label {
            display: block;
            font-size: 0.75rem;
            color: var(--vscode-descriptionForeground, #8b949e);
            margin-bottom: 4px;
            font-weight: 500;
        }

        input, textarea, select {
            width: 100%;
            background-color: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            border: 1px solid var(--vscode-input-border, rgba(255, 255, 255, 0.15));
            padding: 6px 8px;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 0.8rem;
            font-family: inherit;
        }

        input:focus, textarea:focus, select:focus {
            outline: 1px solid var(--vscode-focusBorder);
            border-color: var(--vscode-focusBorder);
        }

        .result-panel {
            margin-top: 15px;
            border-top: 1px solid var(--vscode-panel-border);
            padding-top: 10px;
        }

        .result-header {
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        pre {
            background-color: var(--vscode-textCodeBlock-background, #161b22);
            color: #e6edf3;
            padding: 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            overflow-x: auto;
            max-height: 250px;
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .loader-spinner {
            display: inline-block;
            width: 12px;
            height: 12px;
            border: 2px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
            margin-right: 6px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Coolify app list styles */
        .app-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 6px 8px;
            border-radius: 4px;
            background-color: rgba(255, 255, 255, 0.02);
            margin-bottom: 6px;
            font-size: 0.8rem;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }

        .app-info {
            display: flex;
            flex-direction: column;
            gap: 2px;
            max-width: 70%;
        }

        .app-name {
            font-weight: 600;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .app-status {
            font-size: 0.7rem;
            opacity: 0.8;
        }

        .app-actions {
            display: flex;
            gap: 4px;
        }

        .app-btn {
            padding: 3px 6px;
            font-size: 0.7rem;
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <h2>
        <span>MCP SRE Manager</span>
    </h2>

    <div class="status-container status-Stopped" id="statusContainer">
        <span class="status-dot"></span>
        <span id="statusText">Stopped</span>
    </div>

    <button class="btn" id="startBtn">Iniciar Servidor Go</button>
    <button class="btn btn-secondary" id="stopBtn" style="display:none;">Detener Servidor</button>

    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('ssh')">SSH</button>
        <button class="tab-btn" onclick="switchTab('proxmox')">Proxmox</button>
        <button class="tab-btn" onclick="switchTab('coolify')">Coolify</button>
        <button class="tab-btn" id="tab-btn-settings" onclick="switchTab('settings')">Ajustes</button>
    </div>

    <!-- TAB: SSH -->
    <div id="tab-ssh" class="tab-content active">
        <div class="card">
            <div class="form-group">
                <label>Servidor (IP / Host)</label>
                <input type="text" id="ssh-host" placeholder="e.g. 192.168.1.50">
            </div>
            <div class="form-group">
                <label>Comando Seguro (Diagnostic)</label>
                <input type="text" id="ssh-command" placeholder="e.g. df -h | free -m">
            </div>
            <div class="form-group">
                <label>Usuario (User)</label>
                <input type="text" id="ssh-user" value="root">
            </div>
            <div class="form-group">
                <label>Puerto (Port)</label>
                <input type="number" id="ssh-port" value="22">
            </div>
            <div class="form-group">
                <label>Password / Key Passphrase (Opcional)</label>
                <input type="password" id="ssh-pass" placeholder="Dejar en blanco para usar clave SSH pública">
            </div>
            <button class="btn" onclick="runSSH()">Ejecutar Diagnóstico</button>
        </div>
    </div>

    <!-- TAB: PROXMOX -->
    <div id="tab-proxmox" class="tab-content">
        <div class="card">
            <div class="form-group">
                <label>Nombre del Nodo</label>
                <input type="text" id="px-node" value="pve">
            </div>
            <button class="btn" onclick="runProxmox()">Obtener Estado del Nodo</button>
        </div>
    </div>

    <!-- TAB: COOLIFY -->
    <div id="tab-coolify" class="tab-content">
        <div class="card">
            <button class="btn" onclick="listCoolifyApps()">Listar Aplicaciones</button>
            <div style="margin-top: 10px;" id="coolify-apps-list"></div>
        </div>
    </div>

    <!-- TAB: AJUSTES -->
    <div id="tab-settings" class="tab-content">
        <div class="card">
            <h3 style="font-size: 0.95rem; margin-top: 0; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">SSH Remoto</h3>
            <div class="form-group">
                <label>Host por Defecto</label>
                <input type="text" id="settings-ssh-host" placeholder="e.g. 192.168.1.50">
            </div>
            <div class="form-group">
                <label>Puerto por Defecto</label>
                <input type="number" id="settings-ssh-port" value="22">
            </div>
            <div class="form-group">
                <label>Usuario por Defecto</label>
                <input type="text" id="settings-ssh-user" value="root">
            </div>
            <div class="form-group">
                <label>Clave SSH / Passphrase (Seguro)</label>
                <input type="password" id="settings-ssh-pass" placeholder="Clave de paso (SecretStorage)">
            </div>
            
            <h3 style="font-size: 0.95rem; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">Proxmox VE</h3>
            <div class="form-group">
                <label>URL API</label>
                <input type="text" id="settings-px-url" placeholder="https://192.168.1.100:8006">
            </div>
            <div class="form-group">
                <label>Token ID</label>
                <input type="text" id="settings-px-token-id" placeholder="root@pam!token">
            </div>
            <div class="form-group">
                <label>Token Value (Seguro)</label>
                <input type="password" id="settings-px-token-val" placeholder="SecretStorage">
            </div>
            <div class="form-group" style="display:flex; align-items:center; gap:8px; margin-top: 6px;">
                <input type="checkbox" id="settings-px-skip-tls" style="width:auto; margin:0;">
                <label for="settings-px-skip-tls" style="margin:0; cursor:pointer;">Omitir Verificación TLS</label>
            </div>

            <h3 style="font-size: 0.95rem; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">Coolify</h3>
            <div class="form-group">
                <label>URL API</label>
                <input type="text" id="settings-coolify-url" placeholder="http://192.168.1.150:8000">
            </div>
            <div class="form-group">
                <label>API Token (Seguro)</label>
                <input type="password" id="settings-coolify-token" placeholder="SecretStorage">
            </div>
            <div class="form-group" style="display:flex; align-items:center; gap:8px; margin-top: 6px;">
                <input type="checkbox" id="settings-coolify-skip-tls" style="width:auto; margin:0;">
                <label for="settings-coolify-skip-tls" style="margin:0; cursor:pointer;">Omitir Verificación TLS</label>
            </div>

            <h3 style="font-size: 0.95rem; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px;">Monitoreo</h3>
            <div class="form-group">
                <label>Intervalo de Monitoreo</label>
                <input type="text" id="settings-mon-interval" value="30s">
            </div>
            <div class="form-group">
                <label>Umbral CPU (%)</label>
                <input type="number" id="settings-mon-cpu" value="90">
            </div>
            <div class="form-group">
                <label>Umbral Memoria (%)</label>
                <input type="number" id="settings-mon-mem" value="90">
            </div>

            <button class="btn" style="margin-top: 15px;" onclick="saveSettings()">Guardar Ajustes</button>
        </div>
    </div>

    <!-- RESULT PANEL -->
    <div class="result-panel" id="resultPanel" style="display:none;">
        <div class="result-header">
            <span>Resultado:</span>
            <button class="btn btn-secondary" style="width:auto; padding: 2px 6px; margin:0;" onclick="clearResult()">Limpiar</button>
        </div>
        <pre id="resultOutput"></pre>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let serverRunning = false;

        document.getElementById('startBtn').addEventListener('click', () => {
            vscode.postMessage({ type: 'start' });
        });

        document.getElementById('stopBtn').addEventListener('click', () => {
            vscode.postMessage({ type: 'stop' });
        });

        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'status':
                    updateStatusUI(message.value);
                    break;
                case 'toolResult':
                    showResult(message.tool, message.success, message.result);
                    break;
                case 'settings':
                    document.getElementById('settings-ssh-host').value = message.config.sshHost || '';
                    document.getElementById('settings-ssh-port').value = message.config.sshPort || 22;
                    document.getElementById('settings-ssh-user').value = message.config.sshUser || 'root';
                    document.getElementById('settings-ssh-pass').value = message.secrets.sshPass || '';
                    
                    document.getElementById('settings-px-url').value = message.config.proxmoxUrl || '';
                    document.getElementById('settings-px-token-id').value = message.config.proxmoxTokenId || '';
                    document.getElementById('settings-px-token-val').value = message.secrets.proxmoxTokenValue || '';
                    document.getElementById('settings-px-skip-tls').checked = message.config.proxmoxSkipTlsVerify;
                    
                    document.getElementById('settings-coolify-url').value = message.config.coolifyUrl || '';
                    document.getElementById('settings-coolify-token').value = message.secrets.coolifyToken || '';
                    document.getElementById('settings-coolify-skip-tls').checked = message.config.coolifySkipTlsVerify;
                    
                    document.getElementById('settings-mon-interval').value = message.config.monitoringInterval || '30s';
                    document.getElementById('settings-mon-cpu').value = message.config.monitoringCpuThreshold || 90;
                    document.getElementById('settings-mon-mem').value = message.config.monitoringMemThreshold || 90;
                    
                    // Populate SSH fields if empty
                    if (!document.getElementById('ssh-host').value) {
                        document.getElementById('ssh-host').value = message.config.sshHost || '';
                    }
                    if (!document.getElementById('ssh-user').value) {
                        document.getElementById('ssh-user').value = message.config.sshUser || 'root';
                    }
                    if (!document.getElementById('ssh-port').value) {
                        document.getElementById('ssh-port').value = message.config.sshPort || 22;
                    }
                    if (!document.getElementById('ssh-pass').value) {
                        document.getElementById('ssh-pass').value = message.secrets.sshPass || '';
                    }
                    break;
            }
        });

        // Request settings on webview load
        vscode.postMessage({ type: 'getSettings' });

        function saveSettings() {
            vscode.postMessage({
                type: 'saveSettings',
                config: {
                    sshHost: document.getElementById('settings-ssh-host').value,
                    sshPort: parseInt(document.getElementById('settings-ssh-port').value) || 22,
                    sshUser: document.getElementById('settings-ssh-user').value,
                    proxmoxUrl: document.getElementById('settings-px-url').value,
                    proxmoxTokenId: document.getElementById('settings-px-token-id').value,
                    proxmoxSkipTlsVerify: document.getElementById('settings-px-skip-tls').checked,
                    coolifyUrl: document.getElementById('settings-coolify-url').value,
                    coolifySkipTlsVerify: document.getElementById('settings-coolify-skip-tls').checked,
                    monitoringInterval: document.getElementById('settings-mon-interval').value,
                    monitoringCpuThreshold: parseInt(document.getElementById('settings-mon-cpu').value) || 90,
                    monitoringMemThreshold: parseInt(document.getElementById('settings-mon-mem').value) || 90
                },
                secrets: {
                    sshPass: document.getElementById('settings-ssh-pass').value,
                    proxmoxTokenValue: document.getElementById('settings-px-token-val').value,
                    coolifyToken: document.getElementById('settings-coolify-token').value
                }
            });
        }

        function updateStatusUI(status) {
            const container = document.getElementById('statusContainer');
            const text = document.getElementById('statusText');
            const startBtn = document.getElementById('startBtn');
            const stopBtn = document.getElementById('stopBtn');

            container.className = 'status-container status-' + status;
            text.textContent = status;

            if (status === 'Running') {
                serverRunning = true;
                startBtn.style.display = 'none';
                stopBtn.style.display = 'block';
            } else {
                serverRunning = false;
                startBtn.style.display = 'block';
                stopBtn.style.display = 'none';
            }
        }

        function switchTab(tabId) {
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));

            const buttons = document.querySelectorAll('.tab-btn');
            buttons.forEach(btn => btn.classList.remove('active'));

            document.getElementById('tab-' + tabId).classList.add('active');
            
            // Switch active class on current button
            const activeBtn = document.querySelector('.tab-btn[onclick="switchTab(\\'' + tabId + '\\')"]');
            if (activeBtn) {
                activeBtn.classList.add('active');
            }
        }

        function showResult(tool, success, data) {
            document.getElementById('resultPanel').style.display = 'block';
            const output = document.getElementById('resultOutput');

            // Format result
            let formatted = '';
            if (data && data.content && data.content[0] && data.content[0].text) {
                formatted = data.content[0].text;
            } else {
                formatted = JSON.stringify(data, null, 2);
            }

            if (!success) {
                output.style.color = '#ff6b6b';
            } else {
                output.style.color = '#e6edf3';
            }

            output.textContent = formatted;
        }

        function clearResult() {
            document.getElementById('resultPanel').style.display = 'none';
            document.getElementById('resultOutput').textContent = '';
        }

        function showLoading() {
            document.getElementById('resultPanel').style.display = 'block';
            document.getElementById('resultOutput').innerHTML = '<div class="loader-spinner"></div> Ejecutando herramienta...';
        }

        // --- TOOL RUNNERS ---

        function runSSH() {
            if (!serverRunning) {
                vscode.postMessage({
                    type: 'showMessage',
                    message: 'El servidor MCP no está ejecutándose. Inícialo primero.',
                    severity: 'warning'
                });
                return;
            }
            showLoading();
            vscode.postMessage({
                type: 'executeTool',
                tool: 'execute_ssh_diagnostic',
                args: {
                    host: document.getElementById('ssh-host').value,
                    command: document.getElementById('ssh-command').value,
                    user: document.getElementById('ssh-user').value,
                    port: parseInt(document.getElementById('ssh-port').value) || 22,
                    password: document.getElementById('ssh-pass').value
                }
            });
        }

        function runProxmox() {
            if (!serverRunning) {
                vscode.postMessage({
                    type: 'showMessage',
                    message: 'El servidor MCP no está ejecutándose. Inícialo primero.',
                    severity: 'warning'
                });
                return;
            }
            showLoading();
            vscode.postMessage({
                type: 'executeTool',
                tool: 'get_proxmox_node_status',
                args: {
                    node: document.getElementById('px-node').value
                }
            });
        }

        // Override toolResult handler to render coolify apps list if list_coolify_applications was run
        window.addEventListener('message', event => {
            const message = event.data;
            if (message.type === 'toolResult' && message.tool === 'list_coolify_applications' && message.success) {
                renderAppsList(message.result);
            }
        });

        function listCoolifyApps() {
            if (!serverRunning) {
                vscode.postMessage({
                    type: 'showMessage',
                    message: 'El servidor MCP no está ejecutándose. Inícialo primero.',
                    severity: 'warning'
                });
                return;
            }
            showLoading();
            vscode.postMessage({
                type: 'executeTool',
                tool: 'list_coolify_applications',
                args: {}
            });
        }

        function getAppLogs(uuid) {
            showLoading();
            vscode.postMessage({
                type: 'executeTool',
                tool: 'get_coolify_application_logs',
                args: { uuid: uuid }
            });
        }

        function getAppStatus(uuid) {
            showLoading();
            vscode.postMessage({
                type: 'executeTool',
                tool: 'get_coolify_application_status',
                args: { uuid: uuid }
            });
        }

        function renderAppsList(data) {
            let textData = '';
            if (data && data.content && data.content[0] && data.content[0].text) {
                textData = data.content[0].text;
            } else {
                return;
            }

            try {
                const apps = JSON.parse(textData);
                const listDiv = document.getElementById('coolify-apps-list');
                listDiv.innerHTML = '';

                if (!apps || apps.length === 0) {
                    listDiv.innerHTML = '<div style="font-size:0.8rem; opacity:0.6;">No se encontraron aplicaciones.</div>';
                    return;
                }

                apps.forEach(app => {
                    const item = document.createElement('div');
                    item.className = 'app-item';
                    item.innerHTML = \`
                        <div class="app-info">
                            <span class="app-name">\${app.name}</span>
                            <span class="app-status">UUID: \${app.uuid.substring(0, 8)}... | \${app.status || 'unknown'}</span>
                        </div>
                        <div class="app-actions">
                            <button class="app-btn" onclick="getAppStatus('\${app.uuid}')">Status</button>
                            <button class="app-btn" onclick="getAppLogs('\${app.uuid}')">Logs</button>
                        </div>
                    \`;
                    listDiv.appendChild(item);
                });
                clearResult();
            } catch(e) {
                // Not JSON arrays, fallback to standard display
            }
        }
    </script>
</body>
</html>`;
    }
}
