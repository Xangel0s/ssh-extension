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
                case 'restart':
                    this.stopServer();
                    setTimeout(() => {
                        this.startServer();
                    }, 500);
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
                            sshKeyPath: config.get('sshKeyPath') || '',
                            sshPort: config.get('sshPort') || 22,
                            sshUser: config.get('sshUser') || 'root',
                            proxmoxUrl: config.get('proxmoxUrl') || '',
                            proxmoxTokenId: config.get('proxmoxTokenId') || '',
                            proxmoxSkipTlsVerify: config.get('proxmoxSkipTlsVerify') !== false,
                            proxmoxNode: config.get('proxmoxNode') || 'pve',
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
                    
                    const oldPxUrl = config.get('proxmoxUrl') || '';
                    const oldPxTokenId = config.get('proxmoxTokenId') || '';
                    const oldPxSkipTls = config.get('proxmoxSkipTlsVerify') !== false;
                    const oldCoolifyUrl = config.get('coolifyUrl') || '';
                    const oldCoolifySkipTls = config.get('coolifySkipTlsVerify') !== false;
                    const oldMonInterval = config.get('monitoringInterval') || '30s';
                    const oldMonCpu = config.get('monitoringCpuThreshold') || 90;
                    const oldMonMem = config.get('monitoringMemThreshold') || 90;
                    const oldPxTokenVal = await this._context.secrets.get('proxmoxTokenValue') || '';
                    const oldCoolifyToken = await this._context.secrets.get('coolifyToken') || '';

                    // Check if env settings changed
                    const envChanged = 
                        oldPxUrl !== data.config.proxmoxUrl ||
                        oldPxTokenId !== data.config.proxmoxTokenId ||
                        oldPxSkipTls !== data.config.proxmoxSkipTlsVerify ||
                        oldCoolifyUrl !== data.config.coolifyUrl ||
                        oldCoolifySkipTls !== data.config.coolifySkipTlsVerify ||
                        oldMonInterval !== data.config.monitoringInterval ||
                        oldMonCpu !== data.config.monitoringCpuThreshold ||
                        oldMonMem !== data.config.monitoringMemThreshold ||
                        oldPxTokenVal !== (data.secrets.proxmoxTokenValue || '') ||
                        oldCoolifyToken !== (data.secrets.coolifyToken || '');

                    await config.update('sshHost', data.config.sshHost, vscode.ConfigurationTarget.Global);
                    await config.update('sshKeyPath', data.config.sshKeyPath, vscode.ConfigurationTarget.Global);
                    await config.update('sshPort', data.config.sshPort, vscode.ConfigurationTarget.Global);
                    await config.update('sshUser', data.config.sshUser, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxUrl', data.config.proxmoxUrl, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxTokenId', data.config.proxmoxTokenId, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxSkipTlsVerify', data.config.proxmoxSkipTlsVerify, vscode.ConfigurationTarget.Global);
                    await config.update('proxmoxNode', data.config.proxmoxNode, vscode.ConfigurationTarget.Global);
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
                    
                    if (!data.quiet) {
                        vscode.window.showInformationMessage("Ajustes guardados correctamente.");
                    }

                    // Auto-restart backend server if environment configurations changed and server is running
                    if (envChanged && serverProcess) {
                        if (outputChannel) {
                            outputChannel.appendLine("Ajustes de backend modificados: reiniciando servidor Go automáticamente...");
                        }
                        this.stopServer();
                        setTimeout(() => {
                            this.startServer();
                        }, 500);
                    }
                    
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
                if (activeWebview) {
                    activeWebview.webview.postMessage({
                        type: 'mcpLog',
                        value: str
                    });
                }
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
        if (message.method !== undefined) {
            // Notifications or Custom Requests from Go server
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
            } else if (message.method === 'notifications/alert') {
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
            padding: 12px;
            box-sizing: border-box;
            margin: 0;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        h2 {
            font-size: 1.05rem;
            font-weight: 600;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 8px;
            color: var(--vscode-sideBarTitle-foreground);
        }

        /* Wizard Cards */
        .wizard-card {
            background-color: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border, #30363d);
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .wizard-header {
            border-bottom: 1px solid var(--vscode-panel-border, #30363d);
            padding-bottom: 8px;
            margin-bottom: 4px;
        }

        .wizard-step-indicator {
            font-size: 0.68rem;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--vscode-textPreformat-foreground, #58a6ff);
            letter-spacing: 0.5px;
            display: block;
            margin-bottom: 4px;
        }

        .wizard-title {
            font-size: 0.95rem;
            font-weight: 600;
            margin: 0 0 4px 0;
            color: var(--vscode-foreground);
        }

        .wizard-desc {
            font-size: 0.75rem;
            color: var(--vscode-descriptionForeground);
            margin: 0;
            line-height: 1.3;
        }

        .form-group {
            margin-bottom: 10px;
        }

        .form-group:last-child {
            margin-bottom: 0;
        }

        label {
            display: block;
            font-size: 0.72rem;
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

        /* Dashboard Styles */
        .dashboard-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 4px;
        }

        .dashboard-title {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--vscode-foreground);
        }

        .settings-btn {
            background: none;
            border: none;
            color: var(--vscode-descriptionForeground);
            cursor: pointer;
            font-size: 1.1rem;
            padding: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            transition: background-color 0.2s, color 0.2s;
        }

        .settings-btn:hover {
            background-color: var(--vscode-toolbar-hoverBackground, rgba(255, 255, 255, 0.08));
            color: var(--vscode-foreground);
        }

        .status-container {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
            padding: 8px 12px;
            background-color: var(--vscode-editor-background);
            border-radius: 6px;
            border: 1px solid var(--vscode-widget-border, rgba(255, 255, 255, 0.08));
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-Running .status-dot {
            background-color: #3fb950;
            box-shadow: 0 0 6px #3fb950;
        }

        .status-Stopped .status-dot {
            background-color: #f85149;
            box-shadow: 0 0 6px #f85149;
        }

        .controls-row {
            display: flex;
            gap: 8px;
        }

        .terminal-container {
            display: flex;
            flex-direction: column;
            background-color: #0d1117;
            border: 1px solid var(--vscode-panel-border, #30363d);
            border-radius: 6px;
            overflow: hidden;
            font-family: var(--vscode-editor-font-family, Consolas, "Courier New", monospace);
            min-height: 250px;
            max-height: 380px;
        }

        .terminal-header {
            background-color: #161b22;
            padding: 6px 10px;
            font-size: 0.72rem;
            color: var(--vscode-descriptionForeground, #8b949e);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--vscode-panel-border, #30363d);
            font-weight: 500;
        }

        .terminal-clear-btn {
            background: none;
            border: none;
            color: var(--vscode-button-secondaryForeground, #c9d1d9);
            cursor: pointer;
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 3px;
            transition: background-color 0.2s;
        }

        .terminal-clear-btn:hover {
            background-color: rgba(255,255,255,0.05);
        }

        .terminal-body {
            padding: 10px;
            overflow-y: auto;
            flex-grow: 1;
            font-size: 0.75rem;
            line-height: 1.4;
            color: #c9d1d9;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        .terminal-line {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .terminal-line.stderr {
            color: #ff6b6b;
        }

        .terminal-line.system-msg {
            color: #58a6ff;
            opacity: 0.8;
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
            vertical-align: middle;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h2>
        <span>MCP SRE Manager</span>
    </h2>

    <!-- STEP 1: SSH CONFIGURATION -->
    <div id="step-1" class="wizard-card" style="display:none;">
        <div class="wizard-header">
            <span class="wizard-step-indicator">Paso 1 de 3</span>
            <h3 class="wizard-title">Configuración SSH</h3>
            <p class="wizard-desc">Conexión base para diagnósticos remotos y ejecución segura de comandos.</p>
        </div>
        <div class="form-group">
            <label>IP del Servidor / Host *</label>
            <input type="text" id="ssh-host" placeholder="e.g. 192.168.1.50">
        </div>
        <div class="form-group">
            <label>Usuario *</label>
            <input type="text" id="ssh-user" value="root">
        </div>
        <div class="form-group">
            <label>Puerto *</label>
            <input type="number" id="ssh-port" value="22">
        </div>
        <div class="form-group">
            <label>Ruta a la Llave Privada SSH *</label>
            <input type="text" id="ssh-key-path" placeholder="e.g. C:\\Users\\User\\.ssh\\id_rsa">
        </div>
        <div style="margin-top: 10px;">
            <button class="btn" onclick="saveStep1()">Guardar y Continuar</button>
        </div>
    </div>

    <!-- STEP 2: PROXMOX VE CONFIGURATION -->
    <div id="step-2" class="wizard-card" style="display:none;">
        <div class="wizard-header">
            <span class="wizard-step-indicator">Paso 2 de 3</span>
            <h3 class="wizard-title">Configuración Proxmox VE</h3>
            <p class="wizard-desc">Monitoreo de recursos e hipervisores en tu homelab.</p>
        </div>
        <div class="form-group">
            <label>URL de la API (ej: https://192.168.1.100:8006)</label>
            <input type="text" id="px-url" placeholder="https://192.168.1.100:8006">
        </div>
        <div class="form-group">
            <label>Token ID</label>
            <input type="text" id="px-token-id" placeholder="root@pam!token-name">
        </div>
        <div class="form-group">
            <label>Secret (Token Value)</label>
            <input type="password" id="px-token-val" placeholder="Secret Token Value">
        </div>
        <div class="form-group" style="display:flex; align-items:center; gap:8px; margin-top: 6px; margin-bottom: 8px;">
            <input type="checkbox" id="px-skip-tls" style="width:auto; margin:0;" checked>
            <label for="px-skip-tls" style="margin:0; cursor:pointer;">Omitir Verificación TLS</label>
        </div>
        <div class="form-group">
            <label>Nombre del Nodo</label>
            <input type="text" id="px-node" value="pve">
        </div>
        <div style="margin-top: 10px; display:flex; gap:8px;">
            <button class="btn" onclick="saveStep2()">Guardar y Continuar</button>
            <button class="btn btn-secondary" onclick="skipStep2()">Omitir por ahora</button>
        </div>
    </div>

    <!-- STEP 3: COOLIFY CONFIGURATION -->
    <div id="step-3" class="wizard-card" style="display:none;">
        <div class="wizard-header">
            <span class="wizard-step-indicator">Paso 3 de 3</span>
            <h3 class="wizard-title">Configuración Coolify</h3>
            <p class="wizard-desc">Monitoreo y lectura de logs de aplicaciones y contenedores.</p>
        </div>
        <div class="form-group">
            <label>URL de la API (ej: http://192.168.1.150:8000)</label>
            <input type="text" id="coolify-url" placeholder="http://192.168.1.150:8000">
        </div>
        <div class="form-group">
            <label>Bearer Token</label>
            <input type="password" id="coolify-token" placeholder="Coolify API Token">
        </div>
        <div class="form-group" style="display:flex; align-items:center; gap:8px; margin-top: 6px; margin-bottom: 8px;">
            <input type="checkbox" id="coolify-skip-tls" style="width:auto; margin:0;" checked>
            <label for="coolify-skip-tls" style="margin:0; cursor:pointer;">Omitir Verificación TLS</label>
        </div>
        <div style="margin-top: 10px; display:flex; gap:8px;">
            <button class="btn" onclick="saveStep3()">Guardar y Finalizar</button>
            <button class="btn btn-secondary" onclick="skipStep3()">Omitir por ahora</button>
        </div>
    </div>

    <!-- STEP 4: DASHBOARD -->
    <div id="step-dashboard" class="wizard-card" style="display:none; padding: 12px; gap: 10px;">
        <div class="dashboard-header">
            <span class="dashboard-title">Dashboard Principal</span>
            <button class="settings-btn" onclick="showStep(1)" title="Volver a Configuración">⚙</button>
        </div>

        <div class="status-container status-Stopped" id="statusContainer">
            <span class="status-dot"></span>
            <span id="statusText">Stopped</span>
        </div>

        <div class="controls-row">
            <button class="btn" id="startBtn">Iniciar</button>
            <button class="btn btn-secondary" id="stopBtn" style="display:none;">Detener</button>
            <button class="btn btn-secondary" id="restartBtn">Reiniciar</button>
        </div>

        <div class="terminal-container">
            <div class="terminal-header">
                <span>Terminal de Logs MCP</span>
                <button class="terminal-clear-btn" onclick="clearTerminal()">Limpiar</button>
            </div>
            <div class="terminal-body" id="terminalBody">
                <div class="terminal-line system-msg">Consola de logs inicializada. Servidor listo.</div>
            </div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        let serverRunning = false;
        let onboardingCompleted = false;

        document.getElementById('startBtn').addEventListener('click', function() {
            vscode.postMessage({ type: 'start' });
        });

        document.getElementById('stopBtn').addEventListener('click', function() {
            vscode.postMessage({ type: 'stop' });
        });

        document.getElementById('restartBtn').addEventListener('click', function() {
            vscode.postMessage({ type: 'restart' });
            appendLog('Reiniciando servidor MCP...', false, true);
        });

        window.addEventListener('message', function(event) {
            const message = event.data;
            switch (message.type) {
                case 'status':
                    updateStatusUI(message.value);
                    break;
                case 'settings':
                    document.getElementById('ssh-host').value = message.config.sshHost || '';
                    document.getElementById('ssh-key-path').value = message.config.sshKeyPath || '';
                    document.getElementById('ssh-port').value = message.config.sshPort || 22;
                    document.getElementById('ssh-user').value = message.config.sshUser || 'root';
                    
                    document.getElementById('px-url').value = message.config.proxmoxUrl || '';
                    document.getElementById('px-token-id').value = message.config.proxmoxTokenId || '';
                    document.getElementById('px-token-val').value = message.secrets.proxmoxTokenValue || '';
                    document.getElementById('px-node').value = message.config.proxmoxNode || 'pve';
                    
                    document.getElementById('coolify-url').value = message.config.coolifyUrl || '';
                    document.getElementById('coolify-token').value = message.secrets.coolifyToken || '';
                    
                    // Auto-skip onboarding if SSH config already exists
                    if (message.config.sshHost && message.config.sshUser) {
                        onboardingCompleted = true;
                        showStep('dashboard');
                    } else {
                        showStep(1);
                    }
                    break;
                case 'mcpLog': {
                    const rawText = message.value;
                    const lines = rawText.split('\\n');
                    lines.forEach(function(line) {
                        const trimmed = line.trim();
                        if (!trimmed) return;
                        try {
                            const logObj = JSON.parse(trimmed);
                            const timeStr = logObj.time ? logObj.time.substring(11, 19) : '';
                            const level = logObj.level || 'INFO';
                            const msg = logObj.msg || '';
                            let formatted = (timeStr ? '[' + timeStr + '] ' : '') + '[' + level + '] ' + msg;
                            
                            Object.keys(logObj).forEach(function(key) {
                                if (key !== 'time' && key !== 'level' && key !== 'msg') {
                                    formatted += ' ' + key + '=' + JSON.stringify(logObj[key]);
                                }
                            });
                            appendLog(formatted, level === 'ERROR' || level === 'WARN');
                        } catch (e) {
                            appendLog(trimmed, false);
                        }
                    });
                    break;
                }
            }
        });

        // Request settings on webview load
        vscode.postMessage({ type: 'getSettings' });

        function showStep(step) {
            document.getElementById('step-1').style.display = (step === 1) ? 'block' : 'none';
            document.getElementById('step-2').style.display = (step === 2) ? 'block' : 'none';
            document.getElementById('step-3').style.display = (step === 3) ? 'block' : 'none';
            document.getElementById('step-dashboard').style.display = (step === 'dashboard') ? 'block' : 'none';
        }

        function saveSettings(quiet) {
            vscode.postMessage({
                type: 'saveSettings',
                config: {
                    sshHost: document.getElementById('ssh-host').value,
                    sshKeyPath: document.getElementById('ssh-key-path').value,
                    sshPort: parseInt(document.getElementById('ssh-port').value) || 22,
                    sshUser: document.getElementById('ssh-user').value,
                    proxmoxUrl: document.getElementById('px-url').value,
                    proxmoxTokenId: document.getElementById('px-token-id').value,
                    proxmoxSkipTlsVerify: document.getElementById('px-skip-tls').checked,
                    proxmoxNode: document.getElementById('px-node').value || 'pve',
                    coolifyUrl: document.getElementById('coolify-url').value,
                    coolifySkipTlsVerify: document.getElementById('coolify-skip-tls').checked,
                    monitoringInterval: '30s',
                    monitoringCpuThreshold: 90,
                    monitoringMemThreshold: 90
                },
                secrets: {
                    sshPass: '', // SSH Key route used instead of password
                    proxmoxTokenValue: document.getElementById('px-token-val').value,
                    coolifyToken: document.getElementById('coolify-token').value
                },
                quiet: quiet === true
            });
        }

        function saveStep1() {
            const host = document.getElementById('ssh-host').value.trim();
            const user = document.getElementById('ssh-user').value.trim();
            const keyPath = document.getElementById('ssh-key-path').value.trim();
            if (!host || !user || !keyPath) {
                vscode.postMessage({
                    type: 'showMessage',
                    message: 'Por favor, rellene todos los campos obligatorios (*).',
                    severity: 'warning'
                });
                return;
            }
            saveSettings(true);
            showStep(2);
        }

        function saveStep2() {
            saveSettings(true);
            showStep(3);
        }

        function skipStep2() {
            showStep(3);
        }

        function saveStep3() {
            saveSettings(true);
            onboardingCompleted = true;
            showStep('dashboard');
            // Auto start the Go backend server at the end of onboarding
            vscode.postMessage({ type: 'start' });
        }

        function skipStep3() {
            onboardingCompleted = true;
            showStep('dashboard');
            // Auto start the Go backend server at the end of onboarding
            vscode.postMessage({ type: 'start' });
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

        function appendLog(text, isError, isSystem) {
            const body = document.getElementById('terminalBody');
            const line = document.createElement('div');
            
            let className = 'terminal-line';
            if (isError) className += ' stderr';
            if (isSystem) className += ' system-msg';
            
            line.className = className;
            line.textContent = text;
            body.appendChild(line);
            
            while (body.childNodes.length > 300) {
                body.removeChild(body.firstChild);
            }
            body.scrollTop = body.scrollHeight;
        }

        function clearTerminal() {
            const body = document.getElementById('terminalBody');
            body.innerHTML = '<div class="terminal-line system-msg">Consola de logs limpiada.</div>';
        }
    </script>
</body>
</html>`;
    }
}
