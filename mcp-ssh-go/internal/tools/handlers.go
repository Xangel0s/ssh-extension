package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"mcp-ssh-go/internal/coolify"
	"mcp-ssh-go/internal/proxmox"
	"mcp-ssh-go/internal/ssh"
)

// HandlerContext maintains shared dependencies across tools.
type HandlerContext struct {
	SSHPool          *ssh.ClientPool
	Server           *server.MCPServer
	PendingApprovals map[string]chan bool
	ApprovalMu       sync.Mutex
}

// NewHandlerContext initializes a new tools handler context.
func NewHandlerContext() *HandlerContext {
	return &HandlerContext{
		SSHPool:          ssh.NewClientPool(),
		PendingApprovals: make(map[string]chan bool),
	}
}

// RegisterTools registers all available SRE tools to the MCP server.
func (h *HandlerContext) RegisterTools(s *server.MCPServer) {
	// Register extension approval response handler
	s.AddNotificationHandler("custom/approveResponse", func(ctx context.Context, notification mcp.JSONRPCNotification) {
		idVal, okId := notification.Params.AdditionalFields["id"].(string)
		appVal, okApp := notification.Params.AdditionalFields["approved"].(bool)
		if okId && okApp {
			h.ApprovalMu.Lock()
			ch, ok := h.PendingApprovals[idVal]
			h.ApprovalMu.Unlock()
			if ok {
				select {
				case ch <- appVal:
				default:
				}
			}
		}
	})

	// --- SSH Tools ---
	sshTool := mcp.NewTool("execute_ssh_diagnostic",
		mcp.WithDescription("Executes a safe, read-only diagnostic command on a remote Linux host via SSH. Crucial for system checkups, checking resources (df, free, top), listing docker processes, or checking service logs (journalctl)."),
		mcp.WithString("host", mcp.Required(), mcp.Description("The remote server IP or hostname (e.g. '192.168.1.50')")),
		mcp.WithString("command", mcp.Required(), mcp.Description("The safe diagnostic command (e.g. 'df -h', 'free -m', 'systemctl status docker', 'docker ps', 'journalctl -u nginx -n 50')")),
		mcp.WithString("user", mcp.Description("The SSH user. Defaults to 'root'.")),
		mcp.WithInteger("port", mcp.Description("The SSH port. Defaults to 22.")),
		mcp.WithString("key_path", mcp.Description("Path to custom private key. Defaults to standard locations: ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.")),
		mcp.WithString("password", mcp.Description("Optional password authentication for SSH.")),
	)
	s.AddTool(sshTool, h.handleSSHDiagnostic)

	// --- Proxmox Tools ---
	proxmoxTool := mcp.NewTool("get_proxmox_node_status",
		mcp.WithDescription("Gets CPU, memory, disk usage, and load details for a specific Proxmox VE hypervisor node."),
		mcp.WithString("node", mcp.Required(), mcp.Description("Proxmox node name (e.g., 'pve')")),
	)
	s.AddTool(proxmoxTool, h.handleProxmoxNodeStatus)

	// --- Coolify Tools ---
	listCoolifyAppsTool := mcp.NewTool("list_coolify_applications",
		mcp.WithDescription("Lists all applications managed by the Coolify instance, displaying names, UUIDs, statuses, and domains."),
	)
	s.AddTool(listCoolifyAppsTool, h.handleListCoolifyApps)

	getCoolifyAppStatusTool := mcp.NewTool("get_coolify_application_status",
		mcp.WithDescription("Fetches detailed status of a specific Coolify application by UUID."),
		mcp.WithString("uuid", mcp.Required(), mcp.Description("The UUID of the Coolify application")),
	)
	s.AddTool(getCoolifyAppStatusTool, h.handleGetCoolifyAppStatus)

	getCoolifyAppLogsTool := mcp.NewTool("get_coolify_application_logs",
		mcp.WithDescription("Retrieves the container log history for a specific Coolify application by UUID."),
		mcp.WithString("uuid", mcp.Required(), mcp.Description("The UUID of the Coolify application")),
	)
	s.AddTool(getCoolifyAppLogsTool, h.handleGetCoolifyAppLogs)
}

type SSHArgs struct {
	Host     string `json:"host"`
	Command  string `json:"command"`
	User     string `json:"user"`
	Port     int    `json:"port"`
	KeyPath  string `json:"key_path"`
	Password string `json:"password"`
}

func (h *HandlerContext) handleSSHDiagnostic(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args SSHArgs
	if err := request.BindArguments(&args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse arguments: %v", err)), nil
	}

	if args.Host == "" {
		return mcp.NewToolResultError("missing required parameter: host"), nil
	}
	if args.Command == "" {
		return mcp.NewToolResultError("missing required parameter: command"), nil
	}

	if args.User == "" {
		args.User = "root"
	}
	if args.Port == 0 {
		args.Port = 22
	}

	config := ssh.SSHConfig{
		Host:     args.Host,
		Port:     args.Port,
		User:     args.User,
		KeyPath:  args.KeyPath,
		Password: args.Password,
	}

	cmd := strings.TrimSpace(args.Command)

	// Analyze command for interactive approval
	isSafe, reqApp, err := ssh.AnalyzeCommand(cmd)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Security validation error: %v", err)), nil
	}

	approved := false
	if reqApp {
		if h.Server == nil {
			return mcp.NewToolResultError("MCP Server context missing, cannot request command approval"), nil
		}

		reqID := uuid.New().String()
		approvalChan := make(chan bool, 1)

		h.ApprovalMu.Lock()
		h.PendingApprovals[reqID] = approvalChan
		h.ApprovalMu.Unlock()

		defer func() {
			h.ApprovalMu.Lock()
			delete(h.PendingApprovals, reqID)
			h.ApprovalMu.Unlock()
		}()

		// Request approval from the extension via notification
		h.Server.SendNotificationToAllClients("custom/requestApproval", map[string]any{
			"id":      reqID,
			"command": cmd,
		})

		// Wait for interactive approval (max 30 seconds)
		select {
		case appVal := <-approvalChan:
			approved = appVal
			if !approved {
				return mcp.NewToolResultError("SSH command execution denied by user"), nil
			}
		case <-time.After(30 * time.Second):
			return mcp.NewToolResultError("SSH command approval request timed out"), nil
		case <-ctx.Done():
			return mcp.NewToolResultError("SSH command approval context cancelled"), nil
		}
	} else if !isSafe {
		return mcp.NewToolResultError("SSH command is forbidden by security policies"), nil
	}

	output, err := h.SSHPool.ExecuteCommand(config, cmd, approved)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SSH Execution error: %v", err)), nil
	}

	return mcp.NewToolResultText(output), nil
}

// --- Proxmox Handlers ---

type ProxmoxStatusArgs struct {
	Node string `json:"node"`
}

func (h *HandlerContext) handleProxmoxNodeStatus(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ProxmoxStatusArgs
	if err := request.BindArguments(&args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse arguments: %v", err)), nil
	}

	if args.Node == "" {
		return mcp.NewToolResultError("missing required parameter: node"), nil
	}

	client, err := proxmox.NewClientFromEnv()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Proxmox client initialization failed. Ensure environment variables (PROXMOX_URL, PROXMOX_TOKEN_ID, PROXMOX_TOKEN_VALUE) are set. Error: %v", err)), nil
	}

	status, err := client.GetNodeStatus(args.Node)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch Proxmox node status: %v", err)), nil
	}

	// Format response nicely in JSON
	resBytes, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to serialize status: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resBytes)), nil
}

// --- Coolify Handlers ---

type CoolifyAppArgs struct {
	UUID string `json:"uuid"`
}

func (h *HandlerContext) handleListCoolifyApps(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := coolify.NewClientFromEnv()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Coolify client initialization failed. Ensure environment variables (COOLIFY_URL, COOLIFY_TOKEN) are set. Error: %v", err)), nil
	}

	apps, err := client.ListApplications()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list Coolify applications: %v", err)), nil
	}

	resBytes, err := json.MarshalIndent(apps, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to serialize application list: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resBytes)), nil
}

func (h *HandlerContext) handleGetCoolifyAppStatus(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args CoolifyAppArgs
	if err := request.BindArguments(&args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse arguments: %v", err)), nil
	}

	if args.UUID == "" {
		return mcp.NewToolResultError("missing required parameter: uuid"), nil
	}

	client, err := coolify.NewClientFromEnv()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Coolify client initialization failed. Ensure environment variables (COOLIFY_URL, COOLIFY_TOKEN) are set. Error: %v", err)), nil
	}

	app, err := client.GetApplication(args.UUID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch Coolify application: %v", err)), nil
	}

	resBytes, err := json.MarshalIndent(app, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to serialize application details: %v", err)), nil
	}

	return mcp.NewToolResultText(string(resBytes)), nil
}

func (h *HandlerContext) handleGetCoolifyAppLogs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args CoolifyAppArgs
	if err := request.BindArguments(&args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse arguments: %v", err)), nil
	}

	if args.UUID == "" {
		return mcp.NewToolResultError("missing required parameter: uuid"), nil
	}

	client, err := coolify.NewClientFromEnv()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Coolify client initialization failed. Ensure environment variables (COOLIFY_URL, COOLIFY_TOKEN) are set. Error: %v", err)), nil
	}

	logs, err := client.GetApplicationLogs(args.UUID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to fetch Coolify application logs: %v", err)), nil
	}

	return mcp.NewToolResultText(logs), nil
}
