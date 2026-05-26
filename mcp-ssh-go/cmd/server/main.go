package main

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"mcp-ssh-go/internal/monitoring"
	"mcp-ssh-go/internal/tools"
)

func main() {
	// Configure slog to write JSON to os.Stderr (vital for MCP to keep stdout clean)
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Load environment variables from .env if present
	loadEnv()

	slog.Info("Initializing MCP SRE Manager Server...")

	// Create a new MCP server
	s := server.NewMCPServer(
		"MCP SRE Manager Server",
		"1.0.0",
	)

	// Initialize tools context
	handlerCtx := tools.NewHandlerContext()
	handlerCtx.Server = s
	handlerCtx.RegisterTools(s)

	// Start background monitoring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := monitoring.NewMonitor(s)
	monitor.Start(ctx)

	slog.Info("Starting stdio transport for JSON-RPC...")
	if err := server.ServeStdio(s); err != nil {
		slog.Error("Server termination error", "error", err)
		os.Exit(1)
	}
}

// loadEnv reads a .env file from the current directory or the executable's directory
// and sets variables that are not already set.
func loadEnv() {
	envPaths := []string{".env"}
	execPath, err := os.Executable()
	if err == nil {
		envPaths = append(envPaths, filepath.Join(filepath.Dir(execPath), ".env"))
	}

	for _, path := range envPaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		slog.Debug("Loaded environment variables", "path", path)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				// Clean quotes
				val = strings.Trim(val, `"'`)
				if os.Getenv(key) == "" {
					os.Setenv(key, val)
				}
			}
		}
		break // Stop once the first valid .env is loaded
	}
}
