package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"mcp-ssh-go/internal/monitoring"
	"mcp-ssh-go/internal/tools"
)

func main() {
	execPath, err := os.Executable()
	var execDir string
	if err == nil {
		execDir = filepath.Dir(execPath)
	} else {
		execDir = "."
	}

	lockPath := filepath.Join(execDir, "mcp-server.lock")
	if _, err := os.Stat(lockPath); err == nil {
		data, err := os.ReadFile(lockPath)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil && isProcessRunning(pid) {
				// Another instance is running, exit immediately
				os.Exit(0)
			}
		}
	}

	// Create or overwrite the lock file with current PID
	os.WriteFile(lockPath, []byte(strconv.Itoa(os.Getpid())), 0666)
	defer os.Remove(lockPath)

	// Configure slog to write JSON to os.Stderr (vital for MCP to keep stdout clean)
	var logPath string
	if err == nil {
		logPath = filepath.Join(execDir, "mcp-server-debug.log")
	} else {
		logPath = "mcp-server-debug.log"
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	var logWriter io.Writer = os.Stderr
	if err == nil {
		defer logFile.Close()
		logWriter = io.MultiWriter(os.Stderr, logFile)
	}

	clientName := os.Getenv("MCP_CLIENT")
	if clientName == "" {
		clientName = "Unknown"
	}

	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("client", clientName)
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

func isProcessRunning(pid int) bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid))
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), strconv.Itoa(pid)) {
			return true
		}
		return false
	}
	// Linux/Unix check
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
