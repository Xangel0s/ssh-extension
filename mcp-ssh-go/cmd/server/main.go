package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	"mcp-ssh-go/internal/tools"
)

func main() {
	// Load environment variables from .env if present
	loadEnv()

	// Create a new MCP server
	s := server.NewMCPServer(
		"MCP SRE Devops Server",
		"1.0.0",
	)

	// Initialize tools context
	handlerCtx := tools.NewHandlerContext()
	handlerCtx.RegisterTools(s)

	log.Println("Starting MCP SRE server on stdio...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
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
		log.Printf("Loaded environment variables from: %s", path)
		break // Stop once the first valid .env is loaded
	}
}
