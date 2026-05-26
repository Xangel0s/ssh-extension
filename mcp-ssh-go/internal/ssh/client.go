package ssh

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHConfig holds connection parameters for a host.
type SSHConfig struct {
	Host     string
	Port     int
	User     string
	KeyPath  string // Path to the private key (defaults to ~/.ssh/id_ed25519)
	Password string // Optional password authentication
}

// ClientPool manages active SSH connections.
type ClientPool struct {
	mu      sync.Mutex
	clients map[string]*ssh.Client
}

// NewClientPool initializes a connection pool.
func NewClientPool() *ClientPool {
	return &ClientPool{
		clients: make(map[string]*ssh.Client),
	}
}

// GetClient retrieves an existing SSH connection or establishes a new one.
func (p *ClientPool) GetClient(config SSHConfig) (*ssh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	hostKey := fmt.Sprintf("%s:%d", config.Host, config.Port)
	if client, ok := p.clients[hostKey]; ok {
		// Verify if the client is still alive
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			return client, nil
		}
		// Connection dead, close and remove
		client.Close()
		delete(p.clients, hostKey)
	}

	client, err := dialSSH(config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH: %w", err)
	}

	p.clients[hostKey] = client
	return client, nil
}

// CloseAll closes all connections in the pool.
func (p *ClientPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for k, client := range p.clients {
		client.Close()
		delete(p.clients, k)
	}
}

// dialSSH establishes a raw SSH connection.
func dialSSH(config SSHConfig) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	// 1. Try private key if specified
	if config.KeyPath != "" {
		signer, err := readPrivateKey(config.KeyPath, config.Password)
		if err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	} else {
		// Try default private keys
		homeDir, err := os.UserHomeDir()
		if err == nil {
			defaultKeys := []string{
				filepath.Join(homeDir, ".ssh", "id_ed25519"),
				filepath.Join(homeDir, ".ssh", "id_rsa"),
			}
			for _, keyPath := range defaultKeys {
				if _, err := os.Stat(keyPath); err == nil {
					signer, err := readPrivateKey(keyPath, config.Password)
					if err == nil {
						authMethods = append(authMethods, ssh.PublicKeys(signer))
						break
					}
				}
			}
		}
	}

	// 2. Try Windows SSH agent (Named Pipe) or Unix socket agent
	agentAuth := connectToAgent()
	if agentAuth != nil {
		authMethods = append(authMethods, agentAuth)
	}

	// 3. Try password if provided
	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication methods available")
	}

	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For homelabs; in production, use proper host key verification
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func readPrivateKey(path string, password string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if password != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(password))
		if err == nil {
			return signer, nil
		}
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func connectToAgent() ssh.AuthMethod {
	// Try standard SSH_AUTH_SOCK env var
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return ssh.PublicKeysCallback(agent.NewClient(conn).Signers)
		}
	}

	// On Windows, try named pipe for OpenSSH Agent
	// OpenSSH agent pipe on Windows is standard \\.\pipe\openssh-ssh-agent
	if os.PathSeparator == '\\' {
		conn, err := net.Dial("pipe", `\\.\pipe\openssh-ssh-agent`)
		if err == nil {
			return ssh.PublicKeysCallback(agent.NewClient(conn).Signers)
		}
	}

	return nil
}

// Allowed Commands and validation regexes
var (
	// List of allowed root commands
	allowedRootCommands = map[string]bool{
		"df":         true,
		"free":       true,
		"uptime":     true,
		"uname":      true,
		"hostname":   true,
		"top":        true,
		"ps":         true,
		"journalctl": true,
		"systemctl":  true,
		"smartctl":   true,
		"docker":     true,
		"cat":        true,
		"grep":       true,
		"tail":       true,
		"head":       true,
		"ls":         true,
		"ping":       true,
		"netstat":    true,
		"ss":         true,
		"ip":         true,
		"ifconfig":   true,
		"lsof":       true,
	}

	// Blocked shell features
	blockedPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[>><&;]`), // Redirects, chaining, backgrounding (we split by pipeline/&&/|| manually first)
		regexp.MustCompile(`\$\(.*?\)`), // Command substitution
		regexp.MustCompile("`.*?`"),     // Backtick substitution
		regexp.MustCompile(`\b(sudo|su|bash|sh|zsh|eval|rm|mv|cp|chmod|chown|wget|curl|apt|dpkg|yum|dnf|pip|npm|docker-compose)\b`),
	}
)

// ValidateCommand strictly validates the command to ensure it's a read-only SRE diagnostic command.
func ValidateCommand(cmd string) error {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return fmt.Errorf("command cannot be empty")
	}

	// Split by pipeline character '|' to validate each segment separately
	segments := strings.Split(trimmed, "|")
	for _, segment := range segments {
		segTrimmed := strings.TrimSpace(segment)
		if segTrimmed == "" {
			return fmt.Errorf("empty command segment in pipeline")
		}

		// Quick check for blocked patterns in this segment
		for _, pattern := range blockedPatterns {
			if pattern.MatchString(segTrimmed) {
				return fmt.Errorf("command segment '%s' contains blocked operators or forbidden keywords", segTrimmed)
			}
		}

		parts := strings.Fields(segTrimmed)
		if len(parts) == 0 {
			return fmt.Errorf("invalid command structure in segment '%s'", segTrimmed)
		}

		rootCmd := parts[0]
		if !allowedRootCommands[rootCmd] {
			return fmt.Errorf("command '%s' is not allowed. Only read-only diagnostic commands are permitted", rootCmd)
		}

		// Specific subcommand validations
		switch rootCmd {
		case "systemctl":
			// Only status, is-active, is-failed, list-units, list-sockets, list-timers, show allowed
			if len(parts) > 1 {
				subCmd := parts[1]
				allowedSub := map[string]bool{
					"status":       true,
					"is-active":    true,
					"is-failed":    true,
					"list-units":   true,
					"list-sockets": true,
					"list-timers":  true,
					"show":         true,
				}
				if !allowedSub[subCmd] {
					return fmt.Errorf("systemctl subcommand '%s' is forbidden. Only status/read commands are allowed", subCmd)
				}
			}
		case "docker":
			// Only ps, stats, logs, inspect, port, version, info allowed
			if len(parts) > 1 {
				subCmd := parts[1]
				allowedSub := map[string]bool{
					"ps":      true,
					"stats":   true,
					"logs":    true,
					"inspect": true,
					"port":    true,
					"version": true,
					"info":    true,
				}
				if !allowedSub[subCmd] {
					return fmt.Errorf("docker subcommand '%s' is forbidden. Only read-only commands are allowed", subCmd)
				}
			}
		case "cat":
			// Only allow viewing system files or configuration files in /etc or /proc
			// Block viewing /etc/shadow, /etc/passwd or any sensitive key file
			for _, arg := range parts[1:] {
				argLower := strings.ToLower(arg)
				if strings.Contains(argLower, "shadow") || strings.Contains(argLower, "passwd") || strings.Contains(argLower, "key") || strings.Contains(argLower, "secret") || strings.Contains(argLower, ".ssh") {
					return fmt.Errorf("reading sensitive files with cat is forbidden")
				}
			}
		}
	}

	return nil
}

// ExecuteCommand executes a validated command on the specified host.
func (p *ClientPool) ExecuteCommand(config SSHConfig, cmd string) (string, error) {
	if err := ValidateCommand(cmd); err != nil {
		return "", fmt.Errorf("security validation failed: %w", err)
	}

	client, err := p.GetClient(config)
	if err != nil {
		return "", err
	}

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err = session.Run(cmd)
	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()

	if err != nil {
		return "", fmt.Errorf("command execution failed: %v. Stderr: %s. Stdout: %s", err, stderrStr, stdoutStr)
	}

	if stderrStr != "" {
		return fmt.Sprintf("%s\nWarnings/Errors:\n%s", stdoutStr, stderrStr), nil
	}

	return stdoutStr, nil
}
