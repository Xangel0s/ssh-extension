package ssh

import (
	"testing"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		// Safe commands
		{"Simple df", "df -h", false},
		{"Simple free", "free -m", false},
		{"Simple uptime", "uptime", false},
		{"Systemctl status", "systemctl status nginx", false},
		{"Docker ps", "docker ps", false},
		{"Docker stats", "docker stats --no-stream", false},
		{"Journalctl", "journalctl -u docker -n 50", false},
		{"Piped grep", "docker ps | grep nginx", false},
		{"Double pipe", "docker ps | grep nginx | head -n 5", false},
		{"Safe cat proc", "cat /proc/meminfo", false},

		// Blocked commands / Forbidden root
		{"Forbidden root command", "rm -rf /", true},
		{"Forbidden sudo prefix", "sudo df -h", true},
		{"Forbidden curl", "curl http://example.com", true},
		{"Forbidden bash execution", "bash script.sh", true},

		// Dangerous systemctl
		{"Systemctl stop", "systemctl stop nginx", true},
		{"Systemctl restart", "systemctl restart docker", true},
		{"Systemctl disable", "systemctl disable firewall", true},

		// Dangerous docker
		{"Docker run", "docker run -d alpine", true},
		{"Docker rm", "docker rm container_id", true},
		{"Docker exec", "docker exec -it container sh", true},

		// Chaining / Redirection
		{"Command injection with semicolon", "uptime; rm -rf /", true},
		{"Command injection with double-ampersand", "df -h && rm -rf /", true},
		{"Command injection with pipe to dangerous", "df -h | bash", true},
		{"Redirect to file", "df -h > output.txt", true},
		{"Append redirect", "free -m >> /tmp/free.txt", true},
		{"Command substitution", "df -h $(rm -rf /)", true},
		{"Backticks substitution", "df -h `rm -rf /`", true},

		// Sensitive cat files
		{"Sensitive cat file", "cat /etc/shadow", true},
		{"Sensitive cat key", "cat ~/.ssh/id_rsa", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand(%q) error = %v, wantErr %v", tt.command, err, tt.wantErr)
			}
		})
	}
}

func TestAnalyzeCommand(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		wantSafe         bool
		wantApproval     bool
		wantErr          bool
	}{
		{"Safe free", "free -m", true, false, false},
		{"Write systemctl restart", "systemctl restart nginx", false, true, false},
		{"Write docker run", "docker run -d alpine", false, true, false},
		{"Write docker rm", "docker rm container_id", false, true, false},
		{"Forbidden sudo restart", "sudo systemctl restart nginx", false, false, true},
		{"Forbidden rm", "rm -rf /", false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSafe, requiresApproval, err := AnalyzeCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("AnalyzeCommand(%q) err = %v, wantErr %v", tt.command, err, tt.wantErr)
				return
			}
			if isSafe != tt.wantSafe {
				t.Errorf("AnalyzeCommand(%q) isSafe = %v, wantSafe %v", tt.command, isSafe, tt.wantSafe)
			}
			if requiresApproval != tt.wantApproval {
				t.Errorf("AnalyzeCommand(%q) requiresApproval = %v, wantApproval %v", tt.command, requiresApproval, tt.wantApproval)
			}
		})
	}
}
