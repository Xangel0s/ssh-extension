package monitoring

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"mcp-ssh-go/internal/coolify"
	"mcp-ssh-go/internal/proxmox"
)

type Monitor struct {
	server       *server.MCPServer
	interval     time.Duration
	cpuThreshold float64
	memThreshold float64
	proxmoxNodes []string

	coolifyAppsStatus map[string]string
	coolifyMu         sync.Mutex
}

func NewMonitor(s *server.MCPServer) *Monitor {
	intervalStr := os.Getenv("MONITORING_INTERVAL")
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		interval = 30 * time.Second
	}

	cpuThresh, err := strconv.ParseFloat(os.Getenv("MONITORING_CPU_THRESHOLD"), 64)
	if err != nil {
		cpuThresh = 90.0
	}

	memThresh, err := strconv.ParseFloat(os.Getenv("MONITORING_MEM_THRESHOLD"), 64)
	if err != nil {
		memThresh = 90.0
	}

	nodesStr := os.Getenv("MONITORING_PROXMOX_NODES")
	var nodes []string
	if nodesStr != "" {
		for _, n := range strings.Split(nodesStr, ",") {
			nodes = append(nodes, strings.TrimSpace(n))
		}
	} else {
		nodes = []string{"pve"}
	}

	return &Monitor{
		server:            s,
		interval:          interval,
		cpuThreshold:      cpuThresh,
		memThreshold:      memThresh,
		proxmoxNodes:      nodes,
		coolifyAppsStatus: make(map[string]string),
	}
}

func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	log.Printf("[Monitoring]: Started background monitoring. Interval: %s, CPU threshold: %.1f%%, Memory threshold: %.1f%%", m.interval, m.cpuThreshold, m.memThreshold)

	// Run initial check immediately
	go m.check()

	go func() {
		for {
			select {
			case <-ticker.C:
				m.check()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (m *Monitor) check() {
	m.checkProxmox()
	m.checkCoolify()
}

func (m *Monitor) checkProxmox() {
	pxUrl := os.Getenv("PROXMOX_URL")
	pxTokenID := os.Getenv("PROXMOX_TOKEN_ID")
	pxTokenVal := os.Getenv("PROXMOX_TOKEN_VALUE")

	if pxUrl == "" || pxTokenID == "" || pxTokenVal == "" {
		return
	}

	client, err := proxmox.NewClientFromEnv()
	if err != nil {
		log.Printf("[Monitoring]: Failed to initialize Proxmox client: %v", err)
		return
	}

	for _, node := range m.proxmoxNodes {
		status, err := client.GetNodeStatus(node)
		if err != nil {
			log.Printf("[Monitoring]: Failed to get status for Proxmox node %s: %v", node, err)
			continue
		}

		cpuPercent := status.CPU * 100
		var memPercent float64
		if status.Memory.Total > 0 {
			memPercent = (float64(status.Memory.Used) / float64(status.Memory.Total)) * 100
		}

		if cpuPercent > m.cpuThreshold {
			m.server.SendNotificationToAllClients("notifications/alert", map[string]any{
				"message": fmt.Sprintf("Alerta PVE: El nodo '%s' superó el umbral de CPU: %.1f%% (límite: %.1f%%)", node, cpuPercent, m.cpuThreshold),
				"level":   "warning",
			})
		}

		if memPercent > m.memThreshold {
			m.server.SendNotificationToAllClients("notifications/alert", map[string]any{
				"message": fmt.Sprintf("Alerta PVE: El nodo '%s' superó el umbral de Memoria: %.1f%% (límite: %.1f%%)", node, memPercent, m.memThreshold),
				"level":   "warning",
			})
		}
	}
}

func (m *Monitor) checkCoolify() {
	cfUrl := os.Getenv("COOLIFY_URL")
	cfToken := os.Getenv("COOLIFY_TOKEN")

	if cfUrl == "" || cfToken == "" {
		return
	}

	client, err := coolify.NewClientFromEnv()
	if err != nil {
		log.Printf("[Monitoring]: Failed to initialize Coolify client: %v", err)
		return
	}

	apps, err := client.ListApplications()
	if err != nil {
		log.Printf("[Monitoring]: Failed to list Coolify applications: %v", err)
		return
	}

	m.coolifyMu.Lock()
	defer m.coolifyMu.Unlock()

	for _, app := range apps {
		prevStatus, exists := m.coolifyAppsStatus[app.UUID]
		currentStatus := app.Status

		if currentStatus == "" {
			currentStatus = "unknown"
		}

		if exists && prevStatus != currentStatus {
			if strings.HasPrefix(currentStatus, "running") && !strings.HasPrefix(prevStatus, "running") {
				m.server.SendNotificationToAllClients("notifications/alert", map[string]any{
					"message": fmt.Sprintf("Coolify Info: La aplicación '%s' está ONLINE (%s)", app.Name, currentStatus),
					"level":   "info",
				})
			} else if !strings.HasPrefix(currentStatus, "running") && strings.HasPrefix(prevStatus, "running") {
				m.server.SendNotificationToAllClients("notifications/alert", map[string]any{
					"message": fmt.Sprintf("Coolify Alerta: La aplicación '%s' está OFFLINE (estado: %s)", app.Name, currentStatus),
					"level":   "error",
				})
			}
		}

		m.coolifyAppsStatus[app.UUID] = currentStatus
	}
}
