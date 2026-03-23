package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var (
	sidecarToken string
	sidecarHost  string
	sidecarPort  int
)

var sidecarCmd = &cobra.Command{
	Use:   "sidecar",
	Short: "Run the gateway sidecar — connect to the OpenClaw gateway and enforce policy in real time",
	Long: `Start a long-running sidecar process that connects to the OpenClaw gateway
WebSocket as an operator client. The sidecar monitors tool_call and tool_result
events, handles exec.approval requests, and can disable skills via the gateway
RPC protocol.

The sidecar runs three subsystems as independent goroutines:
  1. Gateway connection loop — WebSocket connection with auto-reconnect
  2. Skill/MCP watcher — filesystem watcher for new installs (opt-in)
  3. REST API server — local HTTP API for CLI and plugin communication

Configure the gateway address and token in ~/.defenseclaw/config.yaml under the
"gateway" section, or use the --token, --host, and --port flags.`,
	RunE: runSidecar,
}

var sidecarStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show health of the running sidecar's subsystems",
	Long: `Query the sidecar's REST API to display the health of all three subsystems:
gateway connection, skill watcher, and API server.

The sidecar must be running for this command to work.`,
	RunE: runSidecarStatus,
}

func init() {
	sidecarCmd.Flags().StringVar(&sidecarToken, "token", "", "Gateway auth token (overrides config)")
	sidecarCmd.Flags().StringVar(&sidecarHost, "host", "", "Gateway host (default: from config)")
	sidecarCmd.Flags().IntVar(&sidecarPort, "port", 0, "Gateway port (default: from config)")
	sidecarCmd.AddCommand(sidecarStatusCmd)
	rootCmd.AddCommand(sidecarCmd)
}

func runSidecar(_ *cobra.Command, _ []string) error {
	if sidecarToken != "" {
		cfg.Gateway.Token = sidecarToken
	}
	if sidecarHost != "" {
		cfg.Gateway.Host = sidecarHost
	}
	if sidecarPort > 0 {
		cfg.Gateway.Port = sidecarPort
	}

	if cfg.Gateway.Token == "" {
		token := os.Getenv("OPENCLAW_GATEWAY_TOKEN")
		if token != "" {
			cfg.Gateway.Token = token
		}
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║       DefenseClaw Gateway Sidecar            ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Gateway:      %s:%d\n", cfg.Gateway.Host, cfg.Gateway.Port)
	fmt.Printf("  Auto-approve: %v\n", cfg.Gateway.AutoApprove)
	fmt.Printf("  Auth:         %s\n", tokenStatus(cfg.Gateway.Token))
	fmt.Printf("  API port:     %d\n", cfg.Gateway.APIPort)
	fmt.Printf("  Watcher:      %v\n", cfg.Gateway.Watcher.Enabled)
	if cfg.Gateway.Watcher.Enabled {
		fmt.Printf("    Skill:      enabled=%v take_action=%v\n",
			cfg.Gateway.Watcher.Skill.Enabled, cfg.Gateway.Watcher.Skill.TakeAction)
		if len(cfg.Gateway.Watcher.Skill.Dirs) > 0 {
			fmt.Printf("    Skill dirs: %v\n", cfg.Gateway.Watcher.Skill.Dirs)
		} else {
			fmt.Printf("    Skill dirs: autodiscover (from claw mode)\n")
		}
	}
	fmt.Println()

	sc, err := gateway.NewSidecar(cfg, auditStore, auditLog, shell)
	if err != nil {
		return fmt.Errorf("sidecar: init: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[sidecar] shutting down...")
		cancel()
	}()

	return sc.Run(ctx)
}

func runSidecarStatus(_ *cobra.Command, _ []string) error {
	addr := fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Gateway.APIPort)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(addr)
	if err != nil {
		fmt.Println("Sidecar Status: NOT RUNNING")
		fmt.Printf("  Could not reach %s\n", addr)
		fmt.Println("  Start the sidecar with: defenseclaw sidecar")
		return nil
	}
	defer resp.Body.Close()

	var snap gateway.HealthSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return fmt.Errorf("sidecar status: parse response: %w", err)
	}

	uptime := time.Duration(snap.UptimeMs) * time.Millisecond

	fmt.Println("DefenseClaw Sidecar Health")
	fmt.Println("══════════════════════════")
	fmt.Printf("  Started:  %s\n", snap.StartedAt.Format(time.RFC3339))
	fmt.Printf("  Uptime:   %s\n", formatDuration(uptime))
	fmt.Println()

	printSubsystem("Gateway", snap.Gateway)
	printSubsystem("Watcher", snap.Watcher)
	printSubsystem("API", snap.API)

	return nil
}

func printSubsystem(name string, h gateway.SubsystemHealth) {
	stateStr := strings.ToUpper(string(h.State))
	fmt.Printf("  %-10s %s", name+":", stateStr)
	if !h.Since.IsZero() {
		fmt.Printf(" (since %s)", h.Since.Format(time.RFC3339))
	}
	fmt.Println()

	if h.LastError != "" {
		fmt.Printf("             last error: %s\n", h.LastError)
	}
	if len(h.Details) > 0 {
		for k, v := range h.Details {
			fmt.Printf("             %s: %v\n", k, v)
		}
	}
	fmt.Println()
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func tokenStatus(token string) string {
	if token == "" {
		return "none (will use device identity only)"
	}
	if len(token) > 8 {
		return token[:4] + "..." + token[len(token)-4:]
	}
	return "***"
}
