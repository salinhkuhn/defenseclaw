package unit

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestSkillScanEndpointConfigured(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Scanners.SkillScanner.Binary == "" {
		t.Error("expected default skill-scanner binary to be set")
	}
	if cfg.Scanners.SkillScanner.Binary != "skill-scanner" {
		t.Errorf("expected 'skill-scanner', got %q", cfg.Scanners.SkillScanner.Binary)
	}
}

func TestMCPScanEndpointConfigured(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Scanners.MCPScanner.Binary == "" {
		t.Error("expected default mcp-scanner binary to be set")
	}
	if cfg.Scanners.MCPScanner.Binary != "mcp-scanner" {
		t.Errorf("expected 'mcp-scanner', got %q", cfg.Scanners.MCPScanner.Binary)
	}
	if cfg.Scanners.MCPScanner.LLMTimeout != 30 {
		t.Errorf("expected LLMTimeout=30, got %d", cfg.Scanners.MCPScanner.LLMTimeout)
	}
	if cfg.Scanners.MCPScanner.LLMMaxRetries != 3 {
		t.Errorf("expected LLMMaxRetries=3, got %d", cfg.Scanners.MCPScanner.LLMMaxRetries)
	}
}

func TestSkillWatcherConfigDefaults(t *testing.T) {
	cfg := config.DefaultConfig()

	if !cfg.Gateway.Watcher.Skill.Enabled {
		t.Error("expected skill watcher enabled by default")
	}
	if !cfg.Gateway.Watcher.Skill.TakeAction {
		t.Error("expected skill watcher take_action=true by default")
	}
}
