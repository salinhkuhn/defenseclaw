package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type MCPScanner struct {
	Config config.MCPScannerConfig
}

func NewMCPScanner(cfg config.MCPScannerConfig) *MCPScanner {
	if cfg.Binary == "" {
		cfg.Binary = "mcp-scanner"
	}
	return &MCPScanner{Config: cfg}
}

func (s *MCPScanner) Name() string              { return "mcp-scanner" }
func (s *MCPScanner) Version() string            { return "1.0.0" }
func (s *MCPScanner) SupportedTargets() []string { return []string{"mcp"} }

func (s *MCPScanner) buildArgs(target string) []string {
	args := []string{"scan", "--format", "json"}

	if s.Config.Analyzers != "" {
		args = append(args, "--analyzers", s.Config.Analyzers)
	}
	if s.Config.ScanPrompts {
		args = append(args, "--scan-prompts")
	}
	if s.Config.ScanResources {
		args = append(args, "--scan-resources")
	}
	if s.Config.ScanInstructions {
		args = append(args, "--scan-instructions")
	}

	args = append(args, target)
	return args
}

func (s *MCPScanner) scanEnv() []string {
	env := os.Environ()

	inject := []struct {
		envVar string
		value  string
	}{
		{"MCP_SCANNER_API_KEY", s.Config.APIKey},
		{"MCP_SCANNER_ENDPOINT", s.Config.EndpointURL},
		{"MCP_SCANNER_LLM_API_KEY", s.Config.LLMAPIKey},
		{"MCP_SCANNER_LLM_MODEL", s.Config.LLMModel},
		{"MCP_SCANNER_LLM_BASE_URL", s.Config.LLMBaseURL},
	}

	existing := make(map[string]bool)
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				existing[e[:i]] = true
				break
			}
		}
	}

	for _, kv := range inject {
		if kv.value != "" && !existing[kv.envVar] {
			env = append(env, kv.envVar+"="+kv.value)
		}
	}

	return env
}

func (s *MCPScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()

	args := s.buildArgs(target)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = s.scanEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
		Duration:  duration,
	}

	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: uv tool install cisco-ai-mcp-scanner", s.Name(), s.Config.Binary)
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("scanner: %s failed: %s", s.Name(), stderr.String())
		}
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseMCPOutput(stdout.Bytes())
		if parseErr != nil {
			return nil, fmt.Errorf("scanner: failed to parse %s output: %w", s.Name(), parseErr)
		}
		result.Findings = findings
	}

	return result, nil
}

type mcpOutput struct {
	Findings []mcpFinding `json:"findings"`
}

type mcpFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
}

func parseMCPOutput(data []byte) ([]Finding, error) {
	var out mcpOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "mcp-scanner",
		})
	}
	return findings, nil
}
