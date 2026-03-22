package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type MCPScanner struct {
	BinaryPath string
}

func NewMCPScanner(binaryPath string) *MCPScanner {
	if binaryPath == "" {
		binaryPath = "mcp-scanner"
	}
	return &MCPScanner{BinaryPath: binaryPath}
}

func (s *MCPScanner) Name() string              { return "mcp-scanner" }
func (s *MCPScanner) Version() string            { return "1.0.0" }
func (s *MCPScanner) SupportedTargets() []string { return []string{"mcp"} }

func (s *MCPScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, s.BinaryPath, "scan", "--format", "json", target)
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
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: uv tool install cisco-ai-mcp-scanner", s.Name(), s.BinaryPath)
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
