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

type SkillScanner struct {
	BinaryPath string
}

func NewSkillScanner(binaryPath string) *SkillScanner {
	if binaryPath == "" {
		binaryPath = "skill-scanner"
	}
	return &SkillScanner{BinaryPath: binaryPath}
}

func (s *SkillScanner) Name() string              { return "skill-scanner" }
func (s *SkillScanner) Version() string            { return "1.0.0" }
func (s *SkillScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *SkillScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
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
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: uv pip install cisco-ai-skill-scanner", s.Name(), s.BinaryPath)
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("scanner: %s failed: %s", s.Name(), stderr.String())
		}
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseSkillOutput(stdout.Bytes())
		if parseErr != nil {
			return nil, fmt.Errorf("scanner: failed to parse %s output: %w", s.Name(), parseErr)
		}
		result.Findings = findings
	}

	return result, nil
}

type skillOutput struct {
	Findings []skillFinding `json:"findings"`
}

type skillFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
}

func parseSkillOutput(data []byte) ([]Finding, error) {
	var out skillOutput
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
			Scanner:     "skill-scanner",
		})
	}
	return findings, nil
}
