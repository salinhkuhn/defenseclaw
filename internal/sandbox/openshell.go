package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type OpenShell struct {
	BinaryPath    string
	PolicyDir     string
	FallbackDir   string
}

func New(binaryPath, policyDir string) *OpenShell {
	return &OpenShell{BinaryPath: binaryPath, PolicyDir: policyDir}
}

func NewWithFallback(binaryPath, policyDir, fallbackDir string) *OpenShell {
	return &OpenShell{BinaryPath: binaryPath, PolicyDir: policyDir, FallbackDir: fallbackDir}
}

func (o *OpenShell) IsAvailable() bool {
	_, err := exec.LookPath(o.BinaryPath)
	return err == nil
}

func (o *OpenShell) PolicyPath() string {
	return filepath.Join(o.PolicyDir, "defenseclaw-policy.yaml")
}

func (o *OpenShell) fallbackPolicyPath() string {
	if o.FallbackDir != "" {
		return filepath.Join(o.FallbackDir, "defenseclaw-policy.yaml")
	}
	return ""
}

func (o *OpenShell) effectivePolicyPath() string {
	primary := o.PolicyPath()
	dir := filepath.Dir(primary)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if fb := o.fallbackPolicyPath(); fb != "" {
			return fb
		}
	}
	return primary
}

func (o *OpenShell) LoadPolicy() (*Policy, error) {
	path := o.effectivePolicyPath()
	return LoadPolicy(path)
}

func (o *OpenShell) SavePolicy(p *Policy) error {
	path := o.effectivePolicyPath()
	return p.Save(path)
}

func (o *OpenShell) ReloadPolicy() error {
	if !o.IsAvailable() {
		return fmt.Errorf("sandbox: openshell binary not found at %q", o.BinaryPath)
	}
	cmd := exec.Command(o.BinaryPath, "policy", "reload")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sandbox: reload policy: %s: %w", string(out), err)
	}
	return nil
}

func (o *OpenShell) Start() error {
	if !o.IsAvailable() {
		return fmt.Errorf("sandbox: openshell binary not found at %q", o.BinaryPath)
	}
	return fmt.Errorf("sandbox: openshell start not yet implemented — coming in iteration 4")
}
