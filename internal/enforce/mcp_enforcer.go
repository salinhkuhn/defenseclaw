package enforce

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

type MCPEnforcer struct {
	shell *sandbox.OpenShell
}

func NewMCPEnforcer(shell *sandbox.OpenShell) *MCPEnforcer {
	return &MCPEnforcer{shell: shell}
}

func (e *MCPEnforcer) BlockEndpoint(url string) error {
	policy, err := e.shell.LoadPolicy()
	if err != nil {
		return fmt.Errorf("enforce: load sandbox policy: %w", err)
	}

	policy.DenyEndpoint(url)

	if err := e.shell.SavePolicy(policy); err != nil {
		return fmt.Errorf("enforce: save sandbox policy: %w", err)
	}

	if e.shell.IsAvailable() {
		if err := e.shell.ReloadPolicy(); err != nil {
			return fmt.Errorf("enforce: reload sandbox policy: %w", err)
		}
	}
	return nil
}

func (e *MCPEnforcer) AllowEndpoint(url string) error {
	policy, err := e.shell.LoadPolicy()
	if err != nil {
		return fmt.Errorf("enforce: load sandbox policy: %w", err)
	}

	policy.AllowEndpoint(url)

	if err := e.shell.SavePolicy(policy); err != nil {
		return fmt.Errorf("enforce: save sandbox policy: %w", err)
	}

	if e.shell.IsAvailable() {
		if err := e.shell.ReloadPolicy(); err != nil {
			return fmt.Errorf("enforce: reload sandbox policy: %w", err)
		}
	}
	return nil
}
