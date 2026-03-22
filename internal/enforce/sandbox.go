package enforce

import (
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

type SandboxPolicy struct {
	shell *sandbox.OpenShell
}

func NewSandboxPolicy(shell *sandbox.OpenShell) *SandboxPolicy {
	return &SandboxPolicy{shell: shell}
}

func (s *SandboxPolicy) IsAvailable() bool {
	return s.shell.IsAvailable()
}

func (s *SandboxPolicy) LoadPolicy() (*sandbox.Policy, error) {
	return s.shell.LoadPolicy()
}

func (s *SandboxPolicy) SavePolicy(p *sandbox.Policy) error {
	return s.shell.SavePolicy(p)
}
