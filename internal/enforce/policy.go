package enforce

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type PolicyEngine struct {
	store *audit.Store
}

func NewPolicyEngine(store *audit.Store) *PolicyEngine {
	return &PolicyEngine{store: store}
}

func (e *PolicyEngine) IsBlocked(targetType, name string) (bool, error) {
	return e.store.IsBlocked(targetType, name)
}

func (e *PolicyEngine) IsAllowed(targetType, name string) (bool, error) {
	return e.store.IsAllowed(targetType, name)
}

func (e *PolicyEngine) Block(targetType, name, reason string) error {
	if err := e.store.RemoveAllow(targetType, name); err != nil {
		return fmt.Errorf("enforce: remove from allow list: %w", err)
	}
	return e.store.AddBlock(targetType, name, reason)
}

func (e *PolicyEngine) Allow(targetType, name, reason string) error {
	if err := e.store.RemoveBlock(targetType, name); err != nil {
		return fmt.Errorf("enforce: remove from block list: %w", err)
	}
	return e.store.AddAllow(targetType, name, reason)
}

func (e *PolicyEngine) Unblock(targetType, name string) error {
	return e.store.RemoveBlock(targetType, name)
}

func (e *PolicyEngine) ListBlocked() ([]audit.BlockEntry, error) {
	return e.store.ListBlocked()
}

func (e *PolicyEngine) ListAllowed() ([]audit.AllowEntry, error) {
	return e.store.ListAllowed()
}
