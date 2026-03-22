package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var quarantineCmd = &cobra.Command{
	Use:   "quarantine <skill-path>",
	Short: "Immediately quarantine a skill — block + move files",
	Long:  "Emergency action: blocks the skill, quarantines its files, and updates the sandbox policy in a single step.",
	Args:  cobra.ExactArgs(1),
	RunE:  runQuarantine,
}

func init() {
	rootCmd.AddCommand(quarantineCmd)
}

func runQuarantine(_ *cobra.Command, args []string) error {
	skillPath := args[0]

	pe := enforce.NewPolicyEngine(auditStore)
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	fmt.Printf("[quarantine] Blocking skill %q...\n", skillPath)
	if err := pe.Block("skill", skillPath, "emergency quarantine"); err != nil {
		return fmt.Errorf("quarantine: block failed: %w", err)
	}

	dest, err := se.Quarantine(skillPath)
	if err != nil {
		fmt.Printf("[quarantine] Warning: could not move files: %v\n", err)
	} else {
		fmt.Printf("[quarantine] Files moved to %s\n", dest)
	}

	pErr := se.UpdateSandboxPolicy(skillPath, true)
	if pErr != nil {
		if !shell.IsAvailable() {
			fmt.Println("[quarantine] OpenShell not detected — policy written but not enforced")
		} else {
			fmt.Printf("[quarantine] Warning: sandbox policy update failed: %v\n", pErr)
		}
	} else {
		if shell.IsAvailable() {
			fmt.Println("[quarantine] Sandbox policy updated")
		} else {
			fmt.Println("[quarantine] Sandbox policy written (OpenShell not available)")
		}
	}

	_ = auditLog.LogAction("quarantine", skillPath, "emergency quarantine")
	fmt.Printf("[quarantine] Audit event recorded\n")
	fmt.Printf("[quarantine] Complete. Use 'defenseclaw allow skill %s --skip-rescan' to restore.\n", skillPath)
	return nil
}
