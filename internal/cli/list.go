package cli

import (
	"fmt"
	"text/tabwriter"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List blocked or allowed items",
}

var listBlockedCmd = &cobra.Command{
	Use:   "blocked",
	Short: "List blocked skills and MCP servers",
	RunE:  runListBlocked,
}

var listAllowedCmd = &cobra.Command{
	Use:   "allowed",
	Short: "List allowed skills and MCP servers",
	RunE:  runListAllowed,
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.AddCommand(listBlockedCmd)
	listCmd.AddCommand(listAllowedCmd)
}

func runListBlocked(_ *cobra.Command, _ []string) error {
	pe := enforce.NewPolicyEngine(auditStore)
	entries, err := pe.ListBlocked()
	if err != nil {
		return fmt.Errorf("list blocked: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No blocked items.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tNAME\tREASON\tBLOCKED AT")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.TargetType, e.TargetName, e.Reason, e.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	return w.Flush()
}

func runListAllowed(_ *cobra.Command, _ []string) error {
	pe := enforce.NewPolicyEngine(auditStore)
	entries, err := pe.ListAllowed()
	if err != nil {
		return fmt.Errorf("list allowed: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No allowed items.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tNAME\tREASON\tALLOWED AT")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.TargetType, e.TargetName, e.Reason, e.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	return w.Flush()
}
