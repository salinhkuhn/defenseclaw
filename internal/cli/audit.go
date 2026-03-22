package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var auditLimit int

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View audit log",
	Long:  "Display recent audit events from the SQLite event store.",
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().IntVarP(&auditLimit, "limit", "n", 25, "Number of events to show")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(_ *cobra.Command, _ []string) error {
	events, err := auditStore.ListEvents(auditLimit)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No audit events.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tACTION\tTARGET\tSEVERITY\tDETAILS")
	for _, e := range events {
		details := e.Details
		if len(details) > 60 {
			details = details[:57] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Action,
			e.Target,
			e.Severity,
			details,
		)
	}
	return w.Flush()
}
