package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zzwong/coned-cli/internal/build"
)

func newVersionCommand(jsonOutput *bool) *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Show build version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if *jsonOutput {
			data, err := json.Marshal(map[string]string{"version": build.Version, "commit": build.Commit, "date": build.Date, "dirty": build.Dirty})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return err
		}
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "coned %s (%s, built %s, dirty=%s)\n", build.Version, build.Commit, build.Date, build.Dirty)
		return err
	}}
}
