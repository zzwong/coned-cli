package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/spf13/cobra"
	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/diagnostics"
)

type schemaService interface {
	SchemaDiagnostics(context.Context, auth.Session) ([]diagnostics.Fingerprint, error)
}

func newDiagnosticsCommand(options *Options, deps Dependencies) *cobra.Command {
	root := &cobra.Command{Use: "diagnostics", Short: "Create value-free provider diagnostics", Args: cobra.NoArgs}
	var output string
	schema := &cobra.Command{Use: "schema", Short: "Record provider JSON structure without values", Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.NoArgs(cmd, args); err != nil {
			return err
		}
		if output == "" && !options.JSON && !options.Envelope {
			return invalidArgument(errors.New("--output is required unless --json is set"))
		}
		return nil
	}, RunE: func(cmd *cobra.Command, _ []string) error {
		if output == "" && !options.JSON && !options.Envelope {
			return invalidArgument(errors.New("--output is required unless --json is set"))
		}
		var fingerprints []diagnostics.Fingerprint
		if options.Demo {
			entities, _, err := entityContext(cmd, options, deps)
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(map[string]any{"entities": entities})
			f, _ := diagnostics.Collect("demo-entities", "synthetic-adversarial", raw, deps.Clock())
			fingerprints = []diagnostics.Fingerprint{f}
		} else {
			service, ok := any(deps.Bills).(schemaService)
			if !ok {
				return coned.ErrProtocolChanged
			}
			session, err := billingSession(deps, options.Profile)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
			defer cancel()
			fingerprints, err = service.SchemaDiagnostics(ctx, session)
			if err != nil {
				return safeOpowerError(err)
			}
		}
		data, err := json.MarshalIndent(fingerprints, "", "  ")
		if err != nil {
			return coned.ErrProtocolChanged
		}
		data = append(data, '\n')
		if output == "" {
			_, err = cmd.OutOrStdout().Write(data)
			return err
		}
		file, temp, err := newOutputFileWithPrefix(output, false, ".coned-diagnostics-*")
		if err != nil {
			return err
		}
		if _, err = file.Write(data); err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(temp)
			return outputFailedError()
		}
		if err = publishOutput(temp, output, false); err != nil {
			_ = os.Remove(temp)
			return err
		}
		if options.Envelope {
			setEnvelopeData(deps, envelopeFile{Path: output, Bytes: int64(len(data)), SHA256: sha256Hex(data), Format: "json"})
		}
		return nil
	}}
	schema.Flags().StringVarP(&output, "output", "o", "", "owner-only diagnostic file")
	inspect := &cobra.Command{Use: "inspect FILE", Short: "Inspect a diagnostic file", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return coned.ErrProtocolChanged
		}
		var value []diagnostics.Fingerprint
		if json.Unmarshal(data, &value) != nil {
			return coned.ErrProtocolChanged
		}
		return writeJSON(cmd.OutOrStdout(), value)
	}}
	root.AddCommand(schema, inspect)
	return root
}
