package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// doctorReport deliberately excludes provider, profile, path and credential
// values. A local report never attests to authentication or storage readiness.
type doctorReport struct {
	ReportVersion int           `json:"report_version"`
	Mode          string        `json:"mode"`
	Ready         *bool         `json:"ready"`
	Checks        []doctorCheck `json:"checks"`
}

type doctorCheck struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	NextAction string `json:"next_action"`
}

type doctorFailure struct {
	report doctorReport
	cause  error
}

func (e *doctorFailure) Error() string { return "local diagnostic checks failed" }
func (e *doctorFailure) Unwrap() error { return e.cause }

func newDoctorCommand(options *Options, deps Dependencies, configErr error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local configuration without accessing credentials or providers",
		Long:  "Check local configuration without accessing credentials or providers.\n\nThis first local-only diagnostic does not inspect credential storage, verify a\nprovider session, or test destination permissions. Online and destination\ndiagnostics are not yet supported. A passing local report is not readiness\nfor unattended account commands. Demo mode is not yet supported.",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return invalidArgument(nil)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := localDoctorReport(options, configErr)
			if options.Envelope {
				setEnvelopeData(deps, report)
			} else if options.JSON {
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
					return err
				}
			} else {
				for _, check := range report.Checks {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (%s). %s\n", check.ID, check.Status, check.Reason, check.NextAction); err != nil {
						return err
					}
				}
			}
			if report.Ready != nil && !*report.Ready {
				return &doctorFailure{report: report, cause: internalBoundary(errDoctorConfiguration)}
			}
			return nil
		},
	}
	cmd.SilenceUsage = true
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, _ error) error { return invalidArgument(nil) })
	return cmd
}

// This fixed error is intentionally unrelated to the raw configuration error.
// Configuration parse failures may include paths or caller-provided values.
var errDoctorConfiguration = errors.New("local diagnostic checks failed")

func localDoctorReport(options *Options, configErr error) doctorReport {
	report := doctorReport{ReportVersion: 1, Mode: "local", Checks: []doctorCheck{
		{"build", "not_checked", "not_verified", "Use a verified project build."},
		{"platform", "passed", "supported", "No local platform action required."},
		{"storage.backend", "not_checked", "not_inspected", "Credential storage is not inspected by local diagnostics."},
		{"config", "passed", "valid", "No local configuration action required."},
		{"session.live", "not_checked", "local_only", "Provider session readiness requires separate authorized verification."},
		{"selection.account", "not_checked", "local_only", "Account selection requires provider discovery."},
		{"selection.meter", "not_checked", "local_only", "Meter selection requires provider discovery."},
		{"destination.metadata", "not_checked", "not_requested", "Destination diagnostics are not yet supported."},
	}}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		report.Checks[1] = doctorCheck{"platform", "warning", "not_qualified", "Use a supported Linux or macOS build."}
	}
	if configErr != nil || strings.TrimSpace(options.Profile) == "" || options.Timeout <= 0 {
		notReady := false
		report.Ready = &notReady
		report.Checks[3] = doctorCheck{"config", "failed", "invalid", "Review non-secret configuration and command options."}
	}
	return report
}
