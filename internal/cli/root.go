// Package cli defines the coned command-line interface.
package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/config"
	"github.com/zzwong/coned-cli/internal/provider"
	"github.com/zzwong/coned-cli/internal/securestore"
)

// Options contains values shared by all commands.
type Options struct {
	Profile    string
	JSON       bool
	Envelope   bool
	Timeout    time.Duration
	Demo       bool
	Account    string
	Meter      string
	selections map[string]config.Selection
}

// Dependencies configure the command services and the profile/configuration
// sources used by production and tests.
type Dependencies struct {
	Store            securestore.Store
	Authenticator    auth.Authenticator
	Clock            func() time.Time
	Prompter         auth.Prompter
	PasswordTerminal auth.PasswordTerminal
	Bills            BillService
	Opower           OpowerService
	Discovery        provider.Discovery
	DemoDiscovery    provider.Discovery
	// ConfigPath optionally selects a non-secret configuration file. The
	// production constructor supplies config.DefaultPath().
	ConfigPath      string
	Envelope        bool
	ExplainEnvelope bool
	envelope        *envelopeCapture
}

// NewRootCommand creates the root command with injectable terminal streams.
func NewRootCommand(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	return NewRootCommandWithDependencies(stdin, stdout, stderr, Dependencies{ConfigPath: config.DefaultPath()})
}

// NewRootCommandWithDependencies creates the root command using supplied services.
func NewRootCommandWithDependencies(stdin io.Reader, stdout, stderr io.Writer, deps Dependencies) *cobra.Command {
	input := bufio.NewReader(stdin)
	settings := config.Default()
	var configErr error
	if deps.ConfigPath != "" {
		settings, configErr = config.Load(deps.ConfigPath)
	}
	if deps.Store == nil {
		deps.Store = securestore.KeyringStore{}
	}
	if deps.Authenticator == nil || deps.Bills == nil {
		client, err := coned.NewClient(coned.Options{BaseURL: settings.BaseURL, Timeout: settings.RequestTimeout})
		if err != nil && configErr == nil {
			configErr = fmt.Errorf("invalid configured client: %w", err)
		}
		if err == nil {
			if deps.Authenticator == nil {
				deps.Authenticator = client
			}
			if deps.Bills == nil {
				deps.Bills = client
			}
		}
	}
	// A configuration error is reported by PersistentPreRunE before any
	// command accesses its dependencies. Keep safe defaults solely to satisfy
	// the command's dependency graph in that error path.
	if deps.Authenticator == nil {
		deps.Authenticator = coned.NewDefaultClient()
	}
	if deps.Bills == nil {
		deps.Bills = coned.NewDefaultClient()
	}
	if deps.Discovery == nil {
		if service, ok := any(deps.Bills).(provider.Discovery); ok {
			deps.Discovery = service
		}
	}
	if deps.DemoDiscovery == nil {
		deps.DemoDiscovery = &provider.Simulator{}
	}
	if deps.Opower == nil {
		if service, ok := any(deps.Bills).(OpowerService); ok {
			deps.Opower = service
		} else {
			deps.Opower = unavailableOpower{}
		}
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.Prompter == nil {
		deps.Prompter = auth.NewTerminalPrompter(input, stderr)
	}
	if deps.PasswordTerminal == nil {
		deps.PasswordTerminal = auth.SystemPasswordTerminal{}
	}

	options := Options{Profile: settings.Profile, JSON: deps.Envelope, Envelope: deps.Envelope, Timeout: settings.RequestTimeout, selections: settings.Selections}
	cmd := &cobra.Command{Use: "coned", Short: "Con Edison account command-line client", Args: cobra.NoArgs}
	if deps.Envelope || deps.ExplainEnvelope {
		cmd.Long = "Con Edison account command-line client. Add --json-envelope to request the versioned v1 JSON or authentication NDJSON contract."
	}
	cmd.PersistentPreRunE = func(run *cobra.Command, _ []string) error {
		if options.Envelope {
			options.JSON = true
		}
		if configErr != nil {
			return configErr
		}
		if options.Demo {
			path := run.CommandPath()
			if path != "coned bills sync" && !strings.Contains(path, " entities ") && !strings.Contains(path, " diagnostics ") && !strings.Contains(path, " usage ") && !strings.Contains(path, " accounts ") {
				return fmt.Errorf("demo mode supports only bills sync, entities, diagnostics, accounts, and usage commands")
			}
		}
		return nil
	}
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.PersistentFlags().StringVar(&options.Profile, "profile", options.Profile, "profile to use")
	cmd.PersistentFlags().BoolVar(&options.JSON, "json", false, "output JSON")
	cmd.PersistentFlags().DurationVar(&options.Timeout, "timeout", options.Timeout, "request timeout")
	cmd.PersistentFlags().BoolVar(&options.Demo, "demo", false, "use deterministic offline sample data")
	cmd.PersistentFlags().StringVar(&options.Account, "account", "", "account handle or alias")
	cmd.PersistentFlags().StringVar(&options.Meter, "meter", "", "meter handle or alias")
	cmd.AddCommand(newAuthCommand(&options, deps, input, stdin))
	cmd.AddCommand(newBillsCommand(&options, deps))
	cmd.AddCommand(newEntitiesCommand(&options, deps))
	cmd.AddCommand(newDiagnosticsCommand(&options, deps))
	cmd.AddCommand(newGreenButtonCommand(&options, deps))
	for _, opowerCommand := range newOpowerCommands(&options, deps) {
		cmd.AddCommand(opowerCommand)
	}
	cmd.AddCommand(newVersionCommand(&options.JSON))
	cmd.AddCommand(newCapabilitiesCommand())
	if deps.Envelope {
		installDefaultHelpAndCompletion(cmd)
		markArgumentValidation(cmd)
		cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return invalidArgument(err) })
	}
	return cmd
}

func installDefaultHelpAndCompletion(root *cobra.Command) {
	root.InitDefaultHelpFlag()
	root.InitDefaultHelpCmd()
	for _, child := range root.Commands() {
		if child.Name() == "help" {
			root.RemoveCommand(child)
			break
		}
	}
	root.AddCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			target, remaining, err := root.Find(args)
			if err != nil || target == root || len(remaining) != 0 {
				return invalidArgument(coned.ErrProtocolChanged)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return root.Help()
			}
			target, _, err := root.Find(args)
			if err != nil || target == root {
				return invalidArgument(coned.ErrProtocolChanged)
			}
			return target.Help()
		},
	})
	root.InitDefaultCompletionCmd()
}

func markArgumentValidation(command *cobra.Command) {
	if command.Args != nil {
		validate := command.Args
		command.Args = func(cmd *cobra.Command, args []string) error {
			if err := validate(cmd, args); err != nil {
				return invalidArgument(err)
			}
			return nil
		}
	}
	for _, child := range command.Commands() {
		markArgumentValidation(child)
	}
}
