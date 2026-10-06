package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

const envelopeSchemaVersion = 1

var envelopeErrorCodes = []string{
	"invalid_argument", "selection_required", "session_expired", "mfa_required",
	"invalid_credentials", "storage_locked", "storage_access_denied", "storage_failed",
	"transport_failed", "timeout", "canceled", "provider_protocol_changed", "bill_not_found",
	"output_conflict", "output_failed", "unsupported_platform", "internal_error",
}

var envelopeCommandIDs = []string{
	"accounts", "accounts.list", "auth", "auth.import-browser", "auth.init", "auth.login", "auth.logout", "auth.status",
	"bills", "bills.download", "bills.list", "bills.sync", "capabilities", "completion", "completion.bash", "completion.fish",
	"completion.powershell", "completion.zsh", "coned", "diagnostics", "diagnostics.inspect", "diagnostics.schema",
	"entities", "entities.alias", "entities.list", "entities.select", "green-button", "green-button.download", "green-button.export",
	"green-button.inspect", "help", "usage", "usage.bills", "usage.costs", "usage.export", "usage.forecast",
	"usage.meters", "usage.neighbors", "usage.reads", "usage.realtime", "usage.summary", "usage.weather", "version",
}

func availableEnvelopeCommandIDs() []string {
	if billSyncPlatformSupported() {
		return append([]string(nil), envelopeCommandIDs...)
	}
	commands := make([]string, 0, len(envelopeCommandIDs)-1)
	for _, command := range envelopeCommandIDs {
		if command != "bills.sync" {
			commands = append(commands, command)
		}
	}
	return commands
}

// Dependencies keeps optional implementation details out of the exported
// command constructors while allowing the production wrapper to collect a
// typed result from handlers that do not already write structured JSON.
type envelopeCapture struct {
	data any
	set  bool
}

type envelopeFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Format string `json:"format,omitempty"`
}

type errorClass struct {
	legacy error
	code   string
}

func (e *errorClass) Error() string { return e.legacy.Error() }
func (e *errorClass) Unwrap() error { return e.legacy }
func (e *errorClass) Is(target error) bool {
	if target == ErrInvalidArgument && e.code == "invalid_argument" || target == ErrOutputConflict && e.code == "output_conflict" || target == ErrOutputFailed && e.code == "output_failed" || target == ErrUnsupportedPlatform && e.code == "unsupported_platform" {
		return true
	}
	return errors.Is(e.legacy, target)
}

// ErrInvalidArgument marks locally validated command inputs without changing
// the legacy safe error visible to callers of NewRootCommand.Execute.
var ErrInvalidArgument = errors.New("invalid argument")
var ErrOutputConflict = errors.New("output already exists or conflicts")
var ErrOutputFailed = errors.New("output could not be written")
var ErrUnsupportedPlatform = errors.New("operation is not supported on this platform")

func invalidArgument(legacy error) error {
	if legacy == nil {
		legacy = ErrInvalidArgument
	}
	return &errorClass{legacy: legacy, code: "invalid_argument"}
}

func outputConflictError() error {
	return &errorClass{legacy: coned.ErrProtocolChanged, code: "output_conflict"}
}

func outputFailedError() error {
	return &errorClass{legacy: coned.ErrProtocolChanged, code: "output_failed"}
}

func unsupportedPlatformError() error {
	return &errorClass{legacy: ErrUnsupportedPlatform, code: "unsupported_platform"}
}

func internalBoundary(legacy error) error {
	return &errorClass{legacy: legacy, code: "internal_error"}
}

func setEnvelopeData(deps Dependencies, value any) {
	if deps.envelope == nil {
		return
	}
	deps.envelope.data = value
	deps.envelope.set = true
}

type envelopeError struct {
	Code          string              `json:"code"`
	Retryable     bool                `json:"retryable"`
	HTTPStatus    *int                `json:"http_status,omitempty"`
	TransportKind coned.TransportKind `json:"transport_kind,omitempty"`
}

type oneShotEnvelope struct {
	SchemaVersion int            `json:"schema_version"`
	Command       string         `json:"command"`
	OK            bool           `json:"ok"`
	CapturedAt    string         `json:"captured_at"`
	Data          any            `json:"data,omitempty"`
	Error         *envelopeError `json:"error,omitempty"`
}

type authStreamEvent struct {
	SchemaVersion int            `json:"schema_version"`
	Command       string         `json:"command"`
	Event         string         `json:"event"`
	OK            *bool          `json:"ok,omitempty"`
	Error         *envelopeError `json:"error,omitempty"`
}

type mappedError struct {
	value   envelopeError
	arg     bool
	data    any
	hasData bool
}

// ExecuteCLI is the production entry point. NewRootCommand.Execute remains a
// legacy-compatible API; only invocations opting into --json-envelope use the
// versioned renderer and error contract.
func ExecuteCLI(args []string, stdin io.Reader, stdout, stderr io.Writer, deps Dependencies) int {
	cleanArgs, enabled, invalidSwitch := envelopeArguments(args)
	if isCapabilitiesInvocation(cleanArgs) {
		return executeCapabilities(cleanArgs, stdin, stdout, stderr, deps, enabled, invalidSwitch)
	}
	if !enabled && !invalidSwitch {
		deps.ExplainEnvelope = true
		cmd := NewRootCommandWithDependencies(stdin, stdout, stderr, deps)
		cmd.SetArgs(cleanArgs)
		if err := cmd.Execute(); err != nil {
			return 1
		}
		return 0
	}
	if invalidSwitch {
		return writeEnvelopeFailure(stdout, "coned", mappedError{value: envelopeError{Code: "invalid_argument"}, arg: true}, deps)
	}

	capture := &envelopeCapture{}
	deps.Envelope = true
	deps.envelope = capture
	var buffered bytes.Buffer
	cmd := NewRootCommandWithDependencies(stdin, &buffered, stderr, deps)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs(cleanArgs)
	selected, remaining, findErr := cmd.Find(cleanArgs)
	if hasUnknownSubcommand(selected, remaining) {
		return writeEnvelopeFailure(stdout, "coned", mappedError{value: envelopeError{Code: "invalid_argument"}, arg: true}, deps)
	}
	streamAuth := isAuthStreamCommand(selected) && !helpRequested(cleanArgs)
	if streamAuth {
		cmd.SetOut(stdout)
	}
	err := cmd.Execute()
	commandID := commandID(selected)
	if err == nil {
		if streamAuth {
			return 0
		}
		if helpRequested(cleanArgs) {
			return writeEnvelopeSuccess(stdout, commandID, map[string]any{"text": strings.TrimSpace(buffered.String())}, deps)
		}
		data, dataErr := envelopeData(commandID, cleanArgs, capture, buffered.Bytes())
		if dataErr != nil {
			return writeEnvelopeFailure(stdout, commandID, mappedError{value: envelopeError{Code: "internal_error"}}, deps)
		}
		return writeEnvelopeSuccess(stdout, commandID, data, deps)
	}
	if streamAuth {
		mapped := mapEnvelopeError(err, findErr != nil)
		return writeAuthFailure(stdout, commandID, mapped.value, deps, mapped.arg)
	}
	mapped := mapEnvelopeError(err, findErr != nil)
	return writeEnvelopeFailure(stdout, commandID, mapped, deps)
}

func envelopeArguments(args []string) (clean []string, enabled bool, invalid bool) {
	clean = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			clean = append(clean, args[i:]...)
			break
		}
		flagName, _, hasEquals := strings.Cut(arg, "=")
		if !hasEquals && takesFlagValue(flagName) {
			clean = append(clean, arg)
			if i+1 < len(args) && args[i+1] != "--" {
				clean = append(clean, args[i+1])
				i++
			}
			continue
		}
		if arg == "--json-envelope" {
			enabled = true
			continue
		}
		if strings.HasPrefix(arg, "--json-envelope=") {
			value := strings.TrimPrefix(arg, "--json-envelope=")
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				enabled = true
				invalid = true
			} else {
				enabled = parsed
			}
			continue
		}
		clean = append(clean, arg)
	}
	return clean, enabled, invalid
}

func takesFlagValue(name string) bool {
	switch name {
	case "--profile", "--timeout", "--account", "--meter", "--output", "-o", "--format", "--from", "--to", "--aggregate", "--endpoint", "--type":
		return true
	default:
		return false
	}
}

func isCapabilitiesInvocation(args []string) bool {
	commandIndex := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "-") {
			name, _, found := strings.Cut(arg, "=")
			switch name {
			case "--profile", "--timeout", "--account", "--meter":
				if !found && i+1 < len(args) {
					i++
				}
			}
			continue
		}
		if commandIndex == 0 {
			return arg == "capabilities"
		}
		commandIndex++
	}
	return false
}

func executeCapabilities(args []string, stdin io.Reader, stdout, stderr io.Writer, deps Dependencies, envelope bool, invalidSwitch bool) int {
	if invalidSwitch {
		return writeEnvelopeFailure(stdout, "capabilities", mappedError{value: envelopeError{Code: "invalid_argument"}, arg: true}, deps)
	}
	var buffered bytes.Buffer
	commandOut := stdout
	if envelope {
		commandOut = &buffered
	}
	cmd := newOfflineCapabilitiesCommand(stdin, commandOut, stderr)
	cmd.SilenceErrors = envelope
	cmd.SilenceUsage = envelope
	clean := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--json-envelope" || strings.HasPrefix(arg, "--json-envelope=") {
			continue
		}
		clean = append(clean, arg)
	}
	cmd.SetArgs(clean)
	selected, remaining, findErr := cmd.Find(clean)
	if envelope && hasUnknownSubcommand(selected, remaining) {
		return writeEnvelopeFailure(stdout, "capabilities", mappedError{value: envelopeError{Code: "invalid_argument"}, arg: true}, deps)
	}
	err := cmd.Execute()
	if !envelope {
		if err != nil {
			return 1
		}
		return 0
	}
	command := commandID(selected)
	if err != nil {
		mapped := mapEnvelopeError(err, findErr != nil)
		return writeEnvelopeFailure(stdout, command, mapped, deps)
	}
	if selected != nil && selected.Name() != "capabilities" || helpRequested(clean) {
		return writeEnvelopeSuccess(stdout, command, map[string]any{"text": strings.TrimSpace(buffered.String())}, deps)
	}
	var data any
	if err := json.Unmarshal(bytes.TrimSpace(buffered.Bytes()), &data); err != nil {
		return writeEnvelopeFailure(stdout, command, mappedError{value: envelopeError{Code: "internal_error"}}, deps)
	}
	return writeEnvelopeSuccess(stdout, command, data, deps)
}

func newOfflineCapabilitiesCommand(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "coned", Short: "Con Edison account command-line client", Long: "Add --json-envelope to request the versioned v1 JSON or authentication NDJSON contract.", SilenceErrors: true, SilenceUsage: true, Args: cobra.NoArgs}
	var profile, account, meter string
	var timeout time.Duration
	var jsonOutput, demo bool
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVar(&profile, "profile", "default", "profile to use")
	root.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output JSON")
	root.PersistentFlags().BoolVar(&demo, "demo", false, "use deterministic offline sample data")
	root.PersistentFlags().StringVar(&account, "account", "", "account handle or alias")
	root.PersistentFlags().StringVar(&meter, "meter", "", "meter handle or alias")
	capabilities := &cobra.Command{Use: "capabilities", Short: "Describe supported automation contracts", Long: "Add --json-envelope to return the capabilities document inside the v1 envelope.", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return writeJSON(cmd.OutOrStdout(), map[string]any{
			"schema_versions": []int{envelopeSchemaVersion},
			"commands":        availableEnvelopeCommandIDs(),
			"error_codes":     envelopeErrorCodes,
		})
	}}
	root.AddCommand(capabilities)
	installDefaultHelpAndCompletion(root)
	markArgumentValidation(root)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return invalidArgument(err) })
	return root
}

func hasUnknownSubcommand(selected *cobra.Command, args []string) bool {
	if selected == nil || !selected.HasSubCommands() {
		return false
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return i+1 < len(args)
		}
		if strings.HasPrefix(arg, "-") {
			name, _, hasValue := strings.Cut(arg, "=")
			if !hasValue && takesFlagValue(name) && i+1 < len(args) {
				i++
			}
			continue
		}
		return true
	}
	return false
}

func newCapabilitiesCommand() *cobra.Command {
	return &cobra.Command{Use: "capabilities", Short: "Describe supported automation contracts", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return writeJSON(cmd.OutOrStdout(), map[string]any{
			"schema_versions": []int{envelopeSchemaVersion},
			"commands":        availableEnvelopeCommandIDs(),
			"error_codes":     envelopeErrorCodes,
		})
	}}
}

func isAuthStreamCommand(cmd *cobra.Command) bool {
	if cmd == nil || cmd.Parent() == nil || cmd.Parent().Name() != "auth" {
		return false
	}
	return cmd.Name() == "login" || cmd.Name() == "init"
}

func commandID(cmd *cobra.Command) string {
	if cmd == nil {
		return "coned"
	}
	parts := strings.Fields(cmd.CommandPath())
	if len(parts) <= 1 {
		return "coned"
	}
	return strings.Join(parts[1:], ".")
}

func envelopeData(command string, args []string, capture *envelopeCapture, output []byte) (any, error) {
	if capture != nil && capture.set {
		return capture.data, nil
	}
	if command == "green-button.export" {
		format := flagValue(args, "--format", "csv")
		return map[string]any{"format": strings.ToLower(format), "content": string(output)}, nil
	}
	if envelopeJSONCommand(command) {
		var result any
		if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
			return nil, err
		}
		return result, nil
	}
	if len(bytes.TrimSpace(output)) == 0 {
		return map[string]any{"status": "completed"}, nil
	}
	if command == "help" || strings.HasPrefix(command, "completion") || isCommandGroup(command) {
		return map[string]any{"text": strings.TrimSpace(string(output))}, nil
	}
	return nil, errors.New("command produced unexpected non-JSON output")
}

func isCommandGroup(command string) bool {
	switch command {
	case "coned", "auth", "bills", "entities", "diagnostics", "green-button", "accounts", "usage":
		return true
	default:
		return false
	}
}

func envelopeJSONCommand(command string) bool {
	switch command {
	case "auth.status", "bills.list", "diagnostics.inspect", "diagnostics.schema", "entities.list", "green-button.inspect", "version",
		"accounts.list", "usage.bills", "usage.weather", "usage.neighbors", "usage.meters", "usage.realtime", "usage.summary":
		return true
	default:
		return false
	}
}

func flagValue(args []string, name, fallback string) string {
	for i := 0; i < len(args); i++ {
		if value, ok := strings.CutPrefix(args[i], name+"="); ok {
			return value
		}
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return fallback
}

func helpRequested(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return false
		}
		if !strings.Contains(arg, "=") && takesFlagValue(arg) {
			if i+1 < len(args) {
				i++
			}
			continue
		}
		if arg == "--help" || arg == "-h" {
			return true
		}
		if value, ok := strings.CutPrefix(arg, "--help="); ok {
			parsed, err := strconv.ParseBool(value)
			return err != nil || parsed
		}
	}
	return false
}

func mapEnvelopeError(err error, argument bool) mappedError {
	var partial *billSyncFailure
	if errors.As(err, &partial) && partial != nil {
		mapped := mapEnvelopeError(partial.cause, argument)
		mapped.data = partial.manifest
		mapped.hasData = true
		return mapped
	}
	var classified *errorClass
	if errors.As(err, &classified) && classified != nil {
		return mappedError{value: envelopeError{Code: classified.code}, arg: classified.code == "invalid_argument"}
	}
	if errors.Is(err, context.Canceled) {
		return mappedError{value: envelopeError{Code: "canceled"}}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return mappedError{value: envelopeError{Code: "timeout", Retryable: true}}
	}
	if transport, ok := coned.AsSafeTransportError(err); ok {
		code := "transport_failed"
		if transport.Kind == coned.TransportTimeout {
			code = "timeout"
		}
		return mappedError{value: envelopeError{Code: code, Retryable: transport.Retryable, TransportKind: transport.Kind}}
	}
	if protocol, ok := coned.AsSafeProtocolError(err); ok {
		status := protocol.Status
		return mappedError{value: envelopeError{Code: "provider_protocol_changed", HTTPStatus: &status}}
	}
	for _, item := range []struct {
		err  error
		code string
	}{
		{ErrInvalidArgument, "invalid_argument"},
		{coned.ErrSelectionRequired, "selection_required"},
		{coned.ErrSessionExpired, "session_expired"},
		{coned.ErrMFARequired, "mfa_required"},
		{coned.ErrChallengeRequired, "mfa_required"},
		{coned.ErrInvalidCredentials, "invalid_credentials"},
		{auth.ErrInvalidCredentials, "invalid_credentials"},
		{auth.ErrInvalidSession, "session_expired"},
		{auth.ErrPromptFailed, "invalid_argument"},
		{auth.ErrPasswordInputNotTerminal, "invalid_argument"},
		{auth.ErrInvalidPasswordStdin, "invalid_argument"},
		{auth.ErrPasswordReadFailed, "invalid_argument"},
		{auth.ErrStorageLocked, "storage_locked"},
		{auth.ErrStorageAccessDenied, "storage_access_denied"},
		{auth.ErrStorageFailed, "storage_failed"},
		{coned.ErrBillNotFound, "bill_not_found"},
		{ErrOutputConflict, "output_conflict"},
		{ErrOutputFailed, "output_failed"},
		{coned.ErrProtocolChanged, "provider_protocol_changed"},
	} {
		if errors.Is(err, item.err) {
			return mappedError{value: envelopeError{Code: item.code}, arg: item.code == "invalid_argument"}
		}
	}
	if argument {
		return mappedError{value: envelopeError{Code: "invalid_argument"}, arg: true}
	}
	return mappedError{value: envelopeError{Code: "internal_error"}}
}

func writeEnvelopeSuccess(w io.Writer, command string, data any, deps Dependencies) int {
	result := oneShotEnvelope{SchemaVersion: envelopeSchemaVersion, Command: command, OK: true, CapturedAt: envelopeNow(deps), Data: data}
	payload, err := json.Marshal(result)
	if err != nil {
		return writeEnvelopeFailure(w, command, mappedError{value: envelopeError{Code: "internal_error"}}, deps)
	}
	if _, err := fmt.Fprintln(w, string(payload)); err != nil {
		return 1
	}
	return 0
}

func writeEnvelopeFailure(w io.Writer, command string, mapped mappedError, deps Dependencies) int {
	result := oneShotEnvelope{SchemaVersion: envelopeSchemaVersion, Command: command, OK: false, CapturedAt: envelopeNow(deps), Error: &mapped.value}
	if mapped.hasData {
		result.Data = mapped.data
	}
	status := 1
	if mapped.arg {
		status = 2
	}
	if writeJSONResult(w, result) != 0 {
		return 1
	}
	return status
}

func writeAuthFailure(w io.Writer, command string, failure envelopeError, deps Dependencies, argument bool) int {
	ok := false
	result := authStreamEvent{SchemaVersion: envelopeSchemaVersion, Command: command, Event: "failure", OK: &ok, Error: &failure}
	if writeJSONResult(w, result) != 0 {
		return 1
	}
	if argument {
		return 2
	}
	return 1
}

func writeJSONResult(w io.Writer, value any) int {
	data, err := json.Marshal(value)
	if err != nil {
		return 1
	}
	if _, err := fmt.Fprintln(w, string(data)); err != nil {
		return 1
	}
	return 0
}

func envelopeNow(deps Dependencies) string {
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	return clock().UTC().Format("2006-01-02T15:04:05.999999999-07:00")
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
