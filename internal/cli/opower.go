package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

// OpowerService is the narrow, injectable read-only boundary implemented by coned.Client.
type OpowerService interface {
	Fetch(context.Context, auth.Session, string) (any, error)
}
type SelectedOpowerService interface {
	FetchSelected(context.Context, auth.Session, string, coned.EntitySelection) (any, error)
}
type UsageQueryService interface {
	Forecast(context.Context, auth.Session) ([]coned.Forecast, error)
	HistoricalReads(context.Context, auth.Session, coned.ReadOptions) ([]coned.HistoricalRead, error)
	HistoricalCosts(context.Context, auth.Session, coned.ReadOptions) ([]coned.CostRead, error)
}
type unavailableOpower struct{}

func (unavailableOpower) Fetch(context.Context, auth.Session, string) (any, error) {
	return nil, coned.ErrProtocolChanged
}
func (unavailableOpower) Forecast(context.Context, auth.Session) ([]coned.Forecast, error) {
	return nil, coned.ErrProtocolChanged
}
func (unavailableOpower) HistoricalReads(context.Context, auth.Session, coned.ReadOptions) ([]coned.HistoricalRead, error) {
	return nil, coned.ErrProtocolChanged
}
func (unavailableOpower) HistoricalCosts(context.Context, auth.Session, coned.ReadOptions) ([]coned.CostRead, error) {
	return nil, coned.ErrProtocolChanged
}

func newOpowerCommands(options *Options, deps Dependencies) []*cobra.Command {
	accounts := &cobra.Command{Use: "accounts", Short: "Manage Opower accounts", Args: cobra.NoArgs}
	accounts.AddCommand(opowerDataCommand("list", "List accounts", "accounts", options, deps))

	usage := &cobra.Command{Use: "usage", Short: "View energy usage", Args: cobra.NoArgs}
	for _, item := range []struct{ name, resource string }{
		{"bills", "usage-bills"}, {"weather", "weather"}, {"neighbors", "neighbors"},
		{"meters", "meters"}, {"realtime", "realtime"}, {"summary", "summary"},
	} {
		usage.AddCommand(opowerDataCommand(item.name, "Show "+item.name, item.resource, options, deps))
	}
	var format, output string
	var force bool
	export := &cobra.Command{Use: "export", Short: "Export usage data", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runOpowerExport(cmd, options, deps, format, output, force)
	}}
	export.Flags().StringVar(&format, "format", "json", "export format (csv or json)")
	export.Flags().StringVarP(&output, "output", "o", "", "output path (default: stdout)")
	export.Flags().BoolVar(&force, "force", false, "replace an existing regular file")
	usage.AddCommand(export)
	usage.AddCommand(usageForecastCommand(options, deps))
	usage.AddCommand(usageHistoryCommand("reads", false, options, deps))
	usage.AddCommand(usageHistoryCommand("costs", true, options, deps))
	return []*cobra.Command{accounts, usage}
}

func usageForecastCommand(options *Options, deps Dependencies) *cobra.Command {
	return &cobra.Command{Use: "forecast", Short: "Show current bill usage and cost forecast", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if !options.Demo && (options.Account != "" || options.Meter != "") {
			return coned.ErrSelectionRequired
		}
		var source any = deps.Opower
		if options.Demo {
			source = demoOpower{}
		}
		service, ok := source.(UsageQueryService)
		if !ok {
			return coned.ErrProtocolChanged
		}
		var session auth.Session
		var err error
		if !options.Demo {
			session, err = billingSession(deps, options.Profile)
			if err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
		defer cancel()
		value, err := service.Forecast(ctx, session)
		if err != nil {
			return safeOpowerError(err)
		}
		if options.JSON {
			return writeJSON(cmd.OutOrStdout(), value)
		}
		return writeTable(cmd.OutOrStdout(), value)
	}}
}

func usageHistoryCommand(name string, costs bool, options *Options, deps Dependencies) *cobra.Command {
	var aggregate, from, to string
	short := "Show historical usage"
	if costs {
		short += " and costs"
	}
	command := &cobra.Command{Use: name, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if !options.Demo && (options.Account != "" || options.Meter != "") {
			return coned.ErrSelectionRequired
		}
		aggregate = strings.ToLower(strings.TrimSpace(aggregate))
		if !validReadFlags(aggregate, from, to) {
			return coned.ErrProtocolChanged
		}
		var source any = deps.Opower
		if options.Demo {
			source = demoOpower{}
		}
		service, ok := source.(UsageQueryService)
		if !ok {
			return coned.ErrProtocolChanged
		}
		var session auth.Session
		var err error
		if !options.Demo {
			session, err = billingSession(deps, options.Profile)
			if err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
		defer cancel()
		query := coned.ReadOptions{Aggregate: aggregate, From: from, To: to}
		var value any
		if costs {
			value, err = service.HistoricalCosts(ctx, session, query)
		} else {
			value, err = service.HistoricalReads(ctx, session, query)
		}
		if err != nil {
			return safeOpowerError(err)
		}
		if options.JSON {
			return writeJSON(cmd.OutOrStdout(), value)
		}
		return writeTable(cmd.OutOrStdout(), value)
	}}
	command.Flags().StringVar(&aggregate, "aggregate", "bill", "aggregation: bill, day, or hour")
	command.Flags().StringVar(&from, "from", "", "start date (YYYY-MM-DD)")
	command.Flags().StringVar(&to, "to", "", "end date (YYYY-MM-DD)")
	return command
}

func validReadFlags(aggregate, from, to string) bool {
	if aggregate != "bill" && aggregate != "day" && aggregate != "hour" {
		return false
	}
	if from == "" && to == "" {
		return aggregate == "bill"
	}
	if from == "" || to == "" {
		return false
	}
	start, err1 := time.Parse("2006-01-02", from)
	end, err2 := time.Parse("2006-01-02", to)
	return err1 == nil && err2 == nil && !end.Before(start)
}

func opowerDataCommand(name, short, resource string, options *Options, deps Dependencies) *cobra.Command {
	return &cobra.Command{Use: name, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return runOpowerData(cmd, options, deps, resource)
	}}
}

func runOpowerData(cmd *cobra.Command, options *Options, deps Dependencies, resource string) error {
	value, err := fetchOpower(cmd, options, deps, resource)
	if err != nil {
		return safeOpowerError(err)
	}
	if options.JSON {
		return writeJSON(cmd.OutOrStdout(), value)
	}
	return writeTable(cmd.OutOrStdout(), value)
}

func fetchOpower(cmd *cobra.Command, options *Options, deps Dependencies, resource string) (any, error) {
	service := deps.Opower
	var session auth.Session
	var err error
	if options.Demo {
		service = demoOpower{}
	} else {
		session, err = billingSession(deps, options.Profile)
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
	defer cancel()
	selection := coned.EntitySelection{}
	if !options.Demo {
		selection, err = resolveEntitySelection(ctx, options, deps, session)
		if err != nil {
			return nil, err
		}
	}
	if selected, ok := service.(SelectedOpowerService); ok {
		return selected.FetchSelected(ctx, session, resource, selection)
	}
	if selection.Account != "" || selection.Meter != "" {
		return nil, coned.ErrSelectionRequired
	}
	return service.Fetch(ctx, session, resource)
}

func runOpowerExport(cmd *cobra.Command, options *Options, deps Dependencies, format, output string, force bool) error {
	format = strings.ToLower(format)
	if format != "csv" && format != "json" {
		return coned.ErrProtocolChanged
	}
	value, err := fetchOpower(cmd, options, deps, "export")
	if err != nil {
		return safeOpowerError(err)
	}
	var data []byte
	if format == "json" {
		data, err = json.Marshal(value)
		if err == nil {
			data = append(data, '\n')
		}
	} else {
		var b strings.Builder
		err = writeCSV(&b, value)
		data = []byte(b.String())
	}
	if err != nil {
		return coned.ErrProtocolChanged
	}
	if output == "" {
		_, err = cmd.OutOrStdout().Write(data)
		return err
	}
	file, temp, err := newOutputFileWithPrefix(output, force, ".coned-opower-*")
	if err != nil {
		return coned.ErrProtocolChanged
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
			_ = os.Remove(temp)
		}
	}()
	if _, err = file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil {
		return coned.ErrProtocolChanged
	}
	if err = publishOutput(temp, output, force); err != nil {
		return coned.ErrProtocolChanged
	}
	keep = true
	return nil
}

func writeJSON(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return coned.ErrProtocolChanged
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func writeTable(w io.Writer, value any) error {
	rows := records(value)
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "(no data)")
		return err
	}
	keys := map[string]bool{}
	for _, row := range rows {
		for key := range row {
			keys[key] = true
		}
	}
	header := make([]string, 0, len(keys))
	for key := range keys {
		header = append(header, key)
	}
	sort.Strings(header)
	if _, err := fmt.Fprintln(w, strings.Join(header, "\t")); err != nil {
		return err
	}
	for _, row := range rows {
		cells := make([]string, len(header))
		for i, key := range header {
			cells[i] = sanitizeTableCell(fmt.Sprint(row[key]))
		}
		if _, err := fmt.Fprintln(w, strings.Join(cells, "\t")); err != nil {
			return err
		}
	}
	return nil
}

func writeCSV(w io.Writer, value any) error {
	rows := records(value)
	if len(rows) == 0 {
		return nil
	}
	keys := map[string]bool{}
	for _, row := range rows {
		for key := range row {
			keys[key] = true
		}
	}
	header := make([]string, 0, len(keys))
	for key := range keys {
		header = append(header, key)
	}
	sort.Strings(header)
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		record := make([]string, len(header))
		for i, key := range header {
			record[i] = fmt.Sprint(row[key])
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func records(value any) []map[string]any {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var raw any
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	if list, ok := raw.([]any); ok {
		out := make([]map[string]any, 0, len(list))
		for _, item := range list {
			if row, ok := item.(map[string]any); ok {
				out = append(out, flattenRecord(row))
			} else {
				out = append(out, map[string]any{"value": item})
			}
		}
		return out
	}
	if row, ok := raw.(map[string]any); ok {
		return []map[string]any{flattenRecord(row)}
	}
	return []map[string]any{{"value": raw}}
}

func flattenRecord(row map[string]any) map[string]any {
	out := make(map[string]any)
	var walk func(string, any)
	walk = func(prefix string, value any) {
		if nested, ok := value.(map[string]any); ok {
			for key, child := range nested {
				name := key
				if prefix != "" {
					name = prefix + "_" + key
				}
				walk(name, child)
			}
			return
		}
		out[prefix] = value
	}
	for key, value := range row {
		walk(key, value)
	}
	return out
}

func safeOpowerError(err error) error {
	if transport, ok := coned.AsSafeTransportError(err); ok {
		return transport
	}
	for _, safe := range []error{coned.ErrSessionExpired, coned.ErrRealtimeUnavailable, coned.ErrSelectionRequired, coned.ErrProtocolChanged, auth.ErrStorageLocked, auth.ErrStorageAccessDenied, auth.ErrStorageFailed, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	if protocol, ok := coned.AsSafeProtocolError(err); ok {
		return &coned.ProtocolError{Status: protocol.Status}
	}
	return coned.ErrProtocolChanged
}

// newOutputFileWithPrefix mirrors the bills atomic writer without changing the
// existing bill command's behavior.
func newOutputFileWithPrefix(output string, force bool, prefix string) (*os.File, string, error) {
	info, err := os.Lstat(output)
	if err == nil {
		if info.IsDir() || !info.Mode().IsRegular() || !force {
			return nil, "", coned.ErrProtocolChanged
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", coned.ErrProtocolChanged
	}
	file, err := os.CreateTemp(filepath.Dir(output), prefix)
	if err != nil {
		return nil, "", err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, "", err
	}
	return file, file.Name(), nil
}
