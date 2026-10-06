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
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

type GreenButtonService interface {
	GreenButtonInspect(context.Context, auth.Session) (coned.GreenButtonMetadata, error)
	GreenButtonExport(context.Context, auth.Session, coned.GreenButtonOptions) (string, error)
}

func newGreenButtonCommand(options *Options, deps Dependencies) *cobra.Command {
	g := &cobra.Command{Use: "green-button", Short: "Inspect and export Green Button usage data", Args: cobra.NoArgs}
	inspect := &cobra.Command{Use: "inspect", Short: "Inspect available Green Button data", RunE: func(c *cobra.Command, _ []string) error { return greenInspect(c, options, deps, options.JSON) }}
	g.AddCommand(inspect)
	for _, download := range []bool{false, true} {
		var format, from, to, output string
		var force bool
		use := "export"
		short := "Export Green Button usage to standard output"
		if download {
			use = "download"
			short = "Download the original Green Button ZIP"
		}
		cmd := &cobra.Command{Use: use, Short: short, Args: func(c *cobra.Command, args []string) error {
			format = strings.ToLower(format)
			if err := cobra.NoArgs(c, args); err != nil {
				return err
			}
			if (download && format != "csv" && format != "xml") || (!download && format != "csv" && format != "xml" && format != "json") || !greenDate(from) || !greenDate(to) || (from == "") != (to == "") || (from != "" && from > to) {
				return invalidArgument(coned.ErrProtocolChanged)
			}
			return nil
		}, RunE: func(c *cobra.Command, _ []string) error {
			return greenExport(c, options, deps, format, from, to, output, force, download)
		}}
		cmd.Flags().StringVar(&format, "format", "csv", "csv, json (export only), or xml")
		cmd.Flags().StringVar(&from, "from", "", "start date (YYYY-MM-DD)")
		cmd.Flags().StringVar(&to, "to", "", "end date (YYYY-MM-DD)")
		if download {
			cmd.Flags().StringVarP(&output, "output", "o", "", "ZIP output path")
			cmd.Flags().BoolVar(&force, "force", false, "replace existing regular file")
		}
		g.AddCommand(cmd)
	}
	return g
}
func greenService(d Dependencies) (GreenButtonService, bool) {
	if x, ok := d.Opower.(GreenButtonService); ok {
		return x, true
	}
	x, ok := d.Bills.(GreenButtonService)
	return x, ok
}
func greenInspect(cmd *cobra.Command, o *Options, d Dependencies, jsonOutput bool) error {
	s, e := billingSession(d, o.Profile)
	if e != nil {
		return e
	}
	svc, ok := greenService(d)
	if !ok {
		return coned.ErrOpowerUnavailable
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), o.Timeout)
	defer cancel()
	v, e := svc.GreenButtonInspect(ctx, s)
	if e != nil {
		return safeGreenError(e)
	}
	if jsonOutput || o.JSON {
		b, err := json.Marshal(v)
		if err != nil {
			return coned.ErrProtocolChanged
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return err
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "customer class: %s\ntime zone: %s\nbill intervals: %d\nAMI intervals: %d\n", v.CustomerClass, v.TimeZone, len(v.BillIntervals), len(v.AMIIntervals))
	return err
}
func greenExport(cmd *cobra.Command, o *Options, d Dependencies, format, from, to, output string, force, download bool) error {
	format = strings.ToLower(format)
	if (download && (format != "csv" && format != "xml")) || (!download && format != "csv" && format != "xml" && format != "json") || !greenDate(from) || !greenDate(to) || (from == "") != (to == "") || (from != "" && from > to) {
		return invalidArgument(coned.ErrProtocolChanged)
	}
	s, e := billingSession(d, o.Profile)
	if e != nil {
		return e
	}
	svc, ok := greenService(d)
	if !ok {
		return coned.ErrOpowerUnavailable
	}
	providerFormat := format
	if format == "json" {
		providerFormat = "csv"
	}
	exportTimeout := o.Timeout
	if exportTimeout < 3*time.Minute {
		exportTimeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), exportTimeout)
	defer cancel()
	spool, e := svc.GreenButtonExport(ctx, s, coned.GreenButtonOptions{Format: providerFormat, From: from, To: to})
	if e != nil {
		return safeGreenError(e)
	}
	defer func() { _ = os.Remove(spool) }()
	if download {
		if output == "" {
			output = "green-button-usage.zip"
		}
		f, tmp, e := newOutputFile(output, force)
		if e != nil {
			return e
		}
		keep := false
		defer func() {
			if !keep {
				_ = f.Close()
				_ = os.Remove(tmp)
			}
		}()
		in, e := os.Open(spool)
		if e != nil {
			return outputFailedError()
		}
		hasher := sha256.New()
		count, e := io.Copy(io.MultiWriter(f, hasher), in)
		closeErr := in.Close()
		syncErr := f.Sync()
		fileCloseErr := f.Close()
		if e != nil || closeErr != nil || syncErr != nil || fileCloseErr != nil {
			return outputFailedError()
		}
		if publishErr := publishOutput(tmp, output, force); publishErr != nil {
			return publishErr
		}
		keep = true
		if o.Envelope {
			setEnvelopeData(d, envelopeFile{Path: output, Bytes: count, SHA256: hex.EncodeToString(hasher.Sum(nil)), Format: format})
			return nil
		}
		_, e = fmt.Fprintln(cmd.OutOrStdout(), output)
		return e
	}
	var content bytes.Buffer
	destination := cmd.OutOrStdout()
	if o.Envelope {
		destination = &content
	}
	if format == "json" {
		e = coned.GreenButtonCSVJSON(spool, destination)
	} else {
		e = coned.ExtractGreenButton(spool, format, destination)
	}
	if e != nil {
		return safeGreenError(e)
	}
	if o.Envelope {
		setEnvelopeData(d, map[string]any{"format": format, "content": content.String()})
	}
	return nil
}
func greenDate(s string) bool {
	if s == "" {
		return true
	}
	_, e := time.Parse("2006-01-02", s)
	return e == nil
}
func safeGreenError(e error) error {
	if e == nil {
		return nil
	}
	if transport, ok := coned.AsSafeTransportError(e); ok {
		return transport
	}
	for _, x := range []error{coned.ErrSessionExpired, coned.ErrProtocolChanged, coned.ErrGreenButtonUnavailable, coned.ErrOpowerUnavailable, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(e, x) {
			return x
		}
	}
	return internalBoundary(coned.ErrProtocolChanged)
}
