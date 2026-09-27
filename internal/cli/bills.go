package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/securestore"
)

// BillService is the narrow, injectable billing boundary used by the CLI.
type BillService interface {
	ListBills(context.Context, auth.Session) ([]coned.Bill, error)
	DownloadBill(context.Context, auth.Session, string, io.Writer) error
}

func newBillsCommand(options *Options, deps Dependencies) *cobra.Command {
	bills := &cobra.Command{Use: "bills", Short: "List and download bills", Args: cobra.NoArgs}
	bills.AddCommand(&cobra.Command{Use: "list", Short: "List bills", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return listBills(cmd, options, deps)
	}})
	var output string
	var force bool
	download := &cobra.Command{Use: "download <bill-id>", Short: "Download a bill PDF", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return downloadBill(cmd, options, deps, args[0], output, force)
	}}
	download.Flags().StringVarP(&output, "output", "o", "", "PDF output path")
	download.Flags().BoolVar(&force, "force", false, "replace an existing regular file")
	bills.AddCommand(download)
	return bills
}

func billingSession(deps Dependencies, profile string) (auth.Session, error) {
	session, err := auth.LoadSession(deps.Store, profile)
	if err != nil {
		if errors.Is(err, securestore.ErrNotFound) || errors.Is(err, auth.ErrInvalidSession) {
			return auth.Session{}, coned.ErrSessionExpired
		}
		return auth.Session{}, auth.StorageError(err)
	}
	if session.State(deps.Clock()) != auth.SessionValid {
		return auth.Session{}, coned.ErrSessionExpired
	}
	return session, nil
}

func listBills(cmd *cobra.Command, options *Options, deps Dependencies) error {
	session, err := billingSession(deps, options.Profile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
	defer cancel()
	bills, err := deps.Bills.ListBills(ctx, session)
	if err != nil {
		return safeBillError(err)
	}
	sort.SliceStable(bills, func(i, j int) bool { return bills[i].Date > bills[j].Date })
	if options.JSON {
		data, err := json.Marshal(bills)
		if err != nil {
			return coned.ErrProtocolChanged
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}
	if _, err = fmt.Fprintln(cmd.OutOrStdout(), "ID\tDATE\tCYCLE\tTYPE"); err != nil {
		return err
	}
	for _, bill := range bills {
		if _, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", bill.ID, bill.Date, sanitizeTableCell(bill.Cycle), sanitizeTableCell(bill.DocumentType)); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeTableCell prevents untrusted provider values from changing the table
// layout or terminal state. JSON output intentionally retains original values.
func sanitizeTableCell(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}

func downloadBill(cmd *cobra.Command, options *Options, deps Dependencies, id, output string, force bool) error {
	session, err := billingSession(deps, options.Profile)
	if err != nil {
		return err
	}
	date, ok := billDateFromID(id)
	if !ok {
		return coned.ErrProtocolChanged
	}
	if output == "" {
		output = "coned-bill-" + date + ".pdf"
	}
	file, temp, err := newOutputFile(output, force)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = file.Close()
			_ = os.Remove(temp)
		}
	}()
	ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
	err = deps.Bills.DownloadBill(ctx, session, id, file)
	cancel()
	if err != nil {
		return safeBillError(err)
	}
	if err := file.Sync(); err != nil {
		return coned.ErrProtocolChanged
	}
	if err := file.Close(); err != nil {
		return coned.ErrProtocolChanged
	}
	if err := publishOutput(temp, output, force); err != nil {
		return coned.ErrProtocolChanged
	}
	keep = true
	_, err = fmt.Fprintln(cmd.OutOrStdout(), output)
	return err
}

func billDateFromID(id string) (string, bool) {
	return coned.BillIDDate(id)
}

// publishOutput atomically publishes a closed temporary file. Hard-linking
// gives the non-force path no-replace semantics even if another process
// creates the destination after its initial preflight check.
func publishOutput(temp, output string, force bool) error {
	if force {
		return os.Rename(temp, output)
	}
	if err := os.Link(temp, output); err != nil {
		return err
	}
	return os.Remove(temp)
}

func newOutputFile(output string, force bool) (*os.File, string, error) {
	info, err := os.Lstat(output)
	if err == nil {
		if info.IsDir() || !info.Mode().IsRegular() || !force {
			return nil, "", coned.ErrProtocolChanged
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", coned.ErrProtocolChanged
	}
	directory := filepath.Dir(output)
	file, err := os.CreateTemp(directory, ".coned-bill-*")
	if err != nil {
		return nil, "", coned.ErrProtocolChanged
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, "", coned.ErrProtocolChanged
	}
	return file, file.Name(), nil
}

func safeBillError(err error) error {
	// The concrete client constructs BillDownloadError only from validated
	// public IDs and its Error method reduces causes to safe categories.
	var downloadErr *coned.BillDownloadError
	if errors.As(err, &downloadErr) {
		return downloadErr
	}
	if protocol, ok := coned.AsSafeProtocolError(err); ok {
		// Bill-facing errors retain only the safe HTTP status, never a
		// request ID intended for authentication diagnostics.
		return &coned.ProtocolError{Status: protocol.Status}
	}
	for _, safe := range []error{coned.ErrSessionExpired, coned.ErrBillNotFound, coned.ErrProtocolChanged, auth.ErrStorageAccessDenied, auth.ErrStorageFailed, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return coned.ErrProtocolChanged
}
