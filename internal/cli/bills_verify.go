package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

type billVerifyResult struct {
	BillID         string `json:"bill_id"`
	Date           string `json:"date"`
	Filename       string `json:"filename"`
	Status         string `json:"status"`
	LocalBytes     int64  `json:"local_bytes,omitempty"`
	LocalSHA256    string `json:"local_sha256,omitempty"`
	ProviderBytes  int64  `json:"provider_bytes,omitempty"`
	ProviderSHA256 string `json:"provider_sha256,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
}

type billVerifyReport struct {
	ReportVersion  int                `json:"report_version"`
	Since          *string            `json:"since"`
	Directory      string             `json:"directory"`
	Results        []billVerifyResult `json:"results"`
	Unchanged      int                `json:"unchanged"`
	Changed        int                `json:"changed"`
	MissingLocal   int                `json:"missing_local"`
	Failed         int                `json:"failed"`
	NotAttempted   int                `json:"not_attempted"`
	ContentChanged bool               `json:"content_changed"`
}

type billVerifyFailure struct {
	cause  error
	report billVerifyReport
}

func (e *billVerifyFailure) Error() string { return e.cause.Error() }
func (e *billVerifyFailure) Unwrap() error { return e.cause }

// billVerifySink retains only a signature prefix and the streaming digest.
// Validation is sticky even when an injected service ignores Write errors.
type billVerifySink struct {
	hasher hash.Hash
	bytes  int64
	prefix [5]byte
	err    error
}

func newBillVerifySink() *billVerifySink { return &billVerifySink{hasher: sha256.New()} }

func (w *billVerifySink) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > billSyncMaxBytes-w.bytes {
		w.err = coned.ErrProtocolChanged
		return 0, w.err
	}
	if w.bytes < int64(len(w.prefix)) {
		copy(w.prefix[w.bytes:], p)
	}
	if w.bytes+int64(len(p)) >= int64(len(w.prefix)) && string(w.prefix[:]) != "%PDF-" {
		w.err = coned.ErrProtocolChanged
		return 0, w.err
	}
	n, _ := w.hasher.Write(p)
	w.bytes += int64(n)
	return n, nil
}

func (w *billVerifySink) complete() (billSyncVerifiedFile, error) {
	if w.err != nil || w.bytes < 5 || string(w.prefix[:]) != "%PDF-" {
		return billSyncVerifiedFile{}, coned.ErrProtocolChanged
	}
	return billSyncVerifiedFile{Bytes: w.bytes, SHA256: hex.EncodeToString(w.hasher.Sum(nil))}, nil
}

func newBillVerifyCommand(options *Options, deps Dependencies) *cobra.Command {
	var since, directory string
	var sinceSet bool
	command := &cobra.Command{
		Use:   "verify",
		Short: "Compare retained bills with fresh PDF bytes without writing files",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return invalidArgument(err)
			}
			sinceSet = cmd.Flags().Changed("since")
			if strings.TrimSpace(directory) == "" || sinceSet && !validBillSyncDate(since) {
				return invalidArgument(fmt.Errorf("invalid bill verify arguments"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBillVerify(cmd, options, deps, since, sinceSet, directory)
		},
	}
	command.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return invalidArgument(err) })
	command.Flags().StringVar(&since, "since", "", "exclusive bill-document date cutoff (YYYY-MM-DD)")
	command.Flags().StringVar(&directory, "directory", "", "existing directory containing retained bill PDFs (not accessed in demo)")
	return command
}

func runBillVerify(cmd *cobra.Command, options *Options, deps Dependencies, since string, sinceSet bool, directory string) error {
	if options.Account != "" || options.Meter != "" {
		return coned.ErrSelectionRequired
	}
	selection := options.selections[options.Profile]
	if !options.Demo && (selection.DefaultAccount != "" || selection.DefaultMeter != "") {
		return coned.ErrSelectionRequired
	}
	if !billSyncPlatformSupported() {
		return unsupportedPlatformError()
	}
	if options.Demo {
		report := demoBillVerifyReport(since, sinceSet)
		setEnvelopeData(deps, report)
		return writeBillVerifyTable(cmd.OutOrStdout(), report)
	}
	service, ok := deps.Bills.(BillSyncService)
	if !ok || service == nil {
		return coned.ErrSelectionRequired
	}
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.close() }()
	session, err := billingSession(deps, options.Profile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
	defer cancel()
	bills, err := service.ListBillsForSync(ctx, session)
	if err != nil {
		return safeSyncDownloadError(err)
	}
	bills, err = validateBillSyncRows(bills)
	if err != nil {
		return err
	}
	report, failure := verifyBillRows(ctx, filesystem, service, session, selectBillSyncRows(bills, since, sinceSet), since, sinceSet)
	if err := writeBillVerifyTable(cmd.OutOrStdout(), report); err != nil {
		return billSyncOutputFailedError()
	}
	if failure != nil {
		return &billVerifyFailure{cause: failure, report: report}
	}
	setEnvelopeData(deps, report)
	return nil
}

func newBillVerifyReport(directory, since string, sinceSet bool) billVerifyReport {
	report := billVerifyReport{ReportVersion: 1, Directory: directory, Results: []billVerifyResult{}}
	if sinceSet {
		cutoff := since
		report.Since = &cutoff
	}
	return report
}

func verifyBillRows(ctx context.Context, filesystem *billSyncFS, service BillSyncService, session auth.Session, bills []coned.Bill, since string, sinceSet bool) (billVerifyReport, error) {
	report := newBillVerifyReport(filesystem.canonical, since, sinceSet)
	var failure, stop error
	for _, bill := range bills {
		result := newBillVerifyResult(bill)
		if stop == nil && ctx.Err() != nil {
			stop = safeSyncDownloadError(ctx.Err())
			if failure == nil {
				failure = stop
			}
		}
		if stop != nil {
			result.Status = "not_attempted"
		} else {
			var err error
			result, err = processVerifyBill(ctx, filesystem, service, session, bill)
			if err != nil {
				if failure == nil {
					failure = err
				}
				if billSyncErrorStops(err) {
					stop = err
				}
			}
		}
		report.add(result)
	}
	// Empty selections still respect cancellation and directory drift.
	if failure == nil && ctx.Err() != nil {
		failure = safeSyncDownloadError(ctx.Err())
	}
	if failure == nil {
		failure = filesystem.verify()
	}
	return report, failure
}

func newBillVerifyResult(bill coned.Bill) billVerifyResult {
	return billVerifyResult{BillID: bill.ID, Date: bill.Date, Filename: "coned-bill-" + bill.ID + ".pdf"}
}

func (r *billVerifyReport) add(result billVerifyResult) {
	r.Results = append(r.Results, result)
	switch result.Status {
	case "unchanged":
		r.Unchanged++
	case "content_changed":
		r.Changed++
		r.ContentChanged = true
	case "missing_local":
		r.MissingLocal++
	case "failed":
		r.Failed++
	case "not_attempted":
		r.NotAttempted++
	}
}

func processVerifyBill(ctx context.Context, filesystem *billSyncFS, service BillSyncService, session auth.Session, bill coned.Bill) (result billVerifyResult, resultErr error) {
	result = newBillVerifyResult(bill)
	fail := func(err error) (billVerifyResult, error) {
		result.Status = "failed"
		result.ErrorCode = mapEnvelopeError(err, false).value.Code
		return result, err
	}
	retained, exists, err := filesystem.retainForVerify(result.Filename)
	if err != nil {
		return fail(err)
	}
	if !exists {
		result.Status = "missing_local"
		return result, nil
	}
	defer func() {
		if err := retained.file.Close(); err != nil {
			result = newBillVerifyResult(bill)
			result.Status, result.ErrorCode = "failed", "output_failed"
			resultErr = billSyncOutputFailedError()
		}
	}()
	sink := newBillVerifySink()
	err = service.DownloadBillForSync(ctx, session, bill.ID, sink)
	if err != nil {
		return fail(safeSyncDownloadError(err))
	}
	if err := ctx.Err(); err != nil {
		return fail(safeSyncDownloadError(err))
	}
	observed, err := sink.complete()
	if err != nil {
		return fail(err)
	}
	if err := retained.recheck(filesystem); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(safeSyncDownloadError(err))
	}
	result.Status = "unchanged"
	if retained.verified.Bytes != observed.Bytes || retained.verified.SHA256 != observed.SHA256 {
		result.Status = "content_changed"
	}
	result.LocalBytes, result.LocalSHA256 = retained.verified.Bytes, retained.verified.SHA256
	result.ProviderBytes, result.ProviderSHA256 = observed.Bytes, observed.SHA256
	return result, nil
}

func writeBillVerifyTable(output io.Writer, report billVerifyReport) error {
	if _, err := fmt.Fprintln(output, "Byte comparison only; a change does not establish changed charges or a replacement bill."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "STATUS\tDATE\tBILL_ID\tFILE\tLOCAL_BYTES\tLOCAL_SHA256\tPROVIDER_BYTES\tPROVIDER_SHA256\tERROR"); err != nil {
		return err
	}
	for _, result := range report.Results {
		if _, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\n", result.Status, result.Date, result.BillID, result.Filename, result.LocalBytes, result.LocalSHA256, result.ProviderBytes, result.ProviderSHA256, result.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}

func demoBillVerifyReport(since string, sinceSet bool) billVerifyReport {
	report := newBillVerifyReport("demo:memory", since, sinceSet)
	var bills []coned.Bill
	for _, date := range []string{"2026-01-15", "2026-02-15"} {
		sum := sha256.Sum256([]byte(date))
		bills = append(bills, coned.Bill{ID: date + "-" + hex.EncodeToString(sum[:])[:8], Date: date})
	}
	for _, bill := range selectBillSyncRows(bills, since, sinceSet) {
		result := newBillVerifyResult(bill)
		local, provider := "%PDF-synthetic retained\n", "%PDF-synthetic retained\n"
		result.Status = "unchanged"
		if bill.Date == "2026-02-15" {
			provider = "%PDF-synthetic changed bytes\n"
			result.Status = "content_changed"
		}
		localSum, providerSum := sha256.Sum256([]byte(local)), sha256.Sum256([]byte(provider))
		result.LocalBytes, result.ProviderBytes = int64(len(local)), int64(len(provider))
		result.LocalSHA256, result.ProviderSHA256 = hex.EncodeToString(localSum[:]), hex.EncodeToString(providerSum[:])
		report.add(result)
	}
	return report
}
