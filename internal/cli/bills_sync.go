package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

const maxBillSyncRecords = 1000

// BillSyncService is deliberately stricter than BillService. Implementations
// must reject ambiguous billing scope and duplicate same-date provider
// documents before returning any public rows.
type BillSyncService interface {
	ListBillsForSync(context.Context, auth.Session) ([]coned.Bill, error)
	DownloadBillForSync(context.Context, auth.Session, string, io.Writer) error
}

type billSyncResult struct {
	BillID    string `json:"bill_id"`
	Date      string `json:"date"`
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Bytes     int64  `json:"bytes,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

type billSyncManifest struct {
	Since        *string          `json:"since"`
	Directory    string           `json:"directory"`
	Results      []billSyncResult `json:"results"`
	Downloaded   int              `json:"downloaded"`
	Existing     int              `json:"existing"`
	Failed       int              `json:"failed"`
	NotAttempted int              `json:"not_attempted"`
}

type billSyncFailure struct {
	cause    error
	manifest billSyncManifest
}

func (e *billSyncFailure) Error() string { return e.cause.Error() }
func (e *billSyncFailure) Unwrap() error { return e.cause }

type billSyncWriter struct {
	file *os.File
	err  error
}

func billSyncOutputConflictError() error {
	return &errorClass{legacy: ErrOutputConflict, code: "output_conflict"}
}

func billSyncOutputFailedError() error {
	return &errorClass{legacy: ErrOutputFailed, code: "output_failed"}
}

func (w *billSyncWriter) Write(data []byte) (int, error) {
	n, err := w.file.Write(data)
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

func newBillSyncCommand(options *Options, deps Dependencies) *cobra.Command {
	var since, directory string
	var sinceSet bool
	command := &cobra.Command{
		Use:   "sync",
		Short: "Download missing bill PDFs with a verified manifest",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return err
			}
			sinceSet = cmd.Flags().Changed("since")
			if strings.TrimSpace(directory) == "" || sinceSet && !validBillSyncDate(since) {
				return fmt.Errorf("invalid bill sync arguments")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBillSync(cmd, options, deps, since, sinceSet, directory)
		},
	}
	command.Flags().StringVar(&since, "since", "", "exclusive bill-document date cutoff (YYYY-MM-DD)")
	command.Flags().StringVar(&directory, "directory", "", "existing directory for verified bill PDFs")
	return command
}

func validBillSyncDate(value string) bool {
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}

func runBillSync(cmd *cobra.Command, options *Options, deps Dependencies, since string, sinceSet bool, directory string) error {
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
	service := deps.Bills
	if options.Demo {
		service = demoBillSyncService{}
	}
	syncService, ok := service.(BillSyncService)
	if !ok || syncService == nil {
		return coned.ErrSelectionRequired
	}
	filesystem, err := openBillSyncFS(directory)
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.close() }()

	var session auth.Session
	if !options.Demo {
		session, err = billingSession(deps, options.Profile)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
	defer cancel()
	bills, err := syncService.ListBillsForSync(ctx, session)
	if err != nil {
		return safeBillError(err)
	}
	bills, err = validateBillSyncRows(bills)
	if err != nil {
		return err
	}
	bills = selectBillSyncRows(bills, since, sinceSet)
	manifest := billSyncManifest{Since: nil, Directory: filesystem.canonical, Results: make([]billSyncResult, 0, len(bills))}
	if sinceSet {
		cutoff := since
		manifest.Since = &cutoff
	}
	var failure error
	if err := ctx.Err(); err != nil {
		failure = safeSyncDownloadError(err)
		for _, remaining := range bills {
			manifest.Results = append(manifest.Results, notAttemptedBill(remaining))
			manifest.NotAttempted++
		}
	}
	for index, bill := range bills {
		if failure != nil {
			break
		}
		if err := ctx.Err(); err != nil {
			failure = safeSyncDownloadError(err)
			for _, remaining := range bills[index:] {
				manifest.Results = append(manifest.Results, notAttemptedBill(remaining))
				manifest.NotAttempted++
			}
			break
		}
		result, complete, stopErr := processSyncBill(ctx, filesystem, syncService, session, bill)
		manifest.Results = append(manifest.Results, result)
		switch result.Status {
		case "downloaded":
			manifest.Downloaded++
		case "existing":
			manifest.Existing++
		case "failed":
			manifest.Failed++
		}
		if stopErr != nil {
			failure = stopErr
			for _, remaining := range bills[index+1:] {
				manifest.Results = append(manifest.Results, notAttemptedBill(remaining))
				manifest.NotAttempted++
			}
			break
		}
		if !complete && failure == nil {
			failure = coned.ErrProtocolChanged
		}
	}
	if manifest.Failed > 0 || failure != nil {
		if failure == nil {
			for _, result := range manifest.Results {
				if result.Status == "failed" {
					failure = errorForEnvelopeCode(result.ErrorCode)
					break
				}
			}
		}
		if failure == nil {
			failure = coned.ErrProtocolChanged
		}
		if err := writeBillSyncTable(cmd.OutOrStdout(), manifest); err != nil {
			return billSyncOutputFailedError()
		}
		return &billSyncFailure{cause: failure, manifest: manifest}
	}
	setEnvelopeData(deps, manifest)
	return writeBillSyncTable(cmd.OutOrStdout(), manifest)
}

func validateBillSyncRows(bills []coned.Bill) ([]coned.Bill, error) {
	if len(bills) > maxBillSyncRecords {
		return nil, coned.ErrProtocolChanged
	}
	seen := make(map[string]struct{}, len(bills))
	for _, bill := range bills {
		date, ok := coned.BillIDDate(bill.ID)
		if !ok || date != bill.Date || !validBillSyncDate(bill.Date) {
			return nil, coned.ErrProtocolChanged
		}
		if _, duplicate := seen[bill.ID]; duplicate {
			return nil, coned.ErrSelectionRequired
		}
		seen[bill.ID] = struct{}{}
	}
	return bills, nil
}

func selectBillSyncRows(bills []coned.Bill, since string, sinceSet bool) []coned.Bill {
	selected := make([]coned.Bill, 0, len(bills))
	for _, bill := range bills {
		if !sinceSet || bill.Date > since {
			selected = append(selected, bill)
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Date == selected[j].Date {
			return selected[i].ID < selected[j].ID
		}
		return selected[i].Date < selected[j].Date
	})
	if !sinceSet && len(selected) > 1 {
		selected = selected[len(selected)-1:]
	}
	return selected
}

func processSyncBill(ctx context.Context, filesystem *billSyncFS, service BillSyncService, session auth.Session, bill coned.Bill) (result billSyncResult, complete bool, stopErr error) {
	result = billSyncResult{BillID: bill.ID, Date: bill.Date, Filename: "coned-bill-" + bill.ID + ".pdf"}
	verified, exists, err := filesystem.existing(result.Filename)
	if err != nil {
		if errors.Is(err, ErrOutputConflict) {
			result.Status = "failed"
			result.ErrorCode = "output_conflict"
			return result, true, nil
		}
		result.Status = "failed"
		result.ErrorCode = mapEnvelopeError(err, false).value.Code
		return result, false, err
	}
	if exists {
		result.Status = "existing"
		result.Bytes = verified.Bytes
		result.SHA256 = verified.SHA256
		return result, true, nil
	}
	temp, tempName, err := filesystem.createTemp()
	if err != nil {
		result.Status = "failed"
		result.ErrorCode = mapEnvelopeError(err, false).value.Code
		return result, false, err
	}
	keepTemp := false
	defer func() {
		if !keepTemp {
			if cleanupErr := filesystem.removeOwned(tempName, temp); cleanupErr != nil {
				result.Status = "failed"
				result.ErrorCode = "output_failed"
				complete = false
				stopErr = billSyncOutputFailedError()
			}
			_ = temp.Close()
		}
	}()
	writer := &billSyncWriter{file: temp}
	err = service.DownloadBillForSync(ctx, session, bill.ID, writer)
	if writer.err != nil {
		err = billSyncOutputFailedError()
	} else if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	} else if err != nil {
		err = safeSyncDownloadError(err)
	}
	if err != nil {
		result.Status = "failed"
		result.ErrorCode = mapEnvelopeError(err, false).value.Code
		if billSyncErrorStops(err) {
			return result, false, err
		}
		return result, true, nil
	}
	verified, err = inspectBillPDF(temp)
	if errors.Is(err, errBillSyncInvalidPDF) {
		result.Status = "failed"
		result.ErrorCode = "provider_protocol_changed"
		return result, true, nil
	}
	if err != nil {
		err = billSyncOutputFailedError()
		result.Status = "failed"
		result.ErrorCode = "output_failed"
		return result, false, err
	}
	if err := ctx.Err(); err != nil {
		result.Status = "failed"
		result.ErrorCode = mapEnvelopeError(err, false).value.Code
		return result, false, safeSyncDownloadError(err)
	}
	if err := filesystem.publish(tempName, temp, result.Filename, &verified); err != nil {
		result.Status = "failed"
		result.ErrorCode = mapEnvelopeError(err, false).value.Code
		if errors.Is(err, ErrOutputConflict) {
			return result, true, nil
		}
		return result, false, err
	}
	keepTemp = true
	if err := temp.Close(); err != nil {
		_ = filesystem.removePublished(result.Filename, verified.snapshot)
		result.Status = "failed"
		result.ErrorCode = "output_failed"
		return result, false, billSyncOutputFailedError()
	}
	result.Status = "downloaded"
	result.Bytes = verified.Bytes
	result.SHA256 = verified.SHA256
	return result, true, nil
}

func safeSyncDownloadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if transport, ok := coned.AsSafeTransportError(err); ok {
		return transport
	}
	if protocol, ok := coned.AsSafeProtocolError(err); ok {
		return &coned.ProtocolError{Status: protocol.Status}
	}
	for _, safe := range []error{coned.ErrSelectionRequired, coned.ErrSessionExpired, coned.ErrBillNotFound, coned.ErrProtocolChanged, auth.ErrStorageLocked, auth.ErrStorageAccessDenied, auth.ErrStorageFailed} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	if errors.Is(err, ErrOutputConflict) {
		return billSyncOutputConflictError()
	}
	if errors.Is(err, ErrOutputFailed) {
		return billSyncOutputFailedError()
	}
	return internalBoundary(coned.ErrProtocolChanged)
}

func billSyncErrorStops(err error) bool {
	var classified *errorClass
	if errors.As(err, &classified) && classified != nil && classified.code == "internal_error" {
		return true
	}
	if err == nil || errors.Is(err, ErrOutputConflict) || errors.Is(err, coned.ErrBillNotFound) || errors.Is(err, coned.ErrProtocolChanged) {
		return false
	}
	return true
}

func notAttemptedBill(bill coned.Bill) billSyncResult {
	return billSyncResult{BillID: bill.ID, Date: bill.Date, Filename: "coned-bill-" + bill.ID + ".pdf", Status: "not_attempted"}
}

func errorForEnvelopeCode(code string) error {
	switch code {
	case "output_conflict":
		return billSyncOutputConflictError()
	case "output_failed":
		return billSyncOutputFailedError()
	case "session_expired":
		return coned.ErrSessionExpired
	case "timeout":
		return context.DeadlineExceeded
	case "canceled":
		return context.Canceled
	case "bill_not_found":
		return coned.ErrBillNotFound
	case "transport_failed":
		return &coned.TransportError{Kind: coned.TransportUnknown}
	case "provider_protocol_changed":
		return coned.ErrProtocolChanged
	default:
		return internalBoundary(coned.ErrProtocolChanged)
	}
}

func writeBillSyncTable(output io.Writer, manifest billSyncManifest) error {
	if _, err := fmt.Fprintln(output, "STATUS\tDATE\tBILL_ID\tFILE\tBYTES\tSHA256\tERROR"); err != nil {
		return err
	}
	for _, result := range manifest.Results {
		if _, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", result.Status, result.Date, result.BillID, result.Filename, result.Bytes, result.SHA256, result.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}

type demoBillSyncService struct{}

func (demoBillSyncService) ListBillsForSync(context.Context, auth.Session) ([]coned.Bill, error) {
	const date = "2026-02-15"
	sum := sha256.Sum256([]byte(date))
	return []coned.Bill{{ID: date + "-" + hex.EncodeToString(sum[:])[:8], Date: date, Cycle: "Sample", DocumentType: "bill"}}, nil
}

func (demoBillSyncService) ListBills(context.Context, auth.Session) ([]coned.Bill, error) {
	return demoBillSyncService{}.ListBillsForSync(context.Background(), auth.Session{})
}

func (demoBillSyncService) DownloadBill(_ context.Context, _ auth.Session, _ string, output io.Writer) error {
	_, err := io.WriteString(output, "%PDF-1.4\n% Synthetic offline demo bill\n")
	return err
}

func (demoBillSyncService) DownloadBillForSync(ctx context.Context, session auth.Session, id string, output io.Writer) error {
	return demoBillSyncService{}.DownloadBill(ctx, session, id, output)
}
