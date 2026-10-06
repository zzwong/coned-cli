package coned

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

const (
	billHistoryPath            = "/en/accounts-billing/my-account/bill-history-assistance"
	residentialBillHistoryPath = billHistoryPath + "/billing-types/billing-residential"
	billInsertImagePath        = "/sitecore/api/ssc/ConEdWeb-Feature-Maui-Areas-MauiAPI/AccountPrograms/0/BillInsertImage"
	maxBillPDFBytes            = 100 << 20
	maxBillHistoryBodyBytes    = 4 << 20
)

// Bill is the safe, public representation of a bill. In particular it does
// not contain Con Edison account metadata, document identifiers, or URLs.
type Bill struct {
	ID           string `json:"id"`
	Date         string `json:"date"`
	Cycle        string `json:"cycle"`
	DocumentType string `json:"document_type"`
}

type billRecord struct {
	Bill
	documentID string
}

type billingMetadata map[string]string

// ListBills obtains account metadata from the authenticated history page, then
// uses it only to call the residential asynchronous history endpoint.
func (c *Client) ListBills(ctx context.Context, session auth.Session) ([]Bill, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	_, records, err := c.billRecords(ctx, session)
	if err != nil {
		return nil, err
	}
	// A date-only public ID cannot distinguish two source records from the
	// same date. Show it once rather than inventing a document-derived suffix.
	seen := make(map[string]bool)
	bills := make([]Bill, 0, len(records))
	for _, record := range records {
		if !seen[record.ID] {
			seen[record.ID] = true
			bills = append(bills, record.Bill)
		}
	}
	return bills, nil
}

// ListBillsForSync is the strict listing boundary used by repeatable local
// synchronization. Unlike ListBills, it refuses to collapse distinct source
// documents that share the same date-derived public ID or conflicting billing
// scope metadata.
func (c *Client) ListBillsForSync(ctx context.Context, session auth.Session) ([]Bill, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	c.syncScope = nil
	metadata, records, err := c.billRecordsForSync(ctx, session)
	if err != nil {
		return nil, err
	}
	c.syncScope = cloneBillingMetadata(metadata)
	bills := make([]Bill, 0, len(records))
	for _, record := range records {
		bills = append(bills, record.Bill)
	}
	return bills, nil
}

// DownloadBill locates a public local bill ID in a freshly fetched history and
// streams its PDF to dst. It never returns a signed document URL to callers.
func (c *Client) DownloadBill(ctx context.Context, session auth.Session, id string, dst io.Writer) error {
	return c.downloadBill(ctx, session, id, dst, false)
}

// DownloadBillForSync repeats the strict scope and duplicate-document checks
// immediately before resolving a document. A prior strict listing is not
// treated as a durable scope guarantee.
func (c *Client) DownloadBillForSync(ctx context.Context, session auth.Session, id string, dst io.Writer) error {
	return c.downloadBill(ctx, session, id, dst, true)
}

func (c *Client) downloadBill(ctx context.Context, session auth.Session, id string, dst io.Writer, strict bool) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()

	if dst == nil || !validPublicBillID(id) {
		return ErrProtocolChanged
	}
	var metadata billingMetadata
	var records []billRecord
	var err error
	if strict {
		if c.syncScope == nil {
			return billDownloadError(id, ErrSelectionRequired)
		}
		metadata, err = c.historyMetadataForSync(ctx, session)
		if err != nil {
			return billDownloadError(id, err)
		}
		if !sameBillingScope(c.syncScope, metadata) {
			return billDownloadError(id, ErrSelectionRequired)
		}
		records, err = c.billRecordsFromMetadata(ctx, metadata, true)
	} else {
		metadata, records, err = c.billRecordsWithMode(ctx, session, false)
	}
	if err != nil {
		return billDownloadError(id, err)
	}
	var record *billRecord
	for i := range records {
		if records[i].ID == id {
			record = &records[i]
			break
		}
	}
	if record == nil {
		return billDownloadError(id, ErrBillNotFound)
	}
	// Selecting one of multiple documents with the same date would be
	// arbitrary. Refuse the download rather than exposing an internal ID to
	// disambiguate it.
	for i := range records {
		if &records[i] != record && records[i].ID == id {
			return billDownloadError(id, ErrProtocolChanged)
		}
	}
	documentEndpoint := c.endpoint(billInsertImagePath)
	query := documentEndpoint.Query()
	query.Set("ScId", metadata["ScId"])
	query.Set("Maid", metadata["AccountMaid"])
	query.Set("DocumentId", record.documentID)
	query.Set("BillDate", record.Date)
	query.Set("Type", "image")
	documentEndpoint.RawQuery = query.Encode()
	response, err := c.request(ctx, stepBillDocument, http.MethodGet, documentEndpoint, nil, false)
	if err != nil {
		return billDownloadError(id, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		if readErr != nil || closeErr != nil {
			cause := readErr
			if cause == nil {
				cause = closeErr
			}
			return billDownloadError(id, c.transportFailure(ctx, stepBillDocument, cause))
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || isLoginRedirect(response) {
			return billDownloadError(id, ErrSessionExpired)
		}
		return billDownloadError(id, protocolError(response))
	}
	documentURL, err := parseDocumentURL(body)
	if err == nil {
		err = checkDocumentURL(documentURL)
	}
	if err != nil {
		return billDownloadError(id, err)
	}
	pdf, err := c.request(ctx, stepPDFDownload, http.MethodGet, documentURL, nil, false)
	if err != nil {
		return billDownloadError(id, err)
	}
	defer func() { _ = pdf.Body.Close() }()
	if pdf.StatusCode < 200 || pdf.StatusCode >= 300 {
		if pdf.StatusCode == http.StatusUnauthorized || pdf.StatusCode == http.StatusForbidden || isLoginRedirect(pdf) {
			return billDownloadError(id, ErrSessionExpired)
		}
		return billDownloadError(id, protocolError(pdf))
	}
	trackedBody := &transportReadTracker{reader: pdf.Body}
	copyErr := copyPDF(dst, trackedBody)
	if trackedBody.err != nil {
		return billDownloadError(id, c.transportFailure(ctx, stepPDFDownload, trackedBody.err))
	}
	return billDownloadError(id, copyErr)
}

func (c *Client) billRecords(ctx context.Context, session auth.Session) (billingMetadata, []billRecord, error) {
	return c.billRecordsWithMode(ctx, session, false)
}

func (c *Client) billRecordsForSync(ctx context.Context, session auth.Session) (billingMetadata, []billRecord, error) {
	return c.billRecordsWithMode(ctx, session, true)
}

func (c *Client) billRecordsWithMode(ctx context.Context, session auth.Session, strict bool) (billingMetadata, []billRecord, error) {
	var metadata billingMetadata
	var err error
	if strict {
		metadata, err = c.historyMetadataForSync(ctx, session)
	} else {
		metadata, err = c.historyMetadata(ctx, session)
	}
	if err != nil {
		return nil, nil, err
	}
	records, err := c.billRecordsFromMetadata(ctx, metadata, strict)
	if err != nil {
		return nil, nil, err
	}
	return metadata, records, nil
}

func (c *Client) billRecordsFromMetadata(ctx context.Context, metadata billingMetadata, strict bool) ([]billRecord, error) {
	data, err := json.Marshal(map[string]string{"AccountMaid": metadata["AccountMaid"], "ScId": metadata["ScId"]})
	if err != nil {
		return nil, ErrProtocolChanged
	}
	historyEndpoint := c.endpoint(residentialBillHistoryPath)
	historyEndpoint.RawQuery = "asynchronous=1&bhistory=1"
	response, err := c.request(ctx, stepBillHistory, http.MethodPost, historyEndpoint, bytes.NewReader(data), true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBillHistoryBodyBytes+1))
	if err != nil {
		return nil, c.transportFailure(ctx, stepBillHistory, err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || isLoginRedirect(response) {
		return nil, ErrSessionExpired
	}
	if response.StatusCode >= 500 && c.sessionRejected(ctx) {
		return nil, ErrSessionExpired
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, protocolError(response)
	}
	if strict && len(body) > maxBillHistoryBodyBytes {
		return nil, ErrProtocolChanged
	}
	var records []billRecord
	if strict {
		records, err = parseBillRecordsForSync(body)
	} else {
		records, err = parseBillRecords(body)
	}
	if err != nil {
		if strict && errors.Is(err, ErrSelectionRequired) {
			return nil, ErrSelectionRequired
		}
		return nil, ErrProtocolChanged
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Date > records[j].Date })
	return records, nil
}

func cloneBillingMetadata(metadata billingMetadata) billingMetadata {
	if metadata == nil {
		return nil
	}
	copy := make(billingMetadata, len(metadata))
	for key, value := range metadata {
		copy[key] = value
	}
	return copy
}

func sameBillingScope(a, b billingMetadata) bool {
	for _, key := range []string{"AccountMaid", "ScId", "AccountId"} {
		if a[key] != b[key] {
			return false
		}
	}
	return true
}

func (c *Client) historyMetadata(ctx context.Context, session auth.Session) (billingMetadata, error) {
	return c.historyMetadataWithMode(ctx, session, false)
}

func (c *Client) historyMetadataForSync(ctx context.Context, session auth.Session) (billingMetadata, error) {
	return c.historyMetadataWithMode(ctx, session, true)
}

func (c *Client) historyMetadataWithMode(ctx context.Context, session auth.Session, strict bool) (billingMetadata, error) {
	if session.State(time.Now()) != auth.SessionValid || c.restoreSession(session) != nil {
		return nil, ErrSessionExpired
	}
	response, err := c.request(ctx, stepBillHistory, http.MethodGet, c.endpoint(billHistoryPath), nil, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBillHistoryBodyBytes+1))
	if err != nil {
		return nil, c.transportFailure(ctx, stepBillHistory, err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || (response.StatusCode >= 300 && response.StatusCode < 400 && strings.Contains(strings.ToLower(response.Header.Get("Location")), "/login")) {
		return nil, ErrSessionExpired
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, protocolError(response)
	}
	if strict && len(body) > maxBillHistoryBodyBytes {
		return nil, ErrProtocolChanged
	}
	metadata := parseBillingMetadata(string(body))
	if strict {
		metadata, err = parseBillingMetadataForSync(string(body))
		if err != nil {
			return nil, err
		}
	}
	if len(metadata) == 0 {
		return nil, ErrProtocolChanged
	}
	return metadata, nil
}

var (
	htmlTag       = regexp.MustCompile(`(?is)<[^>]+>`)
	htmlAttribute = regexp.MustCompile(`(?is)([[:alnum:]_-]+)\s*=\s*["']([^"']+)["']`)
	metadataJSON  = regexp.MustCompile(`(?i)["'](accountmaid|maid|scid|sitecoreid|accountid)["']\s*:\s*["']([^"']+)["']`)
)

func parseBillingMetadata(page string) billingMetadata {
	out := billingMetadata{}
	set := func(key, value string) {
		switch normalizeBillKey(key) {
		case "accountmaid", "maid":
			out["AccountMaid"] = value
		case "scid", "sitecoreid":
			out["ScId"] = value
		case "accountid":
			out["AccountId"] = value
		}
	}
	// Examine complete tags rather than assuming attribute order. This supports
	// both data attributes and hidden inputs used by different page versions.
	for _, tag := range htmlTag.FindAllString(page, -1) {
		attributes := map[string]string{}
		for _, pair := range htmlAttribute.FindAllStringSubmatch(tag, -1) {
			attributes[strings.ToLower(pair[1])] = pair[2]
		}
		for key, value := range attributes {
			if strings.HasPrefix(key, "data-") {
				set(strings.TrimPrefix(key, "data-"), value)
			}
		}
		if name, ok := attributes["name"]; ok {
			set(name, attributes["value"])
		}
	}
	for _, pair := range metadataJSON.FindAllStringSubmatch(page, -1) {
		set(pair[1], pair[2])
	}
	return out
}

func parseBillingMetadataForSync(page string) (billingMetadata, error) {
	values := map[string]map[string]struct{}{
		"AccountMaid": {},
		"ScId":        {},
		"AccountId":   {},
	}
	add := func(key, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		switch normalizeBillKey(key) {
		case "accountmaid", "maid":
			values["AccountMaid"][value] = struct{}{}
		case "scid", "sitecoreid":
			values["ScId"][value] = struct{}{}
		case "accountid":
			values["AccountId"][value] = struct{}{}
		}
	}
	for _, tag := range htmlTag.FindAllString(page, -1) {
		attributes, err := strictBillHTMLAttributes(tag)
		if err != nil {
			return nil, err
		}
		for key, value := range attributes {
			if strings.HasPrefix(key, "data-") {
				add(strings.TrimPrefix(key, "data-"), value)
			}
		}
		if name, ok := attributes["name"]; ok {
			add(name, attributes["value"])
		}
	}
	for _, pair := range metadataJSON.FindAllStringSubmatch(page, -1) {
		add(pair[1], pair[2])
	}
	metadata := billingMetadata{}
	for key, found := range values {
		if len(found) > 1 {
			return nil, ErrSelectionRequired
		}
		for value := range found {
			metadata[key] = value
		}
	}
	if metadata["AccountMaid"] == "" || metadata["ScId"] == "" {
		return nil, ErrSelectionRequired
	}
	return metadata, nil
}

func parseBillRecords(data []byte) ([]billRecord, error) {
	var records []billRecord
	var root any
	if json.Unmarshal(data, &root) == nil {
		walkBillJSON(root, &records)
	} else {
		records = parseBillHTML(string(data))
		if len(records) == 0 {
			return nil, errors.New("invalid bill history")
		}
	}
	// De-duplicate repeated JSON nodes, but retain distinct documents on the
	// same date so DownloadBill can reject that ambiguous public ID safely.
	seen := make(map[string]bool)
	out := records[:0]
	for _, record := range records {
		key := record.Date + "\x00" + record.documentID
		if record.ID != "" && !seen[key] {
			seen[key] = true
			out = append(out, record)
		}
	}
	return out, nil
}

func parseBillRecordsForSync(data []byte) ([]billRecord, error) {
	var records []billRecord
	root, isJSON, err := decodeBillSyncJSON(data)
	if err != nil {
		return nil, ErrProtocolChanged
	}
	if isJSON {
		if err := walkBillJSONForSync(root, &records); err != nil {
			return nil, err
		}
	} else {
		for _, tag := range htmlTag.FindAllString(string(data), -1) {
			attributes, err := strictBillHTMLAttributes(tag)
			if err != nil {
				return nil, err
			}
			values := map[string]string{}
			for key, value := range attributes {
				normalized := normalizeBillKey(strings.TrimPrefix(key, "data-"))
				if previous, exists := values[normalized]; exists && previous != value {
					return nil, ErrSelectionRequired
				}
				values[normalized] = value
			}
			documentID, err := uniqueBillValue(values, "documentid", "billdocumentid")
			if err != nil {
				return nil, err
			}
			if documentID == "" {
				continue
			}
			dateValue, err := uniqueBillValue(values, "billdate", "statementdate", "date", "issuedate")
			if err != nil {
				return nil, err
			}
			date, ok := normalizeBillDate(dateValue)
			if !ok {
				return nil, ErrProtocolChanged
			}
			cycle, err := uniqueBillValue(values, "billcycle", "cycle", "billingcycle", "cycledate")
			if err != nil {
				return nil, err
			}
			documentType, err := uniqueBillValue(values, "type", "documenttype", "doctype")
			if err != nil {
				return nil, err
			}
			records = append(records, billRecord{Bill: Bill{ID: localBillID(date), Date: date, Cycle: cycle, DocumentType: documentType}, documentID: documentID})
		}
	}
	if len(records) == 0 {
		if recognizedEmptyBillCollection(root) {
			return []billRecord{}, nil
		}
		return nil, ErrProtocolChanged
	}
	byID := make(map[string]billRecord, len(records))
	ordered := make([]billRecord, 0, len(records))
	for _, record := range records {
		date, ok := BillIDDate(record.ID)
		if !ok || date != record.Date || record.documentID == "" {
			return nil, ErrProtocolChanged
		}
		if previous, ok := byID[record.ID]; ok {
			if previous.documentID != record.documentID || previous.Cycle != record.Cycle || previous.DocumentType != record.DocumentType {
				return nil, ErrSelectionRequired
			}
			continue
		}
		byID[record.ID] = record
		ordered = append(ordered, record)
	}
	return ordered, nil
}

func recognizedEmptyBillCollection(value any) bool {
	switch node := value.(type) {
	case []any:
		return len(node) == 0
	case map[string]any:
		if emptyBillArrayAt(node, "bills", "billhistory", "billinghistory", "results", "items") {
			return true
		}
		data, ok := billJSONField(node, "data")
		if !ok {
			return false
		}
		if rows, ok := data.([]any); ok {
			return len(rows) == 0
		}
		if nested, ok := data.(map[string]any); ok {
			return emptyBillArrayAt(nested, "bills", "billhistory", "billinghistory", "results", "items")
		}
	}
	return false
}

func emptyBillArrayAt(object map[string]any, names ...string) bool {
	for key, value := range object {
		for _, name := range names {
			if normalizeBillKey(key) != name {
				continue
			}
			if rows, ok := value.([]any); ok && len(rows) == 0 {
				return true
			}
		}
	}
	return false
}

func billJSONField(object map[string]any, name string) (any, bool) {
	for key, value := range object {
		if normalizeBillKey(key) == name {
			return value, true
		}
	}
	return nil, false
}

func strictBillHTMLAttributes(tag string) (map[string]string, error) {
	attributes := make(map[string]string)
	for _, pair := range htmlAttribute.FindAllStringSubmatch(tag, -1) {
		key := strings.ToLower(pair[1])
		value := strings.TrimSpace(pair[2])
		if previous, exists := attributes[key]; exists && previous != value {
			return nil, ErrSelectionRequired
		}
		attributes[key] = value
	}
	return attributes, nil
}

func decodeBillSyncJSON(data []byte) (any, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' && trimmed[0] != '[' {
		return nil, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	root, err := decodeBillSyncJSONValue(decoder)
	if err != nil {
		return nil, true, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, true, ErrProtocolChanged
	}
	return root, true, nil
}

func decodeBillSyncJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrProtocolChanged
			}
			if _, duplicate := object[key]; duplicate {
				return nil, ErrProtocolChanged
			}
			value, err := decodeBillSyncJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrProtocolChanged
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeBillSyncJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrProtocolChanged
		}
		return array, nil
	default:
		return nil, ErrProtocolChanged
	}
}

func walkBillJSONForSync(value any, records *[]billRecord) error {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			if err := walkBillJSONForSync(child, records); err != nil {
				return err
			}
		}
	case map[string]any:
		values := map[string]string{}
		for key, child := range node {
			if text, ok := child.(string); ok {
				normalized := normalizeBillKey(key)
				text = strings.TrimSpace(text)
				if previous, exists := values[normalized]; exists && previous != text {
					return ErrSelectionRequired
				}
				values[normalized] = text
			}
		}
		documentID, err := uniqueBillValue(values, "documentid", "billdocumentid", "documentidentifier")
		if err != nil {
			return err
		}
		if documentID != "" {
			dateValue, err := uniqueBillValue(values, "billdate", "statementdate", "date", "issuedate")
			if err != nil {
				return err
			}
			date, ok := normalizeBillDate(dateValue)
			if !ok {
				return ErrProtocolChanged
			}
			cycle, err := uniqueBillValue(values, "cycle", "billingcycle", "cycledate")
			if err != nil {
				return err
			}
			typ, err := uniqueBillValue(values, "documenttype", "doctype", "type")
			if err != nil {
				return err
			}
			*records = append(*records, billRecord{Bill: Bill{ID: localBillID(date), Date: date, Cycle: cycle, DocumentType: typ}, documentID: documentID})
		}
		for _, child := range node {
			if err := walkBillJSONForSync(child, records); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseBillHTML(page string) []billRecord {
	var records []billRecord
	for _, tag := range htmlTag.FindAllString(page, -1) {
		values := map[string]string{}
		for _, pair := range htmlAttribute.FindAllStringSubmatch(tag, -1) {
			values[normalizeBillKey(strings.TrimPrefix(pair[1], "data-"))] = strings.TrimSpace(pair[2])
		}
		documentID := firstValue(values, "documentid", "billdocumentid")
		date, ok := normalizeBillDate(firstValue(values, "billdate", "statementdate"))
		if documentID != "" && ok {
			records = append(records, billRecord{Bill: Bill{ID: localBillID(date), Date: date, Cycle: firstValue(values, "billcycle", "cycle"), DocumentType: firstValue(values, "type", "documenttype")}, documentID: documentID})
		}
	}
	return records
}

func walkBillJSON(value any, records *[]billRecord) {
	switch v := value.(type) {
	case []any:
		for _, child := range v {
			walkBillJSON(child, records)
		}
	case map[string]any:
		values := map[string]string{}
		for key, child := range v {
			if text, ok := child.(string); ok {
				values[normalizeBillKey(key)] = strings.TrimSpace(text)
			}
			walkBillJSON(child, records)
		}
		documentID := firstValue(values, "documentid", "billdocumentid", "documentidentifier")
		date, ok := normalizeBillDate(firstValue(values, "billdate", "statementdate", "date", "issuedate"))
		if documentID != "" && ok {
			cycle := firstValue(values, "cycle", "billingcycle", "cycledate")
			typ := firstValue(values, "documenttype", "doctype", "type")
			*records = append(*records, billRecord{Bill: Bill{ID: localBillID(date), Date: date, Cycle: cycle, DocumentType: typ}, documentID: documentID})
		}
	}
}
func normalizeBillKey(key string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
}
func firstValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if values[key] != "" {
			return values[key]
		}
	}
	return ""
}

func uniqueBillValue(values map[string]string, keys ...string) (string, error) {
	var found string
	for _, key := range keys {
		value := strings.TrimSpace(values[key])
		if value == "" {
			continue
		}
		if found != "" && found != value {
			return "", ErrSelectionRequired
		}
		found = value
	}
	return found, nil
}
func normalizeBillDate(value string) (string, bool) {
	for _, layout := range []string{"2006-01-02", "01/02/2006", "1/2/2006", "Jan 2, 2006", "January 2, 2006", time.RFC3339} {
		if date, err := time.Parse(layout, value); err == nil {
			return date.Format("2006-01-02"), true
		}
	}
	return "", false
}
func localBillID(date string) string {
	sum := sha256.Sum256([]byte(date))
	return date + "-" + hex.EncodeToString(sum[:])[:8]
}

// BillIDDate validates a public local bill ID and returns its date. Its hash is
// derived solely from that date, never an opaque provider document ID.
func BillIDDate(id string) (string, bool) {
	if len(id) != 19 || id[10] != '-' {
		return "", false
	}
	date := id[:10]
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil || parsed.Format("2006-01-02") != date {
		return "", false
	}
	if id != localBillID(date) {
		return "", false
	}
	return date, true
}

func validPublicBillID(id string) bool {
	_, ok := BillIDDate(id)
	return ok
}

func isLoginRedirect(response *http.Response) bool {
	return response != nil && response.StatusCode >= 300 && response.StatusCode < 400 && strings.Contains(strings.ToLower(response.Header.Get("Location")), "/login")
}

const (
	documentNotJSON  = "response is not JSON"
	documentNoURL    = "response has no URL"
	documentBadURL   = "URL is malformed"
	documentBadHost  = "URL host is not an allowed bill store"
	documentUnsigned = "URL is not signed"
	documentNotPDF   = "document is not a PDF"
)

func parseDocumentURL(data []byte) (*url.URL, error) {
	var root any
	if json.Unmarshal(data, &root) != nil {
		return nil, &DocumentError{Reason: documentNotJSON}
	}
	var find func(any) string
	find = func(value any) string {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				normalized := normalizeBillKey(key)
				if strings.Contains(normalized, "url") || normalized == "link" {
					if text, ok := child.(string); ok {
						return text
					}
				}
			}
			for _, child := range v {
				if found := find(child); found != "" {
					return found
				}
			}
		case []any:
			for _, child := range v {
				if found := find(child); found != "" {
					return found
				}
			}
		}
		return ""
	}
	raw := find(root)
	if raw == "" {
		return nil, &DocumentError{Reason: documentNoURL}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &DocumentError{Reason: documentBadURL}
	}
	return u, nil
}

// checkDocumentURL admits only a signed HTTPS Azure Blob URL, so a changed
// response cannot redirect the download to an arbitrary host.
func checkDocumentURL(u *url.URL) error {
	if u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return &DocumentError{Reason: documentBadURL}
	}
	host := strings.ToLower(u.Hostname())
	if !strings.HasSuffix(host, ".blob.core.windows.net") {
		return &DocumentError{Reason: documentBadHost, Host: host}
	}
	if u.Query().Get("sig") == "" {
		return &DocumentError{Reason: documentUnsigned}
	}
	return nil
}
func copyPDF(dst io.Writer, source io.Reader) error {
	prefix := make([]byte, 5)
	if _, err := io.ReadFull(source, prefix); err != nil || string(prefix) != "%PDF-" {
		return &DocumentError{Reason: documentNotPDF}
	}
	n, err := dst.Write(prefix)
	if n != len(prefix) {
		return io.ErrShortWrite
	}
	if err != nil {
		return ErrProtocolChanged
	}
	// Copy at most the remaining allowed bytes. Probe only after that limit is
	// reached, so an oversized response never writes its detection byte.
	_, err = io.CopyN(dst, source, maxBillPDFBytes-int64(len(prefix)))
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return ErrProtocolChanged
	}
	var probe [1]byte
	n, probeErr := source.Read(probe[:])
	if n != 0 || probeErr != io.EOF {
		return ErrProtocolChanged
	}
	return nil
}
