package coned

import (
	"archive/zip"
	"context"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

const (
	maxExportZIP     = 100 << 20
	maxExportEntry   = 500 << 20
	maxExportEntries = 20
)

var ErrGreenButtonUnavailable = errors.New("coned: green button export unavailable")

//go:embed graphql/green_button_metadata.graphql
var greenMetadataQuery string

//go:embed graphql/green_button_ami.graphql
var greenAMIQuery string

//go:embed graphql/green_button_bills.graphql
var greenBillsQuery string

//go:embed graphql/green_button_generate.graphql
var greenGenerateMutation string

//go:embed graphql/green_button_job.graphql
var greenJobQuery string

type GreenButtonMetadata struct {
	CustomerClass string   `json:"customer_class"`
	TimeZone      string   `json:"time_zone"`
	AMIIntervals  []string `json:"ami_intervals"`
	BillIntervals []string `json:"bill_intervals"`
}
type GreenButtonOptions struct{ Format, From, To string }

func (c *Client) GreenButtonInspect(ctx context.Context, s auth.Session) (GreenButtonMetadata, error) {
	options, err := c.defaultUsageOptions(ctx, s)
	if err != nil {
		return GreenButtonMetadata{}, err
	}
	accountURN := options.Account
	var m struct {
		Billing struct {
			CustomerClass string `json:"customerClass"`
			Premises      struct {
				Edges []struct {
					Node struct {
						TimeZone string `json:"timeZone"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"premisesConnection"`
		} `json:"billingAccountByAuthContext"`
	}
	if err := c.opowerCall(ctx, s, "WUE_GetMetadata", greenMetadataQuery, map[string]any{"selectedAccount": accountURN}, &m); err != nil {
		return GreenButtonMetadata{}, err
	}
	out := GreenButtonMetadata{CustomerClass: m.Billing.CustomerClass}
	if len(m.Billing.Premises.Edges) > 0 {
		out.TimeZone = m.Billing.Premises.Edges[0].Node.TimeZone
	}
	var b struct {
		Billing struct {
			Bills []struct {
				Interval string `json:"timeInterval"`
			} `json:"bills"`
		} `json:"billingAccountByAuthContext"`
	}
	if err := c.opowerCall(ctx, s, "WUE_GetUsageExportBills", greenBillsQuery, map[string]any{"selectedAccount": accountURN, "last": 39, "forceLegacyData": false}, &b); err != nil {
		return GreenButtonMetadata{}, err
	}
	for _, x := range b.Billing.Bills {
		if x.Interval != "" {
			out.BillIntervals = append(out.BillIntervals, x.Interval)
		}
	}
	for cursor := ""; ; {
		var a struct {
			Billing struct {
				Agreements struct {
					Page struct {
						HasNext bool   `json:"hasNextPage"`
						End     string `json:"endCursor"`
					} `json:"pageInfo"`
					Edges []struct {
						Node struct {
							Points []struct {
								Registers []struct {
									Interval string `json:"availableReadsTimeInterval"`
								} `json:"registers"`
							} `json:"servicePoints"`
						} `json:"node"`
					} `json:"edges"`
				} `json:"serviceAgreementsConnection"`
			} `json:"billingAccountByAuthContext"`
		}
		vars := map[string]any{"selectedAccount": accountURN, "first": 50, "forceLegacyData": false, "aliased": false}
		if cursor != "" {
			vars["nextCursor"] = cursor
		}
		if err := c.opowerCall(ctx, s, "WUE_GetUsageExportAvailableAMIReadsTimeInterval", greenAMIQuery, vars, &a); err != nil {
			return GreenButtonMetadata{}, err
		}
		for _, e := range a.Billing.Agreements.Edges {
			for _, p := range e.Node.Points {
				for _, r := range p.Registers {
					if r.Interval != "" {
						out.AMIIntervals = append(out.AMIIntervals, r.Interval)
					}
				}
			}
		}
		if !a.Billing.Agreements.Page.HasNext || a.Billing.Agreements.Page.End == "" {
			break
		}
		cursor = a.Billing.Agreements.Page.End
	}
	return out, nil
}

// GreenButtonExport downloads the provider ZIP into a private spool. Callers own and remove it.
func (c *Client) GreenButtonExport(ctx context.Context, s auth.Session, o GreenButtonOptions) (string, error) {
	options, err := c.defaultUsageOptions(ctx, s)
	if err != nil {
		return "", err
	}
	accountURN := options.Account
	f := strings.ToUpper(o.Format)
	if f != "CSV" && f != "XML" {
		return "", ErrProtocolChanged
	}
	accounts, err := c.callMap(ctx, s, "WBAS_BillingAccounts", accountsQuery, map[string]any{"first": 100, "onlyActive": true})
	if err != nil {
		return "", err
	}
	utilityCode := ""
	for _, edge := range edges(accounts, "billingAccountsConnection") {
		node := field(obj(edge), "node")
		if text(node["urn"]) == accountURN || text(node["uuid"]) == accountURN {
			utilityCode = text(node["utilityCode"])
			break
		}
	}
	if utilityCode == "" {
		return "", ErrProtocolChanged
	}
	// These are the widget's documented default configuration values. The
	// provider expects query parameters flattened into this input (not nested).
	q := map[string]any{"format": f, "urns": []string{accountURN}, "utilityCode": utilityCode, "forceLegacyData": false, "maxAgeOfDataInDays": 1095,
		"messages": []any{}, "unitsOfMeasureAllowed": []any{}, "displayNameStrategy": "UTILITY_ACCOUNT_ID_AS_DISPLAY_NAME_STRATEGY",
		"showServicePoint": false, "showDevice": true, "enableServiceAgreementAliasing": false, "enableFinerResolutions": true,
		"fileUtilityCode": "", "utilityServiceQuantityIdentifiersAllowed": nil, "useLegacyRating": true, "hideIntervalCosts": false, "hideBillingCosts": false,
		"showOnlyNetUsage": false, "showAccountNumber": false, "showAccountNickname": true, "accountNicknameSource": "VMODEL"}
	if o.From != "" || o.To != "" {
		q["timeInterval"] = o.From + "T00:00:00Z/" + o.To + "T23:59:59Z"
	}
	var generated struct {
		Generate struct {
			UUID string `json:"uuid"`
		} `json:"generateUsageExportFile"`
	}
	if err := c.opowerCall(ctx, s, "WUE_GenerateUsageExportFile", greenGenerateMutation, map[string]any{"usageExportFileConfigurationInput": q}, &generated); err != nil {
		return "", err
	}
	if generated.Generate.UUID == "" {
		return "", ErrProtocolChanged
	}
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var result string
	for {
		var job struct {
			Job struct {
				Result   string `json:"result"`
				Running  bool   `json:"isRunning"`
				Failed   bool   `json:"isFailed"`
				Finished bool   `json:"isFinished"`
			} `json:"exportJob"`
		}
		if err := c.opowerCall(ctx, s, "WUE_GetExportJob", greenJobQuery, map[string]any{"jobUuid": generated.Generate.UUID}, &job); err != nil {
			return "", err
		}
		if job.Job.Failed {
			return "", ErrGreenButtonUnavailable
		}
		if job.Job.Finished && !job.Job.Running && job.Job.Result != "" {
			result = job.Job.Result
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return "", ErrGreenButtonUnavailable
		case <-tick.C:
		}
	}
	u, err := url.Parse(result)
	if err != nil || !validExportURL(u) {
		if u != nil {
			return "", errors.New("unsupported Green Button export host: " + u.Hostname())
		}
		return "", ErrProtocolChanged
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", ErrProtocolChanged
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", c.transportFailure(ctx, stepUsageExport, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", protocolError(resp)
	}
	file, err := os.CreateTemp("", ".coned-green-button-*")
	if err != nil {
		return "", ErrProtocolChanged
	}
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", ErrProtocolChanged
	}
	trackedBody := &transportReadTracker{reader: io.LimitReader(resp.Body, maxExportZIP+1)}
	n, err := io.Copy(file, trackedBody)
	if err != nil || n > maxExportZIP {
		_ = file.Close()
		_ = os.Remove(file.Name())
		if trackedBody.err != nil {
			return "", c.transportFailure(ctx, stepUsageExport, trackedBody.err)
		}
		return "", ErrProtocolChanged
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", ErrProtocolChanged
	}
	if err = validateExportZIP(file.Name()); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}
func validExportURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return u.Scheme == "https" && u.User == nil && (strings.HasSuffix(h, ".blob.core.windows.net") || strings.HasSuffix(h, ".opower.com") || strings.HasPrefix(h, "objectstorage.") && strings.HasSuffix(h, ".oraclecloud.com"))
}
func validateExportZIP(name string) error {
	z, err := zip.OpenReader(name)
	if err != nil {
		return ErrProtocolChanged
	}
	defer func() { _ = z.Close() }()
	if len(z.File) == 0 || len(z.File) > maxExportEntries {
		return ErrProtocolChanged
	}
	for _, f := range z.File {
		if f.Flags&1 != 0 || f.FileInfo().Mode()&os.ModeSymlink != 0 || f.UncompressedSize64 > maxExportEntry || f.UncompressedSize64 > f.CompressedSize64*1000+1024 || unsafeExportName(f.Name) {
			return ErrProtocolChanged
		}
	}
	return nil
}
func unsafeExportName(name string) bool {
	return name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, ":") || filepath.IsAbs(name) || strings.Contains("/"+name+"/", "/../")
}

func ExtractGreenButton(name, format string, out io.Writer) error {
	z, err := zip.OpenReader(name)
	if err != nil {
		return ErrProtocolChanged
	}
	defer func() { _ = z.Close() }()
	ext := "." + strings.ToLower(format)
	for _, f := range z.File {
		if strings.EqualFold(filepath.Ext(f.Name), ext) {
			r, e := f.Open()
			if e != nil {
				return ErrProtocolChanged
			}
			_, e = io.Copy(out, io.LimitReader(r, maxExportEntry+1))
			closeErr := r.Close()
			if e != nil || closeErr != nil {
				return ErrProtocolChanged
			}
			return nil
		}
	}
	return ErrProtocolChanged
}
func GreenButtonCSVJSON(name string, out io.Writer) error {
	z, err := zip.OpenReader(name)
	if err != nil {
		return ErrProtocolChanged
	}
	defer func() { _ = z.Close() }()
	for _, f := range z.File {
		if strings.EqualFold(filepath.Ext(f.Name), ".csv") {
			r, e := f.Open()
			if e != nil {
				return ErrProtocolChanged
			}
			defer func() { _ = r.Close() }()
			cr := csv.NewReader(io.LimitReader(r, maxExportEntry+1))
			cr.FieldsPerRecord = -1
			var heads []string
			for i := 0; i < 100; i++ {
				row, readErr := cr.Read()
				if readErr != nil {
					return ErrProtocolChanged
				}
				if len(row) > 1 && strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(row[0]), "\ufeff"), "TYPE") {
					heads = row
					heads[0] = strings.TrimPrefix(heads[0], "\ufeff")
					break
				}
			}
			if len(heads) < 2 {
				return ErrProtocolChanged
			}
			enc := json.NewEncoder(out)
			for {
				row, e := cr.Read()
				if e == io.EOF {
					return nil
				}
				if e != nil || len(row) > len(heads) {
					return ErrProtocolChanged
				}
				for len(row) < len(heads) {
					row = append(row, "")
				}
				m := map[string]string{}
				for i := range heads {
					m[heads[i]] = row[i]
				}
				if enc.Encode(m) != nil {
					return ErrProtocolChanged
				}
			}
		}
	}
	return ErrProtocolChanged
}
