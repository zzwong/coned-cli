package coned

import (
	"context"
	"strings"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

type Account struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	UtilityCode           string `json:"utility_code"`
	CustomerClass         string `json:"customer_class"`
	ServiceAgreementCount int    `json:"service_agreement_count"`
}
type EntitySelection struct{ Account, Meter string }
type UsageOptions struct {
	Account          string
	Premise          string
	ServiceAgreement string
	ServicePoint     string
	Start            string
	End              string
}
type Quantity struct {
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}
type UsageBill struct {
	Start     string   `json:"start"`
	End       string   `json:"end"`
	Estimated bool     `json:"estimated"`
	Usage     Quantity `json:"usage"`
	Charges   float64  `json:"charges"`
}
type Weather struct {
	Start   string  `json:"start"`
	End     string  `json:"end"`
	Minimum float64 `json:"minimum"`
	Mean    float64 `json:"mean"`
	Maximum float64 `json:"maximum"`
}
type NeighborComparison struct {
	MeterType          string   `json:"meter_type"`
	Start              string   `json:"start"`
	End                string   `json:"end"`
	You                Quantity `json:"you"`
	EfficientNeighbors Quantity `json:"efficient_neighbors"`
	AllNeighbors       Quantity `json:"all_neighbors"`
	NeighborCount      int      `json:"neighbor_count"`
}
type Meter struct {
	ID                   string `json:"id"`
	ServiceType          string `json:"service_type"`
	ReadResolution       string `json:"read_resolution"`
	Unit                 string `json:"unit"`
	AvailableStart       string `json:"available_start"`
	AvailableEnd         string `json:"available_end"`
	serviceAgreementUUID string
	servicePointUUID     string
}
type UsageRead struct {
	Start string  `json:"start"`
	End   string  `json:"end"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}
type UsageSummary struct {
	Bills   int      `json:"bills"`
	Usage   Quantity `json:"usage"`
	Charges float64  `json:"charges"`
}

func maskedID(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 4 {
		if v == "" {
			return ""
		}
		return "****"
	}
	return "****" + v[len(v)-4:]
}
func interval(o UsageOptions) any {
	if o.Start == "" && o.End == "" {
		return nil
	}
	return o.Start + "/" + o.End
}
func timeParts(v string) (string, string) {
	p := strings.SplitN(v, "/", 2)
	if len(p) == 2 {
		return p[0], p[1]
	}
	return v, ""
}
func obj(v any) map[string]any                        { x, _ := v.(map[string]any); return x }
func arr(v any) []any                                 { x, _ := v.([]any); return x }
func text(v any) string                               { x, _ := v.(string); return x }
func number(v any) float64                            { x, _ := v.(float64); return x }
func truth(v any) bool                                { x, _ := v.(bool); return x }
func field(m map[string]any, k string) map[string]any { return obj(m[k]) }
func edges(m map[string]any, k string) []any          { return arr(field(m, k)["edges"]) }
func quantity(v any) Quantity {
	m := obj(v)
	return Quantity{Unit: text(m["unit"]), Value: number(m["value"])}
}

func (c *Client) opowerCall(ctx context.Context, s auth.Session, op, q string, vars any, out any) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if s.State(time.Now()) != auth.SessionValid || c.restoreSession(s) != nil {
		return ErrSessionExpired
	}
	return c.opower(ctx, s, op, q, vars, out)
}
func (c *Client) callMap(ctx context.Context, s auth.Session, op, q string, vars any) (map[string]any, error) {
	var out map[string]any
	err := c.opowerCall(ctx, s, op, q, vars, &out)
	return out, err
}

// ListAccounts returns only masked provider identifiers.
func (c *Client) ListAccounts(ctx context.Context, s auth.Session) ([]Account, error) {
	d, e := c.callMap(ctx, s, "WBAS_BillingAccounts", accountsQuery, map[string]any{"first": 100, "onlyActive": true})
	if e != nil {
		return nil, e
	}
	var out []Account
	for _, x := range edges(d, "billingAccountsConnection") {
		n := field(obj(x), "node")
		id := text(n["urn"])
		if id == "" {
			id = text(n["uuid"])
		}
		out = append(out, Account{maskedID(id), text(n["name"]), text(n["utilityCode"]), text(n["customerClass"]), int(number(field(n, "serviceAgreementsConnection")["totalCount"]))})
	}
	return out, nil
}
func vars(o UsageOptions) map[string]any {
	return map[string]any{"selectedAccount": o.Account, "forceLegacyData": false, "premiseUuid": o.Premise}
}
func (c *Client) UsageBills(ctx context.Context, s auth.Session, o UsageOptions) ([]UsageBill, error) {
	v := vars(o)
	v["last"] = 26
	v["timeInterval"] = interval(o)
	v["aliased"] = false
	d, e := c.callMap(ctx, s, "WDB_GetCostUsageReadsForBills", billUsageQuery, v)
	if e != nil {
		return nil, e
	}
	var out []UsageBill
	for _, b := range arr(field(d, "billingAccountByAuthContext")["bills"]) {
		bm := obj(b)
		for _, x := range arr(bm["segments"]) {
			m := obj(x)
			start, end := timeParts(text(m["usageInterval"]))
			if start == "" {
				start, end = timeParts(text(bm["timeInterval"]))
			}
			q := Quantity{}
			if qs := arr(m["serviceQuantities"]); len(qs) > 0 {
				qm := obj(qs[0])
				q = Quantity{text(qm["unit"]), number(field(qm, "serviceQuantity")["value"])}
			}
			out = append(out, UsageBill{start, end, truth(m["estimated"]), q, number(field(m, "usageCharges")["value"])})
		}
	}
	return out, nil
}
func (c *Client) UsageWeather(ctx context.Context, s auth.Session, o UsageOptions) ([]Weather, error) {
	now := time.Now()
	o.Start, o.End = now.AddDate(0, -6, 1).Format(time.RFC3339), now.Format(time.RFC3339)
	v := vars(o)
	v["unit"] = "FAHRENHEIT"
	v["timeInterval"] = []any{interval(o)}
	v["weatherResolution"] = "MULTI_DAY"
	d, e := c.callMap(ctx, s, "WDB_GetWeather", weatherQuery, v)
	if e != nil {
		return nil, e
	}
	var out []Weather
	for _, x := range edges(field(d, "billingAccountByAuthContext"), "premisesConnection") {
		n := field(obj(x), "node")
		for _, w := range arr(n["weather"]) {
			m := obj(w)
			a, b := timeParts(text(m["timeInterval"]))
			out = append(out, Weather{a, b, number(field(m, "minTemperature")["value"]), number(field(m, "meanTemperature")["value"]), number(field(m, "maxTemperature")["value"])})
		}
	}
	return out, nil
}
func (c *Client) UsageNeighbors(ctx context.Context, s auth.Session, o UsageOptions) ([]NeighborComparison, error) {
	d, e := c.callMap(ctx, s, "WDB_GetNeighborComparisons", neighborsQuery, vars(o))
	if e != nil {
		return nil, e
	}
	var out []NeighborComparison
	for _, x := range edges(field(d, "billingAccountByAuthContext"), "premisesConnection") {
		edge := obj(x)
		for _, key := range []string{"elec", "gas", "combined"} {
			for _, z := range arr(edge[key]) {
				m := obj(z)
				a, b := timeParts(text(m["timeInterval"]))
				out = append(out, NeighborComparison{text(m["meterType"]), a, b, quantity(m["youUsage"]), quantity(m["efficientNeighborsThresholdUsage"]), quantity(m["averageOfAllNeighborsUsage"]), int(number(m["numberOfNeighbors"]))})
			}
		}
	}
	return out, nil
}
func (c *Client) UsageMeters(ctx context.Context, s auth.Session, o UsageOptions) ([]Meter, error) {
	v := vars(o)
	d, e := c.callMap(ctx, s, "WRTAMI_GetMetadata", meterMetadataQuery, v)
	if e != nil {
		return nil, e
	}
	var out []Meter
	for _, a := range edges(field(d, "billingAccountByAuthContext"), "serviceAgreementsConnection") {
		sa := field(obj(a), "node")
		for _, p := range edges(sa, "servicePointsConnection") {
			sp := field(obj(p), "node")
			for _, r := range arr(sp["registers"]) {
				m := obj(r)
				a, b := timeParts(text(m["availableReadsTimeInterval"]))
				out = append(out, Meter{ID: maskedID(text(sp["uuid"])), ServiceType: text(sa["serviceType"]), ReadResolution: text(m["readResolution"]), Unit: text(m["unitOfMeasure"]), AvailableStart: a, AvailableEnd: b, serviceAgreementUUID: text(sa["uuid"]), servicePointUUID: text(sp["uuid"])})
			}
		}
	}
	return out, nil
}
func (c *Client) UsageRealtime(ctx context.Context, s auth.Session, o UsageOptions) ([]UsageRead, error) {
	now := time.Now()
	o.Start, o.End = now.Add(-24*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)
	meters, err := c.UsageMeters(ctx, s, o)
	if err != nil || len(meters) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrRealtimeUnavailable
	}
	m := meters[0]
	v := vars(o)
	v["timeInterval"] = interval(o)
	v["saUuid"] = m.serviceAgreementUUID
	v["spUuid"] = m.servicePointUUID
	d, err := c.callMap(ctx, s, "WRTAMI_GetRegisters", registersQuery, v)
	if err != nil {
		return nil, err
	}
	var register string
	for _, a := range edges(field(d, "billingAccountByAuthContext"), "serviceAgreementsConnection") {
		for _, p := range edges(field(obj(a), "node"), "servicePointsConnection") {
			reads := arr(field(obj(p), "node")["intervalReads"])
			if len(reads) > 0 {
				register = text(obj(reads[0])["registerId"])
			}
		}
	}
	if register == "" {
		return nil, ErrRealtimeUnavailable
	}
	o.ServiceAgreement, o.ServicePoint = m.serviceAgreementUUID, m.servicePointUUID
	r, err := c.usageReads(ctx, s, o, register)
	if err != nil || len(r) == 0 {
		return nil, ErrRealtimeUnavailable
	}
	return r, nil
}
func (c *Client) UsageExport(ctx context.Context, s auth.Session, o UsageOptions) ([]UsageBill, error) {
	return c.UsageBills(ctx, s, o)
}
func (c *Client) usageReads(ctx context.Context, s auth.Session, o UsageOptions, register string) ([]UsageRead, error) {
	v := vars(o)
	v["registerId"] = register
	v["timeInterval"] = interval(o)
	v["saUuid"] = o.ServiceAgreement
	v["spUuid"] = o.ServicePoint
	d, e := c.callMap(ctx, s, "WRTAMI_GetRegisterUsage", registerUsageQuery, v)
	if e != nil {
		return nil, e
	}
	var out []UsageRead
	for _, a := range edges(field(d, "billingAccountByAuthContext"), "serviceAgreementsConnection") {
		for _, p := range edges(field(obj(a), "node"), "servicePointsConnection") {
			for _, r := range arr(field(obj(p), "node")["intervalReads"]) {
				rm := obj(r)
				for _, z := range arr(rm["reads"]) {
					m := obj(z)
					a, b := timeParts(text(m["timeInterval"]))
					out = append(out, UsageRead{a, b, text(rm["unit"]), number(field(m, "measuredAmount")["value"])})
				}
			}
		}
	}
	return out, nil
}

func (c *Client) defaultUsageOptions(ctx context.Context, s auth.Session) (UsageOptions, error) {
	return c.selectedUsageOptions(ctx, s, EntitySelection{})
}
func (c *Client) selectedUsageOptions(ctx context.Context, s auth.Session, selection EntitySelection) (UsageOptions, error) {
	d, err := c.callMap(ctx, s, "WBAS_BillingAccounts", accountsQuery, map[string]any{"first": 100, "onlyActive": true})
	if err != nil {
		return UsageOptions{}, err
	}
	e := edges(d, "billingAccountsConnection")
	if len(e) == 0 {
		return UsageOptions{}, ErrProtocolChanged
	}
	selectedAccount := ""
	for _, edge := range e {
		id := text(field(obj(edge), "node")["urn"])
		if selection.Account == "" {
			if selectedAccount != "" {
				return UsageOptions{}, ErrSelectionRequired
			}
			selectedAccount = id
		} else if id == selection.Account {
			selectedAccount = id
			break
		}
	}
	if selectedAccount == "" {
		return UsageOptions{}, ErrSelectionRequired
	}
	now := time.Now()
	o := UsageOptions{Account: selectedAccount, Start: now.AddDate(-1, -3, 0).Format(time.RFC3339), End: now.AddDate(0, 0, 1).Format(time.RFC3339)}
	m, err := c.callMap(ctx, s, "WRTAMI_GetMetadata", meterMetadataQuery, vars(o))
	if err != nil {
		return o, nil
	}
	for _, a := range edges(field(m, "billingAccountByAuthContext"), "serviceAgreementsConnection") {
		sa := field(obj(a), "node")
		o.ServiceAgreement = text(sa["uuid"])
		for _, p := range edges(sa, "servicePointsConnection") {
			sp := field(obj(p), "node")
			spID := text(sp["uuid"])
			if selection.Meter != "" && selection.Meter != spID {
				continue
			}
			if o.ServicePoint != "" {
				return UsageOptions{}, ErrSelectionRequired
			}
			o.ServiceAgreement = text(sa["uuid"])
			o.ServicePoint = spID
			o.Premise = text(field(sp, "premise")["uuid"])
		}
	}
	if selection.Meter != "" && o.ServicePoint == "" {
		return UsageOptions{}, ErrSelectionRequired
	}
	return o, nil
}

// Fetch implements the CLI's narrow read-only Opower boundary.
func (c *Client) Fetch(ctx context.Context, s auth.Session, resource string) (any, error) {
	return c.FetchSelected(ctx, s, resource, EntitySelection{})
}
func (c *Client) FetchSelected(ctx context.Context, s auth.Session, resource string, selection EntitySelection) (any, error) {
	if resource == "accounts" {
		return c.ListAccounts(ctx, s)
	}
	o, err := c.selectedUsageOptions(ctx, s, selection)
	if err != nil {
		return nil, err
	}
	switch resource {
	case "usage-bills":
		return c.UsageBills(ctx, s, o)
	case "weather":
		return c.UsageWeather(ctx, s, o)
	case "neighbors":
		return c.UsageNeighbors(ctx, s, o)
	case "meters":
		return c.UsageMeters(ctx, s, o)
	case "realtime":
		return c.UsageRealtime(ctx, s, o)
	case "summary":
		return c.UsageSummary(ctx, s, o)
	case "export":
		return c.UsageExport(ctx, s, o)
	default:
		return nil, ErrProtocolChanged
	}
}

func (c *Client) UsageSummary(ctx context.Context, s auth.Session, o UsageOptions) (UsageSummary, error) {
	b, e := c.UsageBills(ctx, s, o)
	if e != nil {
		return UsageSummary{}, e
	}
	var out UsageSummary
	for _, x := range b {
		out.Bills++
		out.Usage.Unit = x.Usage.Unit
		out.Usage.Value += x.Usage.Value
		out.Charges += x.Charges
	}
	return out, nil
}
