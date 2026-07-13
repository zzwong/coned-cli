package coned

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
)

const opowerEdgeBase = "https://cned.opower.com/ei/edge/apis"

type ReadOptions struct {
	Aggregate string
	From      string
	To        string
}

type Forecast struct {
	Account       string  `json:"account"`
	Start         string  `json:"start"`
	End           string  `json:"end"`
	Current       string  `json:"current"`
	Unit          string  `json:"unit"`
	UsageToDate   float64 `json:"usage_to_date"`
	CostToDate    float64 `json:"cost_to_date"`
	ForecastUsage float64 `json:"forecast_usage"`
	ForecastCost  float64 `json:"forecast_cost"`
	TypicalUsage  float64 `json:"typical_usage"`
	TypicalCost   float64 `json:"typical_cost"`
}

type HistoricalRead struct {
	Account string  `json:"account"`
	Start   string  `json:"start"`
	End     string  `json:"end"`
	Value   float64 `json:"value"`
}

type CostRead struct {
	Account string  `json:"account"`
	Start   string  `json:"start"`
	End     string  `json:"end"`
	Value   float64 `json:"value"`
	Cost    float64 `json:"cost"`
}

type opowerAccount struct {
	Customer string
	UUID     string
}

func (c *Client) Forecast(ctx context.Context, session auth.Session) ([]Forecast, error) {
	d, err := c.callMap(ctx, session, "GetBillForecast", forecastQuery, map[string]any{})
	if err != nil {
		return nil, err
	}
	var out []Forecast
	for _, edge := range edges(d, "billingAccountsConnection") {
		forecast := field(obj(edge), "node")["billForecast"]
		fm := obj(forecast)
		start, end := timeParts(text(fm["timeInterval"]))
		if start == "" || end == "" {
			continue
		}
		for _, raw := range arr(fm["segments"]) {
			segment := obj(raw)
			id := text(field(segment, "serviceAgreement")["uuid"])
			if id == "" {
				continue
			}
			out = append(out, Forecast{
				Account: maskedID(id), Start: start, End: end, Current: text(fm["currentDateTime"]),
				Unit:          text(field(segment, "estimatedUsage")["unit"]),
				UsageToDate:   number(field(segment, "soFarUsage")["value"]),
				CostToDate:    number(field(segment, "soFarUsageCharges")["value"]),
				ForecastUsage: number(field(segment, "estimatedUsage")["value"]),
				ForecastCost:  number(field(segment, "estimatedUsageCharges")["value"]),
				TypicalUsage:  number(field(segment, "priorYearUsage")["value"]),
				TypicalCost:   number(field(segment, "priorYearUsageCharges")["value"]),
			})
		}
	}
	return out, nil
}

func (c *Client) HistoricalReads(ctx context.Context, session auth.Session, options ReadOptions) ([]HistoricalRead, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if session.State(time.Now()) != auth.SessionValid || c.restoreSession(session) != nil {
		return nil, ErrSessionExpired
	}
	accounts, token, err := c.opowerAccounts(ctx, session)
	if err != nil {
		return nil, err
	}
	windows, err := readWindows(options)
	if err != nil {
		return nil, err
	}
	var out []HistoricalRead
	for _, account := range accounts {
		for _, window := range windows {
			reads, fetchErr := c.fetchReads(ctx, session, token, account, options.Aggregate, window, false)
			if fetchErr != nil {
				return nil, fetchErr
			}
			for _, read := range reads {
				out = append(out, HistoricalRead{maskedID(account.UUID), read.Start, read.End, read.Value})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

func (c *Client) HistoricalCosts(ctx context.Context, session auth.Session, options ReadOptions) ([]CostRead, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if session.State(time.Now()) != auth.SessionValid || c.restoreSession(session) != nil {
		return nil, ErrSessionExpired
	}
	accounts, token, err := c.opowerAccounts(ctx, session)
	if err != nil {
		return nil, err
	}
	windows, err := readWindows(options)
	if err != nil {
		return nil, err
	}
	var out []CostRead
	for _, account := range accounts {
		for _, window := range windows {
			reads, fetchErr := c.fetchReads(ctx, session, token, account, options.Aggregate, window, true)
			if options.Aggregate == "bill" && protocolStatus(fetchErr) == http.StatusInternalServerError {
				fetchErr = nil
				reads = nil
			}
			meaningful := false
			for _, read := range reads {
				if read.Value != 0 || read.Cost != 0 {
					meaningful = true
					break
				}
			}
			if options.Aggregate != "bill" && (fetchErr != nil || !meaningful) {
				reads, fetchErr = c.fetchReads(ctx, session, token, account, options.Aggregate, window, false)
			}
			if fetchErr != nil {
				return nil, fetchErr
			}
			for _, read := range reads {
				out = append(out, CostRead{maskedID(account.UUID), read.Start, read.End, read.Value, read.Cost})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

type readWindow struct{ Start, End time.Time }
type rawRead struct {
	Start, End  string
	Value, Cost float64
}

func readWindows(options ReadOptions) ([]readWindow, error) {
	if options.Aggregate != "bill" && options.Aggregate != "day" && options.Aggregate != "hour" {
		return nil, ErrProtocolChanged
	}
	if options.From == "" && options.To == "" {
		if options.Aggregate == "bill" {
			return []readWindow{{}}, nil
		}
		return nil, ErrProtocolChanged
	}
	if options.From == "" || options.To == "" {
		return nil, ErrProtocolChanged
	}
	location, _ := time.LoadLocation("America/New_York")
	start, e1 := time.ParseInLocation("2006-01-02", options.From, location)
	end, e2 := time.ParseInLocation("2006-01-02", options.To, location)
	if e1 != nil || e2 != nil || end.Before(start) {
		return nil, ErrProtocolChanged
	}
	end = end.AddDate(0, 0, 1)
	step := 0
	if options.Aggregate == "day" {
		step = 363
	}
	if options.Aggregate == "hour" {
		step = 26
	}
	if step == 0 {
		return []readWindow{{start, end}}, nil
	}
	var windows []readWindow
	for cursor := start; cursor.Before(end); {
		next := cursor.AddDate(0, 0, step)
		if next.After(end) {
			next = end
		}
		windows = append(windows, readWindow{cursor, next})
		cursor = next
	}
	return windows, nil
}

func (c *Client) opowerAccounts(ctx context.Context, session auth.Session) ([]opowerAccount, string, error) {
	token, err := c.mintOpowerToken(ctx)
	if err != nil {
		return nil, "", err
	}
	var response struct {
		Customers []struct {
			UUID            string `json:"uuid"`
			UtilityAccounts []struct {
				UUID string `json:"uuid"`
			} `json:"utilityAccounts"`
		} `json:"customers"`
	}
	endpoint := opowerEdgeBase + "/multi-account-v1/cws/cned/customers?offset=0&batchSize=100&addressFilter="
	if err = c.opowerGET(ctx, session, token, endpoint, "", &response); err != nil {
		return nil, "", err
	}
	var accounts []opowerAccount
	for _, customer := range response.Customers {
		for _, account := range customer.UtilityAccounts {
			if account.UUID != "" {
				accounts = append(accounts, opowerAccount{customer.UUID, account.UUID})
			}
		}
	}
	if len(accounts) == 0 {
		return nil, "", ErrProtocolChanged
	}
	return accounts, token, nil
}

func (c *Client) fetchReads(ctx context.Context, session auth.Session, token string, account opowerAccount, aggregate string, window readWindow, costs bool) ([]rawRead, error) {
	var path string
	if costs {
		path = "/DataBrowser-v1/cws/cost/utilityAccount/" + url.PathEscape(account.UUID)
	} else {
		path = "/DataBrowser-v1/cws/utilities/cned/utilityAccounts/" + url.PathEscape(account.UUID) + "/reads"
	}
	query := url.Values{"aggregateType": {aggregate}}
	if !window.Start.IsZero() {
		if costs {
			query.Set("startDate", window.Start.Format(time.RFC3339))
			query.Set("endDate", window.End.Format(time.RFC3339))
		} else {
			query.Set("startDate", window.Start.Format("2006-01-02"))
			query.Set("endDate", window.End.Format("2006-01-02"))
		}
	}
	var response struct {
		Reads []map[string]any `json:"reads"`
	}
	if err := c.opowerGET(ctx, session, token, opowerEdgeBase+path+"?"+query.Encode(), account.Customer, &response); err != nil {
		return nil, err
	}
	out := make([]rawRead, 0, len(response.Reads))
	for _, item := range response.Reads {
		value := number(item["value"])
		if consumption := field(item, "consumption"); value == 0 && consumption != nil {
			value = number(consumption["value"])
		}
		out = append(out, rawRead{text(item["startTime"]), text(item["endTime"]), value, number(item["providedCost"])})
	}
	return out, nil
}

func protocolStatus(err error) int {
	if err == nil {
		return 0
	}
	if safe, ok := AsSafeProtocolError(err); ok {
		return safe.Status
	}
	return 0
}

func (c *Client) opowerGET(ctx context.Context, session auth.Session, token, endpoint, customer string, output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrProtocolChanged
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", defaultBaseURL+"/")
	entities := session.OpowerEntities
	if customer != "" {
		entities = []string{"urn:opower:customer:uuid:" + customer}
	}
	if len(entities) > 0 {
		encoded, _ := json.Marshal(entities)
		req.Header.Set("Opower-Selected-Entities", string(encoded))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return transportError(ctx)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return ErrProtocolChanged
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return protocolError(resp)
	}
	if json.Unmarshal(body, output) != nil {
		return ErrProtocolChanged
	}
	return nil
}
