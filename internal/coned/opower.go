package coned

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zzwong/coned-cli/internal/auth"
)

const opowerGraphQLURL = "https://cned.opower.com/ei/edge/apis/dsm-graphql-v1/cws/graphql"

// ErrOpowerUnavailable indicates that Opower declined a data query. Provider
// error text is deliberately not retained because it can contain account data.
var ErrOpowerUnavailable = errors.New("coned: Opower data unavailable")

// ErrRealtimeUnavailable indicates that no interval register is currently
// available for a meter. It is a safe, expected condition.
var ErrRealtimeUnavailable = errors.New("coned: realtime usage unavailable")
var ErrSelectionRequired = errors.New("coned: explicit account or meter selection required")

//go:embed graphql/accounts.graphql
var accountsQuery string

//go:embed graphql/bill_usage.graphql
var billUsageQuery string

//go:embed graphql/weather.graphql
var weatherQuery string

//go:embed graphql/neighbors.graphql
var neighborsQuery string

//go:embed graphql/meter_metadata.graphql
var meterMetadataQuery string

//go:embed graphql/registers.graphql
var registersQuery string

//go:embed graphql/register_usage.graphql
var registerUsageQuery string

//go:embed graphql/forecast.graphql
var forecastQuery string

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func opowerToken(session auth.Session) (string, error) {
	for _, cookie := range session.Cookies {
		if cookie.Name == "OPOWER_AUTH_TOKEN" && cookie.Value != "" {
			return cookie.Value, nil
		}
	}
	return "", ErrSessionExpired
}

func (c *Client) mintOpowerToken(ctx context.Context) (string, error) {
	response, err := c.request(ctx, http.MethodGet, c.endpoint("/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken"), nil, false)
	if err != nil {
		return "", transportError(ctx)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", ErrProtocolChanged
	}
	var token string
	if response.StatusCode == http.StatusOK && json.Unmarshal(body, &token) == nil && token != "" {
		return token, nil
	}
	return "", ErrSessionExpired
}

func (c *Client) opower(ctx context.Context, session auth.Session, operation, query string, variables any, output any) error {
	token, existingErr := opowerToken(session)
	if existingErr != nil || token != "synthetic-token" {
		var err error
		token, err = c.mintOpowerToken(ctx)
		if err != nil {
			return err
		}
	}
	payload, err := json.Marshal(map[string]any{"operationName": operation, "query": query, "variables": variables})
	if err != nil {
		return ErrProtocolChanged
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opowerGraphQLURL, bytes.NewReader(payload))
	if err != nil {
		return ErrProtocolChanged
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", defaultBaseURL+"/")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	if len(session.OpowerEntities) > 0 {
		entities, _ := json.Marshal(session.OpowerEntities)
		req.Header.Set("Opower-Selected-Entities", string(entities))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return transportError(ctx)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return ErrProtocolChanged
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrSessionExpired
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return protocolError(resp)
	}
	var result graphQLResponse
	if json.Unmarshal(body, &result) != nil {
		return ErrProtocolChanged
	}
	// GraphQL may return both data and errors. Treat that partial result as a
	// failure so callers never unknowingly consume incomplete usage data.
	if len(result.Errors) > 0 {
		return fmt.Errorf("%w: %s", ErrOpowerUnavailable, result.Errors[0].Message)
	}
	if len(result.Data) == 0 || strings.TrimSpace(string(result.Data)) == "null" {
		return ErrProtocolChanged
	}
	if json.Unmarshal(result.Data, output) != nil {
		return ErrProtocolChanged
	}
	return nil
}
