package coned

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/diagnostics"
)

func (c *Client) SchemaDiagnostics(ctx context.Context, session auth.Session) ([]diagnostics.Fingerprint, error) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if session.State(time.Now()) != auth.SessionValid || c.restoreSession(session) != nil {
		return nil, ErrSessionExpired
	}
	token, err := c.mintOpowerToken(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := opowerEdgeBase + "/multi-account-v1/cws/cned/customers?offset=0&batchSize=100&addressFilter="
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, ErrProtocolChanged
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, transportError(ctx)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, protocolError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, ErrProtocolChanged
	}
	fingerprint, err := diagnostics.Collect("opower-customers", "coned-live-verified", body, time.Now())
	if err != nil {
		return nil, ErrProtocolChanged
	}
	return []diagnostics.Fingerprint{fingerprint}, nil
}
