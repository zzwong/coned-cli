package coned

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zzwong/coned-cli/internal/auth"
)

// DiscoverBrowserEndpoint finds a local Chromium DevToolsActivePort file.
func DiscoverBrowserEndpoint() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("browser endpoint not found")
	}
	patterns := []string{
		filepath.Join(home, ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser/DevToolsActivePort"),
		filepath.Join(home, ".config/BraveSoftware/Brave-Browser/DevToolsActivePort"),
		filepath.Join(home, ".config/google-chrome/DevToolsActivePort"),
		filepath.Join(home, "Library/Application Support/BraveSoftware/Brave-Browser/DevToolsActivePort"),
		filepath.Join(home, "Library/Application Support/Google/Chrome/DevToolsActivePort"),
	}
	for _, path := range patterns {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) >= 2 && lines[0] != "" && strings.HasPrefix(lines[1], "/devtools/browser/") {
			return "ws://127.0.0.1:" + lines[0] + lines[1], nil
		}
	}
	return "", errors.New("browser endpoint not found; enable remote debugging or pass --endpoint")
}

// ImportBrowserSession reads only allowlisted Con Edison cookies over local CDP.
func ImportBrowserSession(ctx context.Context, endpoint string) (auth.Session, error) {
	wsURL, err := resolveBrowserWebSocket(ctx, endpoint)
	if err != nil {
		return auth.Session{}, err
	}
	parsed, _ := url.Parse(wsURL)
	if parsed == nil || parsed.Scheme != "ws" && parsed.Scheme != "wss" || !isLoopbackHost(parsed.Hostname()) {
		return auth.Session{}, errors.New("browser endpoint must use a loopback address")
	}
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return auth.Session{}, errors.New("connect to browser endpoint")
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := conn.WriteJSON(map[string]any{"id": 1, "method": "Storage.getCookies"}); err != nil {
		return auth.Session{}, errors.New("request browser cookies")
	}
	var response struct {
		ID     int `json:"id"`
		Result struct {
			Cookies []struct {
				Name, Value, Domain, Path string
				Secure, HTTPOnly          bool
				Expires                   float64
			} `json:"cookies"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	for {
		if err := conn.ReadJSON(&response); err != nil {
			return auth.Session{}, errors.New("read browser cookies")
		}
		if response.ID == 1 {
			break
		}
	}
	if len(response.Error) != 0 {
		return auth.Session{}, errors.New("browser rejected cookie request")
	}
	session := auth.Session{AuthenticatedAt: time.Now()}
	for _, cookie := range response.Result.Cookies {
		if strings.HasSuffix(strings.TrimPrefix(strings.ToLower(cookie.Domain), "."), "coned.com") {
			if os.Getenv("CONED_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "coned debug: browser cookie observed name=%s domain=%s\n", cookie.Name, cookie.Domain)
			}
		}
		if !allowedAuthCookie(cookie.Name) || strings.TrimPrefix(strings.ToLower(cookie.Domain), ".") != "www.coned.com" || cookie.Value == "" {
			continue
		}
		var expires time.Time
		if cookie.Expires > 0 {
			expires = time.Unix(int64(cookie.Expires), 0)
		}
		session.Cookies = append(session.Cookies, auth.Cookie{Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path, Secure: cookie.Secure, HTTPOnly: cookie.HTTPOnly, Expires: expires})
	}
	if auth.ValidateSession(session) != nil {
		return auth.Session{}, errors.New("no authenticated Con Edison browser session found")
	}
	if entity := browserOpowerEntity(conn); entity != "" {
		session.OpowerEntities = []string{"urn:external:opower:entity:id:" + entity}
	}
	return session, nil
}

func browserOpowerEntity(conn *websocket.Conn) string {
	if conn.WriteJSON(map[string]any{"id": 2, "method": "Target.getTargets"}) != nil {
		return ""
	}
	var targets struct {
		ID     int `json:"id"`
		Result struct {
			Infos []struct{ TargetID, Type, URL string } `json:"targetInfos"`
		} `json:"result"`
	}
	for targets.ID != 2 {
		if conn.ReadJSON(&targets) != nil {
			return ""
		}
	}
	target := ""
	for _, info := range targets.Result.Infos {
		if info.Type == "page" && strings.Contains(info.URL, "coned.com") {
			target = info.TargetID
			if strings.Contains(info.URL, "energy-use") {
				break
			}
		}
	}
	if target == "" {
		return ""
	}
	if conn.WriteJSON(map[string]any{"id": 3, "method": "Target.attachToTarget", "params": map[string]any{"targetId": target, "flatten": true}}) != nil {
		return ""
	}
	var attached struct {
		ID     int `json:"id"`
		Result struct {
			SessionID string `json:"sessionId"`
		} `json:"result"`
	}
	for attached.ID != 3 {
		if conn.ReadJSON(&attached) != nil {
			return ""
		}
	}
	expr := `(()=>{for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);if(k.startsWith('opower-entity-store:')){try{const x=JSON.parse(sessionStorage.getItem(k));return x?.billingAccount?.mappedCustomers?.[0]?.utilityInternalId||''}catch(e){}}}return ''})()`
	if conn.WriteJSON(map[string]any{"id": 4, "sessionId": attached.Result.SessionID, "method": "Runtime.evaluate", "params": map[string]any{"expression": expr, "returnByValue": true}}) != nil {
		return ""
	}
	var evaluated struct {
		ID     int `json:"id"`
		Result struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		} `json:"result"`
	}
	for evaluated.ID != 4 {
		if conn.ReadJSON(&evaluated) != nil {
			return ""
		}
	}
	return evaluated.Result.Result.Value
}

func resolveBrowserWebSocket(ctx context.Context, endpoint string) (string, error) {
	if endpoint == "" {
		return DiscoverBrowserEndpoint()
	}
	u, err := url.Parse(endpoint)
	if err != nil || !isLoopbackHost(u.Hostname()) {
		return "", errors.New("browser endpoint must use a loopback address")
	}
	if u.Scheme == "ws" || u.Scheme == "wss" {
		return endpoint, nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("invalid browser endpoint")
	}
	versionURL := strings.TrimRight(endpoint, "/") + "/json/version"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.New("query browser endpoint")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("query browser endpoint: status %d", response.StatusCode)
	}
	var version struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if json.NewDecoder(response.Body).Decode(&version) != nil || version.WebSocketDebuggerURL == "" {
		return "", errors.New("invalid browser endpoint response")
	}
	ws, err := url.Parse(version.WebSocketDebuggerURL)
	if err != nil || !isLoopbackHost(ws.Hostname()) || net.ParseIP(ws.Hostname()) != nil && !net.ParseIP(ws.Hostname()).IsLoopback() {
		return "", errors.New("unsafe browser websocket endpoint")
	}
	return version.WebSocketDebuggerURL, nil
}
