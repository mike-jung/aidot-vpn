package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HTTPAuth talks to the controller's relay-auth endpoints to verify
// tokens. The relay process owns no user data of its own — it asks the
// controller "is this token valid? for what identity?"
//
// The endpoints we hit:
//
//	POST {controller}/relay/verify-data-node   {"token": "..."} -> {"node_id": "..."}
//	POST {controller}/relay/verify-mobile      {"token": "..."} -> {"session_id": "..."}
//
// Both endpoints are protected by a shared secret (`X-Relay-Secret`
// header) so a random internet caller can't enumerate. The controller
// only responds when the header matches a configured value.
type HTTPAuth struct {
	ControllerBase string
	SharedSecret   string
	Client         *http.Client
}

// NewHTTPAuth returns a ready HTTPAuth with sensible defaults.
func NewHTTPAuth(controllerBase, sharedSecret string) *HTTPAuth {
	return &HTTPAuth{
		ControllerBase: controllerBase,
		SharedSecret:   sharedSecret,
		Client:         &http.Client{Timeout: 5 * time.Second},
	}
}

func (a *HTTPAuth) VerifyDataNode(ctx context.Context, token string) (string, error) {
	var resp struct {
		NodeID string `json:"node_id"`
		Error  string `json:"error,omitempty"`
	}
	if err := a.call(ctx, "/relay/verify-data-node", token, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	if resp.NodeID == "" {
		return "", errors.New("empty node_id in verify response")
	}
	return resp.NodeID, nil
}

func (a *HTTPAuth) VerifyMobile(ctx context.Context, token string) (string, error) {
	var resp struct {
		SessionID string `json:"session_id"`
		Error     string `json:"error,omitempty"`
	}
	if err := a.call(ctx, "/relay/verify-mobile", token, &resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	if resp.SessionID == "" {
		return "", errors.New("empty session_id in verify response")
	}
	return resp.SessionID, nil
}

func (a *HTTPAuth) call(ctx context.Context, path, token string, out any) error {
	form := url.Values{"token": []string{token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.ControllerBase+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	// We pass the token as a form-encoded body so it never lands in
	// query strings or access logs.
	req.URL.RawQuery = ""
	req.Body = io.NopCloser(stringReader(form.Encode()))
	req.ContentLength = int64(len(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Relay-Secret", a.SharedSecret)

	resp, err := a.Client.Do(req)
	if err != nil {
		return fmt.Errorf("auth call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("auth HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// stringReader avoids importing strings.NewReader in this small file.
type stringReader string

func (s stringReader) Read(p []byte) (int, error) {
	n := copy(p, s)
	if n < len(s) {
		return n, nil
	}
	return n, io.EOF
}
