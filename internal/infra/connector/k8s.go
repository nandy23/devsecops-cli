package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// kubeClient is a minimal authenticated client for the Kubernetes API server,
// shared by the Kyverno and Falco connectors.
type kubeClient struct {
	url   string
	token string
	http  *http.Client
}

func newKubeClient(url, token string, insecure bool, hc *http.Client) *kubeClient {
	if hc == nil {
		tr := &http.Transport{}
		if insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - opt-in for self-signed apiservers
		}
		hc = &http.Client{Timeout: 15 * time.Second, Transport: tr}
	}
	return &kubeClient{url: strings.TrimRight(url, "/"), token: token, http: hc}
}

func (k *kubeClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response from %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
