package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// ZoraxyClient handles HTTP communication with the Zoraxy admin API.
// It manages session-based authentication (login + cookie jar).
type ZoraxyClient struct {
	baseURL  string
	username string
	password string
	client   *http.Client
	mu       sync.Mutex
	loggedIn bool
}

func NewZoraxyClient(baseURL, username, password string) *ZoraxyClient {
	jar, _ := cookiejar.New(nil)
	return &ZoraxyClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		username: username,
		password: password,
		client:   &http.Client{Jar: jar},
	}
}

// login authenticates with Zoraxy and stores the session cookie.
func (z *ZoraxyClient) login() error {
	form := url.Values{}
	form.Set("username", z.username)
	form.Set("password", z.password)

	resp, err := z.client.PostForm(z.baseURL+"/api/auth/login", form)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	// Check response for success
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err == nil {
		if errMsg, ok := result["error"].(string); ok && errMsg != "" {
			return fmt.Errorf("login failed: %s", errMsg)
		}
	}

	z.loggedIn = true
	return nil
}

// ensureLoggedIn makes sure we have an active session.
func (z *ZoraxyClient) ensureLoggedIn() error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if !z.loggedIn {
		return z.login()
	}
	return nil
}

// doRequest makes an authenticated request to Zoraxy. Retries login once on 401.
func (z *ZoraxyClient) doRequest(method, path string, form url.Values) ([]byte, int, error) {
	if err := z.ensureLoggedIn(); err != nil {
		return nil, 0, err
	}

	body, status, err := z.rawRequest(method, path, form)
	if err != nil {
		return nil, 0, err
	}

	// If we got a 401, try re-login once and retry
	if status == http.StatusUnauthorized {
		z.mu.Lock()
		z.loggedIn = false
		z.mu.Unlock()

		if err := z.ensureLoggedIn(); err != nil {
			return nil, 0, err
		}
		return z.rawRequest(method, path, form)
	}

	return body, status, nil
}

func (z *ZoraxyClient) rawRequest(method, path string, form url.Values) ([]byte, int, error) {
	fullURL := z.baseURL + path

	var req *http.Request
	var err error

	if method == http.MethodGet {
		if form != nil {
			fullURL += "?" + form.Encode()
		}
		req, err = http.NewRequest(method, fullURL, nil)
	} else {
		var bodyReader io.Reader
		if form != nil {
			bodyReader = strings.NewReader(form.Encode())
		}
		req, err = http.NewRequest(method, fullURL, bodyReader)
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := z.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}

	return body, resp.StatusCode, nil
}

// --- Proxy Management ---

// ListProxies returns all proxy endpoints.
func (z *ZoraxyClient) ListProxies() (json.RawMessage, error) {
	body, status, err := z.doRequest(http.MethodGet, "/api/proxy/list", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list proxies failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// GetProxyDetail returns details for a specific proxy endpoint.
func (z *ZoraxyClient) GetProxyDetail(epType, rootname string) (json.RawMessage, error) {
	form := url.Values{}
	form.Set("type", epType)
	form.Set("ep", rootname)
	body, status, err := z.doRequest(http.MethodGet, "/api/proxy/detail", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get proxy detail failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// AddProxy creates a new proxy endpoint.
func (z *ZoraxyClient) AddProxy(params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/add", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("add proxy failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// EditProxy modifies an existing proxy endpoint.
func (z *ZoraxyClient) EditProxy(params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/edit", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("edit proxy failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// DeleteProxy removes a proxy endpoint.
func (z *ZoraxyClient) DeleteProxy(epType, rootname string) (json.RawMessage, error) {
	form := url.Values{}
	form.Set("type", epType)
	form.Set("ep", rootname)
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/del", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("delete proxy failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// --- Upstream (Load Balancer) Management ---

// ListUpstreams returns all upstreams for a proxy endpoint.
func (z *ZoraxyClient) ListUpstreams(epType, rootname string) (json.RawMessage, error) {
	form := url.Values{}
	form.Set("type", epType)
	form.Set("ep", rootname)
	body, status, err := z.doRequest(http.MethodGet, "/api/proxy/upstream/list", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list upstreams failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// AddUpstream adds a backend server to a proxy endpoint's load balancer pool.
func (z *ZoraxyClient) AddUpstream(params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/upstream/add", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("add upstream failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// UpdateUpstream modifies an existing upstream server.
func (z *ZoraxyClient) UpdateUpstream(params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/upstream/update", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("update upstream failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// RemoveUpstream removes an upstream server from a proxy endpoint.
func (z *ZoraxyClient) RemoveUpstream(params map[string]string) (json.RawMessage, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/upstream/remove", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("remove upstream failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// --- Alias Management ---

// SetAlias sets alias hostnames for a proxy endpoint.
func (z *ZoraxyClient) SetAlias(rootname string, aliases []string) (json.RawMessage, error) {
	form := url.Values{}
	form.Set("ep", rootname)
	aliasJSON, _ := json.Marshal(aliases)
	form.Set("alias", string(aliasJSON))
	body, status, err := z.doRequest(http.MethodPost, "/api/proxy/setAlias", form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("set alias failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}

// --- Certificate Management ---

// ListCerts returns all installed certificates.
func (z *ZoraxyClient) ListCerts() (json.RawMessage, error) {
	body, status, err := z.doRequest(http.MethodGet, "/api/cert/list", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list certs failed (HTTP %d): %s", status, string(body))
	}
	return json.RawMessage(body), nil
}
