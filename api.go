package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	plugin "github.com/dgshue/zoraxy-rest-api-plugin/mod/zoraxy_plugin"
)

// APIHandler provides bearer-token-authenticated REST endpoints
// that wrap Zoraxy's internal proxy/upstream/cert management.
type APIHandler struct {
	token  string
	zoraxy *ZoraxyClient
}

func NewAPIHandler(token string, zoraxy *ZoraxyClient) *APIHandler {
	return &APIHandler{token: token, zoraxy: zoraxy}
}

// RegisterRoutes registers API endpoints on a PluginUiRouter (Zoraxy plugin mode).
func (a *APIHandler) RegisterRoutes(router *plugin.PluginUiRouter) {
	router.HandleFunc("/api/health", a.withAuth(a.handleHealth), nil)

	// Proxy management
	router.HandleFunc("/api/proxy/list", a.withAuth(a.handleProxyList), nil)
	router.HandleFunc("/api/proxy/detail", a.withAuth(a.handleProxyDetail), nil)
	router.HandleFunc("/api/proxy/add", a.withAuth(a.handleProxyAdd), nil)
	router.HandleFunc("/api/proxy/edit", a.withAuth(a.handleProxyEdit), nil)
	router.HandleFunc("/api/proxy/delete", a.withAuth(a.handleProxyDelete), nil)

	// Upstream (LB) management
	router.HandleFunc("/api/upstream/list", a.withAuth(a.handleUpstreamList), nil)
	router.HandleFunc("/api/upstream/add", a.withAuth(a.handleUpstreamAdd), nil)
	router.HandleFunc("/api/upstream/update", a.withAuth(a.handleUpstreamUpdate), nil)
	router.HandleFunc("/api/upstream/remove", a.withAuth(a.handleUpstreamRemove), nil)

	// Alias management
	router.HandleFunc("/api/alias/set", a.withAuth(a.handleAliasSet), nil)

	// Certificate management
	router.HandleFunc("/api/cert/list", a.withAuth(a.handleCertList), nil)
	router.HandleFunc("/api/cert/upload", a.withAuth(a.handleCertUpload), nil)

	// Composite operations (pipeline-friendly)
	router.HandleFunc("/api/register-server", a.withAuth(a.handleRegisterServer), nil)
	router.HandleFunc("/api/deregister-server", a.withAuth(a.handleDeregisterServer), nil)
}

// RegisterRoutesStandalone registers API endpoints on the default mux (standalone mode).
func (a *APIHandler) RegisterRoutesStandalone() {
	http.HandleFunc("/api/health", a.withAuth(a.handleHealth))

	http.HandleFunc("/api/proxy/list", a.withAuth(a.handleProxyList))
	http.HandleFunc("/api/proxy/detail", a.withAuth(a.handleProxyDetail))
	http.HandleFunc("/api/proxy/add", a.withAuth(a.handleProxyAdd))
	http.HandleFunc("/api/proxy/edit", a.withAuth(a.handleProxyEdit))
	http.HandleFunc("/api/proxy/delete", a.withAuth(a.handleProxyDelete))

	http.HandleFunc("/api/upstream/list", a.withAuth(a.handleUpstreamList))
	http.HandleFunc("/api/upstream/add", a.withAuth(a.handleUpstreamAdd))
	http.HandleFunc("/api/upstream/update", a.withAuth(a.handleUpstreamUpdate))
	http.HandleFunc("/api/upstream/remove", a.withAuth(a.handleUpstreamRemove))

	http.HandleFunc("/api/alias/set", a.withAuth(a.handleAliasSet))

	http.HandleFunc("/api/cert/list", a.withAuth(a.handleCertList))
	http.HandleFunc("/api/cert/upload", a.withAuth(a.handleCertUpload))

	http.HandleFunc("/api/register-server", a.withAuth(a.handleRegisterServer))
	http.HandleFunc("/api/deregister-server", a.withAuth(a.handleDeregisterServer))
}

// RegisterRoutesToMux registers API endpoints on a specific http.ServeMux (external listener).
func (a *APIHandler) RegisterRoutesToMux(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", a.withAuth(a.handleHealth))

	mux.HandleFunc("/api/proxy/list", a.withAuth(a.handleProxyList))
	mux.HandleFunc("/api/proxy/detail", a.withAuth(a.handleProxyDetail))
	mux.HandleFunc("/api/proxy/add", a.withAuth(a.handleProxyAdd))
	mux.HandleFunc("/api/proxy/edit", a.withAuth(a.handleProxyEdit))
	mux.HandleFunc("/api/proxy/delete", a.withAuth(a.handleProxyDelete))

	mux.HandleFunc("/api/upstream/list", a.withAuth(a.handleUpstreamList))
	mux.HandleFunc("/api/upstream/add", a.withAuth(a.handleUpstreamAdd))
	mux.HandleFunc("/api/upstream/update", a.withAuth(a.handleUpstreamUpdate))
	mux.HandleFunc("/api/upstream/remove", a.withAuth(a.handleUpstreamRemove))

	mux.HandleFunc("/api/alias/set", a.withAuth(a.handleAliasSet))

	mux.HandleFunc("/api/cert/list", a.withAuth(a.handleCertList))
	mux.HandleFunc("/api/cert/upload", a.withAuth(a.handleCertUpload))

	mux.HandleFunc("/api/register-server", a.withAuth(a.handleRegisterServer))
	mux.HandleFunc("/api/deregister-server", a.withAuth(a.handleDeregisterServer))
}

// --- Auth Middleware ---

func (a *APIHandler) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, "Missing or invalid Authorization header. Use: Bearer <token>", http.StatusUnauthorized)
			return
		}
		if strings.TrimPrefix(auth, "Bearer ") != a.token {
			jsonError(w, "Invalid bearer token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- Health ---

func (a *APIHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "plugin": "zoraxy-rest-api-plugin", "version": "0.1.0"})
}

// --- Proxy Endpoints ---

func (a *APIHandler) handleProxyList(w http.ResponseWriter, r *http.Request) {
	result, err := a.zoraxy.ListProxies()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleProxyDetail(w http.ResponseWriter, r *http.Request) {
	epType := getParam(r, "type")
	rootname := getParam(r, "ep")
	if rootname == "" {
		jsonError(w, "Missing required parameter: ep", http.StatusBadRequest)
		return
	}
	if epType == "" {
		epType = "host"
	}
	result, err := a.zoraxy.GetProxyDetail(epType, rootname)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleProxyAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseJSONBody(r)
	if err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	required := []string{"type", "rootname", "ep"}
	if missing := checkRequired(params, required); missing != "" {
		jsonError(w, "Missing required field: "+missing, http.StatusBadRequest)
		return
	}
	result, err := a.zoraxy.AddProxy(params)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleProxyEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseJSONBody(r)
	if err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := a.zoraxy.EditProxy(params)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleProxyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonError(w, "Method not allowed, use POST or DELETE", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseJSONBody(r)
	if err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	epType := params["type"]
	rootname := params["ep"]
	if rootname == "" {
		jsonError(w, "Missing required field: ep", http.StatusBadRequest)
		return
	}
	if epType == "" {
		epType = "host"
	}
	result, err := a.zoraxy.DeleteProxy(epType, rootname)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

// --- Upstream Endpoints ---

func (a *APIHandler) handleUpstreamList(w http.ResponseWriter, r *http.Request) {
	epType := getParam(r, "type")
	rootname := getParam(r, "ep")
	if rootname == "" {
		jsonError(w, "Missing required parameter: ep", http.StatusBadRequest)
		return
	}
	if epType == "" {
		epType = "host"
	}
	result, err := a.zoraxy.ListUpstreams(epType, rootname)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleUpstreamAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseJSONBody(r)
	if err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := a.zoraxy.AddUpstream(params)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleUpstreamUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseJSONBody(r)
	if err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := a.zoraxy.UpdateUpstream(params)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

func (a *APIHandler) handleUpstreamRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonError(w, "Method not allowed, use POST or DELETE", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseJSONBody(r)
	if err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := a.zoraxy.RemoveUpstream(params)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

// --- Alias Endpoints ---

func (a *APIHandler) handleAliasSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Endpoint string   `json:"ep"`
		Aliases  []string `json:"aliases"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Endpoint == "" {
		jsonError(w, "Missing required field: ep", http.StatusBadRequest)
		return
	}
	result, err := a.zoraxy.SetAlias(body.Endpoint, body.Aliases)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

// --- Cert Endpoints ---

func (a *APIHandler) handleCertList(w http.ResponseWriter, r *http.Request) {
	result, err := a.zoraxy.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeRaw(w, result)
}

// handleCertUpload uploads a certificate to Zoraxy.
// Accepts PFX (PKCS12) format and converts to PEM automatically.
//
// Supports two modes:
//   1. Multipart form: field "file" (PFX binary), "domain", "password" (optional)
//   2. JSON body: {"domain": "...", "pfx_base64": "...", "password": "..."} for pipeline use
func (a *APIHandler) handleCertUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	var domain, password string
	var pfxData []byte

	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Multipart form upload
		if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB max
			jsonError(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		domain = r.FormValue("domain")
		password = r.FormValue("password")

		file, _, err := r.FormFile("file")
		if err != nil {
			jsonError(w, "Missing required file field: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		pfxData, err = io.ReadAll(file)
		if err != nil {
			jsonError(w, "Failed to read uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		// JSON body with base64-encoded PFX
		var body struct {
			Domain    string `json:"domain"`
			PFXBase64 string `json:"pfx_base64"`
			Password  string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
			return
		}
		domain = body.Domain
		password = body.Password

		var err error
		pfxData, err = base64.StdEncoding.DecodeString(body.PFXBase64)
		if err != nil {
			jsonError(w, "Invalid base64 in pfx_base64: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if domain == "" {
		jsonError(w, "Missing required field: domain", http.StatusBadRequest)
		return
	}
	if len(pfxData) == 0 {
		jsonError(w, "Empty PFX data", http.StatusBadRequest)
		return
	}

	// Convert PFX to PEM
	certPEM, keyPEM, err := PFXToPEM(pfxData, password)
	if err != nil {
		jsonError(w, "Failed to convert PFX: "+err.Error(), http.StatusBadRequest)
		return
	}

	results := make(map[string]interface{})

	// Upload public cert (PEM)
	pubResult, err := a.zoraxy.UploadCert(domain, "pub", domain+".pem", certPEM)
	if err != nil {
		jsonError(w, "Failed to upload certificate: "+err.Error(), http.StatusBadGateway)
		return
	}
	results["cert_uploaded"] = true
	results["cert_result"] = rawOrString(pubResult)

	// Upload private key
	keyResult, err := a.zoraxy.UploadCert(domain, "pri", domain+".key", keyPEM)
	if err != nil {
		results["key_uploaded"] = false
		results["key_error"] = err.Error()
		jsonOK(w, results)
		return
	}
	results["key_uploaded"] = true
	results["key_result"] = rawOrString(keyResult)
	results["domain"] = domain

	jsonOK(w, results)
}

// --- Composite Operations (Pipeline-Friendly) ---

// RegisterServerRequest is the payload for the register-server composite endpoint.
// This performs multiple Zoraxy operations in one call:
// 1. Creates the proxy rule if it doesn't exist
// 2. Adds the server as an upstream backend
// 3. Sets aliases if provided
type RegisterServerRequest struct {
	// Hostname is the primary hostname for the proxy rule (e.g., "clientui-us.example.com")
	Hostname string `json:"hostname"`

	// BackendURL is the upstream server address (e.g., "10.0.1.50:8080")
	BackendURL string `json:"backend_url"`

	// RequireTLS whether the backend connection uses TLS
	RequireTLS bool `json:"require_tls"`

	// SkipTLSVerify skips certificate validation for the backend
	SkipTLSVerify bool `json:"skip_tls_verify"`

	// Weight is the load balancer weight for this upstream (default: 1)
	Weight int `json:"weight"`

	// Aliases are additional hostnames that should route to this proxy rule
	Aliases []string `json:"aliases,omitempty"`

	// Tags for organizing proxy rules in Zoraxy
	Tags []string `json:"tags,omitempty"`
}

func (a *APIHandler) handleRegisterServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Hostname == "" || req.BackendURL == "" {
		jsonError(w, "Missing required fields: hostname, backend_url", http.StatusBadRequest)
		return
	}
	if req.Weight <= 0 {
		req.Weight = 1
	}

	results := make(map[string]interface{})

	// Step 1: Try to get existing proxy detail; create if not found
	_, err := a.zoraxy.GetProxyDetail("host", req.Hostname)
	if err != nil {
		// Proxy doesn't exist — create it
		tls := "false"
		if req.RequireTLS {
			tls = "true"
		}
		skipVerify := "false"
		if req.SkipTLSVerify {
			skipVerify = "true"
		}

		params := map[string]string{
			"type":     "host",
			"rootname": req.Hostname,
			"ep":       req.BackendURL,
			"tls":      tls,
			"tlsval":   skipVerify,
		}
		if len(req.Tags) > 0 {
			tagsJSON, _ := json.Marshal(req.Tags)
			params["tags"] = string(tagsJSON)
		}

		addResult, err := a.zoraxy.AddProxy(params)
		if err != nil {
			jsonError(w, "Failed to create proxy rule: "+err.Error(), http.StatusBadGateway)
			return
		}
		results["proxy_created"] = true
		results["proxy_result"] = json.RawMessage(addResult)
	} else {
		results["proxy_created"] = false
		results["proxy_result"] = "already exists"
	}

	// Step 2: Add upstream server
	requireTLS := "false"
	if req.RequireTLS {
		requireTLS = "true"
	}
	skipVerify := "false"
	if req.SkipTLSVerify {
		skipVerify = "true"
	}

	upstreamParams := map[string]string{
		"ep":     req.Hostname,
		"origin": req.BackendURL,
		"tls":    requireTLS,
		"tlsval": skipVerify,
		"active": "true",
	}
	upResult, err := a.zoraxy.AddUpstream(upstreamParams)
	if err != nil {
		results["upstream_added"] = false
		results["upstream_error"] = err.Error()
	} else {
		results["upstream_added"] = true
		results["upstream_result"] = json.RawMessage(upResult)
	}

	// Step 3: Set aliases if provided
	if len(req.Aliases) > 0 {
		aliasResult, err := a.zoraxy.SetAlias(req.Hostname, req.Aliases)
		if err != nil {
			results["aliases_set"] = false
			results["aliases_error"] = err.Error()
		} else {
			results["aliases_set"] = true
			results["aliases_result"] = json.RawMessage(aliasResult)
		}
	}

	jsonOK(w, results)
}

// DeregisterServerRequest removes an upstream from a proxy rule.
type DeregisterServerRequest struct {
	Hostname   string `json:"hostname"`
	BackendURL string `json:"backend_url"`
}

func (a *APIHandler) handleDeregisterServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		jsonError(w, "Method not allowed, use POST or DELETE", http.StatusMethodNotAllowed)
		return
	}

	var req DeregisterServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Hostname == "" || req.BackendURL == "" {
		jsonError(w, "Missing required fields: hostname, backend_url", http.StatusBadRequest)
		return
	}

	params := map[string]string{
		"type":   "host",
		"ep":     req.Hostname,
		"origin": req.BackendURL,
	}

	result, err := a.zoraxy.RemoveUpstream(params)
	if err != nil {
		jsonError(w, "Failed to remove upstream: "+err.Error(), http.StatusBadGateway)
		return
	}

	jsonOK(w, map[string]interface{}{
		"removed":    true,
		"hostname":   req.Hostname,
		"backend":    req.BackendURL,
		"raw_result": json.RawMessage(result),
	})
}

// --- Helpers ---

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// rawOrString tries to use raw JSON, falls back to string if not valid JSON.
func rawOrString(data json.RawMessage) interface{} {
	if json.Valid(data) {
		return data
	}
	return string(data)
}

func writeRaw(w http.ResponseWriter, data json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func getParam(r *http.Request, key string) string {
	// Check query params first, then try JSON body for GET requests
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return ""
}

func parseJSONBody(r *http.Request) (map[string]string, error) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for k, v := range raw {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result, nil
}

func checkRequired(params map[string]string, required []string) string {
	for _, key := range required {
		if params[key] == "" {
			return key
		}
	}
	return ""
}
