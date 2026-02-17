package main

import (
	"embed"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"strconv"

	plugin "github.com/dgshue/zoraxy-rest-api-plugin/mod/zoraxy_plugin"
)

const (
	PLUGIN_ID = "com.github.dgshue.zoraxy-restapi"
	UI_PATH   = "/"
	WEB_ROOT  = "/www"
)

//go:embed www/*
var content embed.FS

func main() {
	// Load plugin configuration from config file or env vars
	cfg := LoadConfig()

	// Zoraxy plugin introspect/configure lifecycle
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            PLUGIN_ID,
		Name:          "Zoraxy REST API Plugin",
		Author:        "dgshue",
		AuthorContact: "",
		Description:   "REST API for managing Zoraxy proxy rules, upstreams, aliases, and certificates with bearer token authentication",
		URL:           "https://github.com/dgshue/zoraxy-rest-api-plugin",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  0,
		VersionMinor:  2,
		VersionPatch:  0,
		UIPath:        UI_PATH,
	})
	if err != nil {
		// If not launched by Zoraxy, run in standalone mode
		fmt.Println("Running in standalone mode (not launched by Zoraxy)")
		port := cfg.Port
		if port == 0 {
			port = 9776
		}
		startStandalone(cfg, port)
		return
	}

	startPlugin(cfg, runtimeCfg.Port)
}

// startPlugin runs in Zoraxy plugin mode.
// Always listens on Zoraxy's assigned port (127.0.0.1) so Zoraxy can proxy to it.
// If config has a port override, ALSO listens on that port (0.0.0.0) for external access.
func startPlugin(cfg *Config, zoraxyPort int) {
	// Create the Zoraxy API client
	zoraxyClient := NewZoraxyClient(cfg.ZoraxyURL, cfg.ZoraxyUser, cfg.ZoraxyPass)

	// Create API handler with bearer token auth
	api := NewAPIHandler(cfg.BearerToken, zoraxyClient)

	// Set up embedded UI router for Zoraxy
	embedWebRouter := plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &content, WEB_ROOT, UI_PATH)
	embedWebRouter.RegisterTerminateHandler(func() {
		fmt.Println("Zoraxy REST API Plugin exited")
	}, nil)

	// Register API routes on the embed router (serves on Zoraxy's assigned port)
	api.RegisterRoutes(embedWebRouter)

	// Serve UI on Zoraxy's assigned port
	http.Handle(UI_PATH, embedWebRouter.Handler())

	// If a fixed port is configured, start a second listener for external access
	if cfg.Port > 0 && cfg.Port != zoraxyPort {
		go func() {
			externalMux := http.NewServeMux()
			api.RegisterRoutesToMux(externalMux)
			addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
			fmt.Printf("External API listening on http://%s\n", addr)
			if err := http.ListenAndServe(addr, externalMux); err != nil {
				fmt.Fprintf(os.Stderr, "External listener error: %v\n", err)
			}
		}()
	}

	// Primary listener on Zoraxy's assigned port (required for Zoraxy communication)
	addr := "127.0.0.1:" + strconv.Itoa(zoraxyPort)
	fmt.Printf("Zoraxy REST API Plugin started at http://%s (Zoraxy port)\n", addr)
	if cfg.Port > 0 {
		fmt.Printf("External API available on port %d\n", cfg.Port)
	}
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// startStandalone runs without Zoraxy, binding to 0.0.0.0 on the configured port.
func startStandalone(cfg *Config, port int) {
	zoraxyClient := NewZoraxyClient(cfg.ZoraxyURL, cfg.ZoraxyUser, cfg.ZoraxyPass)
	api := NewAPIHandler(cfg.BearerToken, zoraxyClient)
	api.RegisterRoutesStandalone()

	http.Handle("/www/", http.FileServer(http.FS(content)))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			data, err := content.ReadFile("www/index.html")
			if err != nil {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	fmt.Printf("Zoraxy REST API Plugin started at http://%s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
