package main

import (
	"embed"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"strconv"

	plugin "github.com/dgshue/zoraxy-lb-plugin/mod/zoraxy_plugin"
)

const (
	PLUGIN_ID = "com.sedgwick.zoraxy-lb-manager"
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
		Name:          "LB Manager",
		Author:        "Sedgwick",
		AuthorContact: "",
		Description:   "REST API for managing Zoraxy load balancer proxy rules, upstreams, and certificates with bearer token authentication",
		URL:           "",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  0,
		UIPath:        UI_PATH,
	})
	if err != nil {
		// If not launched by Zoraxy, run in standalone mode
		fmt.Println("Running in standalone mode (not launched by Zoraxy)")
		standalonePort := os.Getenv("LB_MANAGER_PORT")
		if standalonePort == "" {
			standalonePort = "9776"
		}
		startServer(cfg, standalonePort, 0)
		return
	}

	startServer(cfg, strconv.Itoa(runtimeCfg.Port), runtimeCfg.Port)
}

func startServer(cfg *Config, port string, zoraxyAssignedPort int) {
	// Create the Zoraxy API client
	zoraxyClient := NewZoraxyClient(cfg.ZoraxyURL, cfg.ZoraxyUser, cfg.ZoraxyPass)

	// Create API handler with bearer token auth
	api := NewAPIHandler(cfg.BearerToken, zoraxyClient)

	// Set up embedded UI router (only if launched by Zoraxy)
	if zoraxyAssignedPort > 0 {
		embedWebRouter := plugin.NewPluginEmbedUIRouter(PLUGIN_ID, &content, WEB_ROOT, UI_PATH)
		embedWebRouter.RegisterTerminateHandler(func() {
			fmt.Println("LB Manager plugin exited")
		}, nil)

		// Register API routes on the embed router
		api.RegisterRoutes(embedWebRouter)

		// Serve UI
		http.Handle(UI_PATH, embedWebRouter.Handler())
	} else {
		// Standalone mode: register API routes directly
		api.RegisterRoutesStandalone()

		// Serve embedded static files for UI
		http.Handle("/www/", http.FileServer(http.FS(content)))
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.ServeFileFS(w, r, content, "www/index.html")
				return
			}
			http.NotFound(w, r)
		})
	}

	fmt.Printf("LB Manager started at http://127.0.0.1:%s\n", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
