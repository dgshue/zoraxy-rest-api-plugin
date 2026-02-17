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
		URL:           "https://github.com/dgshue/zoraxy-lb-plugin",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  0,
		VersionMinor:  1,
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
			fmt.Println("Zoraxy REST API Plugin exited")
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
	}

	fmt.Printf("Zoraxy REST API Plugin started at http://127.0.0.1:%s\n", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
