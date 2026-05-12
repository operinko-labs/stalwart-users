package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/operinko-labs/stalwart-users/internal/api"
	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
)

func main() {
	// Parse environment variables
	databaseURL := os.Getenv("DATABASE_URL")
	stalwartURL := os.Getenv("STALWART_URL")
	adminUsers := os.Getenv("ADMIN_USERS")
	pathPrefix := os.Getenv("PATH_PREFIX")
	portStr := os.Getenv("PORT")
	serveUI := os.Getenv("SERVE_UI")
	authBypass := os.Getenv("AUTH_BYPASS")

	// Set defaults
	if portStr == "" {
		portStr = "3000"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid PORT: %v", err)
	}

	if pathPrefix == "" {
		pathPrefix = "/accounts"
	}

	if stalwartURL == "" {
		stalwartURL = "http://localhost:8080"
	}

	// Parse ADMIN_USERS into a slice
	var adminUsersList []string
	if adminUsers != "" {
		adminUsersList = strings.Split(adminUsers, ",")
		// Trim whitespace from each username
		for i := range adminUsersList {
			adminUsersList[i] = strings.TrimSpace(adminUsersList[i])
		}
	}

	// Parse AUTH_BYPASS
	authBypassEnabled := authBypass == "true"

	// Log configuration (non-sensitive)
	log.Printf("Starting Stalwart User Management API")
	log.Printf("  Port: %d", port)
	log.Printf("  Path Prefix: %s", pathPrefix)
	log.Printf("  Serve UI: %s", serveUI)
	log.Printf("  Auth Bypass: %s", authBypass)
	if adminUsers != "" {
		log.Printf("  Admin Users: %s", adminUsers)
	}
	if stalwartURL != "" {
		log.Printf("  Stalwart URL: %s", stalwartURL)
	}
	if databaseURL != "" {
		log.Printf("  Database: configured")
	}

	// Create root mux
	rootMux := http.NewServeMux()

	var pool *db.Pool
	if databaseURL != "" {
		pool, err = db.NewPool(databaseURL)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer func() {
			if err := pool.Close(); err != nil {
				log.Printf("Failed to close database pool: %v", err)
			}
		}()
	}

	// Register health endpoint on root mux (not prefixed)
	rootMux.HandleFunc("GET /healthz", api.HealthHandler(pool))

	// Create API subrouter
	apiRouter := http.NewServeMux()

	apiRouter.HandleFunc("GET /accounts", api.AccountsHandler(pool))
	apiRouter.HandleFunc("GET /accounts/{name}", api.AccountHandler(pool))
	apiRouter.HandleFunc("GET /accounts/{name}/emails", api.ListEmailsHandler(pool))
	apiRouter.HandleFunc("GET /accounts/{name}/groups", api.ListGroupsHandler(pool))
	apiRouter.HandleFunc("POST /accounts", api.CreateAccountHandler(pool))
	apiRouter.HandleFunc("POST /accounts/{name}/emails", api.CreateEmailHandler(pool))
	apiRouter.HandleFunc("POST /accounts/{name}/groups", api.CreateGroupHandler(pool))
	apiRouter.HandleFunc("PATCH /accounts/{name}", api.AccountHandler(pool))
	apiRouter.HandleFunc("DELETE /accounts/{name}", api.AccountHandler(pool))
	apiRouter.HandleFunc("DELETE /accounts/{name}/emails/{address}", api.DeleteEmailHandler(pool))
	apiRouter.HandleFunc("DELETE /accounts/{name}/groups/{group}", api.DeleteGroupHandler(pool))

	// Wrap API subrouter with auth middleware and mount under path prefix
	authMiddleware := auth.JMAPAuthMiddleware(stalwartURL, adminUsersList, authBypassEnabled)
	rootMux.Handle(pathPrefix+"/", authMiddleware(http.StripPrefix(pathPrefix, apiRouter)))

	// Serve UI if configured (lowest priority)
	if serveUI != "" {
		// Use Go 1.22+ pattern matching to ensure API routes take precedence
		rootMux.Handle("GET /", http.FileServer(http.Dir(serveUI)))
	}

	// Start HTTP server
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Listening on %s", addr)
	if err := http.ListenAndServe(addr, rootMux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
