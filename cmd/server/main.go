package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/operinko-labs/stalwart-users/internal/api"
	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/stalwart"
)

const apiBasePath = "/api"

type serverConfig struct {
	DatabaseURL        string
	JWTSecret          string
	StalwartURL        string
	StalwartAdminToken string
	PathPrefix         string
	CORSOrigin         string
	Port               int
}

func main() {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Log configuration (non-sensitive)
	log.Printf("Starting Stalwart User Management API")
	log.Printf("  Port: %d", cfg.Port)
	log.Printf("  Path Prefix: %s", cfg.PathPrefix)
	log.Printf("  CORS Origin: %s", cfg.CORSOrigin)
	if cfg.DatabaseURL != "" {
		log.Printf("  Database: configured")
	}
	if cfg.StalwartURL != "" && cfg.StalwartAdminToken != "" {
		log.Printf("  Stalwart JMAP: configured (%s)", cfg.StalwartURL)
	} else {
		log.Printf("  Stalwart JMAP: disabled")
	}

	var pool *db.Pool
	if cfg.DatabaseURL != "" {
		pool, err = db.NewPool(cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer func() {
			if err := pool.Close(); err != nil {
				log.Printf("Failed to close database pool: %v", err)
			}
		}()
	}

	handler, err := newServerHandler(cfg, pool)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start HTTP server
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func loadConfigFromEnv() (serverConfig, error) {
	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = "3000"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return serverConfig{}, err
	}

	cfg := serverConfig{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		StalwartURL:        os.Getenv("STALWART_URL"),
		StalwartAdminToken: os.Getenv("STALWART_ADMIN_TOKEN"),
		PathPrefix:         os.Getenv("PATH_PREFIX"),
		CORSOrigin:         os.Getenv("CORS_ORIGIN"),
		Port:               port,
	}

	if cfg.CORSOrigin == "" {
		cfg.CORSOrigin = "*"
	}
	if cfg.JWTSecret == "" {
		return serverConfig{}, auth.ErrMissingJWTSecret
	}

	return cfg, nil
}

func newServerHandler(cfg serverConfig, pool *db.Pool) (http.Handler, error) {
	tokens, err := auth.NewTokenManager(cfg.JWTSecret)
	if err != nil {
		return nil, err
	}

	authenticator := auth.NewSQLDirectoryAuthenticator(dbFromPool(pool))

	var stalwartClient *stalwart.Client
	if cfg.StalwartURL != "" && cfg.StalwartAdminToken != "" {
		stalwartClient = stalwart.NewClient(cfg.StalwartURL, cfg.StalwartAdminToken)
	}

	rootMux := http.NewServeMux()
	rootMux.HandleFunc("GET /healthz", api.HealthHandler(pool))

	apiRouter := http.NewServeMux()
	apiRouter.HandleFunc("POST /auth/login", auth.LoginHandler(authenticator, tokens))
	apiRouter.HandleFunc("GET /auth/me", auth.MeHandler(tokens))
	apiRouter.HandleFunc("POST /auth/logout", auth.LogoutHandler(tokens))
	apiRouter.Handle("PUT /accounts/{name}/password", tokens.Middleware(api.ChangePasswordHandler(pool)))

	protectedRouter := http.NewServeMux()
	protectedRouter.HandleFunc("GET /accounts", api.AccountsHandler(pool))
	protectedRouter.HandleFunc("GET /accounts/{name}", api.AccountHandler(pool, stalwartClient))
	protectedRouter.HandleFunc("GET /accounts/{name}/emails", api.ListEmailsHandler(pool))
	protectedRouter.HandleFunc("GET /accounts/{name}/groups", api.ListGroupsHandler(pool))
	protectedRouter.HandleFunc("POST /accounts", api.CreateAccountHandler(pool, stalwartClient))
	protectedRouter.HandleFunc("POST /accounts/{name}/emails", api.CreateEmailHandler(pool))
	protectedRouter.HandleFunc("POST /accounts/{name}/groups", api.CreateGroupHandler(pool))
	protectedRouter.HandleFunc("PATCH /accounts/{name}", api.AccountHandler(pool, stalwartClient))
	protectedRouter.HandleFunc("DELETE /accounts/{name}", api.AccountHandler(pool, stalwartClient))
	protectedRouter.HandleFunc("DELETE /accounts/{name}/emails/{address}", api.DeleteEmailHandler(pool))
	protectedRouter.HandleFunc("DELETE /accounts/{name}/groups/{group}", api.DeleteGroupHandler(pool))

	apiRouter.Handle("/", tokens.Middleware(auth.AuthorizationMiddleware(protectedRouter)))
	rootMux.Handle(apiBasePath+"/", http.StripPrefix(apiBasePath, apiRouter))

	if cfg.PathPrefix != "" {
		rootMux.Handle(cfg.PathPrefix+apiBasePath+"/", http.StripPrefix(cfg.PathPrefix+apiBasePath, apiRouter))
	}

	return newCORSMiddleware(cfg.CORSOrigin)(rootMux), nil
}

func dbFromPool(pool *db.Pool) *sql.DB {
	if pool == nil {
		return nil
	}

	return pool.DB()
}

func newCORSMiddleware(origin string) func(http.Handler) http.Handler {
	if origin == "" {
		origin = "*"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
