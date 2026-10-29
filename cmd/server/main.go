package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/operinko-labs/stalwart-users/internal/api"
	"github.com/operinko-labs/stalwart-users/internal/auth"
	"github.com/operinko-labs/stalwart-users/internal/db"
	"github.com/operinko-labs/stalwart-users/internal/directory"
	"github.com/operinko-labs/stalwart-users/internal/oidc"
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
	OIDCIssuer         string
	OIDCClientID       string
	OIDCClientSecret   string
	OIDCRedirectURL    string
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
	log.Printf("  Stalwart: %s", cfg.StalwartURL)
	log.Printf("  OIDC issuer: %s", cfg.OIDCIssuer)

	pool, err := db.NewPool(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			log.Printf("Failed to close database pool: %v", err)
		}
	}()
	if err := pool.EnsureDomainAdminsTable(); err != nil {
		log.Fatalf("Failed to create domain admins table: %v", err)
	}

	adminStalwart := stalwart.NewClient(cfg.StalwartURL, cfg.StalwartAdminToken)
	store := directory.New(adminStalwart, pool)

	handler, err := newServerHandler(cfg, pool, store)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Register this app's OAuth client in Stalwart in the background; the
	// server doesn't wait for it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go registerOAuthClient(ctx, adminStalwart, oauthClientSpec(cfg), sleepContext)

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
		OIDCIssuer:         os.Getenv("OIDC_ISSUER"),
		OIDCClientID:       os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:    os.Getenv("OIDC_REDIRECT_URL"),
	}

	if cfg.CORSOrigin == "" {
		cfg.CORSOrigin = "*"
	}
	if cfg.JWTSecret == "" {
		return serverConfig{}, auth.ErrMissingJWTSecret
	}
	for _, required := range []struct{ name, value string }{
		{"DATABASE_URL", cfg.DatabaseURL},
		{"STALWART_URL", cfg.StalwartURL},
		{"STALWART_ADMIN_TOKEN", cfg.StalwartAdminToken},
		{"OIDC_ISSUER", cfg.OIDCIssuer},
		{"OIDC_CLIENT_ID", cfg.OIDCClientID},
		{"OIDC_REDIRECT_URL", cfg.OIDCRedirectURL},
	} {
		if required.value == "" {
			return serverConfig{}, fmt.Errorf("%s is required", required.name)
		}
	}

	// OIDC_CLIENT_SECRET is an optional override; by default the secret is
	// derived from JWT_SECRET and registered in Stalwart at startup.
	if cfg.OIDCClientSecret == "" {
		cfg.OIDCClientSecret = auth.DeriveOAuthClientSecret(cfg.JWTSecret)
	}

	return cfg, nil
}

const (
	oauthRegisterTimeout    = 10 * time.Second
	oauthRegisterMinBackoff = 5 * time.Second
	oauthRegisterMaxBackoff = 60 * time.Second
)

type oauthClientEnsurer interface {
	EnsureOAuthClient(ctx context.Context, spec stalwart.OAuthClientSpec) (bool, error)
}

func oauthClientSpec(cfg serverConfig) stalwart.OAuthClientSpec {
	return stalwart.OAuthClientSpec{
		ClientID:    cfg.OIDCClientID,
		Secret:      cfg.OIDCClientSecret,
		RedirectURI: cfg.OIDCRedirectURL,
		Description: "stalwart-users",
	}
}

// registerOAuthClient registers spec in Stalwart, retrying with a doubling
// backoff (5s up to 60s) until it succeeds or ctx is cancelled. sleep waits
// for d and reports false when ctx ended first. Nothing it logs includes the
// secret.
func registerOAuthClient(ctx context.Context, ensurer oauthClientEnsurer, spec stalwart.OAuthClientSpec, sleep func(context.Context, time.Duration) bool) {
	backoff := oauthRegisterMinBackoff
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, oauthRegisterTimeout)
		created, err := ensurer.EnsureOAuthClient(attemptCtx, spec)
		cancel()
		if err == nil {
			state := "updated"
			if created {
				state = "created"
			}
			log.Printf("OAuth client %s %s", spec.ClientID, state)
			return
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("OAuth client %s registration failed, retrying in %s: %v", spec.ClientID, backoff, err)
		if !sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, oauthRegisterMaxBackoff)
	}
}

// sleepContext waits for d and reports whether it ran to the end (false when
// ctx was cancelled first).
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func newServerHandler(cfg serverConfig, pool *db.Pool, store *directory.Store) (http.Handler, error) {
	tokens, err := auth.NewTokenManager(cfg.JWTSecret)
	if err != nil {
		return nil, err
	}

	tokens.SetPaths(cfg.PathPrefix, apiBasePath)

	oidcClient := oidc.New(oidc.Config{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
	}, &http.Client{Timeout: 15 * time.Second})
	// One store for every handler that needs a session's OAuth tokens.
	oauthTokens := auth.NewTokenStore()

	rootMux := http.NewServeMux()
	rootMux.HandleFunc("GET /healthz", api.HealthHandler(pool))

	apiRouter := http.NewServeMux()
	apiRouter.HandleFunc("GET /auth/login", auth.LoginStartHandler(oidcClient, tokens))
	apiRouter.HandleFunc("GET /auth/callback", auth.CallbackHandler(oidcClient, store, tokens, oauthTokens))
	apiRouter.HandleFunc("GET /auth/me", auth.MeHandler(tokens, store))
	apiRouter.HandleFunc("POST /auth/logout", auth.LogoutHandler(tokens, oauthTokens))

	protectedRouter := http.NewServeMux()
	// Self-service password changes run as the user (their OAuth access
	// token), so this client carries no admin key.
	userStalwart := stalwart.NewClient(cfg.StalwartURL, "")
	protectedRouter.HandleFunc("PUT /accounts/{name}/password", api.ChangePasswordHandler(store, oauthTokens, oidcClient, userStalwart))
	protectedRouter.HandleFunc("GET /accounts/{name}/admin-domains", api.AdminDomainsHandler(store))
	protectedRouter.HandleFunc("PUT /accounts/{name}/admin-domains", api.AdminDomainsHandler(store))
	protectedRouter.HandleFunc("GET /accounts", api.AccountsHandler(store))
	protectedRouter.HandleFunc("GET /accounts/{name}", api.AccountHandler(store))
	protectedRouter.HandleFunc("GET /accounts/{name}/emails", api.ListEmailsHandler(store))
	protectedRouter.HandleFunc("GET /accounts/{name}/groups", api.ListGroupsHandler(store))
	protectedRouter.HandleFunc("POST /accounts", api.CreateAccountHandler(store))
	protectedRouter.HandleFunc("POST /accounts/{name}/emails", api.CreateEmailHandler(store))
	protectedRouter.HandleFunc("POST /accounts/{name}/groups", api.CreateGroupHandler(store))
	protectedRouter.HandleFunc("PATCH /accounts/{name}", api.AccountHandler(store))
	protectedRouter.HandleFunc("DELETE /accounts/{name}", api.AccountHandler(store))
	protectedRouter.HandleFunc("DELETE /accounts/{name}/emails/{address}", api.DeleteEmailHandler(store))
	protectedRouter.HandleFunc("DELETE /accounts/{name}/groups/{group}", api.DeleteGroupHandler(store))

	apiRouter.Handle("/", tokens.Middleware(auth.AuthorizationMiddleware(protectedRouter, store)))
	rootMux.Handle(apiBasePath+"/", http.StripPrefix(apiBasePath, apiRouter))

	if cfg.PathPrefix != "" {
		rootMux.Handle(cfg.PathPrefix+apiBasePath+"/", http.StripPrefix(cfg.PathPrefix+apiBasePath, apiRouter))
	}

	return newCORSMiddleware(cfg.CORSOrigin)(rootMux), nil
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
