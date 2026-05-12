package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockStalwartServer creates a test server that mocks Stalwart's /jmap/session endpoint
func mockStalwartServer(t *testing.T, validToken, username string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+validToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"username": username,
			"accounts": map[string]any{},
		})
	}))
}

func TestJMAPAuthMiddleware_NoAuthorizationHeader(t *testing.T) {
	server := mockStalwartServer(t, "valid-token", "admin@vaderrp.com")
	defer server.Close()

	middleware := JMAPAuthMiddleware(server.URL, []string{"admin@vaderrp.com"}, false)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["error"] != "authorization required" {
		t.Errorf("Expected error 'authorization required', got '%s'", resp["error"])
	}
}

func TestJMAPAuthMiddleware_InvalidToken(t *testing.T) {
	server := mockStalwartServer(t, "valid-token", "admin@vaderrp.com")
	defer server.Close()

	middleware := JMAPAuthMiddleware(server.URL, []string{"admin@vaderrp.com"}, false)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["error"] != "invalid token" {
		t.Errorf("Expected error 'invalid token', got '%s'", resp["error"])
	}
}

func TestJMAPAuthMiddleware_NonAdminUser(t *testing.T) {
	server := mockStalwartServer(t, "valid-token", "user@vaderrp.com")
	defer server.Close()

	middleware := JMAPAuthMiddleware(server.URL, []string{"admin@vaderrp.com"}, false)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["error"] != "admin access required" {
		t.Errorf("Expected error 'admin access required', got '%s'", resp["error"])
	}
}

func TestJMAPAuthMiddleware_ValidAdminToken(t *testing.T) {
	server := mockStalwartServer(t, "valid-token", "admin@vaderrp.com")
	defer server.Close()

	handlerCalled := false
	var contextUsername string

	middleware := JMAPAuthMiddleware(server.URL, []string{"admin@vaderrp.com"}, false)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		contextUsername = UsernameFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called")
	}

	if contextUsername != "admin@vaderrp.com" {
		t.Errorf("Expected username 'admin@vaderrp.com' in context, got '%s'", contextUsername)
	}
}

func TestJMAPAuthMiddleware_AuthBypass(t *testing.T) {
	// No need to create a mock server when bypass is enabled
	handlerCalled := false

	middleware := JMAPAuthMiddleware("http://invalid-url", []string{"admin@vaderrp.com"}, true)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called even without auth when bypass is enabled")
	}
}
