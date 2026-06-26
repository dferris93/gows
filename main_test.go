package main

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestLogger() (*log.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return log.New(&buf, "", 0), &buf
}

func TestResolveCredentialValueEnv(t *testing.T) {
	t.Setenv("SERV_TEST_USER", "env-user")

	logger, _ := newTestLogger()
	value, err := resolveCredentialValue(logger, "username", "env:SERV_TEST_USER", false, map[string]basicAuthCredentials{})
	if err != nil {
		t.Fatalf("resolve credential: %v", err)
	}
	if value != "env-user" {
		t.Fatalf("expected env-user, got %q", value)
	}
}

func TestResolveCredentialValueEnvMissingFails(t *testing.T) {
	logger, _ := newTestLogger()
	if _, err := resolveCredentialValue(logger, "username", "env:SERV_TEST_USER_MISSING", false, map[string]basicAuthCredentials{}); err == nil {
		t.Fatalf("expected missing environment variable to fail")
	}
}

func TestResolveCredentialValueFileSharedForUsernameAndPassword(t *testing.T) {
	logger, _ := newTestLogger()
	tempDir := t.TempDir()
	credsPath := filepath.Join(tempDir, "creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"username":"file-user","password":"file-pass"}`), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	cache := map[string]basicAuthCredentials{}
	username, err := resolveCredentialValue(logger, "username", "file:"+credsPath, false, cache)
	if err != nil {
		t.Fatalf("resolve username: %v", err)
	}
	if username != "file-user" {
		t.Fatalf("expected file-user, got %q", username)
	}

	if err := os.Remove(credsPath); err != nil {
		t.Fatalf("remove creds file: %v", err)
	}
	password, err := resolveCredentialValue(logger, "password", "file:"+credsPath, true, cache)
	if err != nil {
		t.Fatalf("resolve password: %v", err)
	}
	if password != "file-pass" {
		t.Fatalf("expected file-pass, got %q", password)
	}
}

func TestResolveCredentialValueFileMissingPasswordFails(t *testing.T) {
	logger, _ := newTestLogger()
	tempDir := t.TempDir()
	credsPath := filepath.Join(tempDir, "creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"username":"only-user"}`), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	_, err := resolveCredentialValue(logger, "password", "file:"+credsPath, true, map[string]basicAuthCredentials{})
	if err == nil || !strings.Contains(err.Error(), "password missing") {
		t.Fatalf("expected missing password error, got %v", err)
	}
}

func TestResolveCredentialValueFileInvalidJSONFails(t *testing.T) {
	logger, _ := newTestLogger()
	tempDir := t.TempDir()
	credsPath := filepath.Join(tempDir, "creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"username":`), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	_, err := resolveCredentialValue(logger, "username", "file:"+credsPath, false, map[string]basicAuthCredentials{})
	if err == nil || !strings.Contains(err.Error(), "parse username credential file") {
		t.Fatalf("expected JSON parse error, got %v", err)
	}
}

func TestResolveCredentialValueWarnOnPlainPassword(t *testing.T) {
	logger, logs := newTestLogger()
	value, err := resolveCredentialValue(logger, "password", "plain-pass", true, map[string]basicAuthCredentials{})
	if err != nil {
		t.Fatalf("resolve password: %v", err)
	}
	if value != "plain-pass" {
		t.Fatalf("expected plain-pass, got %q", value)
	}
	if !strings.Contains(logs.String(), "use env:<VAR> or file:<PATH> instead") {
		t.Fatalf("expected plain password warning, got logs: %s", logs.String())
	}
}

func TestResolveBasicAuthCredentialsRequiresBothValues(t *testing.T) {
	logger, _ := newTestLogger()
	_, _, err := resolveBasicAuthCredentials(logger, "user", "", map[string]basicAuthCredentials{})
	if err == nil || !strings.Contains(err.Error(), "both username and password") {
		t.Fatalf("expected partial credentials to fail, got %v", err)
	}
}

func TestResolveBasicAuthCredentialsAllowsNoAuth(t *testing.T) {
	logger, _ := newTestLogger()
	username, password, err := resolveBasicAuthCredentials(logger, "", "", map[string]basicAuthCredentials{})
	if err != nil {
		t.Fatalf("expected no auth to be allowed: %v", err)
	}
	if username != "" || password != "" {
		t.Fatalf("expected empty credentials, got %q %q", username, password)
	}
}

func TestNewHTTPServerConfiguresTimeouts(t *testing.T) {
	handler := http.NewServeMux()
	server := newHTTPServer("127.0.0.1:0", handler)

	if server.Addr != "127.0.0.1:0" {
		t.Fatalf("unexpected addr %q", server.Addr)
	}
	if server.Handler != handler {
		t.Fatalf("unexpected handler")
	}
	if server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("unexpected ReadHeaderTimeout %s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 30*time.Second {
		t.Fatalf("unexpected ReadTimeout %s", server.ReadTimeout)
	}
	if server.WriteTimeout != 30*time.Second {
		t.Fatalf("unexpected WriteTimeout %s", server.WriteTimeout)
	}
	if server.IdleTimeout != 2*time.Minute {
		t.Fatalf("unexpected IdleTimeout %s", server.IdleTimeout)
	}
}

func TestMaxUploadBytes(t *testing.T) {
	if got := maxUploadBytes(250); got != 250*1024*1024 {
		t.Fatalf("maxUploadBytes(250) = %d, want %d", got, int64(250*1024*1024))
	}
	if got := maxUploadBytes(0); got != 0 {
		t.Fatalf("maxUploadBytes(0) = %d, want unlimited sentinel 0", got)
	}
	if got := maxUploadBytes(-10); got != 100*1024*1024 {
		t.Fatalf("maxUploadBytes(-10) = %d, want default %d", got, int64(100*1024*1024))
	}
}
