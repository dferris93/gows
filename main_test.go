package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestLogger() (*log.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return log.New(&buf, "", 0), &buf
}

func TestResolveCredentialValueEnv(t *testing.T) {
	t.Setenv("SERV_TEST_USER", "env-user")

	logger, _ := newTestLogger()
	value := resolveCredentialValue(logger, "username", "env:SERV_TEST_USER", false, map[string]basicAuthCredentials{})
	if value != "env-user" {
		t.Fatalf("expected env-user, got %q", value)
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
	username := resolveCredentialValue(logger, "username", "file:"+credsPath, false, cache)
	if username != "file-user" {
		t.Fatalf("expected file-user, got %q", username)
	}

	if err := os.Remove(credsPath); err != nil {
		t.Fatalf("remove creds file: %v", err)
	}
	password := resolveCredentialValue(logger, "password", "file:"+credsPath, true, cache)
	if password != "file-pass" {
		t.Fatalf("expected file-pass, got %q", password)
	}
}

func TestResolveCredentialValueFileMissingPasswordWarns(t *testing.T) {
	logger, logs := newTestLogger()
	tempDir := t.TempDir()
	credsPath := filepath.Join(tempDir, "creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"username":"only-user"}`), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	password := resolveCredentialValue(logger, "password", "file:"+credsPath, true, map[string]basicAuthCredentials{})
	if password != "" {
		t.Fatalf("expected empty password, got %q", password)
	}
	if !strings.Contains(logs.String(), "password missing in credential file") {
		t.Fatalf("expected missing password warning, got logs: %s", logs.String())
	}
}

func TestResolveCredentialValueFileInvalidJSONWarns(t *testing.T) {
	logger, logs := newTestLogger()
	tempDir := t.TempDir()
	credsPath := filepath.Join(tempDir, "creds.json")
	if err := os.WriteFile(credsPath, []byte(`{"username":`), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	value := resolveCredentialValue(logger, "username", "file:"+credsPath, false, map[string]basicAuthCredentials{})
	if value != "" {
		t.Fatalf("expected empty username, got %q", value)
	}
	if !strings.Contains(logs.String(), "failed to parse username credential file") {
		t.Fatalf("expected JSON parse warning, got logs: %s", logs.String())
	}
}

func TestResolveCredentialValueWarnOnPlainPassword(t *testing.T) {
	logger, logs := newTestLogger()
	value := resolveCredentialValue(logger, "password", "plain-pass", true, map[string]basicAuthCredentials{})
	if value != "plain-pass" {
		t.Fatalf("expected plain-pass, got %q", value)
	}
	if !strings.Contains(logs.String(), "use env:<VAR> or file:<PATH> instead") {
		t.Fatalf("expected plain password warning, got logs: %s", logs.String())
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
