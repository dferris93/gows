package handler

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"serv/internal/security"
)

func newTestHandler(dir string) *Handler {
	return &Handler{
		Dir:    dir,
		Logger: log.New(io.Discard, "", 0),
	}
}

func TestHandlerServesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	h := newTestHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != "hello" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestHandlerRequiresAuth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	h := newTestHandler(dir)
	h.Username = "user"
	h.Password = "pass"

	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("expected WWW-Authenticate header")
	}
}

func TestHandlerHtaccessOverridesCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	content := "username: ht\npassword: pass\n"
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte(content), 0o600); err != nil {
		t.Fatalf("write htaccess: %v", err)
	}

	h := newTestHandler(dir)
	h.Username = "cli"
	h.Password = "cli"

	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	req.SetBasicAuth("ht", "pass")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHandlerDotfileAccess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write dotfile: %v", err)
	}

	h := newTestHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/.hidden", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}

	h.AllowDotFiles = true
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHandlerSensitivePathNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.pem"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	sensitive, err := security.ResolveSensitiveFiles([]string{filepath.Join(dir, "secret.pem")})
	if err != nil {
		t.Fatalf("resolve sensitive files: %v", err)
	}

	h := newTestHandler(dir)
	h.Sensitive = sensitive
	req := httptest.NewRequest(http.MethodGet, "/secret.pem", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHandlerHtaccessNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("username: x\npassword: y\n"), 0o600); err != nil {
		t.Fatalf("write htaccess: %v", err)
	}
	h := newTestHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/.htaccess", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHandlerBlocksTLSFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.key"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write tls file: %v", err)
	}

	h := newTestHandler(dir)
	h.BlockTLSFiles = true
	req := httptest.NewRequest(http.MethodGet, "/server.key", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHandlerFilterGlobsBlockAccess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.log"), []byte("log"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	h := newTestHandler(dir)
	h.FilterGlobs = []string{"*.log"}
	req := httptest.NewRequest(http.MethodGet, "/app.log", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHandlerListingFiltersEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".htaccess"), []byte("username: x\npassword: y\n"), 0o600); err != nil {
		t.Fatalf("write htaccess: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write dotfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write tls file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write visible file: %v", err)
	}

	h := newTestHandler(dir)
	h.BlockTLSFiles = true
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("x", "y")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "visible.txt") {
		t.Fatalf("expected visible.txt to appear in listing")
	}
	if strings.Contains(body, ".htaccess") {
		t.Fatalf("did not expect .htaccess in listing")
	}
	if strings.Contains(body, ".hidden") {
		t.Fatalf("did not expect .hidden in listing")
	}
	if strings.Contains(body, "server.key") {
		t.Fatalf("did not expect server.key in listing")
	}
}

func TestHandlerListingFiltersTLSSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test is unreliable on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "server.key")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write tls file: %v", err)
	}
	link := filepath.Join(dir, "alias.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	h := newTestHandler(dir)
	h.BlockTLSFiles = true
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "alias.txt") {
		t.Fatalf("did not expect alias.txt in listing")
	}
}

func TestHandlerListingFiltersTLSHardlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hardlink test is unreliable on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "server.key")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write tls file: %v", err)
	}
	link := filepath.Join(dir, "alias.txt")
	if err := os.Link(target, link); err != nil {
		t.Skipf("hardlink not supported: %v", err)
	}
	tlsInodes, err := security.BuildTLSInodeIndex(dir)
	if err != nil {
		t.Fatalf("build tls inode index: %v", err)
	}

	h := newTestHandler(dir)
	h.BlockTLSFiles = true
	h.TLSInodes = tlsInodes
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "alias.txt") {
		t.Fatalf("did not expect alias.txt in listing")
	}
}
