package security

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func runDefaultChecks(t *testing.T, ctx *RequestContext) *CheckResult {
	t.Helper()
	return RunRequestChecks(DefaultRequestChecks(), ctx)
}

func TestSensitivePathReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.pem")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write sensitive file: %v", err)
	}
	sensitive, err := ResolveSensitiveFiles([]string{secret})
	if err != nil {
		t.Fatalf("resolve sensitive files: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/secret.pem", nil)
	ctx := RequestContext{
		Req:       req,
		Dir:       dir,
		Sensitive: sensitive,
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected not found result")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", result.Status)
	}
	if result.Public != "404 not found" {
		t.Fatalf("expected public message to be 404 not found, got %q", result.Public)
	}
	if !result.Auth {
		t.Fatalf("expected auth true for not found response")
	}
}

func TestTLSFilesReturnNotFound(t *testing.T) {
	dir := t.TempDir()
	req := httptest.NewRequest(http.MethodGet, "/server.key", nil)
	ctx := RequestContext{
		Req:           req,
		Dir:           dir,
		BlockTLSFiles: true,
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected not found result")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", result.Status)
	}
	if result.Public != "404 not found" {
		t.Fatalf("expected public message to be 404 not found, got %q", result.Public)
	}
	if !result.Auth {
		t.Fatalf("expected auth true for not found response")
	}
}

func TestTLSFileSymlinkReturnNotFound(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/alias.txt", nil)
	ctx := RequestContext{
		Req:           req,
		Dir:           dir,
		BlockTLSFiles: true,
		AllowInsecure: true,
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected not found result")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", result.Status)
	}
	if result.Public != "404 not found" {
		t.Fatalf("expected public message to be 404 not found, got %q", result.Public)
	}
	if !result.Auth {
		t.Fatalf("expected auth true for not found response")
	}
}

func TestTLSFileHardlinkReturnNotFound(t *testing.T) {
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
	tlsInodes, err := BuildTLSInodeIndex(dir)
	if err != nil {
		t.Fatalf("build tls inode index: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/alias.txt", nil)
	ctx := RequestContext{
		Req:           req,
		Dir:           dir,
		BlockTLSFiles: true,
		TLSInodes:     tlsInodes,
		AllowInsecure: true,
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected not found result")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", result.Status)
	}
	if result.Public != "404 not found" {
		t.Fatalf("expected public message to be 404 not found, got %q", result.Public)
	}
	if !result.Auth {
		t.Fatalf("expected auth true for not found response")
	}
}

func TestHtaccessErrorsReturnNotFound(t *testing.T) {
	dir := t.TempDir()
	htaccess := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(htaccess, []byte("username: admin\n"), 0o600); err != nil {
		t.Fatalf("write htaccess file: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
	ctx := RequestContext{
		Req: req,
		Dir: dir,
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected not found result")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", result.Status)
	}
	if result.Public != "404 not found" {
		t.Fatalf("expected public message to be 404 not found, got %q", result.Public)
	}
	if !result.Auth {
		t.Fatalf("expected auth true for not found response")
	}
}

func TestHtaccessOverridesCredentialsBeforeAuth(t *testing.T) {
	dir := t.TempDir()
	htaccess := filepath.Join(dir, ".htaccess")
	if err := os.WriteFile(htaccess, []byte("username: ht\npassword: pass\n"), 0o600); err != nil {
		t.Fatalf("write htaccess file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
	req.SetBasicAuth("ht", "pass")
	ctx := RequestContext{
		Req:      req,
		Dir:      dir,
		Username: "cliuser",
		Password: "clipass",
	}

	result := runDefaultChecks(t, &ctx)
	if result != nil {
		t.Fatalf("expected request to pass, got status %d", result.Status)
	}
	if !ctx.Authed {
		t.Fatalf("expected request to be authenticated")
	}
	if ctx.Username != "ht" || ctx.Password != "pass" {
		t.Fatalf("expected htaccess credentials to override defaults")
	}
}

func TestHtaccessPathReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	req := httptest.NewRequest(http.MethodGet, "/.htaccess", nil)
	ctx := RequestContext{
		Req: req,
		Dir: dir,
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected not found result")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", result.Status)
	}
}

func TestAllowedIPsPrecedeAuth(t *testing.T) {
	checker, err := ParseAllowedIPs([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("parse allowed IPs: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.SetBasicAuth("user", "pass")
	ctx := RequestContext{
		Req:        req,
		Dir:        t.TempDir(),
		AllowedIPs: checker,
		Username:   "user",
		Password:   "pass",
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected forbidden result")
	}
	if result.Status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", result.Status)
	}
	if result.Auth {
		t.Fatalf("expected auth false for allowed IPs check")
	}
}

func TestCleanPathPrecedesAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/../secret", nil)
	req.SetBasicAuth("bad", "creds")
	ctx := RequestContext{
		Req:      req,
		Dir:      t.TempDir(),
		Username: "user",
		Password: "pass",
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected forbidden result")
	}
	if result.Status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", result.Status)
	}
}

func TestAuthPrecedesRequestAuthorization(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/.secret", nil)
	req.SetBasicAuth("bad", "creds")
	ctx := RequestContext{
		Req:      req,
		Dir:      t.TempDir(),
		Username: "user",
		Password: "pass",
	}

	result := runDefaultChecks(t, &ctx)
	if result == nil {
		t.Fatalf("expected unauthorized result")
	}
	if result.Status != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", result.Status)
	}
	if result.Auth {
		t.Fatalf("expected auth false for unauthorized response")
	}
}
