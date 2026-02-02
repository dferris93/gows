package security

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseAllowedIPs(t *testing.T) {
	checker, err := ParseAllowedIPs([]string{"10.0.0.1", "192.168.0.0/24", ""})
	if err != nil {
		t.Fatalf("parse allowed IPs: %v", err)
	}
	if !checker.Enabled() {
		t.Fatalf("expected checker to be enabled")
	}
	if !checker.Allowed("10.0.0.1:8080") {
		t.Fatalf("expected explicit IP to be allowed")
	}
	if !checker.Allowed("192.168.0.42") {
		t.Fatalf("expected subnet IP to be allowed")
	}
	if checker.Allowed("8.8.8.8") {
		t.Fatalf("expected unrelated IP to be denied")
	}
	if _, err := ParseAllowedIPs([]string{"invalid"}); err == nil {
		t.Fatalf("expected error for invalid IP")
	}
	if _, err := ParseAllowedIPs([]string{"10.0.0.0/999"}); err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
}

func TestCleanRequestPath(t *testing.T) {
	rel, err := CleanRequestPath("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel != "" {
		t.Fatalf("expected empty rel path, got %q", rel)
	}
	rel, err = CleanRequestPath("/foo/../bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel != "bar" {
		t.Fatalf("expected rel path bar, got %q", rel)
	}
	if _, err := CleanRequestPath("/../secret"); err == nil {
		t.Fatalf("expected traversal error")
	}
	if _, err := CleanRequestPath("/../../etc"); err == nil {
		t.Fatalf("expected traversal error")
	}
	if _, err := CleanRequestPath("/%2e%2e/secret"); err == nil {
		t.Fatalf("expected traversal error for encoded path")
	}
	if _, err := CleanRequestPath("/%252e%252e/secret"); err == nil {
		t.Fatalf("expected traversal error for double-encoded path")
	}
}

func TestIsRequestAuthorizedDotFiles(t *testing.T) {
	dir := t.TempDir()
	rel := ".hidden"
	if err := os.WriteFile(filepath.Join(dir, rel), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write dotfile: %v", err)
	}
	if IsRequestAuthorized(dir, rel, false, false) {
		t.Fatalf("expected dotfile to be unauthorized when allowDotFiles=false")
	}
	if !IsRequestAuthorized(dir, rel, false, true) {
		t.Fatalf("expected dotfile to be authorized when allowDotFiles=true")
	}
}

func TestIsRequestAuthorizedSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test is unreliable on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if IsRequestAuthorized(root, "escape.txt", false, true) {
		t.Fatalf("expected symlink escape to be unauthorized")
	}
	if !IsRequestAuthorized(root, "escape.txt", true, true) {
		t.Fatalf("expected allowInsecure to bypass symlink checks")
	}
}

func TestIsRequestAuthorizedHardlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hardlink test is unreliable on Windows")
	}
	root := t.TempDir()
	orig := filepath.Join(root, "orig.txt")
	if err := os.WriteFile(orig, []byte("data"), 0o600); err != nil {
		t.Fatalf("write original: %v", err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Link(orig, link); err != nil {
		t.Skipf("hardlink not supported: %v", err)
	}
	if IsRequestAuthorized(root, "link.txt", false, true) {
		t.Fatalf("expected hardlink to be unauthorized when allowInsecure=false")
	}
	if !IsRequestAuthorized(root, "link.txt", true, true) {
		t.Fatalf("expected allowInsecure to bypass hardlink checks")
	}
}

func TestIsRequestAuthorizedDirectory(t *testing.T) {
	root := t.TempDir()
	subdir := filepath.Join(root, "dir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if !IsRequestAuthorized(root, "dir", false, true) {
		t.Fatalf("expected directory to be authorized")
	}
}

func TestIsSensitivePath(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write sensitive file: %v", err)
	}
	sensitive, err := ResolveSensitiveFiles([]string{secret})
	if err != nil {
		t.Fatalf("resolve sensitive files: %v", err)
	}
	if !IsSensitivePath(root, "secret.txt", sensitive) {
		t.Fatalf("expected sensitive path to be detected")
	}
	if IsSensitivePath(root, "public.txt", sensitive) {
		t.Fatalf("expected non-sensitive path to be allowed")
	}
}

func TestLoadHtaccessCredentials(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	htaccess := filepath.Join(root, ".htaccess")
	content := "username: admin\npassword: secret\n"
	if err := os.WriteFile(htaccess, []byte(content), 0o600); err != nil {
		t.Fatalf("write htaccess: %v", err)
	}
	creds, found, err := LoadHtaccessCredentials(root, "sub/file.txt", false)
	if err != nil {
		t.Fatalf("load htaccess: %v", err)
	}
	if !found {
		t.Fatalf("expected htaccess to be found")
	}
	if creds.Username != "admin" || creds.Password != "secret" {
		t.Fatalf("unexpected credentials: %+v", creds)
	}
}

func TestAuthCheckUsesBasicAuth(t *testing.T) {
	req := httptestRequest(t, "user", "pass")
	if !AuthCheck(req, "user", "pass") {
		t.Fatalf("expected auth to succeed")
	}
	if AuthCheck(req, "user", "wrong") {
		t.Fatalf("expected auth to fail")
	}
}

func httptestRequest(t *testing.T, user, pass string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/file.txt", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	return req
}

func TestIsLikelyTLSFile(t *testing.T) {
	cases := []struct {
		name   string
		expect bool
	}{
		{"server.pem", true},
		{"server.key", true},
		{"server.crt", true},
		{"server.cer", true},
		{"server.p12", true},
		{"server.pfx", true},
		{"notes.txt", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsLikelyTLSFile(tc.name); got != tc.expect {
			t.Fatalf("IsLikelyTLSFile(%q)=%v expected %v", tc.name, got, tc.expect)
		}
	}
}

func TestSplitKeyValue(t *testing.T) {
	key, value := splitKeyValue("username: admin")
	if key != "username" || value != "admin" {
		t.Fatalf("unexpected result: %q %q", key, value)
	}
	key, value = splitKeyValue("password=secret")
	if key != "password" || value != "secret" {
		t.Fatalf("unexpected result: %q %q", key, value)
	}
	key, value = splitKeyValue("user admin")
	if key != "user" || value != "admin" {
		t.Fatalf("unexpected result: %q %q", key, value)
	}
	key, value = splitKeyValue(strings.Repeat(" ", 3))
	if key != "" || value != "" {
		t.Fatalf("expected empty result for blank input")
	}
}
