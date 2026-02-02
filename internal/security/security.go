package security

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

type IPChecker struct {
	subnets []*net.IPNet
	ips     map[string]struct{}
}

type HtaccessCredentials struct {
	Username string
	Password string
}

func ParseAllowedIPs(allowed []string) (IPChecker, error) {
	checker := IPChecker{ips: make(map[string]struct{})}
	for _, entry := range allowed {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			_, ipnet, err := net.ParseCIDR(trimmed)
			if err != nil {
				return checker, fmt.Errorf("invalid allowed subnet %q: %w", trimmed, err)
			}
			checker.subnets = append(checker.subnets, ipnet)
			continue
		}
		ip := net.ParseIP(trimmed)
		if ip == nil {
			return checker, fmt.Errorf("invalid allowed IP %q", trimmed)
		}
		checker.ips[ip.String()] = struct{}{}
	}
	return checker, nil
}

func (c IPChecker) Enabled() bool {
	return len(c.subnets) > 0 || len(c.ips) > 0
}

func (c IPChecker) Allowed(remoteAddr string) bool {
	if !c.Enabled() {
		return true
	}

	host := remoteAddr
	if parsed, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsed
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if _, ok := c.ips[ip.String()]; ok {
		return true
	}
	for _, subnet := range c.subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func CheckBasicAuth(r *http.Request, expectedUsername string, expectedPassword string) bool {
	username, password, ok := r.BasicAuth()
	if ok {
		if username == expectedUsername && password == expectedPassword {
			return true
		}
	}
	return false
}

func AuthCheck(r *http.Request, username, password string) bool {
	if username != "" && password != "" {
		return CheckBasicAuth(r, username, password)
	}
	return true
}

func CleanRequestPath(urlPath string) (string, error) {
	decoded := urlPath
	for i := 0; i < 2; i++ {
		unescaped, err := url.PathUnescape(decoded)
		if err != nil {
			return "", fmt.Errorf("invalid path escape")
		}
		if unescaped == decoded {
			break
		}
		decoded = unescaped
	}

	trimmed := strings.TrimPrefix(decoded, "/")
	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return "", nil
	}
	if strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path traversal detected")
	}
	return cleaned, nil
}

func IsHtaccessPath(relPath string) bool {
	if relPath == "" {
		return false
	}
	return path.Base(relPath) == ".htaccess"
}

func checkPathWithinRoot(root string, relPath string) error {
	if relPath == "" {
		return nil
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	fullPath := filepath.Join(rootAbs, filepath.FromSlash(relPath))
	fullAbs, err := filepath.Abs(fullPath)
	if err != nil {
		return err
	}

	if _, err := os.Lstat(fullAbs); err != nil {
		if os.IsNotExist(err) {
			// If a file doesn't exist we want a 404, not a 403.
			return nil
		}
		return err
	}

	resolved, err := filepath.EvalSymlinks(fullAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if rootAbs == string(filepath.Separator) {
		return nil
	}

	if resolved == rootAbs {
		return nil
	}

	if !strings.HasPrefix(resolved, rootAbs+string(filepath.Separator)) {
		return fmt.Errorf("path escapes root")
	}

	return nil
}

func checkHardLink(root string, relPath string) error {
	if relPath == "" {
		return nil
	}

	fullPath := filepath.Join(root, filepath.FromSlash(relPath))
	fileInfo, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if !fileInfo.Mode().IsRegular() {
		return nil
	}

	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		if stat.Nlink > 1 {
			return fmt.Errorf("hardlink detected: %s", relPath)
		}
	}

	return nil
}

func IsDotFile(dir string, file string) error {
	path := filepath.Join(dir, file)
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if strings.HasPrefix(part, ".") {
			return fmt.Errorf("dot file detected: %s", file)
		}
	}
	return nil
}

func IsRequestAuthorized(dir, relPath string, allowInsecure, allowDotFiles bool) bool {
	if relPath == "" {
		return true
	}

	if IsHtaccessPath(relPath) {
		return false
	}

	if !allowInsecure {
		if checkPathWithinRoot(dir, relPath) != nil {
			return false
		}
	}

	if !allowDotFiles {
		if IsDotFile(dir, relPath) != nil {
			return false
		}
	}

	if !allowInsecure {
		if checkHardLink(dir, relPath) != nil {
			return false
		}
	}

	return true
}

type SensitiveFile struct {
	Path string
	Info os.FileInfo
}

func ResolveSensitiveFiles(files []string) ([]SensitiveFile, error) {
	seen := make(map[string]struct{})
	out := make([]SensitiveFile, 0, len(files))

	for _, file := range files {
		if strings.TrimSpace(file) == "" {
			continue
		}
		abs, err := filepath.Abs(file)
		if err != nil {
			return nil, err
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			resolved = abs
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, SensitiveFile{Path: resolved, Info: info})
	}

	return out, nil
}

func IsSensitivePath(root, relPath string, sensitive []SensitiveFile) bool {
	if relPath == "" || len(sensitive) == 0 {
		return false
	}

	fullPath := filepath.Join(root, filepath.FromSlash(relPath))
	info, err := os.Stat(fullPath)
	if err != nil {
		return false
	}

	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		resolved = fullPath
	}

	for _, file := range sensitive {
		if resolved == file.Path {
			return true
		}
		if file.Info != nil && os.SameFile(info, file.Info) {
			return true
		}
	}

	return false
}

func IsLikelyTLSFile(relPath string) bool {
	if relPath == "" {
		return false
	}
	name := strings.ToLower(filepath.Base(relPath))
	switch filepath.Ext(name) {
	case ".pem", ".key", ".crt", ".cer", ".p12", ".pfx":
		return true
	default:
		return false
	}
}

func ShouldBlockTLSFiles(root string, files []string) (bool, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}

	separator := string(filepath.Separator)
	for _, file := range files {
		if strings.TrimSpace(file) == "" {
			continue
		}
		abs, err := filepath.Abs(file)
		if err != nil {
			return false, err
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			resolved = abs
		}
		if resolved == rootAbs || strings.HasPrefix(resolved, rootAbs+separator) {
			return true, nil
		}
	}

	return false, nil
}

func LoadHtaccessCredentials(root, relPath string, allowInsecure bool) (HtaccessCredentials, bool, error) {
	startDir := relPath
	dir := startDir
	if dir == "." {
		dir = ""
	}

	for {
		htRel := ".htaccess"
		if dir != "" {
			htRel = path.Join(dir, ".htaccess")
		}

		htFull := filepath.Join(root, filepath.FromSlash(htRel))
		info, err := os.Stat(htFull)
		if err == nil && !info.IsDir() {
			if !allowInsecure {
				if err := checkPathWithinRoot(root, htRel); err != nil {
					return HtaccessCredentials{}, true, err
				}
			}

			creds, err := parseHtaccessFile(htFull)
			if err != nil {
				return HtaccessCredentials{}, true, err
			}
			if creds.Username == "" || creds.Password == "" {
				return creds, true, fmt.Errorf(".htaccess missing username or password")
			}
			return creds, true, nil
		}
		if err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTDIR) {
			return HtaccessCredentials{}, true, err
		}

		if dir == "" {
			break
		}
		dir = path.Dir(dir)
		if dir == "." {
			dir = ""
		}
	}

	return HtaccessCredentials{}, false, nil
}

func parseHtaccessFile(filePath string) (HtaccessCredentials, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return HtaccessCredentials{}, err
	}
	defer file.Close()

	var creds HtaccessCredentials
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		key, value := splitKeyValue(line)
		if key == "" {
			continue
		}

		switch strings.ToLower(key) {
		case "username", "user":
			creds.Username = value
		case "password", "pass":
			creds.Password = value
		}
	}

	if err := scanner.Err(); err != nil {
		return HtaccessCredentials{}, err
	}

	return creds, nil
}

func splitKeyValue(line string) (string, string) {
	if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return fields[0], strings.Join(fields[1:], " ")
	}
	return "", ""
}
