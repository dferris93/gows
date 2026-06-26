package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"serv/internal/config"
	"serv/internal/handler"
	"serv/internal/logging"
	"serv/internal/security"
	"serv/internal/tlsconfig"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		log.Printf("Error parsing flags: %v", err)
		os.Exit(1)
	}

	dir, err := config.ResolveDir(cfg.Directory)
	if err != nil {
		log.Printf("Error getting working directory: %v", err)
		os.Exit(1)
	}

	logger, closeLog, err := logging.NewLogger(cfg.LogFile)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		os.Exit(1)
	}
	defer func() {
		if err := closeLog(); err != nil {
			log.Printf("Error closing log file: %v", err)
		}
	}()

	ipChecker, err := security.ParseAllowedIPs(cfg.AllowedIPs)
	if err != nil {
		log.Printf("Error parsing allowed IPs: %v", err)
		os.Exit(1)
	}

	sensitiveFiles, err := security.ResolveSensitiveFiles([]string{cfg.CACertFile, cfg.CertFile, cfg.KeyFile})
	if err != nil {
		log.Printf("Error configuring sensitive TLS paths: %v", err)
		os.Exit(1)
	}

	oneTimeDownloadDirs, err := handler.ResolveOneTimeDownloadDirs(dir, cfg.OneTimeDownloadDirs)
	if err != nil {
		log.Printf("Error configuring one-time download directories: %v", err)
		os.Exit(1)
	}

	oneTimeUploadDirs, err := handler.ResolveOneTimeUploadDirs(dir, cfg.OneTimeUploadDirs)
	if err != nil {
		log.Printf("Error configuring one-time upload directories: %v", err)
		os.Exit(1)
	}
	if err := handler.ValidateOneTimeDirSeparation(oneTimeDownloadDirs, oneTimeUploadDirs); err != nil {
		log.Printf("Error configuring one-time directories: %v", err)
		os.Exit(1)
	}

	credentialFileCache := map[string]basicAuthCredentials{}
	username, password, err := resolveBasicAuthCredentials(logger, cfg.Username, cfg.Password, credentialFileCache)
	if err != nil {
		log.Printf("Error configuring basic auth: %v", err)
		os.Exit(1)
	}

	h := &handler.Handler{
		Dir:                 dir,
		AllowInsecure:       cfg.AllowInsecure,
		AllowDotFiles:       cfg.AllowDotFiles,
		AllowedIPs:          ipChecker,
		Sensitive:           sensitiveFiles,
		Username:            username,
		Password:            password,
		Headers:             cfg.Headers,
		Redirects:           cfg.Redirects,
		FilterGlobs:         cfg.FilterGlobs,
		RequestChecks:       security.DefaultRequestChecks(),
		EntryFilters:        security.DefaultEntryFilters(),
		UploadEnabled:       cfg.UploadEnabled,
		UploadMaxBytes:      maxUploadBytes(cfg.UploadMaxMB),
		UploadOverwrite:     cfg.UploadOverwrite,
		OneTimeDownloadDirs: oneTimeDownloadDirs,
		OneTimeUploadDirs:   oneTimeUploadDirs,
		TrustProxyHeaders:   cfg.TrustProxyHeaders,
		Logger:              logger,
	}

	addr := fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.Port)
	server := newHTTPServer(addr, h)

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		config, err := tlsconfig.Configure(cfg.CACertFile, cfg.CertFile, cfg.KeyFile, cfg.ClientCertAuth)
		if err != nil {
			log.Printf("Error configuring TLS: %v", err)
			os.Exit(1)
		}
		server.TLSConfig = config
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}

	if err != nil {
		log.Printf("Error starting server: %v", err)
		os.Exit(1)
	}
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

func maxUploadBytes(maxMB int) int64 {
	if maxMB < 0 {
		maxMB = 100
	}
	if maxMB == 0 {
		return 0
	}
	return int64(maxMB) * 1024 * 1024
}

type basicAuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func resolveBasicAuthCredentials(logger *log.Logger, usernameValue string, passwordValue string, fileCache map[string]basicAuthCredentials) (string, string, error) {
	username, err := resolveCredentialValue(logger, "username", usernameValue, false, fileCache)
	if err != nil {
		return "", "", err
	}
	password, err := resolveCredentialValue(logger, "password", passwordValue, true, fileCache)
	if err != nil {
		return "", "", err
	}

	if (usernameValue != "" || passwordValue != "") && (username == "" || password == "") {
		return "", "", fmt.Errorf("both username and password must be configured for basic auth")
	}

	return username, password, nil
}

func resolveCredentialValue(logger *log.Logger, label string, value string, warnOnPlain bool, fileCache map[string]basicAuthCredentials) (string, error) {
	const envPrefix = "env:"
	if strings.HasPrefix(value, envPrefix) {
		key := strings.TrimPrefix(value, envPrefix)
		if key == "" {
			return "", fmt.Errorf("%s environment variable name is empty", label)
		}
		environmentValue, ok := os.LookupEnv(key)
		if !ok {
			return "", fmt.Errorf("%s environment variable %q is not set", label, key)
		}
		if environmentValue == "" {
			return "", fmt.Errorf("%s environment variable %q is empty", label, key)
		}
		return environmentValue, nil
	}

	const filePrefix = "file:"
	if strings.HasPrefix(value, filePrefix) {
		path := strings.TrimPrefix(value, filePrefix)
		if path == "" {
			return "", fmt.Errorf("%s file path is empty", label)
		}
		creds, ok := fileCache[path]
		if !ok {
			content, err := os.ReadFile(path)
			if err != nil {
				return "", fmt.Errorf("read %s credential file %q: %w", label, path, err)
			}
			if err := json.Unmarshal(content, &creds); err != nil {
				return "", fmt.Errorf("parse %s credential file %q as JSON: %w", label, path, err)
			}
			fileCache[path] = creds
		}

		if label == "password" {
			if creds.Password == "" {
				return "", fmt.Errorf("password missing in credential file %q", path)
			}
			return creds.Password, nil
		}
		if creds.Username == "" {
			return "", fmt.Errorf("username missing in credential file %q", path)
		}
		return creds.Username, nil
	}

	if warnOnPlain && value != "" {
		logger.Printf("Warning: password provided via -password is visible to other users; use env:<VAR> or file:<PATH> instead")
	}

	return value, nil
}
