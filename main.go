package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"gows/internal/config"
	"gows/internal/handler"
	"gows/internal/logging"
	"gows/internal/security"
	"gows/internal/tlsconfig"
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

	blockTLSFiles, err := security.ShouldBlockTLSFiles(dir, []string{cfg.CACertFile, cfg.CertFile, cfg.KeyFile})
	if err != nil {
		log.Printf("Error configuring TLS file blocking: %v", err)
		os.Exit(1)
	}

	username := resolveEnvValue(logger, "username", cfg.Username, false)
	password := resolveEnvValue(logger, "password", cfg.Password, true)

	h := &handler.Handler{
		Dir:           dir,
		AllowInsecure: cfg.AllowInsecure,
		AllowDotFiles: cfg.AllowDotFiles,
		AllowedIPs:    ipChecker,
		Sensitive:     sensitiveFiles,
		BlockTLSFiles: blockTLSFiles,
		Username:      username,
		Password:      password,
		Headers:       cfg.Headers,
		Redirects:     cfg.Redirects,
		FilterGlobs:   cfg.FilterGlobs,
		RequestChecks: security.DefaultRequestChecks(),
		EntryFilters:  security.DefaultEntryFilters(),
		Logger:        logger,
	}

	addr := fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: h,
	}

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

func resolveEnvValue(logger *log.Logger, label string, value string, warnOnPlain bool) string {
	const prefix = "env:"
	if strings.HasPrefix(value, prefix) {
		key := strings.TrimPrefix(value, prefix)
		if key == "" {
			logger.Printf("Warning: %s environment variable name is empty", label)
			return ""
		}
		environmentValue, ok := os.LookupEnv(key)
		if !ok {
			logger.Printf("Warning: %s environment variable %q is not set", label, key)
		}
		return environmentValue
	}

	if warnOnPlain && value != "" {
		logger.Printf("Warning: password provided via -password is visible to other users; use env:<VAR> instead")
	}

	return value
}
