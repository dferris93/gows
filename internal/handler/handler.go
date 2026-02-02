package handler

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"gows/internal/logging"
	"gows/internal/security"
)

type Handler struct {
	Dir           string
	AllowInsecure bool
	AllowDotFiles bool
	AllowedIPs    security.IPChecker
	Sensitive     []security.SensitiveFile
	BlockTLSFiles bool
	Username      string
	Password      string
	Headers       map[string]string
	Redirects     map[string]string
	FilterGlobs   []string
	Logger        *log.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := logging.NewResponseWriter(w)

	if h.AllowedIPs.Enabled() {
		if !h.AllowedIPs.Allowed(r.RemoteAddr) {
			h.logAndReturnError(rw, r, false, "403 forbidden", http.StatusForbidden)
			return
		}
	}

	relPath, err := security.CleanRequestPath(r.URL.Path)
	if err != nil {
		h.logAndReturnError(rw, r, true, "403 forbidden", http.StatusForbidden)
		return
	}

	if security.IsSensitivePath(h.Dir, relPath, h.Sensitive) {
		h.logAndReturnError(rw, r, true, "403 forbidden", http.StatusForbidden)
		return
	}

	if h.isFilteredPath(relPath) {
		h.logAndReturnError(rw, r, true, "404 not found", http.StatusNotFound)
		return
	}

	if h.BlockTLSFiles && security.IsLikelyTLSFile(relPath) {
		h.logAndReturnError(rw, r, true, "403 forbidden", http.StatusForbidden)
		return
	}

	username := h.Username
	password := h.Password
	htCreds, htFound, err := security.LoadHtaccessCredentials(h.Dir, relPath, h.AllowInsecure)
	if err != nil {
		h.logAndReturnError(rw, r, true, "500 internal server error", http.StatusInternalServerError)
		return
	}
	if htFound {
		username = htCreds.Username
		password = htCreds.Password
	}

	ac := security.AuthCheck(r, username, password)
	if !ac {
		h.logAndReturnError(rw, r, ac, "401 unauthorized", http.StatusUnauthorized)
		return
	}

	if url, ok := h.Redirects[r.URL.Path]; ok {
		http.Redirect(rw, r, url, http.StatusFound)
		logging.LogRequest(h.Logger, r, rw.Size, rw.StatusCode)
		return
	}

	if !security.IsRequestAuthorized(h.Dir, relPath, h.AllowInsecure, h.AllowDotFiles) {
		h.logAndReturnError(rw, r, ac, "403 forbidden", http.StatusForbidden)
		return
	}

	fullPath := filepath.Join(h.Dir, filepath.FromSlash(relPath))
	info, err := os.Stat(fullPath)
	if err != nil {
		h.logAndReturnError(rw, r, ac, "404 not found", http.StatusNotFound)
		return
	}

	for key, value := range h.Headers {
		rw.Header().Set(key, value)
	}

	if info.IsDir() {
		indexFile := filepath.Join(fullPath, "index.html")
		if _, err := os.Stat(indexFile); err == nil {
			http.ServeFile(rw, r, indexFile)
			logging.LogRequest(h.Logger, r, rw.Size, rw.StatusCode)
			return
		}
		h.serveDir(rw, r, fullPath, relPath, ac)
		return
	}

	http.ServeFile(rw, r, fullPath)
	logging.LogRequest(h.Logger, r, rw.Size, rw.StatusCode)
}

func (h *Handler) logAndReturnError(rw *logging.ResponseWriter, r *http.Request, ac bool, errorMsg string, errorCode int) {
	if !ac {
		rw.Header().Set("WWW-Authenticate", `Basic realm="Enter username and password"`)
	}
	http.Error(rw, errorMsg, errorCode)
	logging.LogRequest(h.Logger, r, rw.Size, rw.StatusCode)
}
