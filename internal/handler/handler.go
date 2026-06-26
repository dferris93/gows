package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"

	"serv/internal/logging"
	"serv/internal/security"
)

type Handler struct {
	Dir                 string
	AllowInsecure       bool
	AllowDotFiles       bool
	AllowedIPs          security.IPChecker
	Sensitive           []security.SensitiveFile
	Username            string
	Password            string
	Headers             map[string]string
	Redirects           map[string]string
	FilterGlobs         []string
	RequestChecks       []security.RequestCheck
	EntryFilters        []security.EntryFilter
	UploadEnabled       bool
	UploadMaxBytes      int64
	UploadOverwrite     bool
	OneTimeDownloadDirs []string
	OneTimeUploadDirs   []string
	TrustProxyHeaders   bool
	Logger              *log.Logger

	oneTimeMu     sync.Mutex
	oneTimeActive map[string]struct{}

	uploadMu     sync.Mutex
	uploadActive map[string]struct{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := logging.NewResponseWriter(w)

	ctx := security.RequestContext{
		Req:           r,
		Dir:           h.Dir,
		AllowInsecure: h.AllowInsecure,
		AllowDotFiles: h.AllowDotFiles,
		AllowedIPs:    h.AllowedIPs,
		Sensitive:     h.Sensitive,
		FilterGlobs:   h.FilterGlobs,
		Username:      h.Username,
		Password:      h.Password,
	}
	checks := h.RequestChecks
	if len(checks) == 0 {
		checks = security.DefaultRequestChecks()
	}
	if result := security.RunRequestChecks(checks, &ctx); result != nil {
		h.logAndReturnError(rw, r, result.Auth, result.Public, result.Status)
		return
	}

	if url, ok := h.Redirects[r.URL.Path]; ok {
		http.Redirect(rw, r, url, http.StatusFound)
		h.logRequest(r, rw)
		return
	}

	if !methodAllowed(r.Method) {
		rw.Header().Set("Allow", "GET, HEAD, POST")
		h.logAndReturnError(rw, r, ctx.Authed, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodPost {
		h.handleUpload(rw, r, &ctx)
		h.logRequest(r, rw)
		return
	}

	fullPath := filepath.Join(h.Dir, filepath.FromSlash(ctx.RelPath))
	info, err := os.Stat(fullPath)
	if err != nil {
		h.logAndReturnError(rw, r, ctx.Authed, "404 not found", http.StatusNotFound)
		return
	}

	if !info.IsDir() && h.isOneTimeUploadPath(fullPath) {
		h.logAndReturnError(rw, r, ctx.Authed, "404 not found", http.StatusNotFound)
		return
	}

	for key, value := range h.Headers {
		rw.Header().Set(key, value)
	}

	if info.IsDir() {
		indexFile := filepath.Join(fullPath, "index.html")
		if !h.isOneTimeUploadDir(fullPath) {
			if _, err := os.Stat(indexFile); err == nil {
				indexRel := "index.html"
				if ctx.RelPath != "" {
					indexRel = path.Join(ctx.RelPath, "index.html")
				}
				file, indexInfo, err := h.openAuthorizedFile(indexRel)
				if err != nil {
					h.serveDir(rw, r, fullPath, ctx.RelPath, ctx.Authed)
					return
				}
				defer file.Close()
				http.ServeContent(rw, r, indexInfo.Name(), indexInfo.ModTime(), file)
				h.logRequest(r, rw)
				return
			}
		}
		h.serveDir(rw, r, fullPath, ctx.RelPath, ctx.Authed)
		return
	}

	file, openedInfo, err := h.openAuthorizedFile(ctx.RelPath)
	if err != nil {
		h.logAndReturnError(rw, r, ctx.Authed, "404 not found", http.StatusNotFound)
		return
	}

	if key, ok := h.oneTimeDownloadKey(fullPath, openedInfo); ok && r.Method == http.MethodGet {
		h.serveOneTimeDownload(rw, r, fullPath, file, openedInfo, key, ctx.Authed)
		return
	}
	defer file.Close()

	http.ServeContent(rw, r, openedInfo.Name(), openedInfo.ModTime(), file)
	h.logRequest(r, rw)
}

func methodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodPost
}

func (h *Handler) openAuthorizedFile(relPath string) (*os.File, os.FileInfo, error) {
	fullPath := filepath.Join(h.Dir, filepath.FromSlash(relPath))
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, nil, err
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.IsDir() {
		return nil, nil, fmt.Errorf("path is a directory")
	}

	if err := h.checkReadACLs(relPath); err != nil {
		return nil, nil, err
	}

	pathInfo, err := os.Stat(fullPath)
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(info, pathInfo) {
		return nil, nil, fmt.Errorf("path changed during authorization")
	}

	closeOnError = false
	return file, info, nil
}

func (h *Handler) checkReadACLs(relPath string) error {
	reason := security.EvaluatePathACL(security.PathACLContext{
		Dir:           h.Dir,
		RelPath:       relPath,
		AllowDotFiles: h.AllowDotFiles,
		Sensitive:     h.Sensitive,
		FilterGlobs:   h.FilterGlobs,
	})
	if reason != security.PathACLAllowed {
		return fmt.Errorf("path is not allowed")
	}
	if !security.IsRequestAuthorized(h.Dir, relPath, h.AllowInsecure, h.AllowDotFiles) {
		return fmt.Errorf("path is not authorized")
	}
	return nil
}

func (h *Handler) logAndReturnError(rw *logging.ResponseWriter, r *http.Request, ac bool, errorMsg string, errorCode int) {
	if !ac {
		rw.Header().Set("WWW-Authenticate", `Basic realm="Enter username and password"`)
	}
	http.Error(rw, errorMsg, errorCode)
	h.logRequest(r, rw)
}

func (h *Handler) logRequest(r *http.Request, rw *logging.ResponseWriter) {
	logging.LogRequestWithProxyHeaders(h.Logger, r, rw.Size, rw.StatusCode, h.TrustProxyHeaders)
}
