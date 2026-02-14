package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"serv/internal/logging"
	"serv/internal/security"
)

type uploadFileResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type uploadResponse struct {
	Uploaded int                `json:"uploaded"`
	Failed   int                `json:"failed"`
	Files    []uploadFileResult `json:"files"`
}

func (h *Handler) handleUpload(rw *logging.ResponseWriter, r *http.Request, ctx *security.RequestContext) {
	if !h.UploadEnabled {
		http.Error(rw, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetDir := filepath.Join(h.Dir, filepath.FromSlash(ctx.RelPath))
	info, err := os.Stat(targetDir)
	if err != nil {
		http.Error(rw, "404 not found", http.StatusNotFound)
		return
	}
	if !info.IsDir() {
		http.Error(rw, "400 bad request", http.StatusBadRequest)
		return
	}

	if h.UploadMaxBytes > 0 {
		r.Body = http.MaxBytesReader(rw, r.Body, h.UploadMaxBytes)
	}
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(rw, "413 request entity too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(rw, "400 bad request", http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		files = r.MultipartForm.File["file"]
	}
	logging.SetUploadFilenames(r, uploadFilenames(files))
	if len(files) == 0 {
		h.writeUploadResponse(rw, http.StatusBadRequest, uploadResponse{
			Failed: 1,
			Files: []uploadFileResult{{
				Status:  "error",
				Message: "no files selected",
			}},
		})
		return
	}

	resp := uploadResponse{Files: make([]uploadFileResult, 0, len(files))}
	for _, fileHeader := range files {
		result := h.storeUploadedFile(targetDir, ctx.RelPath, fileHeader)
		resp.Files = append(resp.Files, result)
		if result.Status == "uploaded" {
			resp.Uploaded++
		} else {
			resp.Failed++
		}
	}

	status := http.StatusCreated
	if resp.Uploaded == 0 {
		status = http.StatusBadRequest
	} else if resp.Failed > 0 {
		status = http.StatusMultiStatus
	}
	h.writeUploadResponse(rw, status, resp)
}

func (h *Handler) storeUploadedFile(targetDir string, relDir string, fileHeader *multipart.FileHeader) uploadFileResult {
	name, err := sanitizeUploadFilename(fileHeader.Filename)
	if err != nil {
		return uploadFileResult{Name: fileHeader.Filename, Status: "error", Message: err.Error()}
	}

	relPath := name
	if relDir != "" {
		relPath = path.Join(relDir, name)
	}

	if err := h.checkUploadACLs(relPath); err != nil {
		return uploadFileResult{Name: name, Status: "error", Message: err.Error()}
	}

	src, err := fileHeader.Open()
	if err != nil {
		return uploadFileResult{Name: name, Status: "error", Message: "failed to read uploaded file"}
	}
	defer src.Close()

	dstPath := filepath.Join(targetDir, name)
	if err := writeUploadedFile(dstPath, src, h.UploadOverwrite); err != nil {
		if errors.Is(err, os.ErrExist) {
			return uploadFileResult{Name: name, Status: "error", Message: "file already exists"}
		}
		return uploadFileResult{Name: name, Status: "error", Message: "failed to write file"}
	}

	return uploadFileResult{Name: name, Status: "uploaded"}
}

func (h *Handler) checkUploadACLs(relPath string) error {
	reason := security.EvaluatePathACL(security.PathACLContext{
		Dir:           h.Dir,
		RelPath:       relPath,
		Name:          path.Base(relPath),
		AllowDotFiles: h.AllowDotFiles,
		Sensitive:     h.Sensitive,
		FilterGlobs:   h.FilterGlobs,
	})
	switch reason {
	case security.PathACLHtaccess:
		return fmt.Errorf(".htaccess uploads are blocked")
	case security.PathACLFiltered:
		return fmt.Errorf("blocked by filter rules")
	case security.PathACLDotfile:
		return fmt.Errorf("dotfiles are disabled")
	case security.PathACLSensitive:
		return fmt.Errorf("path is protected")
	}

	if !security.IsRequestAuthorized(h.Dir, relPath, h.AllowInsecure, h.AllowDotFiles) {
		return fmt.Errorf("path is not allowed")
	}

	return nil
}

func uploadFilenames(files []*multipart.FileHeader) []string {
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Filename)
	}
	return names
}

func sanitizeUploadFilename(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("invalid filename")
	}
	if strings.Contains(trimmed, "/") || strings.Contains(trimmed, "\\") {
		return "", fmt.Errorf("filename must not include path separators")
	}
	base := path.Base(trimmed)
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("invalid filename")
	}
	return base, nil
}

func writeUploadedFile(dstPath string, src multipart.File, overwrite bool) error {
	flags := os.O_CREATE | os.O_WRONLY
	if overwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}

	dst, err := os.OpenFile(dstPath, flags, 0o600)
	if err != nil {
		return err
	}

	copyErr := error(nil)
	if _, err := io.Copy(dst, src); err != nil {
		copyErr = err
	}
	closeErr := dst.Close()

	if copyErr != nil {
		_ = os.Remove(dstPath)
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func (h *Handler) writeUploadResponse(rw *logging.ResponseWriter, status int, resp uploadResponse) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(resp)
}
