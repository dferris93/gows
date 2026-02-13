package logging

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type ResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	Size       int
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{ResponseWriter: w, StatusCode: http.StatusOK}
}

func (w *ResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.Size += n
	return n, err
}

func LogRequest(logger *log.Logger, r *http.Request, size int, statusCode int) {
	currentTime := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	requestMethod := r.Method
	requestPath := r.URL.Path
	httpVersion := r.Proto
	proxyIP := splitRemoteHost(r.RemoteAddr)
	clientIP := proxyIP

	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		parts := strings.Split(xForwardedFor, ",")
		clientIP = strings.TrimSpace(parts[0])
	} else if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		clientIP = strings.TrimSpace(xRealIP)
	} else {
		proxyIP = "-"
	}

	if proxyIP == "" {
		proxyIP = "-"
	}
	if clientIP == "" {
		clientIP = "-"
	}

	logger.Printf("%s %s - - [%s] \"%s %s %s\" %d %d\n", proxyIP, clientIP, currentTime, requestMethod, requestPath, httpVersion, statusCode, size)
}

func splitRemoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}
	return remoteAddr
}
