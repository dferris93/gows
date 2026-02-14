package logging

import (
	"bytes"
	"log"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestLogRequestNoProxyUsesRemoteAddress(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	req := httptest.NewRequest("GET", "http://example.test/hello", nil)
	req.RemoteAddr = "203.0.113.8:12345"

	LogRequest(logger, req, 42, 200)
	line := strings.TrimSpace(buf.String())

	if !strings.HasPrefix(line, "203.0.113.8 - - [") {
		t.Fatalf("unexpected log prefix: %q", line)
	}
	if !matchesCLF(line, "203.0.113.8", "GET", "/hello", "HTTP/1.1", 200, 42) {
		t.Fatalf("log line is not valid CLF: %q", line)
	}
}

func TestLogRequestUsesXForwardedForClientIP(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	req := httptest.NewRequest("GET", "http://example.test/proxied", nil)
	req.RemoteAddr = "10.10.0.4:44321"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 198.51.100.10")

	LogRequest(logger, req, 5, 304)
	line := strings.TrimSpace(buf.String())

	if !strings.HasPrefix(line, "198.51.100.9 - - [") {
		t.Fatalf("unexpected log prefix: %q", line)
	}
	if !matchesCLF(line, "198.51.100.9", "GET", "/proxied", "HTTP/1.1", 304, 5) {
		t.Fatalf("log line is not valid CLF: %q", line)
	}
}

func TestLogRequestXRealIPWhenForwardedForMissing(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	req := httptest.NewRequest("POST", "http://example.test/real", nil)
	req.RemoteAddr = "10.0.0.7:5100"
	req.Header.Set("X-Real-IP", "198.18.0.20")

	LogRequest(logger, req, 18, 201)
	line := strings.TrimSpace(buf.String())

	if !strings.HasPrefix(line, "198.18.0.20 - - [") {
		t.Fatalf("unexpected log prefix: %q", line)
	}
	if !matchesCLF(line, "198.18.0.20", "POST", "/real", "HTTP/1.1", 201, 18) {
		t.Fatalf("log line is not valid CLF: %q", line)
	}
}

func TestSplitRemoteHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "ipv4", in: "192.0.2.1:8080", want: "192.0.2.1"},
		{name: "ipv6", in: "[2001:db8::1]:8443", want: "2001:db8::1"},
		{name: "host-only", in: "localhost", want: "localhost"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitRemoteHost(tc.in); got != tc.want {
				t.Fatalf("splitRemoteHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestLogRequestUsesRequestURI(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	req := httptest.NewRequest("GET", "http://example.test/search?q=go", nil)
	req.RemoteAddr = "192.168.5.118:5111"

	LogRequest(logger, req, 0, 200)
	line := strings.TrimSpace(buf.String())

	if !matchesCLF(line, "192.168.5.118", "GET", "/search?q=go", "HTTP/1.1", 200, 0) {
		t.Fatalf("log line is not valid CLF: %q", line)
	}
}

func matchesCLF(line, host, method, requestURI, proto string, status, size int) bool {
	expr := "^" + regexp.QuoteMeta(host) + ` - - \[[^\]]+\] "` +
		regexp.QuoteMeta(method+" "+requestURI+" "+proto) +
		`" ` + regexp.QuoteMeta(strconv.Itoa(status)) + ` ` + regexp.QuoteMeta(strconv.Itoa(size)) + `$`
	return regexp.MustCompile(expr).MatchString(line)
}
