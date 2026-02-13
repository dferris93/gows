package logging

import (
	"bytes"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogRequestNoProxyUsesDashProxyField(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	req := httptest.NewRequest("GET", "http://example.test/hello", nil)
	req.RemoteAddr = "203.0.113.8:12345"

	LogRequest(logger, req, 42, 200)
	line := strings.TrimSpace(buf.String())

	if !strings.HasPrefix(line, "- 203.0.113.8 - - [") {
		t.Fatalf("unexpected log prefix: %q", line)
	}
	if !strings.Contains(line, "\"GET /hello HTTP/1.1\" 200 42") {
		t.Fatalf("unexpected request segment: %q", line)
	}
}

func TestLogRequestProxyHeadersKeepFixedPrefixFields(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	req := httptest.NewRequest("GET", "http://example.test/proxied", nil)
	req.RemoteAddr = "10.10.0.4:44321"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 198.51.100.10")

	LogRequest(logger, req, 5, 304)
	line := strings.TrimSpace(buf.String())

	if !strings.HasPrefix(line, "10.10.0.4 198.51.100.9 - - [") {
		t.Fatalf("unexpected log prefix: %q", line)
	}
	if !strings.Contains(line, "\"GET /proxied HTTP/1.1\" 304 5") {
		t.Fatalf("unexpected request segment: %q", line)
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

	if !strings.HasPrefix(line, "10.0.0.7 198.18.0.20 - - [") {
		t.Fatalf("unexpected log prefix: %q", line)
	}
	if !strings.Contains(line, "\"POST /real HTTP/1.1\" 201 18") {
		t.Fatalf("unexpected request segment: %q", line)
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
