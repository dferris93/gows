package logging

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = old
		_ = writer.Close()
		_ = reader.Close()
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(data)
}

func TestNewLoggerStdout(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{name: "empty", path: ""},
		{name: "dash", path: "-"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				logger, closeFn, err := NewLogger(tc.path)
				if err != nil {
					t.Fatalf("NewLogger(%q) error: %v", tc.path, err)
				}
				if logger == nil {
					t.Fatalf("NewLogger(%q) returned nil logger", tc.path)
				}
				if closeFn == nil {
					t.Fatalf("NewLogger(%q) returned nil close function", tc.path)
				}

				logger.Print("hello")
				if err := closeFn(); err != nil {
					t.Fatalf("close logger for %q: %v", tc.path, err)
				}
			})
			if !strings.Contains(output, "hello") {
				t.Fatalf("expected stdout to contain log message for %q, got %q", tc.path, output)
			}
		})
	}
}

func TestNewLoggerFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	logger, closeFn, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger file error: %v", err)
	}
	if logger == nil {
		t.Fatal("NewLogger file returned nil logger")
	}
	if closeFn == nil {
		t.Fatal("NewLogger file returned nil close function")
	}

	logger.Print("hello")
	if err := closeFn(); err != nil {
		t.Fatalf("close file logger: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("expected log file to contain message, got %q", string(data))
	}
}
