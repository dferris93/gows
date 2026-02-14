package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluatePathACL(t *testing.T) {
	dir := t.TempDir()

	secret := filepath.Join(dir, "secret.pem")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write sensitive file: %v", err)
	}
	sensitive, err := ResolveSensitiveFiles([]string{secret})
	if err != nil {
		t.Fatalf("resolve sensitive files: %v", err)
	}

	tests := []struct {
		name string
		ctx  PathACLContext
		want PathACLReason
	}{
		{
			name: "htaccess blocked",
			ctx: PathACLContext{
				Dir:           dir,
				RelPath:       ".htaccess",
				Name:          ".htaccess",
				AllowDotFiles: true,
			},
			want: PathACLHtaccess,
		},
		{
			name: "sensitive blocked",
			ctx: PathACLContext{
				Dir:           dir,
				RelPath:       "secret.pem",
				Name:          "secret.pem",
				AllowDotFiles: true,
				Sensitive:     sensitive,
			},
			want: PathACLSensitive,
		},
		{
			name: "filtered blocked",
			ctx: PathACLContext{
				Dir:           dir,
				RelPath:       "logs/app.log",
				Name:          "app.log",
				AllowDotFiles: true,
				FilterGlobs:   []string{"*.log"},
			},
			want: PathACLFiltered,
		},
		{
			name: "dotfile blocked",
			ctx: PathACLContext{
				Dir:           dir,
				RelPath:       ".env",
				Name:          ".env",
				AllowDotFiles: false,
			},
			want: PathACLDotfile,
		},
		{
			name: "allowed path",
			ctx: PathACLContext{
				Dir:           dir,
				RelPath:       "public.txt",
				Name:          "public.txt",
				AllowDotFiles: false,
			},
			want: PathACLAllowed,
		},
		{
			name: "root path allowed even when serve dir has dot segment",
			ctx: PathACLContext{
				Dir:           filepath.Join(dir, ".served"),
				RelPath:       "",
				Name:          "",
				AllowDotFiles: false,
			},
			want: PathACLAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluatePathACL(tt.ctx); got != tt.want {
				t.Fatalf("EvaluatePathACL() = %q, want %q", got, tt.want)
			}
		})
	}
}
