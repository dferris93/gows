# serv Summary

serv is a lightweight Go HTTP/HTTPS file server with optional basic auth and access controls. It serves a chosen directory, supports TLS with provided cert/key, and includes a custom directory listing (dark theme). The server logs requests in a common format and can be configured with extra headers and redirects.

Key features
- Serve a directory over HTTP or HTTPS.
- TLS via `-cert`/`-key`, with optional client cert auth (`-mtls`) and CA bundle (`-cacert`).
- Basic auth via CLI or `env:VAR` values; `.htaccess` files can override creds per subtree.
- IP allowlist (`-allowedips`), redirects, and custom response headers.
- Security hardening: blocks path traversal, symlink escapes, hardlinks by default, dotfiles by default, and never serves `.htaccess`.
- TLS file protection: configured TLS cert/key/cacert files are never listed or downloadable, even if they live in the served tree or are symlinked into it.
- Logs request method/path/version/status/size and honors proxy headers for client IP.

Notes
- `-insecure` disables symlink and hardlink checks; `-allowdotfiles` permits dotfiles (except `.htaccess`).
- Directory listing hides sensitive files and respects security rules.
- Secure by default

Testing
- Unit tests: `go test ./...`
- Integration tests: `scripts/integration.sh`
- Both unit and integration tests should pass before doing a git commit and push.
