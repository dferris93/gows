package handler

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"gows/internal/logging"
)

type dirEntry struct {
	Name      string
	Href      string
	Size      string
	ModTime   string
	IconClass string
}

type dirListingData struct {
	Title       string
	Path        string
	ParentHref  string
	HasParent   bool
	Entries     []dirEntry
	GeneratedAt string
}

var dirListingTemplate = template.Must(template.New("dir-listing").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      --bg: #edf1f5;
      --window: #fbfbfc;
      --border: #d6d9de;
      --titlebar: linear-gradient(#f7f7f7, #e7eaee);
      --text: #1b1f24;
      --muted: #70757d;
      --row: #ffffff;
      --row-alt: #f6f8fa;
      --row-hover: #e6f0ff;
      --link: #0a5bd8;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "SF Pro Text", "Helvetica Neue", Helvetica, Arial, sans-serif;
      background: radial-gradient(circle at top, #f8fafc 0%, #edf1f5 55%, #e2e7ee 100%);
      color: var(--text);
      min-height: 100vh;
      padding: 32px 18px 48px;
    }

    .window {
      max-width: 980px;
      margin: 0 auto;
      border-radius: 14px;
      background: var(--window);
      border: 1px solid var(--border);
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.16), 0 6px 20px rgba(15, 23, 42, 0.08);
      overflow: hidden;
    }

    .titlebar {
      height: 44px;
      padding: 0 16px;
      display: flex;
      align-items: center;
      border-bottom: 1px solid var(--border);
      background: var(--titlebar);
    }

    .titlebar .path {
      font-size: 13px;
      color: var(--muted);
      letter-spacing: 0.02em;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      background: #f4f6f9;
    }

    .toolbar h1 {
      font-size: 18px;
      margin: 0;
      font-weight: 600;
    }

    .toolbar .meta {
      font-size: 12px;
      color: var(--muted);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }

    thead th {
      text-align: left;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
      padding: 10px 18px;
      border-bottom: 1px solid var(--border);
      background: #f8f9fb;
    }

    tbody tr {
      background: var(--row);
    }

    tbody tr:nth-child(even) {
      background: var(--row-alt);
    }

    tbody tr:hover {
      background: var(--row-hover);
    }

    tbody td {
      padding: 10px 18px;
      border-bottom: 1px solid #edf0f3;
      vertical-align: middle;
    }

    .name-cell {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .icon {
      width: 18px;
      height: 14px;
      border-radius: 3px;
      background: linear-gradient(180deg, #9cc2ff 0%, #5f90ff 100%);
      box-shadow: inset 0 -2px 0 rgba(0, 0, 0, 0.15);
      flex-shrink: 0;
    }

    .icon.file {
      width: 14px;
      height: 16px;
      border-radius: 2px;
      background: #e7eaee;
      position: relative;
      box-shadow: inset 0 -2px 0 rgba(0, 0, 0, 0.1);
    }

    .icon.file::after {
      content: "";
      position: absolute;
      top: 0;
      right: 0;
      border-top: 6px solid #c9ced6;
      border-left: 6px solid transparent;
    }

    a {
      color: var(--text);
      text-decoration: none;
    }

    a:hover {
      color: var(--link);
    }

    .muted {
      color: var(--muted);
      font-size: 12px;
    }

    @media (max-width: 640px) {
      body {
        padding: 18px 10px 32px;
      }

      .toolbar {
        flex-direction: column;
        align-items: flex-start;
        gap: 6px;
      }

      thead th:nth-child(2),
      thead th:nth-child(3),
      tbody td:nth-child(2),
      tbody td:nth-child(3) {
        display: none;
      }
    }
  </style>
</head>
<body>
  <div class="window">
    <div class="titlebar">
      <div class="path">{{.Path}}</div>
    </div>
    <div class="toolbar">
      <h1>{{.Title}}</h1>
      <div class="meta">Generated {{.GeneratedAt}}</div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Modified</th>
          <th>Size</th>
        </tr>
      </thead>
      <tbody>
        {{if .HasParent}}
        <tr>
          <td>
            <div class="name-cell">
              <span class="icon"></span>
              <a href="{{.ParentHref}}">..</a>
            </div>
          </td>
          <td class="muted">Parent directory</td>
          <td class="muted">--</td>
        </tr>
        {{end}}
        {{range .Entries}}
        <tr>
          <td>
            <div class="name-cell">
              <span class="icon {{.IconClass}}"></span>
              <a href="{{.Href}}">{{.Name}}</a>
            </div>
          </td>
          <td class="muted">{{.ModTime}}</td>
          <td class="muted">{{.Size}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</body>
</html>`))

func (h *Handler) serveDir(rw *logging.ResponseWriter, r *http.Request, fullPath string, ac bool) {
	if !strings.HasSuffix(r.URL.Path, "/") {
		target := r.URL.Path + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(rw, r, target, http.StatusMovedPermanently)
		logging.LogRequest(h.Logger, r, rw.Size, rw.StatusCode)
		return
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		h.logAndReturnError(rw, r, ac, "500 internal server error", http.StatusInternalServerError)
		return
	}

	listing := make([]dirEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		name := entry.Name()
		if name == ".htaccess" {
			continue
		}
		if !h.AllowDotFiles && strings.HasPrefix(name, ".") {
			continue
		}
		href := path.Join(r.URL.Path, url.PathEscape(name))
		iconClass := "file"
		size := formatBytes(info.Size())
		if entry.IsDir() {
			name += "/"
			href += "/"
			iconClass = "dir"
			size = "--"
		}

		listing = append(listing, dirEntry{
			Name:      name,
			Href:      href,
			Size:      size,
			ModTime:   info.ModTime().Format("Jan 02, 2006 15:04"),
			IconClass: iconClass,
		})
	}

	sort.Slice(listing, func(i, j int) bool {
		leftDir := strings.HasSuffix(listing[i].Name, "/")
		rightDir := strings.HasSuffix(listing[j].Name, "/")
		if leftDir != rightDir {
			return leftDir
		}
		return strings.ToLower(listing[i].Name) < strings.ToLower(listing[j].Name)
	})

	data := dirListingData{
		Title:       "Index of " + r.URL.Path,
		Path:        r.URL.Path,
		Entries:     listing,
		GeneratedAt: time.Now().Format("Jan 02, 2006 15:04"),
	}

	if r.URL.Path != "/" {
		parent := path.Dir(strings.TrimSuffix(r.URL.Path, "/"))
		if parent == "." {
			parent = "/"
		}
		if !strings.HasSuffix(parent, "/") {
			parent += "/"
		}
		data.HasParent = true
		data.ParentHref = parent
	}

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dirListingTemplate.Execute(rw, data); err != nil {
		h.logAndReturnError(rw, r, ac, "500 internal server error", http.StatusInternalServerError)
		return
	}

	logging.LogRequest(h.Logger, r, rw.Size, rw.StatusCode)
}

func formatBytes(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}

	units := []string{"KB", "MB", "GB", "TB", "PB"}
	value := float64(size)
	for _, unit := range units {
		value /= 1024
		if value < 1024 {
			if value < 10 {
				return fmt.Sprintf("%.1f %s", value, unit)
			}
			return fmt.Sprintf("%.0f %s", value, unit)
		}
	}

	return fmt.Sprintf("%.0f PB", value)
}
