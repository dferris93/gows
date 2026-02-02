package security

import (
	"path"
	"strings"
)

func IsFilteredPath(relPath string, patterns []string) bool {
	if relPath == "" {
		return false
	}
	name := path.Base(relPath)
	if name == "." || name == "/" {
		name = ""
	}
	return IsFilteredEntry(relPath, name, patterns)
}

func IsFilteredEntry(relPath string, name string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, raw := range patterns {
		pattern := normalizeGlobPattern(raw)
		if pattern == "" {
			continue
		}
		if globMatch(pattern, relPath) || globMatch(pattern, name) {
			return true
		}
	}
	return false
}

func normalizeGlobPattern(pattern string) string {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.ReplaceAll(trimmed, "\\", "/")
	if strings.HasSuffix(trimmed, "/") && trimmed != "/" {
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	return trimmed
}

func globMatch(pattern string, target string) bool {
	matched, err := path.Match(pattern, target)
	if err != nil {
		return false
	}
	return matched
}
