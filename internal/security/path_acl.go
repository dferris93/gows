package security

import "strings"

type PathACLReason string

const (
	PathACLAllowed   PathACLReason = ""
	PathACLHtaccess  PathACLReason = "htaccess"
	PathACLSensitive PathACLReason = "sensitive"
	PathACLFiltered  PathACLReason = "filtered"
	PathACLDotfile   PathACLReason = "dotfile"
)

type PathACLContext struct {
	Dir           string
	RelPath       string
	Name          string
	AllowDotFiles bool
	Sensitive     []SensitiveFile
	FilterGlobs   []string
}

func EvaluatePathACL(ctx PathACLContext) PathACLReason {
	// Root requests map to an empty relative path and should not be treated as
	// dotfile access based on the server's filesystem location.
	if ctx.RelPath == "" {
		return PathACLAllowed
	}

	if IsHtaccessPath(ctx.RelPath) {
		return PathACLHtaccess
	}

	if IsSensitivePath(ctx.Dir, ctx.RelPath, ctx.Sensitive) {
		return PathACLSensitive
	}

	if ctx.Name != "" {
		if IsFilteredEntry(ctx.RelPath, ctx.Name, ctx.FilterGlobs) {
			return PathACLFiltered
		}
	} else if IsFilteredPath(ctx.RelPath, ctx.FilterGlobs) {
		return PathACLFiltered
	}

	if !ctx.AllowDotFiles {
		if ctx.Name != "" {
			if strings.HasPrefix(ctx.Name, ".") {
				return PathACLDotfile
			}
		} else if IsDotFile(ctx.Dir, ctx.RelPath) != nil {
			return PathACLDotfile
		}
	}

	return PathACLAllowed
}
