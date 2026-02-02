package security

import (
	"net/http"
	"strings"
)

type RequestContext struct {
	Req           *http.Request
	Dir           string
	RelPath       string
	AllowInsecure bool
	AllowDotFiles bool
	AllowedIPs    IPChecker
	Sensitive     []SensitiveFile
	FilterGlobs   []string
	Username      string
	Password      string
	Authed        bool
}

type CheckResult struct {
	Status int
	Public string
	Auth   bool
}

type RequestCheck func(*RequestContext) *CheckResult

type EntryContext struct {
	Dir           string
	RelPath       string
	Name          string
	AllowDotFiles bool
	Sensitive     []SensitiveFile
	FilterGlobs   []string
}

type EntryFilter func(*EntryContext) bool

func DefaultRequestChecks() []RequestCheck {
	return []RequestCheck{
		CheckAllowedIPs,
		CheckCleanPath,
		CheckHtaccessPath,
		CheckSensitivePath,
		CheckFilteredPath,
		CheckDotFiles,
		CheckHtaccess,
		CheckAuth,
		CheckRequestAuthorized,
	}
}

func DefaultEntryFilters() []EntryFilter {
	return []EntryFilter{
		FilterHtaccess,
		FilterEntryGlobs,
		FilterSensitive,
		FilterDotFiles,
	}
}

func RunRequestChecks(checks []RequestCheck, ctx *RequestContext) *CheckResult {
	for _, check := range checks {
		if check == nil {
			continue
		}
		if result := check(ctx); result != nil {
			return result
		}
	}
	return nil
}

func ApplyEntryFilters(filters []EntryFilter, ctx *EntryContext) bool {
	for _, filter := range filters {
		if filter == nil {
			continue
		}
		if !filter(ctx) {
			return false
		}
	}
	return true
}

func CheckAllowedIPs(ctx *RequestContext) *CheckResult {
	if ctx.Req == nil {
		return &CheckResult{Status: http.StatusInternalServerError, Public: "500 internal server error", Auth: true}
	}
	if ctx.AllowedIPs.Enabled() && !ctx.AllowedIPs.Allowed(ctx.Req.RemoteAddr) {
		return &CheckResult{Status: http.StatusForbidden, Public: "403 forbidden", Auth: false}
	}
	return nil
}

func CheckCleanPath(ctx *RequestContext) *CheckResult {
	if ctx.Req == nil {
		return &CheckResult{Status: http.StatusInternalServerError, Public: "500 internal server error", Auth: true}
	}
	relPath, err := CleanRequestPath(ctx.Req.URL.Path)
	if err != nil {
		return &CheckResult{Status: http.StatusForbidden, Public: "403 forbidden", Auth: true}
	}
	ctx.RelPath = relPath
	return nil
}

func CheckSensitivePath(ctx *RequestContext) *CheckResult {
	if IsSensitivePath(ctx.Dir, ctx.RelPath, ctx.Sensitive) {
		return &CheckResult{Status: http.StatusNotFound, Public: "404 not found", Auth: true}
	}
	return nil
}

func CheckHtaccessPath(ctx *RequestContext) *CheckResult {
	if IsHtaccessPath(ctx.RelPath) {
		return &CheckResult{Status: http.StatusNotFound, Public: "404 not found", Auth: true}
	}
	return nil
}

func CheckFilteredPath(ctx *RequestContext) *CheckResult {
	if IsFilteredPath(ctx.RelPath, ctx.FilterGlobs) {
		return &CheckResult{Status: http.StatusNotFound, Public: "404 not found", Auth: true}
	}
	return nil
}

func CheckDotFiles(ctx *RequestContext) *CheckResult {
	if ctx.AllowDotFiles {
		return nil
	}
	if IsDotFile(ctx.Dir, ctx.RelPath) != nil {
		return &CheckResult{Status: http.StatusNotFound, Public: "404 not found", Auth: true}
	}
	return nil
}

func CheckHtaccess(ctx *RequestContext) *CheckResult {
	creds, found, err := LoadHtaccessCredentials(ctx.Dir, ctx.RelPath, ctx.AllowInsecure)
	if err != nil {
		return &CheckResult{Status: http.StatusNotFound, Public: "404 not found", Auth: true}
	}
	if found {
		ctx.Username = creds.Username
		ctx.Password = creds.Password
	}
	return nil
}

func CheckAuth(ctx *RequestContext) *CheckResult {
	if ctx.Req == nil {
		return &CheckResult{Status: http.StatusInternalServerError, Public: "500 internal server error", Auth: true}
	}
	authed := AuthCheck(ctx.Req, ctx.Username, ctx.Password)
	ctx.Authed = authed
	if !authed {
		return &CheckResult{Status: http.StatusUnauthorized, Public: "401 unauthorized", Auth: false}
	}
	return nil
}

func CheckRequestAuthorized(ctx *RequestContext) *CheckResult {
	if !IsRequestAuthorized(ctx.Dir, ctx.RelPath, ctx.AllowInsecure, ctx.AllowDotFiles) {
		return &CheckResult{Status: http.StatusForbidden, Public: "403 forbidden", Auth: ctx.Authed}
	}
	return nil
}

func FilterHtaccess(ctx *EntryContext) bool {
	return !IsHtaccessPath(ctx.RelPath)
}

func FilterEntryGlobs(ctx *EntryContext) bool {
	return !IsFilteredEntry(ctx.RelPath, ctx.Name, ctx.FilterGlobs)
}

func FilterSensitive(ctx *EntryContext) bool {
	return !IsSensitivePath(ctx.Dir, ctx.RelPath, ctx.Sensitive)
}

func FilterDotFiles(ctx *EntryContext) bool {
	if ctx.AllowDotFiles {
		return true
	}
	return !strings.HasPrefix(ctx.Name, ".")
}
