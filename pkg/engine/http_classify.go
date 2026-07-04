package engine

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// evalHTTPClassifyWithDetail governs an outbound-HTTP tool call. Returns
// (fired, reason): fired=true means the destination violated a Require
// predicate (deny). A COVERAGE rule for the egress surface — the http/fetch
// tool otherwise connects anywhere ungoverned.
//
// Fail-closed: a missing or unparseable URL fires the rule when any
// allow-list (hosts/schemes/methods/ports) is set, since we cannot confirm
// the destination is permitted.
func evalHTTPClassifyWithDetail(h *domain.HTTPClassify, fields map[string]interface{}) (bool, string) {
	req := h.Require
	hasAllowList := len(req.AllowedHosts) > 0 || len(req.AllowedSchemes) > 0 ||
		len(req.AllowedMethods) > 0 || len(req.AllowedPorts) > 0

	urlField := h.URLField
	if urlField == "" {
		urlField = "parameters.url"
	}
	raw, ok := resolveField(urlField, fields)
	if !ok {
		if hasAllowList {
			return true, fmt.Sprintf("http_classify: url field %q missing but an allow-list is set", urlField)
		}
		return false, ""
	}
	rawURL, ok := raw.(string)
	if !ok || strings.TrimSpace(rawURL) == "" {
		if hasAllowList {
			return true, "http_classify: url is empty/non-string but an allow-list is set"
		}
		return false, ""
	}

	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return true, fmt.Sprintf("http_classify: unparseable url %q", rawURL)
	}

	host := strings.ToLower(u.Hostname())
	scheme := strings.ToLower(u.Scheme)
	port := explicitPort(u)

	// Method (optional field).
	method := ""
	mf := h.MethodField
	if mf == "" {
		mf = "parameters.method"
	}
	if mv, ok := resolveField(mf, fields); ok {
		method = strings.ToUpper(fmt.Sprintf("%v", mv))
	}

	// ── Deny checks first ──
	for _, d := range req.DeniedHosts {
		if hostMatches(host, d) {
			return true, fmt.Sprintf("http_classify: host %s is on the denied list (%s)", host, d)
		}
	}
	if method != "" {
		for _, d := range req.DeniedMethods {
			if strings.EqualFold(method, d) {
				return true, fmt.Sprintf("http_classify: method %s is denied", method)
			}
		}
	}
	if port > 0 {
		for _, d := range req.DeniedPorts {
			if port == d {
				return true, fmt.Sprintf("http_classify: port %d is denied", port)
			}
		}
	}

	// ── Allow-list checks ──
	if len(req.AllowedHosts) > 0 {
		ok := false
		for _, a := range req.AllowedHosts {
			if hostMatches(host, a) {
				ok = true
				break
			}
		}
		if !ok {
			return true, fmt.Sprintf("http_classify: host %s is not on the allowed list", host)
		}
	}
	if len(req.AllowedSchemes) > 0 && !containsFold(req.AllowedSchemes, scheme) {
		return true, fmt.Sprintf("http_classify: scheme %s is not allowed", scheme)
	}
	if len(req.AllowedMethods) > 0 && method != "" && !containsFold(req.AllowedMethods, method) {
		return true, fmt.Sprintf("http_classify: method %s is not allowed", method)
	}
	if len(req.AllowedPorts) > 0 && port > 0 {
		ok := false
		for _, a := range req.AllowedPorts {
			if port == a {
				ok = true
				break
			}
		}
		if !ok {
			return true, fmt.Sprintf("http_classify: port %d is not allowed", port)
		}
	}

	return false, ""
}

// explicitPort returns the URL's port as an int, or the scheme default
// (80/443) when omitted, or 0 when unknown.
func explicitPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
		return 0
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

// hostMatches reports whether host matches an allow/deny entry. An entry
// starting with "." is a suffix match (".example.com" matches
// api.example.com AND example.com); otherwise it's an exact match. All
// case-insensitive.
func hostMatches(host, entry string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" {
		return false
	}
	if strings.HasPrefix(entry, ".") {
		bare := entry[1:]
		return host == bare || strings.HasSuffix(host, entry)
	}
	return host == entry
}

func containsFold(list []string, val string) bool {
	for _, s := range list {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
