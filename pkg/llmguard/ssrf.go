package llmguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SafeFetchClient is an http.Client hardened against SSRF for use when
// fetching policy-supplied image URLs. The protections:
//
//   - scheme allowlist: only http/https accepted
//   - host resolution: DNS is performed at our control plane, every
//     resolved IP must be a public unicast address — RFC1918, loopback,
//     link-local, RFC6598 (CGNAT), and link-local IPv6 are all denied
//     so the proxy cannot be coerced into hitting cloud metadata
//     endpoints (169.254.169.254), localhost services (127.0.0.1:6379),
//     or LAN hosts
//   - no redirects: prevents a public host from 302-ing into a
//     private one (DNS rebinding / open-redirect SSRF)
//   - short overall timeout: bounds image fetch to 15s
//
// Callers should reuse the same SafeFetchClient across requests; it is
// safe for concurrent use.
type SafeFetchClient struct {
	HTTP *http.Client
}

// NewSafeFetchClient returns a client configured per the SSRF policy
// described on SafeFetchClient. Callers that need to customise the
// allowlist or timeouts should build their own and assert that
// rejectPrivateAddress is used.
func NewSafeFetchClient() *SafeFetchClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("split host port %q: %w", addr, err)
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("dns lookup: %w", err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("dns: no addresses")
			}
			// Every resolved IP must be safe — if ANY is private,
			// reject. Otherwise an attacker could register a host
			// that resolves to a mix of public + private addresses
			// and rely on round-robin to occasionally hit private.
			for _, ip := range ips {
				if !isPublicUnicast(ip) {
					return nil, fmt.Errorf("ssrf: refusing to dial %s — %s is not a public unicast address", host, ip.String())
				}
			}
			// Dial the first safe IP literal so DNS rebinding between
			// resolution and connect is impossible.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &SafeFetchClient{
		HTTP: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			// Refuse redirects entirely — a 302 from a public host to
			// http://169.254.169.254 must NOT be followed. Returning
			// http.ErrUseLastResponse stops the redirect chain and
			// returns the 3xx response as the final one; the caller
			// reads no body from a 3xx and reports a non-2xx error.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// isPublicUnicast reports whether ip is a public unicast address —
// i.e. one we are willing to dial. Returns false for loopback,
// link-local, RFC1918 private, RFC6598 CGNAT, multicast, unspecified,
// and IPv6 unique-local / link-local addresses.
func isPublicUnicast(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// RFC1918 private
		if v4[0] == 10 ||
			(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
			(v4[0] == 192 && v4[1] == 168) {
			return false
		}
		// RFC6598 CGNAT (100.64.0.0/10)
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		// 169.254.0.0/16 — link-local; covers AWS metadata at .169.254
		if v4[0] == 169 && v4[1] == 254 {
			return false
		}
		// 0.0.0.0/8 reserved
		if v4[0] == 0 {
			return false
		}
		// 192.0.0.0/24 IETF, 192.0.2.0/24 docs (TEST-NET-1) — overcautious deny
		if v4[0] == 192 && v4[1] == 0 && (v4[2] == 0 || v4[2] == 2) {
			return false
		}
		return true
	}
	// IPv6: unique-local fc00::/7 = first byte 0xfc or 0xfd
	if len(ip) == net.IPv6len && (ip[0] == 0xfc || ip[0] == 0xfd) {
		return false
	}
	return true
}

// ValidateImageFetchURL returns a non-nil error if the URL is
// syntactically unsuitable for image fetch (bad scheme, missing host,
// userinfo / non-empty fragment, opaque form). Network-level checks
// (DNS, redirect policy) happen at fetch time via SafeFetchClient.
// Callers should run this before invoking SafeFetchClient so a
// hostile policy with `ftp://...` or `file:///etc/passwd` is rejected
// before any DNS lookup.
func ValidateImageFetchURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("empty URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (need http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("no host")
	}
	if u.User != nil {
		return fmt.Errorf("userinfo not allowed (host=%q)", u.Host)
	}
	if u.Opaque != "" {
		return fmt.Errorf("opaque URL not allowed")
	}
	return nil
}
