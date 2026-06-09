package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// listEscalations: GET /escalations
//
// Returns a snapshot of all escalations (pending + resolved).
// Read-only; no token required so operator dashboards can poll
// without proliferating credentials. Sensitive payload — operators
// should put the proxy behind their existing auth perimeter.
func (p *proxy) listEscalations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"escalations": p.escalations.list(),
	})
}

// escalationByID handles:
//
//	GET    /escalations/<id>                  → fetch one
//	POST   /escalations/<id>/approve          → operator approves (mutates → token-gated)
//	POST   /escalations/<id>/deny             → operator denies   (mutates → token-gated)
func (p *proxy) escalationByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/escalations/")
	if rest == "" {
		http.Error(w, "missing escalation id", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "":
		// GET /escalations/<id>
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		e := p.escalations.get(id)
		if e == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, e)
		return

	case "approve", "deny":
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if !p.checkApproverToken(r) {
			http.Error(w, "approver token missing or invalid", http.StatusUnauthorized)
			return
		}
		var body struct {
			Approver string `json:"approver"`
			Reason   string `json:"reason"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		_ = json.Unmarshal(raw, &body) // body optional
		approved := action == "approve"
		e, ok := p.escalations.resolve(id, body.Approver, body.Reason, approved)
		if e == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !ok {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":      "already resolved",
				"escalation": e,
			})
			return
		}
		// Audit the state transition. The original escalate decision
		// is already in the chain (from /evaluate); this entry records
		// the human approval/denial as a separate, linked event so a
		// verifier can replay the full lifecycle and answer "who
		// approved this and when". docs/escalation.md commits to this.
		p.emitEscalationResolution(e, approved)
		writeJSON(w, http.StatusOK, e)
		return
	}

	http.Error(w, "unknown action; valid: approve | deny", http.StatusBadRequest)
}

// checkApproverToken validates the bearer token on mutating
// escalation endpoints. Empty configured token blocks the endpoints
// entirely (defensive default).
//
// Both the configured and received tokens are SHA-256 hashed BEFORE
// the constant-time compare so the two compared slices are always 32
// bytes. subtle.ConstantTimeCompare short-circuits on length
// mismatch — comparing raw tokens of unequal length would reveal the
// configured token's length via response latency. Hashing erases
// that length channel.
func (p *proxy) checkApproverToken(r *http.Request) bool {
	if p.approverToken == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	got := strings.TrimPrefix(h, "Bearer ")
	expected := sha256.Sum256([]byte(p.approverToken))
	received := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(expected[:], received[:]) == 1
}
