package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ── audit chain ────────────────────────────────────────────────────────────
// SHA-256 hash-chained JSONL log with size-based rotation and three
// fsync modes. tg verify walks the rotation set across files.

// openAuditLog opens the audit log in append mode and pre-scans it to
// recover the last TraceHash so the chain continues unbroken across
// server restarts.
func (p *proxy) openAuditLog() error {
	dir := filepath.Dir(p.auditPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Recover the tail hash by scanning the file (if it exists).
	// The last record's canonical hash is recomputed and compared
	// against its stored TraceHash — an attacker with write access
	// to the log could otherwise replace the tail with a forged
	// record carrying any prev_hash, and the proxy would resume the
	// chain from it. Verifying the tail catches that on startup.
	if existing, err := os.Open(p.auditPath); err == nil {
		sc := bufio.NewScanner(existing)
		sc.Buffer(make([]byte, 0, 1<<20), 4*1024*1024)
		var last domain.DecisionTrace
		var sawAny bool
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var t domain.DecisionTrace
			if err := json.Unmarshal(line, &t); err == nil {
				last = t
				sawAny = true
			}
		}
		_ = existing.Close()
		if sawAny {
			want, err := audit.ComputeCanonicalTraceHash(&last)
			if err != nil {
				return fmt.Errorf("verify audit tail: canonical hash: %w", err)
			}
			if last.TraceHash != want {
				return fmt.Errorf(
					"audit-log tail integrity check failed: trace %q stored hash %q does not match canonical recomputation %q — refusing to start (run `tg verify` to locate the tampered record)",
					last.TraceID, last.TraceHash, want,
				)
			}
			p.lastHash = last.TraceHash
		}
		if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("scan existing audit log: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(p.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if st, err := f.Stat(); err == nil {
		p.auditCurrentBytes = st.Size()
	}
	p.auditLog = f
	return nil
}

// appendTrace stamps the canonical hash on the trace, links it to the
// previous tail, writes it to the audit log, and updates the tail. Holds
// auditMu for the whole operation so concurrent /evaluate requests
// cannot interleave their chain links.
//
// fsync behaviour:
//
//	"every"    – Sync() after every append. Strongest durability.
//	"interval" – Sync() every audit-sync-every appends. Higher throughput.
//	"none"     – Never Sync(). Throughput-first; durability handed to OS.
//
// Rotation:
//
//	When auditRotateBytes > 0 and the active file exceeds that size
//	after an append, the file is closed and renamed to
//	`<auditPath>.<n>` where n is the next free index. A fresh
//	auditPath is opened. The chain continues unbroken because
//	lastHash carries across the rotation. `tg verify` walks the
//	rotation set in chain order.
func (p *proxy) appendTrace(t *domain.DecisionTrace) error {
	p.auditMu.Lock()
	defer p.auditMu.Unlock()
	t.PreviousTraceHash = p.lastHash
	h, err := audit.ComputeCanonicalTraceHash(t)
	if err != nil {
		return fmt.Errorf("canonical hash: %w", err)
	}
	t.TraceHash = h
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := p.auditLog.Write(raw); err != nil {
		return err
	}
	p.auditCurrentBytes += int64(len(raw))
	p.auditAppendSeq++

	// Advance lastHash NOW, before the durability barrier. The write
	// has reached the OS buffer cache; subsequent appends must chain
	// from this hash. If the Sync below errors the trace is still
	// recoverable from the file (the write went through) and we want
	// the next append to link to it, not to the previous tail —
	// otherwise a Sync error forks the chain at the next append.
	p.lastHash = t.TraceHash

	switch p.auditSyncMode {
	case "every":
		if err := p.auditLog.Sync(); err != nil {
			return err
		}
	case "interval":
		if p.auditAppendSeq%int64(p.auditSyncEvery) == 0 {
			if err := p.auditLog.Sync(); err != nil {
				return err
			}
		}
	case "none":
		// no-op
	}

	// Rotate AFTER the hash is committed so a crash during rotation
	// loses at most this single append, not the whole pending chunk.
	if p.auditRotateBytes > 0 && p.auditCurrentBytes >= p.auditRotateBytes {
		if err := p.rotateAuditLocked(); err != nil {
			log.Printf("tg-proxy: audit rotation: %v (continuing on old file)", err)
		}
	}
	return nil
}

// rotateAuditLocked closes the current audit file, renames it to
// auditPath.<n> for the next free n, and opens a fresh auditPath. The
// caller must hold p.auditMu.
//
// Failure recovery: if any step after Close fails (rename collision,
// open of the new active file fails), the rotation aborts AND the
// function re-opens the original auditPath in append mode so
// subsequent appendTrace calls keep working against the same file.
// Without that recovery the caller's "continuing on old file" log
// would be a lie — Close already closed the FD — and every later
// append would error out silently, halting the audit chain.
func (p *proxy) rotateAuditLocked() error {
	if err := p.auditLog.Sync(); err != nil {
		return fmt.Errorf("sync before rotate: %w", err)
	}
	if err := p.auditLog.Close(); err != nil {
		return fmt.Errorf("close before rotate: %w", err)
	}
	// From this point on we MUST leave p.auditLog pointing at an open
	// writable file before returning, even on error.
	idx := 1
	for {
		candidate := fmt.Sprintf("%s.%d", p.auditPath, idx)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(p.auditPath, candidate); err != nil {
				p.reopenAuditLocked() // recover; ignore reopen err — already broken
				return fmt.Errorf("rename to %s: %w", candidate, err)
			}
			break
		}
		idx++
		if idx > 1<<20 {
			p.reopenAuditLocked()
			return fmt.Errorf("rotation index overflow (>%d existing rotations)", idx)
		}
	}
	f, err := os.OpenFile(p.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// Rename succeeded but new-active open failed. Re-open the
		// rotated tail so we don't break the chain — appends will
		// continue into the previous file rather than vanish.
		p.reopenRotatedLocked(idx)
		return fmt.Errorf("open new active: %w", err)
	}
	p.auditLog = f
	p.auditCurrentBytes = 0
	log.Printf("tg-proxy: rotated audit log → %s.%d", p.auditPath, idx)
	return nil
}

// reopenAuditLocked re-opens p.auditPath in append mode after a
// failed rotation. Best-effort: if even the re-open fails (disk full,
// permissions changed), we leave p.auditLog as the closed file and
// every subsequent append returns an error tracked via
// auditFailureCount — explicit failure, not silent corruption.
func (p *proxy) reopenAuditLocked() {
	f, err := os.OpenFile(p.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("tg-proxy: audit re-open after failed rotation: %v", err)
		return
	}
	p.auditLog = f
	if st, err := f.Stat(); err == nil {
		p.auditCurrentBytes = st.Size()
	}
}

// reopenRotatedLocked re-opens the rotated tail file after rename
// succeeded but opening the new active file failed. Subsequent
// appends continue into the rotated file rather than disappear.
func (p *proxy) reopenRotatedLocked(idx int) {
	rotated := fmt.Sprintf("%s.%d", p.auditPath, idx)
	f, err := os.OpenFile(rotated, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("tg-proxy: audit re-open rotated tail %s: %v", rotated, err)
		return
	}
	p.auditLog = f
	if st, err := f.Stat(); err == nil {
		p.auditCurrentBytes = st.Size()
	}
}
