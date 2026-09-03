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
	"sort"
	"strconv"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ── audit chain ────────────────────────────────────────────────────────────
// SHA-256 hash-chained JSONL log with size-based rotation and three
// fsync modes. tg verify walks the rotation set across files.

var (
	errAuditWriterPoisoned         = errors.New("audit writer poisoned")
	errAuditStateIndeterminate     = errors.New("audit state indeterminate")
	errAuditRotationStateUncertain = errors.New("audit rotation state uncertain")
	// errAuditRecordCommitted marks an uncertain durability-barrier error after
	// the full record reached the file and the in-memory chain advanced. The
	// writer is poisoned at the same time: callers must not append a conflicting
	// retry, and state transitions that require durable audit are indeterminate.
	errAuditRecordCommitted = errors.New("audit record committed")
)

// diskAuditLog keeps the path alongside the open descriptor so the Windows
// implementation can obtain a rollback-capable handle without giving up
// O_APPEND for normal writes. See audit_file_windows.go.
type diskAuditLog struct {
	*os.File
	path string
}

func openDiskAuditLog(path string) (*diskAuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &diskAuditLog{File: f, path: path}, nil
}

// recoverAuditTail returns the last parseable DecisionTrace from the
// newest non-empty file in the audit rotation set — the active file if
// it has records, otherwise the highest-indexed rotated sibling. This
// keeps the hash chain continuous when a restart happens right after a
// size rotation left the active file empty.
func (p *proxy) recoverAuditTail() (domain.DecisionTrace, bool, bool, error) {
	for _, path := range p.auditCandidatesNewestFirst() {
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return domain.DecisionTrace{}, false, false, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), audit.MaxTraceRecordScanBytes)
		var last domain.DecisionTrace
		var sawAny bool
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) > audit.MaxTraceRecordBytes {
				_ = f.Close()
				return domain.DecisionTrace{}, false, false, fmt.Errorf("audit log %q contains a record exceeding %d bytes — repair or rotate it before restarting", path, audit.MaxTraceRecordBytes)
			}
			if len(line) == 0 {
				continue
			}
			var t domain.DecisionTrace
			if err := json.Unmarshal(line, &t); err != nil {
				// A corrupted line must stop recovery: silently resuming from
				// the last parseable trace would append after the corruption
				// and leave a chain that fails `tg verify` forever. Make the
				// operator repair or rotate the file instead.
				_ = f.Close()
				return domain.DecisionTrace{}, false, false, fmt.Errorf("audit log %q contains an unparseable line — repair or rotate it before restarting: %w", path, err)
			}
			last = t
			sawAny = true
		}
		scanErr := sc.Err()
		if scanErr != nil && !errors.Is(scanErr, io.EOF) {
			_ = f.Close()
			return domain.DecisionTrace{}, false, false, fmt.Errorf("scan audit log %q: %w", path, scanErr)
		}
		if sawAny {
			needsSeparator, sepErr := audit.NeedsRecordSeparator(f)
			_ = f.Close()
			if sepErr != nil {
				return domain.DecisionTrace{}, false, false, fmt.Errorf("inspect audit log %q tail delimiter: %w", path, sepErr)
			}
			return last, true, needsSeparator, nil
		}
		_ = f.Close()
	}
	return domain.DecisionTrace{}, false, false, nil
}

// auditCandidatesNewestFirst lists the rotation set newest-first: the
// active file, then rotated siblings auditPath.<n> by descending n.
func (p *proxy) auditCandidatesNewestFirst() []string {
	out := []string{p.auditPath}
	dir, base := filepath.Split(p.auditPath)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	type rotated struct {
		idx  int
		path string
	}
	var rots []rotated
	prefix := base + "."
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		idx, err := strconv.Atoi(strings.TrimPrefix(name, prefix))
		if err != nil {
			continue
		}
		rots = append(rots, rotated{idx: idx, path: filepath.Join(dir, name)})
	}
	sort.Slice(rots, func(i, j int) bool { return rots[i].idx > rots[j].idx })
	for _, r := range rots {
		out = append(out, r.path)
	}
	return out
}

// openAuditLog opens the audit log in append mode and pre-scans the
// rotation set to recover the last TraceHash so the chain continues
// unbroken across server restarts (including a restart right after a
// rotation).
func (p *proxy) openAuditLog() error {
	// Do not carry a prior recovery attempt's tail through a failed reopen.
	// The value is republished only after the complete rotation set verifies.
	p.lastHash = ""
	p.auditNeedsSeparator = false
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
	//
	// Recover from the newest NON-EMPTY file in the rotation set, not
	// just the active file: a restart right after a size rotation
	// leaves the active file empty while the real tail sits in the
	// most recent rotated sibling. Scanning only the active file there
	// would reset lastHash to "" and fork the chain.
	last, sawAny, needsSeparator, err := p.recoverAuditTail()
	if err != nil {
		return err
	}
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
		// The tail check above only proves the LAST record is internally
		// self-consistent (its own hash matches its own fields) — it says
		// nothing about a tampered record buried in the middle of the file,
		// whose neighbors' prev_hash links would no longer line up but
		// which itself could still carry a valid hash for its own (possibly
		// forged) content. Walk the FULL chain across the whole rotation
		// set, oldest to newest, the same way `tg verify` does, and refuse
		// to start if any link is broken anywhere — a middle-of-file
		// tamper is exactly as disqualifying as a tampered tail, and
		// serving traffic on top of a chain an operator can no longer
		// trust defeats the entire point of an audit log.
		if err := p.verifyFullAuditChain(); err != nil {
			return err
		}
		// Publish the recovered tail only after the complete rotation set has
		// passed verification. A failed open must not leave reusable proxy state
		// pointing at an untrusted suffix.
		p.lastHash = last.TraceHash
		p.auditNeedsSeparator = needsSeparator
	}
	f, err := openDiskAuditLog(p.auditPath)
	if err != nil {
		return err
	}
	if st, err := f.Stat(); err == nil {
		p.auditCurrentBytes = st.Size()
	}
	p.auditLog = f
	return nil
}

// verifyFullAuditChain replays the ENTIRE rotation set, oldest file first,
// through the same streaming verifier `tg verify -file` uses, and returns
// an error (refuse to start) if any link is broken anywhere in it — not
// just at the tail. Concatenating the files in RotationSetOldestFirst's
// order reproduces the original append order exactly, so the chain reads
// as one continuous stream across rotation boundaries.
func (p *proxy) verifyFullAuditChain() error {
	files, err := audit.RotationSetOldestFirst(p.auditPath)
	if err != nil {
		return fmt.Errorf("list audit rotation set: %w", err)
	}
	readers := make([]io.Reader, 0, len(files))
	closers := make([]io.Closer, 0, len(files))
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open audit file %q for startup verification: %w", path, err)
		}
		readers = append(readers, f)
		closers = append(closers, f)
	}

	report, err := audit.VerifyChainFromReader(io.MultiReader(readers...))
	if err != nil {
		return fmt.Errorf("startup audit chain verification: %w", err)
	}
	if !report.Intact {
		return fmt.Errorf(
			"audit chain integrity check failed at line %d across %d file(s) (%v): %s — refusing to start (run `tg verify -file %s` for the full report)",
			report.FirstFailureAt, len(files), files, report.FailureReason, p.auditPath,
		)
	}
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
//	When auditRotateBytes > 0 and the next record would make a non-empty
//	active file meet or exceed that size, the current file is renamed to
//	`<auditPath>.<n>` where n is the next free index. A fresh
//	auditPath is opened before the record is written. The chain continues because
//	lastHash carries across the rotation. `tg verify` walks the
//	rotation set in chain order.
func (p *proxy) appendTrace(t *domain.DecisionTrace) error {
	return p.appendTraceWithDurability(t, false)
}

// appendTraceDurable performs the same append but always requires a successful
// durability barrier, regardless of the proxy's throughput-oriented sync mode.
// Human approval and denial use this path because a terminal authorization
// must not be published before its audit transition is durable.
func (p *proxy) appendTraceDurable(t *domain.DecisionTrace) error {
	return p.appendTraceWithDurability(t, true)
}

func (p *proxy) appendTraceWithDurability(t *domain.DecisionTrace, forceDurable bool) error {
	p.auditMu.Lock()
	defer p.auditMu.Unlock()
	if p.auditPoisoned {
		return p.auditPoisonErrorLocked()
	}
	// Every new record carries its hash-schema version on disk. A missing
	// marker is reserved for pre-v2 records and is interpreted as v1 by the
	// verifier, which lets upgraded proxies continue an existing chain.
	t.CanonicalVersion = audit.CanonicalTraceVersion
	t.PreviousTraceHash = p.lastHash
	h, err := audit.ComputeCanonicalTraceHash(t)
	if err != nil {
		return fmt.Errorf("canonical hash: %w", err)
	}
	t.TraceHash = h
	raw, err := audit.MarshalTraceRecord(t)
	if err != nil {
		return err
	}
	// Resolve size-triggered rotation before writing the current trace. If post-write
	// rotation failed, the durable record could still say "allowed" even though
	// fail-closed changed the response to "denied". Pre-rotation keeps the current action
	// transactional: either rotation completes first, or no bytes for this trace reach the
	// audit set.
	st, err := p.auditLog.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log before append: %w", err)
	}
	recordBytes := int64(len(raw) + 1)
	if p.auditNeedsSeparator {
		recordBytes++
	}
	if p.auditRotateBytes > 0 && st.Size() > 0 && st.Size()+recordBytes >= p.auditRotateBytes {
		if err := p.rotateAuditLocked(); err != nil {
			if errors.Is(err, errAuditRotationStateUncertain) {
				return p.poisonAuditLocked(fmt.Sprintf("audit pre-rotation failed before current trace write: %v", err))
			}
			return fmt.Errorf("rotate audit log before append: %w", err)
		}
		// Preserve auditNeedsSeparator across the file boundary. Full-chain
		// verification concatenates rotation members as one logical JSONL stream,
		// so a tail that ended at EOF still needs LF before the first active record.
		st, err = p.auditLog.Stat()
		if err != nil {
			return fmt.Errorf("stat new active audit log before append: %w", err)
		}
	}
	preWriteSize := st.Size()
	previousLastHash := p.lastHash
	previousAppendSeq := p.auditAppendSeq
	previousNeedsSeparator := p.auditNeedsSeparator
	record := make([]byte, 0, len(raw)+2)
	if p.auditNeedsSeparator {
		record = append(record, '\n')
	}
	record = append(record, raw...)
	record = append(record, '\n')

	// A write can return both n > 0 and an error (or n < len(record) with a
	// nil error). Capture an exact rollback boundary before touching the file.
	// Without this, a retry would append after truncated JSON and permanently
	// fork the hash chain even though lastHash was never advanced.
	n, err := p.auditLog.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if rollbackErr := p.rollbackAuditWriteLocked(preWriteSize); rollbackErr != nil {
			reason := fmt.Sprintf(
				"append failed after writing %d of %d bytes (%v); rollback to byte %d failed: %v",
				n, len(record), err, preWriteSize, rollbackErr,
			)
			return p.poisonIndeterminateAuditLocked(reason, n == len(record))
		}
		p.auditCurrentBytes = preWriteSize
		return fmt.Errorf("append audit record after writing %d of %d bytes: %w (partial write rolled back)", n, len(record), err)
	}
	p.auditCurrentBytes = preWriteSize + int64(len(record))
	p.auditAppendSeq++
	p.auditNeedsSeparator = false

	// Advance lastHash before the durability barrier so the successful path has
	// one committed in-memory tail. If Sync fails, the rollback path below
	// restores this value and every related counter before returning.
	p.lastHash = t.TraceHash

	shouldSync := forceDurable || p.auditSyncMode == "every"
	if p.auditSyncMode == "interval" && p.auditAppendSeq%int64(p.auditSyncEvery) == 0 {
		shouldSync = true
	}
	if shouldSync {
		if syncErr := p.auditLog.Sync(); syncErr != nil {
			if rollbackErr := p.rollbackAuditWriteLocked(preWriteSize); rollbackErr != nil {
				return p.poisonCommittedAuditLocked(syncErr, rollbackErr)
			}
			p.lastHash = previousLastHash
			p.auditCurrentBytes = preWriteSize
			p.auditAppendSeq = previousAppendSeq
			p.auditNeedsSeparator = previousNeedsSeparator
			return fmt.Errorf(
				"sync audit log: %w (full write rolled back durably to byte %d)",
				syncErr, preWriteSize,
			)
		}
	}

	return nil
}

// rollbackAuditWriteLocked restores and durably verifies the exact file size
// observed before a failed append. The caller must hold auditMu. Any failure
// here makes the on-disk tail ambiguous, so appendTrace converts it into a
// sticky poisoned state rather than risking a second append.
func (p *proxy) rollbackAuditWriteLocked(preWriteSize int64) error {
	if err := p.auditLog.Truncate(preWriteSize); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	// Rollback durability is mandatory even when normal append durability is
	// configured as interval or none: readiness must never claim a repair that
	// only exists in the page cache.
	if err := p.auditLog.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	st, err := p.auditLog.Stat()
	if err != nil {
		return fmt.Errorf("verify size: %w", err)
	}
	if st.Size() != preWriteSize {
		return fmt.Errorf("verify size: got %d, want %d", st.Size(), preWriteSize)
	}
	return nil
}

// poisonAuditLocked marks the writer unusable until process restart. The
// caller must hold auditMu. The first reason wins so all later failures point
// operators back to the event that made the tail uncertain.
func (p *proxy) poisonAuditLocked(reason string) error {
	if !p.auditPoisoned {
		p.auditPoisoned = true
		p.auditPoisonReason = reason
	}
	return p.auditPoisonErrorLocked()
}

// poisonCommittedAuditLocked reports both facts a caller must distinguish:
// the complete record may be present in the live file, but its durability is
// uncertain and no further append is safe until an operator verifies the tail.
// The caller must hold auditMu.
func (p *proxy) poisonCommittedAuditLocked(syncErr, rollbackErr error) error {
	reason := fmt.Sprintf(
		"full audit record write completed but durability sync failed (%v) and rollback could not be proven durable (%v)",
		syncErr, rollbackErr,
	)
	return p.poisonIndeterminateAuditLocked(reason, true)
}

// poisonIndeterminateAuditLocked marks any unprovable rollback as an
// indeterminate audit transition. A complete record may also be present, which
// is reported separately so callers and diagnostics can distinguish it from a
// truncated tail. The caller must hold auditMu.
func (p *proxy) poisonIndeterminateAuditLocked(reason string, recordComplete bool) error {
	errs := []error{errAuditStateIndeterminate, p.poisonAuditLocked(reason)}
	if recordComplete {
		errs = append(errs, errAuditRecordCommitted)
	}
	return errors.Join(errs...)
}

func (p *proxy) auditPoisonErrorLocked() error {
	if p.auditPoisonReason == "" {
		return errAuditWriterPoisoned
	}
	return fmt.Errorf("%w: %s", errAuditWriterPoisoned, p.auditPoisonReason)
}

// rotateAuditLocked closes the current audit file, renames it to
// auditPath.<n> for the next free n, and opens a fresh auditPath. The
// caller must hold p.auditMu.
//
// Failure recovery: if a step after Close fails, the function makes a
// best-effort re-open so operators can inspect the current state. The returned
// errAuditRotationStateUncertain is mandatory even when re-open succeeds;
// appendTrace poisons the writer and never writes the current trace because the
// rotation's on-disk transition did not complete as a proven transaction.
func (p *proxy) rotateAuditLocked() error {
	if p.auditRotation.rename == nil || p.auditRotation.syncDirectory == nil {
		return errors.New("audit rotation operations are not configured")
	}
	if err := p.auditLog.Sync(); err != nil {
		return fmt.Errorf("sync before rotate: %w", err)
	}
	if err := p.auditLog.Close(); err != nil {
		// Close may have released the descriptor despite returning an error. Treat its
		// usability as uncertain instead of assuming appends can continue on the current
		// handle.
		return fmt.Errorf("%w: close before rotate: %v", errAuditRotationStateUncertain, err)
	}
	// From this point on, best-effort recovery should leave p.auditLog pointing
	// at an inspectable file, but the caller will poison it on every error.
	idx := 1
	for {
		candidate := fmt.Sprintf("%s.%d", p.auditPath, idx)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			if err := p.auditRotation.rename(p.auditPath, candidate); err != nil {
				p.reopenAuditLocked() // recover; ignore reopen err — already broken
				return fmt.Errorf("%w: rename to %s: %v", errAuditRotationStateUncertain, candidate, err)
			}
			break
		}
		idx++
		if idx > 1<<20 {
			p.reopenAuditLocked()
			return fmt.Errorf("%w: rotation index overflow (>%d existing rotations)", errAuditRotationStateUncertain, idx)
		}
	}
	f, err := openDiskAuditLog(p.auditPath)
	if err != nil {
		// Rename succeeded but new-active open failed. Re-open the rotated tail so we don't
		// break the chain; appends will continue into the previous file rather than vanish.
		p.reopenRotatedLocked(idx)
		return fmt.Errorf("%w: open new active: %v", errAuditRotationStateUncertain, err)
	}
	p.auditLog = f
	p.auditCurrentBytes = 0
	// The replacement is intentionally empty. If the process crashes before
	// the barriers below complete, startup can recover the chain tail from the
	// newest rotated sibling and recreate a missing active path. Once both
	// barriers succeed, the empty file and both directory-entry changes are
	// durable before this function reports success.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("%w: sync new active audit file: %v", errAuditRotationStateUncertain, err)
	}
	if err := p.auditRotation.syncDirectory(filepath.Dir(p.auditPath)); err != nil {
		return fmt.Errorf("%w: sync audit rotation directory: %v", errAuditRotationStateUncertain, err)
	}
	log.Printf("tg-proxy: rotated audit log → %s.%d", p.auditPath, idx)
	return nil
}

// reopenAuditLocked re-opens p.auditPath in append mode after a failed rotation.
// Best-effort: if even the re-open fails (disk full, permissions changed), we leave
// p.auditLog as the closed file and every subsequent append returns an error tracked
// via auditFailureCount; explicit failure, not silent corruption.
func (p *proxy) reopenAuditLocked() {
	f, err := openDiskAuditLog(p.auditPath)
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
	f, err := openDiskAuditLog(rotated)
	if err != nil {
		log.Printf("tg-proxy: audit re-open rotated tail %s: %v", rotated, err)
		return
	}
	p.auditLog = f
	if st, err := f.Stat(); err == nil {
		p.auditCurrentBytes = st.Size()
	}
}
