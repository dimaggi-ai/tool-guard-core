// tg-proxy is the Tool Guard Core runtime HTTP service. It loads policies
// from disk, exposes /evaluate to score tool calls against them, and
// writes every decision to a SHA-256 hash-chained JSONL audit log.
//
// Endpoints:
//
//	POST /evaluate         — body: ActionEnvelope JSON; returns EvaluationResult JSON
//	GET  /healthz          — 200 OK if process is alive
//	GET  /readyz           — 200 OK if at least one policy is loaded
//	GET  /policies         — list of loaded policy IDs (debugging)
//	GET  /metrics          — plain-text counters
//	POST /reload           — re-read -policy-dir on demand (also fires on SIGHUP)
//
// Flags:
//
//	-listen       Host:port to bind (default :9090)
//	-policy-dir   Directory of *.yaml policies to load (default ./policies)
//	-audit-log    Path to append the JSONL audit chain (default ./decisions.jsonl)
//	-default-mode shadow | enforcement (default enforcement)
//	-fail-closed  Deny calls when no policies are loaded (default true)
//
// Audit chain semantics: on startup the server scans -audit-log for the
// tail TraceHash and continues the chain from there. Restarting the
// service does not break `tg verify`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"

	// Default SQL dialect classifiers: tokenizer-based lite package
	// covers postgres/mysql/sqlite; mssql lives in its own package
	// (already tokenizer-based). All pure Go, no cgo.
	//
	// Strict variants (pg_query_go via cgo, tidb/parser, rqlite/sql)
	// are opt-in via build tags pg_strict / mysql_strict / sqlite_strict.
	// Their init() runs after lite's and overrides the same dialect
	// name via sqlguard.Register's last-write-wins semantic.
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/mssql"
)

// proxy holds the runtime state of the server. policies and lastHash are
// the only mutable fields; both are guarded by mu so SIGHUP reload and
// concurrent /evaluate requests do not race.
type proxy struct {
	mu       sync.RWMutex
	policies []domain.Policy

	auditMu  sync.Mutex
	auditLog *os.File
	lastHash string

	defaultMode          domain.PolicyMode
	failClosed           bool
	unknownToolsDeny     bool
	maxJSONDepth         int
	auditSyncMode        string // every | interval | none
	auditSyncEvery       int
	auditRotateBytes     int64
	auditAppendSeq       int64
	auditCurrentBytes    int64
	rateLimit            *rateLimiter // nil if disabled
	rateLimitKeyBy       string
	escalations          *escalationStore
	approverToken        string
	escalationDefaultMin int
	policyDir            string
	auditPath            string

	eval *engine.Evaluator

	startedAt time.Time

	// counters — observed via /metrics
	evalCount         atomic.Int64
	allowCount        atomic.Int64
	denyCount         atomic.Int64
	escalateCount     atomic.Int64
	flagCount         atomic.Int64
	failClosedCount   atomic.Int64
	auditFailureCount atomic.Int64
	loadCount         atomic.Int64
}

// Version, Commit, and BuildDate are injected by the release pipeline
// via -ldflags (see .goreleaser.yaml). Empty for plain `go build`; the
// -version handler then falls back to ReadBuildInfo.
var (
	Version   string
	Commit    string
	BuildDate string
)

func main() {
	var (
		listen            = flag.String("listen", ":9090", "host:port to bind")
		policyDir         = flag.String("policy-dir", "./policies", "directory of YAML policy files to load")
		auditPath         = flag.String("audit-log", "./decisions.jsonl", "path to append the JSONL audit chain")
		defaultMode       = flag.String("default-mode", "enforcement", "shadow | enforcement")
		failClosed        = flag.Bool("fail-closed", true, "deny calls when no policies are loaded")
		unknownToolsDeny  = flag.Bool("unknown-tools-deny", false, "deny any tool_name not explicitly listed in scope.tool_names of some loaded policy (closes tool-name-spoofing class)")
		maxJSONDepth      = flag.Int("max-envelope-depth", 32, "reject /evaluate envelopes whose JSON nests deeper than this (DoS defense)")
		auditSyncMode     = flag.String("audit-sync-mode", "every", "audit fsync mode: every | interval | none")
		auditSyncEvery    = flag.Int("audit-sync-every", 100, "when audit-sync-mode=interval, fsync once every N appends")
		auditRotateBytes  = flag.Int64("audit-rotate-bytes", 0, "rotate audit log when active file exceeds this many bytes (0 = never rotate)")
		rateLimitRPS      = flag.Float64("rate-limit-rps", 0, "per-agent steady-state limit (req/s); 0 disables rate limiting")
		rateLimitBurst    = flag.Float64("rate-limit-burst", 50, "per-agent burst capacity used when -rate-limit-rps > 0")
		rateLimitKeyBy    = flag.String("rate-limit-key-by", "agent_id", "envelope field to key the limiter on: agent_id | session_id | org_id")
		toolsYAML         = flag.String("tools-yaml", "", "path to a tools.yaml function classification registry (enables sql_classify {denied,allowed}_function_classes)")
		approverToken     = flag.String("approver-token", "", "static bearer token required on POST /escalations/<id>/{approve,deny}; empty disables the endpoints")
		approverTokenFile = flag.String("approver-token-file", "", "read the approver token from this file instead of the command line (keeps it out of /proc cmdline); mutually exclusive with -approver-token")
		escalationTimeout = flag.Int("escalation-default-timeout-min", 15, "default timeout (minutes) for an escalation that doesn't specify one")
		version           = flag.Bool("version", false, "print build version and exit")
	)
	flag.Parse()

	if *version {
		info, ok := debug.ReadBuildInfo()
		if Version != "" {
			fmt.Printf("tg-proxy %s (commit %s, built %s)\n", Version, Commit, BuildDate)
			if ok {
				fmt.Printf("go %s\n", info.GoVersion)
			}
			os.Exit(0)
		}
		if !ok {
			fmt.Println("tg-proxy: build info unavailable")
			os.Exit(0)
		}
		v := info.Main.Version
		if v == "" || v == "(devel)" {
			v = "(devel)"
		}
		fmt.Printf("tg-proxy %s\ngo %s\n", v, info.GoVersion)
		os.Exit(0)
	}

	resolvedApproverToken := *approverToken
	if *approverTokenFile != "" {
		if *approverToken != "" {
			log.Fatalf("tg-proxy: -approver-token and -approver-token-file are mutually exclusive")
		}
		raw, err := os.ReadFile(*approverTokenFile)
		if err != nil {
			log.Fatalf("tg-proxy: read -approver-token-file: %v", err)
		}
		resolvedApproverToken = strings.TrimSpace(string(raw))
		if resolvedApproverToken == "" {
			log.Fatalf("tg-proxy: -approver-token-file %q is empty", *approverTokenFile)
		}
	}

	depthCap := *maxJSONDepth
	if depthCap < 4 {
		depthCap = 32
	}
	mode := strings.ToLower(*auditSyncMode)
	switch mode {
	case "every", "interval", "none":
	default:
		log.Fatalf("tg-proxy: invalid -audit-sync-mode=%q (want every|interval|none)", *auditSyncMode)
	}
	syncEvery := *auditSyncEvery
	if syncEvery < 1 {
		syncEvery = 1
	}
	var rl *rateLimiter
	if *rateLimitRPS > 0 {
		burst := *rateLimitBurst
		if burst < 1 {
			burst = 1
		}
		rl = newRateLimiter(*rateLimitRPS, burst)
	}
	switch *rateLimitKeyBy {
	case "agent_id", "session_id", "org_id":
	default:
		log.Fatalf("tg-proxy: invalid -rate-limit-key-by=%q (want agent_id|session_id|org_id)", *rateLimitKeyBy)
	}

	if *toolsYAML != "" {
		reg, err := sqlguard.LoadRegistryFile(*toolsYAML)
		if err != nil {
			log.Fatalf("tg-proxy: load -tools-yaml: %v", err)
		}
		sqlguard.SetRegistry(reg)
		classes := 0
		for range reg.FunctionClass {
			classes++
		}
		log.Printf("tg-proxy: tools.yaml registered %d function classes", classes)
	}

	p := &proxy{
		eval:                 engine.NewEvaluator(),
		defaultMode:          domain.PolicyModeEnforcement,
		failClosed:           *failClosed,
		unknownToolsDeny:     *unknownToolsDeny,
		maxJSONDepth:         depthCap,
		auditSyncMode:        mode,
		auditSyncEvery:       syncEvery,
		auditRotateBytes:     *auditRotateBytes,
		rateLimit:            rl,
		rateLimitKeyBy:       *rateLimitKeyBy,
		escalations:          newEscalationStore(),
		approverToken:        resolvedApproverToken,
		escalationDefaultMin: *escalationTimeout,
		policyDir:            *policyDir,
		auditPath:            *auditPath,
		startedAt:            time.Now().UTC(),
	}
	switch *defaultMode {
	case "shadow":
		p.defaultMode = domain.PolicyModeShadow
	case "enforcement":
	default:
		log.Fatalf("tg-proxy: unknown -default-mode %q (must be shadow|enforcement)", *defaultMode)
	}

	if err := p.openAuditLog(); err != nil {
		log.Fatalf("tg-proxy: open audit log %q: %v", *auditPath, err)
	}
	defer p.auditLog.Close()

	if err := p.reload(); err != nil {
		log.Fatalf("tg-proxy: initial policy load from %q: %v", *policyDir, err)
	}
	log.Printf("tg-proxy: loaded %d policies from %q", len(p.policies), *policyDir)
	log.Printf("tg-proxy: audit chain continues from tail %q", short(p.lastHash))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", p.healthz)
	mux.HandleFunc("/readyz", p.readyz)
	mux.HandleFunc("/policies", p.listPolicies)
	mux.HandleFunc("/metrics", p.metrics)
	mux.HandleFunc("/evaluate", p.evaluate)
	mux.HandleFunc("/reload", p.reloadHandler)
	mux.HandleFunc("/escalations", p.listEscalations)
	mux.HandleFunc("/escalations/", p.escalationByID) // /escalations/<id> + /escalations/<id>/approve|deny

	srv := &http.Server{
		Addr:              *listen,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// SIGHUP triggers a policy reload without restarting the server.
	// SIGINT / SIGTERM trigger a graceful shutdown.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := p.reload(); err != nil {
				log.Printf("tg-proxy: SIGHUP reload failed: %v", err)
				continue
			}
			log.Printf("tg-proxy: reloaded %d policies", len(p.policies))
		}
	}()

	// Reap expired escalations every 30s.
	reaperCtx, reaperCancel := context.WithCancel(context.Background())
	defer reaperCancel()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-reaperCtx.Done():
				return
			case <-t.C:
				if expired := p.escalations.reapExpired(); len(expired) > 0 {
					log.Printf("tg-proxy: escalation reaper expired %d pending entries", len(expired))
					// Append a synthetic deny trace for each
					// expired entry so the audit chain reflects
					// the terminal state. Without this an operator
					// scanning the chain would see only the
					// original "escalated" trace with no record
					// that the lifecycle ended in deny-by-timeout.
					for _, e := range expired {
						trace := domain.DecisionTrace{
							TraceID:        fmt.Sprintf("trc-%d", time.Now().UnixNano()),
							Timestamp:      time.Now().UTC(),
							EnvelopeID:     e.Envelope.EnvelopeID,
							AgentID:        e.Envelope.AgentID,
							SessionID:      e.Envelope.SessionID,
							OrgID:          e.Envelope.OrgID,
							ToolName:       e.Envelope.ToolName,
							ToolGroup:      e.Envelope.ToolGroup,
							Decision:       domain.DecisionDenied,
							ActionTaken:    domain.ActionDenied,
							DecisionReason: fmt.Sprintf("escalation %s expired without approval", e.ID),
							Mode:           domain.PolicyModeEnforcement,
						}
						if err := p.appendTrace(&trace); err != nil {
							log.Printf("tg-proxy: append expiry trace for %s: %v", e.ID, err)
						}
					}
				}
			}
		}
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdown
		log.Printf("tg-proxy: shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("tg-proxy: listening on %s (default-mode=%s fail-closed=%t unknown-tools-deny=%t)",
		*listen, p.defaultMode, p.failClosed, p.unknownToolsDeny)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("tg-proxy: serve: %v", err)
	}
}

// ── handlers ───────────────────────────────────────────────────────────────
