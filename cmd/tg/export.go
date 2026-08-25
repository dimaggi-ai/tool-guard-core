package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

type exportSelectorFlag []string

func (f *exportSelectorFlag) String() string { return strings.Join(*f, ",") }

func (f *exportSelectorFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("selector values must not be empty")
		}
		*f = append(*f, part)
	}
	return nil
}

type auditExportFilter struct {
	since    *time.Time
	until    *time.Time
	policies map[string]struct{}
	actions  map[domain.ActionTaken]struct{}
}

type auditExportView struct {
	Timestamp   time.Time          `json:"timestamp"`
	ActionTaken domain.ActionTaken `json:"action_taken"`
	RuleResults []struct {
		PolicyID string `json:"policy_id"`
	} `json:"rule_results"`
}

type auditFileSnapshot struct {
	path string
	file *os.File
	size int64
}

type verifiedAuditFileSet struct {
	files  []auditFileSnapshot
	report *audit.StreamReport
}

func (s *verifiedAuditFileSet) close() {
	for _, snapshot := range s.files {
		_ = snapshot.file.Close()
	}
}

func cmdExport(args []string) int {
	return runExport(args, os.Stdout, os.Stderr)
}

func runExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	filePath := fs.String("file", "", "path to decisions.jsonl; rotated siblings are included oldest-first")
	format := fs.String("format", "jsonl", "output format (jsonl)")
	sinceRaw := fs.String("since", "", "include records at or after this RFC3339 timestamp")
	untilRaw := fs.String("until", "", "include records before this RFC3339 timestamp")
	var policySelectors exportSelectorFlag
	var actionSelectors exportSelectorFlag
	fs.Var(&policySelectors, "policy", "exact policy_id to include; repeat or comma-separate for OR")
	fs.Var(&actionSelectors, "action", "exact action_taken to include; repeat or comma-separate for OR")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *filePath == "" {
		fmt.Fprintln(stderr, "export: -file is required")
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "export: unexpected positional arguments: %v\n", fs.Args())
		return 2
	}
	if strings.ToLower(strings.TrimSpace(*format)) != "jsonl" {
		fmt.Fprintf(stderr, "export: unsupported -format %q (supported: jsonl)\n", *format)
		return 2
	}

	filter, err := newAuditExportFilter(*sinceRaw, *untilRaw, policySelectors, actionSelectors)
	if err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 2
	}
	fileSet, err := openVerifiedAuditFileSet(*filePath)
	if err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	defer fileSet.close()
	if !fileSet.report.Intact {
		fmt.Fprintf(stderr, "export: source audit chain is not intact at line %d: %s (run `tg verify`)\n", fileSet.report.FirstFailureAt, fileSet.report.FailureReason)
		return 1
	}
	if err := streamAuditExport(fileSet.files, filter, stdout); err != nil {
		fmt.Fprintln(stderr, "export:", err)
		return 1
	}
	return 0
}

func newAuditExportFilter(sinceRaw, untilRaw string, policies, actions []string) (auditExportFilter, error) {
	filter := auditExportFilter{
		policies: make(map[string]struct{}, len(policies)),
		actions:  make(map[domain.ActionTaken]struct{}, len(actions)),
	}
	var err error
	if filter.since, err = parseExportTimestamp("-since", sinceRaw); err != nil {
		return auditExportFilter{}, err
	}
	if filter.until, err = parseExportTimestamp("-until", untilRaw); err != nil {
		return auditExportFilter{}, err
	}
	if filter.since != nil && filter.until != nil && !filter.since.Before(*filter.until) {
		return auditExportFilter{}, fmt.Errorf("-until must be after -since")
	}
	for _, policyID := range policies {
		filter.policies[policyID] = struct{}{}
	}
	validActions := map[domain.ActionTaken]struct{}{
		domain.ActionAllowed:       {},
		domain.ActionDenied:        {},
		domain.ActionEscalated:     {},
		domain.ActionFlagged:       {},
		domain.ActionAllowedShadow: {},
	}
	for _, raw := range actions {
		action := domain.ActionTaken(strings.ToLower(raw))
		if _, ok := validActions[action]; !ok {
			return auditExportFilter{}, fmt.Errorf("unknown -action %q (must be allowed|denied|escalated|flagged|allowed_shadow)", raw)
		}
		filter.actions[action] = struct{}{}
	}
	return filter, nil
}

func parseExportTimestamp(flagName, value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be RFC3339: %w", flagName, err)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func (f auditExportFilter) matches(record auditExportView) bool {
	if f.since != nil && record.Timestamp.Before(*f.since) {
		return false
	}
	if f.until != nil && !record.Timestamp.Before(*f.until) {
		return false
	}
	if len(f.actions) > 0 {
		if _, ok := f.actions[record.ActionTaken]; !ok {
			return false
		}
	}
	if len(f.policies) > 0 {
		for _, result := range record.RuleResults {
			if _, ok := f.policies[result.PolicyID]; ok {
				return true
			}
		}
		return false
	}
	return true
}

func openVerifiedAuditFileSet(activePath string) (*verifiedAuditFileSet, error) {
	paths, err := audit.RotationSetOldestFirst(activePath)
	if err != nil {
		return nil, err
	}
	fileSet := &verifiedAuditFileSet{files: make([]auditFileSnapshot, 0, len(paths))}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			fileSet.close()
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			fileSet.close()
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}
		fileSet.files = append(fileSet.files, auditFileSnapshot{path: path, file: f, size: info.Size()})
	}

	readers := make([]io.Reader, 0, len(fileSet.files))
	for _, snapshot := range fileSet.files {
		readers = append(readers, io.NewSectionReader(snapshot.file, 0, snapshot.size))
	}
	report, err := audit.VerifyChainFromReader(io.MultiReader(readers...))
	if err != nil {
		fileSet.close()
		return nil, err
	}
	// Appends beyond the captured size are deliberately outside this export
	// snapshot. A shrink means the verified byte range no longer exists.
	for _, snapshot := range fileSet.files {
		info, err := snapshot.file.Stat()
		if err != nil {
			fileSet.close()
			return nil, fmt.Errorf("restat %s: %w", snapshot.path, err)
		}
		if info.Size() < snapshot.size {
			fileSet.close()
			return nil, fmt.Errorf("audit file %s shrank during verification", snapshot.path)
		}
	}
	if len(paths) > 1 {
		report.Note = fmt.Sprintf("walked %d files (rotation set): %v", len(paths), paths)
	}
	fileSet.report = report
	return fileSet, nil
}

func streamAuditExport(files []auditFileSnapshot, filter auditExportFilter, stdout io.Writer) error {
	out := bufio.NewWriter(stdout)
	for _, snapshot := range files {
		scanner := bufio.NewScanner(io.NewSectionReader(snapshot.file, 0, snapshot.size))
		scanner.Buffer(make([]byte, 0, 1<<20), 4*1024*1024)
		for scanner.Scan() {
			raw := scanner.Bytes()
			if len(bytes.TrimSpace(raw)) == 0 {
				continue
			}
			var record auditExportView
			if err := json.Unmarshal(raw, &record); err != nil {
				return fmt.Errorf("decode %s: %w", snapshot.path, err)
			}
			if !filter.matches(record) {
				continue
			}
			if _, err := out.Write(raw); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if err := out.WriteByte('\n'); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scan %s: %w", snapshot.path, err)
		}
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}
	return nil
}
