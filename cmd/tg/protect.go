package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

const (
	claudeTarget           = "claude"
	managedAgent           = "tool-guard-claude"
	minClaudeExecHookMajor = 2
	minClaudeExecHookMinor = 1
	minClaudeExecHookPatch = 139
)

const codingAgentStarterPolicy = `policy_id: pol-coding-agent-baseline
status: approved
mode: enforcement
scope:
  tool_names: [bash, shell, run_command]
  tool_groups: [shell]
rules:
  - rule_id: deny-recursive-root-delete
    rule_type: regex
    conditions:
      and:
        - field: parameters.command
          operator: regex
          value: '(^|[\s;&|(])(\S+/)?rm(\s|$)'
        - field: parameters.command
          operator: regex
          value: '(--recursive|-[a-zA-Z]*[rR])'
        - field: parameters.command
          operator: regex
          value: '(\s|["''=])(/\*?|/(bin|boot|dev|etc|home|lib|lib64|opt|proc|root|sbin|srv|sys|usr|var)/?|\$\{?HOME\}?|~)(\s|["'';&|]|$)'
    effect: deny
    citation:
      excerpt: "Recursive deletion of root, a system directory, or HOME is forbidden."
  - rule_id: review-recursive-or-forced-delete
    rule_type: regex
    conditions:
      and:
        - field: parameters.command
          operator: regex
          value: '(^|[\s;&|(])(\S+/)?rm(\s|$)'
        - or:
            - field: parameters.command
              operator: regex
              value: '(--recursive|-[a-zA-Z]*[rR])'
            - field: parameters.command
              operator: regex
              value: '(--force|-[a-zA-Z]*f)'
    effect: escalate
    citation:
      excerpt: "Recursive or forced deletion requires human review."
  - rule_id: review-dangerous-git-mutation
    rule_type: regex
    conditions:
      field: parameters.command
      operator: regex
      value: '\bgit\s+(push\b|reset\s+--hard|clean\b[^|;&]*\s-[a-zA-Z]*f|rebase\b|filter-repo|filter-branch|update-ref\s+-d|branch\s+-D)'
    effect: escalate
    citation:
      excerpt: "Outbound or history-rewriting Git actions require human review."
`

type protectPaths struct {
	config string
	policy string
	audit  string
	backup string
	state  string
	tg     string
}

type protectState struct {
	Version          int      `json:"version"`
	Target           string   `json:"target"`
	ConfigPath       string   `json:"config_path"`
	PolicyPath       string   `json:"policy_path"`
	AuditPath        string   `json:"audit_path"`
	BackupPath       string   `json:"backup_path"`
	Command          string   `json:"command"`
	Args             []string `json:"args,omitempty"`
	InstalledSHA256  string   `json:"installed_sha256"`
	OriginalExisted  bool     `json:"original_existed"`
	OriginalMode     uint32   `json:"original_mode,omitempty"`
	ExactRestoreSafe bool     `json:"exact_restore_safe"`
}

type protectPlan struct {
	Action     string         `json:"action"`
	Target     string         `json:"target"`
	Apply      bool           `json:"apply"`
	Changed    bool           `json:"changed"`
	ConfigPath string         `json:"config_path"`
	PolicyPath string         `json:"policy_path,omitempty"`
	BackupPath string         `json:"backup_path,omitempty"`
	Config     map[string]any `json:"proposed_config,omitempty"`
}

func cmdProtect(args []string) int {
	return runProtect(args, os.Stdout, os.Stderr)
}

func runProtect(args []string, stdout, stderr io.Writer) int {
	target, rest, ok := protectTarget(args, stderr, "protect")
	if !ok {
		return 2
	}
	fs := flag.NewFlagSet("protect "+target, flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "apply the displayed change (default is dry-run)")
	config := fs.String("config", "", "Claude settings.json path")
	policy := fs.String("policy", "", "existing policy YAML (default installs the coding-agent baseline)")
	tgPath := fs.String("tg", "", "tg executable path (default is this executable)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if *config == "" {
		if err := requireClaudeExecHookSupport(); err != nil {
			fmt.Fprintln(stderr, "protect:", err)
			return 1
		}
	}
	p, defaultPolicy, err := resolveProtectPaths(*config, *policy, *tgPath)
	if err != nil {
		fmt.Fprintln(stderr, "protect:", err)
		return 1
	}
	original, existed, root, err := readJSONConfig(p.config)
	if err != nil {
		fmt.Fprintln(stderr, "protect:", err)
		return 1
	}
	handler := claudeHookHandler(p)
	proposed, changed, err := mergeClaudeHook(root, handler)
	if err != nil {
		fmt.Fprintln(stderr, "protect:", err)
		return 1
	}
	plan := protectPlan{Action: "protect", Target: target, Apply: *apply, Changed: changed, ConfigPath: p.config, PolicyPath: p.policy, BackupPath: p.backup, Config: proposed}
	if !*apply {
		return writePlan(stdout, plan)
	}
	prior, priorErr := loadProtectState(p.state)
	firstInstall := errors.Is(priorErr, os.ErrNotExist)
	if priorErr != nil && !firstInstall {
		fmt.Fprintln(stderr, "protect: existing protection state is unreadable:", priorErr)
		return 1
	}
	if defaultPolicy {
		if err := writeIfAbsent(p.policy, []byte(codingAgentStarterPolicy), 0o600); err != nil {
			fmt.Fprintln(stderr, "protect:", err)
			return 1
		}
	} else if info, statErr := os.Stat(p.policy); statErr != nil || info.IsDir() {
		fmt.Fprintf(stderr, "protect: policy is not a readable file: %s\n", p.policy)
		return 1
	}
	policyToValidate, err := loadPolicyYAML(p.policy)
	if err != nil {
		fmt.Fprintln(stderr, "protect: policy is invalid:", err)
		return 1
	}
	if err := engine.ValidatePolicy(&policyToValidate); err != nil {
		fmt.Fprintln(stderr, "protect: policy is invalid:", err)
		return 1
	}
	if firstInstall && existed {
		if err := writeIfAbsent(p.backup, original, 0o600); err != nil {
			fmt.Fprintln(stderr, "protect:", err)
			return 1
		}
	}
	encoded, err := json.MarshalIndent(proposed, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "protect:", err)
		return 1
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(p.audit), 0o700); err != nil {
		fmt.Fprintln(stderr, "protect:", err)
		return 1
	}
	originalMode := uint32(0o600)
	if existed {
		if info, statErr := os.Stat(p.config); statErr == nil {
			originalMode = uint32(info.Mode().Perm())
		}
	}
	if changed {
		if err := atomicWrite(p.config, encoded, 0o600); err != nil {
			fmt.Fprintln(stderr, "protect:", err)
			return 1
		}
	}
	state := protectState{Version: 2, Target: target, ConfigPath: p.config, PolicyPath: p.policy, AuditPath: p.audit, BackupPath: p.backup, Command: p.tg, Args: claudeHookArgs(p), InstalledSHA256: digest(encoded), OriginalExisted: existed, OriginalMode: originalMode, ExactRestoreSafe: true}
	if !firstInstall {
		state.OriginalExisted = prior.OriginalExisted
		state.OriginalMode = prior.OriginalMode
		state.ExactRestoreSafe = prior.ExactRestoreSafe && digest(original) == prior.InstalledSHA256
	}
	stateBytes, _ := json.MarshalIndent(state, "", "  ")
	if err := atomicWrite(p.state, append(stateBytes, '\n'), 0o600); err != nil {
		if changed {
			if existed {
				_ = atomicWrite(p.config, original, os.FileMode(originalMode))
			} else {
				_ = os.Remove(p.config)
			}
		}
		fmt.Fprintln(stderr, "protect:", err)
		return 1
	}
	fmt.Fprintf(stdout, "protected claude: %s\npolicy: %s\naudit: %s\n", p.config, p.policy, p.audit)
	return 0
}

func cmdProtectStatus(args []string) int {
	return runProtectStatus(args, os.Stdout, os.Stderr)
}

func runProtectStatus(args []string, stdout, stderr io.Writer) int {
	target := claudeTarget
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = strings.ToLower(args[0]), args[1:]
	}
	if target != claudeTarget {
		fmt.Fprintf(stderr, "status: unsupported target %q (supported: claude)\n", target)
		return 2
	}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "Claude settings.json path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, _, err := resolveProtectPaths(*config, "", "")
	if err != nil {
		fmt.Fprintln(stderr, "status:", err)
		return 1
	}
	state, err := loadProtectState(p.state)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stdout, "{\"target\":\"claude\",\"protected\":false,\"config_path\":%q}\n", p.config)
			return 3
		}
		fmt.Fprintln(stderr, "status:", err)
		return 1
	}
	raw, _, root, err := readJSONConfig(p.config)
	if err != nil {
		fmt.Fprintln(stderr, "status:", err)
		return 1
	}
	markerInstalled := hasManagedClaudeHook(root)
	executableOK := state.Version == 1 || validateTGExecutable(state.Command) == nil
	policyOK := validPolicyFile(state.PolicyPath)
	installed := markerInstalled && executableOK && policyOK
	result := map[string]any{"target": claudeTarget, "protected": installed, "config_path": p.config, "policy_path": state.PolicyPath, "drifted": digest(raw) != state.InstalledSHA256, "executable_ok": executableOK, "policy_ok": policyOK}
	b, _ := json.Marshal(result)
	fmt.Fprintln(stdout, string(b))
	if !installed {
		return 3
	}
	return 0
}

func cmdUnprotect(args []string) int {
	return runUnprotect(args, os.Stdout, os.Stderr)
}

func runUnprotect(args []string, stdout, stderr io.Writer) int {
	target, rest, ok := protectTarget(args, stderr, "unprotect")
	if !ok {
		return 2
	}
	fs := flag.NewFlagSet("unprotect "+target, flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "apply the displayed removal (default is dry-run)")
	config := fs.String("config", "", "Claude settings.json path")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	p, _, err := resolveProtectPaths(*config, "", "")
	if err != nil {
		fmt.Fprintln(stderr, "unprotect:", err)
		return 1
	}
	state, err := loadProtectState(p.state)
	if err != nil {
		fmt.Fprintln(stderr, "unprotect: no managed installation found:", err)
		return 1
	}
	raw, _, root, err := readJSONConfig(p.config)
	if err != nil {
		fmt.Fprintln(stderr, "unprotect:", err)
		return 1
	}
	cleaned, found, err := removeManagedClaudeHooks(root)
	if err != nil || !found {
		fmt.Fprintln(stderr, "unprotect: managed hook is missing; refusing to alter the configuration")
		return 1
	}
	plan := protectPlan{Action: "unprotect", Target: target, Apply: *apply, Changed: true, ConfigPath: p.config, BackupPath: state.BackupPath, Config: cleaned}
	if !*apply {
		return writePlan(stdout, plan)
	}
	if state.ExactRestoreSafe && digest(raw) == state.InstalledSHA256 {
		if state.OriginalExisted {
			backup, readErr := os.ReadFile(state.BackupPath)
			if readErr != nil {
				fmt.Fprintln(stderr, "unprotect: pristine backup unavailable; refusing exact restore:", readErr)
				return 1
			}
			mode := os.FileMode(state.OriginalMode)
			if mode == 0 {
				mode = 0o600
			}
			if err := atomicWrite(p.config, backup, mode); err != nil {
				fmt.Fprintln(stderr, "unprotect:", err)
				return 1
			}
		} else if err := os.Remove(p.config); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "unprotect:", err)
			return 1
		}
	} else {
		encoded, marshalErr := json.MarshalIndent(cleaned, "", "  ")
		if marshalErr != nil {
			fmt.Fprintln(stderr, "unprotect:", marshalErr)
			return 1
		}
		mode := os.FileMode(0o600)
		if state.OriginalExisted && state.OriginalMode != 0 {
			mode = os.FileMode(state.OriginalMode)
		}
		if err := atomicWrite(p.config, append(encoded, '\n'), mode); err != nil {
			fmt.Fprintln(stderr, "unprotect:", err)
			return 1
		}
	}
	if err := os.Remove(p.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "unprotect: hook removed, but state cleanup failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "unprotected claude: %s\n", p.config)
	return 0
}

func protectTarget(args []string, stderr io.Writer, verb string) (string, []string, bool) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(stderr, "%s: target is required (supported: claude)\n", verb)
		return "", nil, false
	}
	target := strings.ToLower(args[0])
	if target != claudeTarget {
		fmt.Fprintf(stderr, "%s: unsupported target %q (supported: claude)\n", verb, target)
		return "", nil, false
	}
	return target, args[1:], true
}

func resolveProtectPaths(configOverride, policyOverride, tgOverride string) (protectPaths, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return protectPaths{}, false, err
	}
	config := configOverride
	if config == "" {
		config = filepath.Join(home, ".claude", "settings.json")
	}
	tgPath := tgOverride
	if tgPath == "" {
		tgPath, err = os.Executable()
		if err != nil {
			return protectPaths{}, false, err
		}
	}
	defaultPolicy := policyOverride == ""
	policy := policyOverride
	base := filepath.Join(home, ".config", "tool-guard")
	if defaultPolicy {
		policy = filepath.Join(base, "policies", "coding-agent-baseline.yaml")
	}
	abs := func(path string) (string, error) { return filepath.Abs(filepath.Clean(path)) }
	config, err = abs(config)
	if err != nil {
		return protectPaths{}, false, err
	}
	policy, err = abs(policy)
	if err != nil {
		return protectPaths{}, false, err
	}
	tgPath, err = abs(tgPath)
	if err != nil {
		return protectPaths{}, false, err
	}
	if err := validateTGExecutable(tgPath); err != nil {
		return protectPaths{}, false, err
	}
	return protectPaths{config: config, policy: policy, audit: filepath.Join(base, "audit", "claude.jsonl"), backup: config + ".tool-guard.bak", state: config + ".tool-guard-state.json", tg: tgPath}, defaultPolicy, nil
}

func validateTGExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("tg executable is unavailable: %w", err)
	}
	if info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return fmt.Errorf("tg executable is not executable: %s", path)
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(path), ".exe") {
		return fmt.Errorf("tg executable must be a real .exe on Windows: %s", path)
	}
	return nil
}

func requireClaudeExecHookSupport() error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return errors.New("Claude Code is not installed or not on PATH; install Claude Code >= 2.1.139, or use -config for an isolated/advanced profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, claudePath, "--version")
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return errors.New("Claude Code version check exceeded 5 seconds")
	}
	if err != nil {
		return fmt.Errorf("Claude Code version check failed: %w", err)
	}
	major, minor, patch, err := parseClaudeVersionOutput(string(out))
	if err != nil {
		return fmt.Errorf("cannot parse Claude Code version %q: %w", strings.TrimSpace(string(out)), err)
	}
	if versionLess(major, minor, patch, minClaudeExecHookMajor, minClaudeExecHookMinor, minClaudeExecHookPatch) {
		return fmt.Errorf("Claude Code %d.%d.%d is too old; exec-form hooks require >= 2.1.139", major, minor, patch)
	}
	return nil
}

func parseClaudeVersionOutput(output string) (int, int, int, error) {
	for _, field := range strings.Fields(output) {
		candidate := strings.Trim(field, "()[]{}<>,;:")
		major, minor, patch, err := parseThreePartVersion(candidate)
		if err == nil {
			return major, minor, patch, nil
		}
	}
	if strings.TrimSpace(output) == "" {
		return 0, 0, 0, errors.New("empty output")
	}
	return 0, 0, 0, errors.New("no major.minor.patch token found")
}

func parseThreePartVersion(version string) (int, int, int, error) {
	parts := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3)
	if len(parts) != 3 {
		return 0, 0, 0, errors.New("expected major.minor.patch")
	}
	values := [3]int{}
	for i, part := range parts {
		digits := strings.TrimRightFunc(part, func(r rune) bool { return r < '0' || r > '9' })
		if digits == "" {
			return 0, 0, 0, errors.New("version component is not numeric")
		}
		value, err := strconv.Atoi(digits)
		if err != nil {
			return 0, 0, 0, err
		}
		values[i] = value
	}
	return values[0], values[1], values[2], nil
}

func versionLess(aMajor, aMinor, aPatch, bMajor, bMinor, bPatch int) bool {
	if aMajor != bMajor {
		return aMajor < bMajor
	}
	if aMinor != bMinor {
		return aMinor < bMinor
	}
	return aPatch < bPatch
}

func claudeHookArgs(p protectPaths) []string {
	args := []string{"hook", "-policy", p.policy, "-agent-id", managedAgent}
	for _, path := range []string{p.config, p.backup, p.state, filepath.Dir(p.audit)} {
		args = append(args, "-protect-path", path)
	}
	return append(args, "-protect-self", "-fail-closed-tools", "bash,write,edit,notebookedit", "-audit-log", p.audit)
}

func validPolicyFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	policy, err := loadPolicyYAML(path)
	return err == nil && engine.ValidatePolicy(&policy) == nil
}

func claudeHookHandler(p protectPaths) map[string]any {
	return map[string]any{
		"type":    "command",
		"command": p.tg,
		"args":    claudeHookArgs(p),
		"timeout": 10,
	}
}

func readJSONConfig(path string) ([]byte, bool, map[string]any, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, map[string]any{}, nil
	}
	if err != nil {
		return nil, false, nil, err
	}
	var root map[string]any
	if len(strings.TrimSpace(string(raw))) == 0 {
		root = map[string]any{}
	} else if err := json.Unmarshal(raw, &root); err != nil {
		return nil, true, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return raw, true, root, nil
}

func mergeClaudeHook(root map[string]any, handler map[string]any) (map[string]any, bool, error) {
	copyRoot, err := cloneMap(root)
	if err != nil {
		return nil, false, err
	}
	cleaned, found, err := removeManagedClaudeHooks(copyRoot)
	if err != nil {
		return nil, false, err
	}
	hooks, err := objectChild(cleaned, "hooks")
	if err != nil {
		return nil, false, err
	}
	pre, err := arrayChild(hooks, "PreToolUse")
	if err != nil {
		return nil, false, err
	}
	entry := map[string]any{"matcher": "", "hooks": []any{handler}}
	hooks["PreToolUse"] = append(pre, entry)
	if found {
		before, _ := json.Marshal(root)
		after, _ := json.Marshal(cleaned)
		return cleaned, string(before) != string(after), nil
	}
	return cleaned, true, nil
}

func removeManagedClaudeHooks(root map[string]any) (map[string]any, bool, error) {
	hooksValue, ok := root["hooks"]
	if !ok {
		return root, false, nil
	}
	hooks, ok := hooksValue.(map[string]any)
	if !ok {
		return nil, false, errors.New("Claude settings field hooks must be an object")
	}
	preValue, ok := hooks["PreToolUse"]
	if !ok {
		return root, false, nil
	}
	pre, ok := preValue.([]any)
	if !ok {
		return nil, false, errors.New("Claude settings hooks.PreToolUse must be an array")
	}
	var groups []any
	found := false
	for _, item := range pre {
		group, ok := item.(map[string]any)
		if !ok {
			groups = append(groups, item)
			continue
		}
		nested, ok := group["hooks"].([]any)
		if !ok {
			groups = append(groups, item)
			continue
		}
		kept := make([]any, 0, len(nested))
		for _, hookValue := range nested {
			hook, ok := hookValue.(map[string]any)
			if ok && isManagedClaudeHook(hook) {
				found = true
				continue
			}
			kept = append(kept, hookValue)
		}
		if len(kept) > 0 {
			group["hooks"] = kept
			groups = append(groups, group)
		}
	}
	hooks["PreToolUse"] = groups
	return root, found, nil
}

func isManagedClaudeHook(hook map[string]any) bool {
	command, _ := hook["command"].(string)
	// Legacy shell-form entry used before protection-state v2. Keep recognizing
	// it so a re-protect or unprotect migrates/removes it without duplication.
	if strings.Contains(command, "-agent-id "+managedAgent) {
		return true
	}
	argsValue, ok := hook["args"].([]any)
	if !ok {
		// Programmatically constructed handlers may carry []string before the
		// map is serialized and cloned through JSON.
		if args, stringsOK := hook["args"].([]string); stringsOK {
			return containsManagedAgentArgs(args)
		}
		return false
	}
	args := make([]string, 0, len(argsValue))
	for _, value := range argsValue {
		arg, ok := value.(string)
		if !ok {
			return false
		}
		args = append(args, arg)
	}
	return containsManagedAgentArgs(args)
}

func containsManagedAgentArgs(args []string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-agent-id" && args[i+1] == managedAgent {
			return true
		}
	}
	return false
}

func hasManagedClaudeHook(root map[string]any) bool {
	cloned, err := cloneMap(root)
	if err != nil {
		return false
	}
	_, found, err := removeManagedClaudeHooks(cloned)
	return err == nil && found
}

func objectChild(parent map[string]any, key string) (map[string]any, error) {
	value, ok := parent[key]
	if !ok {
		child := map[string]any{}
		parent[key] = child
		return child, nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Claude settings field %s must be an object", key)
	}
	return child, nil
}

func arrayChild(parent map[string]any, key string) ([]any, error) {
	value, ok := parent[key]
	if !ok {
		return []any{}, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("Claude settings field %s must be an array", key)
	}
	return array, nil
}

func cloneMap(value map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tool-guard-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func writeIfAbsent(path string, data []byte, mode os.FileMode) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(path, data, mode)
}

func loadProtectState(path string) (protectState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return protectState{}, err
	}
	var state protectState
	if err := json.Unmarshal(raw, &state); err != nil {
		return protectState{}, err
	}
	if (state.Version != 1 && state.Version != 2) || state.Target != claudeTarget {
		return protectState{}, errors.New("unsupported protection state")
	}
	return state, nil
}

func digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func writePlan(stdout io.Writer, plan protectPlan) int {
	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}
