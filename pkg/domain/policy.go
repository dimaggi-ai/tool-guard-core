package domain

import (
	"encoding/json"
	"time"
)

// PolicyStatus represents the lifecycle status of a policy.
type PolicyStatus string

const (
	PolicyStatusDraft    PolicyStatus = "draft"
	PolicyStatusReview   PolicyStatus = "review"
	PolicyStatusApproved PolicyStatus = "approved"
	PolicyStatusArchived PolicyStatus = "archived"
)

// PolicyMode determines how the policy is enforced.
type PolicyMode string

const (
	PolicyModeShadow      PolicyMode = "shadow"
	PolicyModeEnforcement PolicyMode = "enforcement"
)

// Effect determines the action taken when a rule matches.
type Effect string

const (
	EffectAllow    Effect = "allow"
	EffectFlag     Effect = "flag"
	EffectEscalate Effect = "escalate"
	EffectDeny     Effect = "deny"
)

// EffectSeverity returns the numeric severity of an effect for comparison.
func EffectSeverity(e Effect) int {
	switch e {
	case EffectDeny:
		return 4
	case EffectEscalate:
		return 3
	case EffectFlag:
		return 2
	case EffectAllow:
		return 1
	default:
		return 0
	}
}

// Operator defines the comparison operation for conditions.
type Operator string

const (
	OpEq       Operator = "eq"
	OpNeq      Operator = "neq"
	OpGt       Operator = "gt"
	OpGte      Operator = "gte"
	OpLt       Operator = "lt"
	OpLte      Operator = "lte"
	OpIn       Operator = "in"
	OpContains Operator = "contains"
	OpRegex    Operator = "regex"
	OpGtField  Operator = "gt_field"
	OpLtField  Operator = "lt_field"
)

// Policy represents a versioned, citation-backed policy object.
// Spec: 02_Policy_Object_v0
type Policy struct {
	PolicyID    string       `json:"policy_id"`
	OrgID       string       `json:"org_id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Version     int          `json:"version"`
	Priority    int          `json:"priority,omitempty"` // 1 = highest priority, default 100
	Status      PolicyStatus `json:"status"`
	Mode        PolicyMode   `json:"mode"`

	// Scope determines which agents/tools this policy applies to
	Scope PolicyScope `json:"scope"`

	// Source documents this policy derives from
	SourceDocuments []SourceDocument `json:"source_documents,omitempty"`

	// Rules are the individual evaluation rules
	Rules []Rule `json:"rules"`

	// DeepEvaluation is parsed for forward compatibility but NOT
	// evaluated — no shipped evaluator consumes it. Policies that
	// set deep_evaluation behave identically to policies that omit
	// it. Use the llm_classify condition for semantic checks that
	// actually run.
	DeepEvaluation *DeepEvalConfig `json:"deep_evaluation,omitempty"`

	// Compliance maps this policy to framework control IDs (e.g.
	// {"eu_ai_act": ["art_12", "art_14"]}). The mapping is stored
	// without validation — there is no cross-check against a
	// framework manifest. Operator-supplied metadata.
	Compliance map[string][]string `json:"compliance,omitempty"`

	// Audit
	CreatedBy  string    `json:"created_by"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// PolicyScope defines what agents and tools a policy applies to.
type PolicyScope struct {
	OrgIDs    []string `json:"org_ids,omitempty"`
	AgentIDs  []string `json:"agent_ids,omitempty"`
	ToolNames []string `json:"tool_names,omitempty"`
	ToolGroups []string `json:"tool_groups,omitempty"`
}

// SourceDocument references an SOP document that a policy derives from.
type SourceDocument struct {
	DocumentID  string     `json:"document_id"`
	Title       string     `json:"title"`
	Version     string     `json:"version,omitempty"`
	Path        string     `json:"path,omitempty"`         // e.g. "s3://policies/refund-sop-v3.pdf"
	ContentHash string     `json:"content_hash,omitempty"`
	UploadedAt  *time.Time `json:"uploaded_at,omitempty"`
}

// Rule is an individual policy rule with conditions, effect, and citation.
type Rule struct {
	RuleID      string    `json:"rule_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	RuleType    string    `json:"rule_type"` // threshold, budget, velocity, justification, sanity
	Enabled     *bool     `json:"enabled,omitempty"` // nil or true = enabled, false = disabled
	Conditions  Condition `json:"conditions"`
	Effect      Effect    `json:"effect"`
	EffectConfig EffectConfig `json:"effect_config,omitempty"`
	Citation    Citation  `json:"citation"`
	Priority    int       `json:"priority,omitempty"`
}

// IsEnabled returns whether this rule should be evaluated.
func (r *Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// Condition represents a logical condition tree (AND/OR/NOT with leaf comparisons).
type Condition struct {
	// Logical operators (only one should be set for branch nodes)
	And []Condition `json:"and,omitempty"`
	Or  []Condition `json:"or,omitempty"`
	Not *Condition  `json:"not,omitempty"`

	// Leaf comparison (set for leaf nodes)
	Field    string      `json:"field,omitempty"`
	Operator Operator    `json:"operator,omitempty"`
	Value    interface{} `json:"value,omitempty"`

	// SQLClassify, if non-nil, evaluates the leaf by parsing a SQL
	// string through a dialect-specific parser (sqlguard) rather than
	// the generic operator path. Returning true here means "rule fires"
	// — i.e. the SQL violated one of the Require predicates. The Field
	// path resolves to the SQL string; missing/non-string/parse-error
	// fail closed.
	SQLClassify *SQLClassify `json:"sql_classify,omitempty"`

	// PathClassify, if non-nil, evaluates the leaf as a filesystem
	// path: normalizes via filepath.Clean, optionally resolves
	// symlinks, then matches against denied / allowed canonical prefix
	// lists. Closes the regex-bypass family (/etc//shadow,
	// /etc/./shadow, /etc/../etc/shadow). Returning true = "rule
	// fires" = deny.
	PathClassify *PathClassify `json:"path_classify,omitempty"`

	// ShellClassify, if non-nil, evaluates a parsed argv list (NOT a
	// shell-quoted string) for safety. The tool must accept argv as
	// an array and exec the program directly, never via `sh -c`. The
	// classifier checks argv[0] against an allowlist and argv[1:]
	// against a pattern denylist. Closes the family of
	// shell-injection bypasses ($IFS, $(), backticks, env expansion,
	// glob, redirection) — none of those happen when no shell runs.
	ShellClassify *ShellClassify `json:"shell_classify,omitempty"`

	// LLMClassify, if non-nil, asks a local Ollama-served model
	// (Gemma 4 multimodal variants by default) to classify a
	// generative prompt — text only or text+image — against a list
	// of forbidden content categories. Implemented in
	// pkg/llmguard.Classifier. Fail-closed: any error or low-
	// confidence answer denies the call. The model name and Ollama
	// endpoint are policy-configured so operators can swap to a
	// different local LLM without code changes.
	LLMClassify *LLMClassify `json:"llm_classify,omitempty"`
}

// SQLClassify is the per-rule config for a SQL-aware leaf condition.
// All Require fields are inclusive — a SQL string must satisfy every
// listed predicate to pass. Any violation makes the rule fire.
type SQLClassify struct {
	// Field is the dotted envelope path that resolves to the SQL
	// string. Typically "parameters.sql".
	Field string `json:"field"`

	// Dialect names which parser to dispatch to. Must match a dialect
	// registered with the sqlguard package. Unknown dialect = deny.
	Dialect string `json:"dialect"`

	Require SQLRequire `json:"require"`
}

// SQLRequire enumerates the predicates the SQL must satisfy. Empty/zero
// fields are not checked. The semantics are "ALL of these must hold;
// any violation makes the rule fire."
type SQLRequire struct {
	// TopLevelKinds lists the only allowed top-level statement kinds
	// (case-insensitive: "SELECT", "INSERT", etc.). Multi-statement
	// inputs are always rejected when this list is non-empty. Empty
	// list disables the check.
	TopLevelKinds []string `json:"top_level_kinds,omitempty"`

	// DeniedTopLevelKinds is the inverse: fire the rule when the SQL
	// IS one of these kinds. Use this when the policy's purpose is
	// "escalate writes" rather than "only allow reads". When both
	// fields are set, the deny check is consulted first.
	DeniedTopLevelKinds []string `json:"denied_top_level_kinds,omitempty"`

	// NoDynamicSQL rejects DO blocks, EXECUTE, PREPARE, CALL, and
	// CREATE FUNCTION bodies — anything that constructs or runs SQL
	// at runtime.
	NoDynamicSQL bool `json:"no_dynamic_sql,omitempty"`

	// NoProgramExec rejects COPY ... FROM/TO PROGRAM and the MSSQL
	// xp_cmdshell equivalent — shell access via the DB engine.
	NoProgramExec bool `json:"no_program_exec,omitempty"`

	// AllowedFunctions is the function-call allowlist. When non-empty,
	// every function invoked in the statement tree must appear in this
	// list (last-name match, schema qualifier ignored).
	AllowedFunctions []string `json:"allowed_functions,omitempty"`

	// NoFunctions rejects any statement containing ANY function call.
	// Use this when the policy wants "no function calls at all" — an
	// empty AllowedFunctions list silently skips the check, which is
	// the opposite of what an operator typing `allowed_functions: []`
	// would intend.
	NoFunctions bool `json:"no_functions,omitempty"`

	// DeniedFunctionClasses lists registry-defined class names whose
	// member functions are denied even if not in AllowedFunctions.
	// Closes the "custom UDF" gap: operator declares
	// `cleanup_users` belongs to class `destructive` in tools.yaml,
	// policy lists `destructive` here, agent's call to
	// cleanup_users() is denied regardless of allowlist content.
	DeniedFunctionClasses []string `json:"denied_function_classes,omitempty"`

	// AllowedFunctionClasses inverts the model: only functions
	// belonging to one of these classes are permitted. Use this OR
	// AllowedFunctions; not both. Closes the open-class problem.
	AllowedFunctionClasses []string `json:"allowed_function_classes,omitempty"`

	// DeniedTables names table prefixes (lowercased, prefix-match)
	// that the SQL must NOT reference. Catches `TABLE pg_authid` and
	// any read of pg_catalog / information_schema / a sensitive
	// view the operator names. Example:
	//   denied_tables: [pg_, information_schema., secrets.]
	DeniedTables []string `json:"denied_tables,omitempty"`

	// AllowedTables, when non-empty, requires every referenced table
	// to be in this set (exact, case-insensitive). Use this when the
	// agent should only ever touch a small fixed schema; the engine
	// then rejects everything not in the list — TABLE pg_authid
	// included.
	AllowedTables []string `json:"allowed_tables,omitempty"`
}

// PathClassify is the per-rule config for a filesystem-path leaf.
// Predicates compose with AND semantics: every populated requirement
// must hold for the rule to PASS (not fire). Any violation makes the
// rule fire (deny).
type PathClassify struct {
	// Field is the dotted envelope path that resolves to the filesystem
	// path string. Typically "parameters.path".
	Field string `json:"field"`

	Require PathRequire `json:"require"`
}

// PathRequire enumerates the predicates a filesystem path must satisfy.
// Empty/zero fields are not checked.
type PathRequire struct {
	// CleanFirst applies filepath.Clean to the input path before any
	// other check. Collapses "..", "/./", "//", trailing slashes.
	// Strongly recommended — without this, /etc//shadow,
	// /etc/./shadow, etc. slip past prefix-based denies.
	CleanFirst bool `json:"clean_first,omitempty"`

	// AbsoluteOnly rejects any non-absolute path (rejects "etc/passwd"
	// and any relative form).
	AbsoluteOnly bool `json:"absolute_only,omitempty"`

	// ResolveSymlinks runs filepath.EvalSymlinks before prefix
	// matching. Catches the hostile-symlink trick where /var/log
	// resolves to /etc/passwd. Costs one stat() per evaluation.
	ResolveSymlinks bool `json:"resolve_symlinks,omitempty"`

	// DenyOnResolveFailure makes the rule fire when EvalSymlinks
	// returns an error (ENOENT, permission denied, etc.). Defends
	// against the TOCTOU pattern on write-tool paths: an attacker
	// submits a non-existent path, proxy can't resolve, and the file
	// is created as a symlink before the tool follows it. Set this
	// on policies that protect write tools; the demo's read tool
	// doesn't need it.
	DenyOnResolveFailure bool `json:"deny_on_resolve_failure,omitempty"`

	// DeniedCanonicalPrefixes denies any path whose canonical form
	// starts with one of these prefixes. Each prefix may contain "*"
	// to wildcard a single path component (e.g.
	// "/home/*/.ssh"). No other glob features.
	DeniedCanonicalPrefixes []string `json:"denied_canonical_prefixes,omitempty"`

	// AllowedCanonicalPrefixes, when non-empty, requires the
	// canonical path to start with one of these prefixes. Use either
	// the deny-list OR the allow-list pattern — for high-trust
	// environments the allow-list is the safer pattern.
	AllowedCanonicalPrefixes []string `json:"allowed_canonical_prefixes,omitempty"`

	// DenyShellMetas, when true, denies any path containing shell
	// metacharacters or control bytes:
	//
	//   ; & | $ ` newline tab carriage-return NUL redirects
	//
	// Filesystem syscalls treat these as literal bytes in filenames,
	// so a legitimate agent has no reason to ask for a path like
	// /etc/shadow;cat /tmp/x. The presence of such characters is a
	// strong attack signal — deny on suspicion, log the attempt.
	//
	// Backslash ('\') is NOT flagged by default because it's a
	// legitimate path separator on Windows. Set IncludeBackslash to
	// add it to the denied-meta set when deploying on Linux-only
	// installations.
	DenyShellMetas bool `json:"deny_shell_metas,omitempty"`

	// IncludeBackslash augments DenyShellMetas to flag '\' as well.
	// Use only on Linux-only deployments where backslash in a path
	// cannot be legitimate.
	IncludeBackslash bool `json:"include_backslash,omitempty"`

	// MaxPathLength, when > 0, denies any path whose post-Clean
	// byte length exceeds this. Linux PATH_MAX is 4096; agents
	// should never need longer.
	MaxPathLength int `json:"max_path_length,omitempty"`
}

// ShellClassify is the per-rule config for an argv-shaped leaf.
type ShellClassify struct {
	// Field is the dotted envelope path that resolves to an []any
	// (the JSON array of argv strings). Typically "parameters.argv".
	Field string `json:"field"`

	Require ShellRequire `json:"require"`
}

// ShellRequire enumerates the predicates an argv list must satisfy.
// Empty/zero fields are not checked.
type ShellRequire struct {
	// Argv0Allowlist names the only program names allowed as argv[0]
	// (exact match, no path; "ls" matches both /usr/bin/ls and bare
	// ls because the tool resolves PATH itself).
	Argv0Allowlist []string `json:"argv0_allowlist,omitempty"`

	// ArgvDenyPatterns is a list of Go regex patterns; any argv
	// element (including argv[0]) that matches any pattern fires the
	// rule. Use this to deny shell metacharacters that the tool
	// might re-introduce, or sensitive flag values.
	ArgvDenyPatterns []string `json:"argv_deny_patterns,omitempty"`

	// MaxArgc caps the total number of argv elements. Zero = no cap.
	// Defends against pathologically long arg lists.
	MaxArgc int `json:"max_argc,omitempty"`

	// DeniedArgvPaths is a list of canonical filesystem prefixes; if
	// any argv element looks like an absolute path AND starts with
	// any denied prefix (after filepath.Clean), fire the rule. Lets
	// the policy author say "no command arg may reach /etc/shadow"
	// without enumerating every program.
	DeniedArgvPaths []string `json:"denied_argv_paths,omitempty"`

	// ResolveSymlinks, when true, also tests each absolute argv
	// element through filepath.EvalSymlinks before the denied-prefix
	// check. Catches "argv = [cat, /tmp/innocent]" where /tmp/innocent
	// is a symlink to /etc/shadow. Symmetric with PathRequire.
	ResolveSymlinks bool `json:"resolve_symlinks,omitempty"`

	// ArgvEnvPatternDeny: when argv[0] is one of env/sudo/nice/ionice
	// (env-wrapping helpers), any argv element matching this regex
	// fires the rule. Default-applied when the regex is non-empty.
	// Closes the ShellShock-style "argv=[env, BASH_FUNC_x%%=()..., ls]"
	// smuggling class.
	ArgvEnvPatternDeny string `json:"argv_env_pattern_deny,omitempty"`
}

// IsLeaf returns true if this is a leaf condition (has a field comparison
// or a sql/path/shell/llm classify leaf).
func (c *Condition) IsLeaf() bool {
	return c.SQLClassify != nil || c.PathClassify != nil || c.ShellClassify != nil ||
		c.LLMClassify != nil || (c.Field != "" && c.Operator != "")
}

// LLMClassify configures a Gemma-class content classifier for
// generative tool prompts (image_gen, audio_gen, video_gen, text_gen).
// The engine calls an Ollama-served model (default Gemma 4 e4b) and
// asks for a strict-JSON verdict against the Forbidden category list.
// Returning a category from that list — or an error / low confidence
// — makes the rule fire.
type LLMClassify struct {
	// PromptField is the dotted envelope path resolving to the
	// generative prompt text. Typically parameters.prompt.
	PromptField string `json:"prompt_field"`

	// ImageURLField is optional — if set, the engine fetches the
	// image and includes it in the classification call (Gemma 4
	// multimodal). Useful for image-to-image / image-edit tools
	// where the SOURCE image is part of the policy decision.
	ImageURLField string `json:"image_url_field,omitempty"`

	// Forbidden is the closed-set of category labels the model may
	// return alongside "safe". Examples: ["csam", "real_person",
	// "weapons", "self_harm", "copyrighted_style", "voice_clone"].
	// The model is told to choose the most specific applicable label
	// or "safe"; any non-"safe" label fires the rule.
	Forbidden []string `json:"forbidden"`

	// Model names the Ollama model tag to use. Defaults to
	// "gemma4:e4b". Operators can swap to any multimodal Ollama
	// model — qwen2-vl, llava, etc.
	Model string `json:"model,omitempty"`

	// OllamaURL overrides the default http://localhost:11434
	// endpoint. Useful for containerised deployments where Ollama
	// runs on a sibling host.
	OllamaURL string `json:"ollama_url,omitempty"`

	// TimeoutSeconds bounds the classifier call. Default 30s — a
	// Gemma 4 e4b prompt classification typically lands inside 5s.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// EffectConfig provides additional configuration for the effect.
type EffectConfig struct {
	Severity          string `json:"severity,omitempty"`           // low, medium, high, critical
	EscalateTo        string `json:"escalate_to,omitempty"`        // role or user
	TimeoutMinutes    int    `json:"timeout_minutes,omitempty"`
	SuggestedResponse string `json:"suggested_response,omitempty"`
}

// Citation links a rule to a specific clause in a source document.
type Citation struct {
	DocumentID    string `json:"document_id"`
	DocumentTitle string `json:"document_title,omitempty"`
	Section       string `json:"section,omitempty"`
	Page          int    `json:"page,omitempty"`
	Line          int    `json:"line,omitempty"`
	Excerpt       string `json:"excerpt"`
}

// DeepEvalConfig declares the policy's request for Gemma 4 hybrid eval.
// Mirrors the YAML schema used by the (frozen) Python hackathon submission
// so existing policy authors can write the same shape in Go.
//
// FailMode controls what happens when Gemma is unavailable / ambiguous:
//   - "closed" (default and recommended) — any non-OK status downgrades the
//     deterministic decision to DENY. Required for clinical / high-risk.
//   - "open" — ignore the deep eval failure and use the deterministic
//     decision as-is. Only acceptable for advisory / monitoring policies.
type DeepEvalConfig struct {
	Model                string  `json:"model" yaml:"model"`                                 // e.g. "gemma4:e4b"
	ContextFile          string  `json:"context_file,omitempty" yaml:"context"`              // path or label loaded into the prompt
	ConfidenceThreshold  float64 `json:"confidence_threshold,omitempty" yaml:"confidence_threshold"` // default 0.6
	ResponseFormat       string  `json:"response_format,omitempty" yaml:"response_format"`   // currently only "json"
	FailMode             string  `json:"fail_mode,omitempty" yaml:"fail_mode"`               // closed | open (default closed)
}

// UnmarshalJSON customizes unmarshaling for DeepEvalConfig to support both
// "context" (from YAML schema) and "context_file" (from JSON schema).
func (d *DeepEvalConfig) UnmarshalJSON(b []byte) error {
	type Alias DeepEvalConfig
	aux := &struct {
		Context string `json:"context"`
		*Alias
	}{
		Alias: (*Alias)(d),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Context != "" && d.ContextFile == "" {
		d.ContextFile = aux.Context
	}
	return nil
}
