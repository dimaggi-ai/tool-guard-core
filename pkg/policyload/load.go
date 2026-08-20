// Package policyload decodes Tool Guard policy files.
package policyload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"gopkg.in/yaml.v3"
)

// asWholeInt accepts the YAML scalar shapes an author can plausibly write
// for an integer version (1, or the whole-valued 1.0) and nothing else.
func asWholeInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}

const currentSchemaVersion = 1

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// Load reads and strictly decodes a policy YAML file. An omitted
// schema_version is version 1 for compatibility with policies written before
// the field was introduced.
func Load(path string) (domain.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("read policy: %w", err)
	}

	// Exactly one YAML document: yaml.Unmarshal would silently take the
	// first document and drop everything after a `---` separator — a
	// policy whose scope and rules live in a second document would load
	// as an empty (and therefore permissive) shell.
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var raw any
	if err := dec.Decode(&raw); err != nil && err != io.EOF {
		return domain.Policy{}, fmt.Errorf("parse policy YAML: %w", err)
	}
	// A trailing bare `---` yields an empty extra document; only reject
	// when a later document carries actual content.
	for {
		var extra any
		err := dec.Decode(&extra)
		if err == io.EOF {
			break
		}
		if err != nil || extra != nil {
			return domain.Policy{}, fmt.Errorf("parse policy YAML: a policy file is exactly one YAML document; content after a `---` separator would be silently ignored")
		}
	}
	raw = normalizeYAML(raw)
	root, _ := raw.(map[string]any)

	// Validate schema_version from the raw document, before any other
	// schema check: a future-versioned file must get the unsupported-
	// version error (not v1 migration guidance for fields it may
	// legitimately contain), and a mistyped value must get a contract
	// error, not a Go decoding internal.
	if v, present := root["schema_version"]; present {
		n, ok := asWholeInt(v)
		if !ok {
			return domain.Policy{}, fmt.Errorf("unsupported schema_version %v (supported: %d; must be an unquoted whole number)", v, currentSchemaVersion)
		}
		if n != currentSchemaVersion {
			return domain.Policy{}, fmt.Errorf("unsupported schema_version %d (supported: %d)", n, currentSchemaVersion)
		}
	}
	if _, present := root["deep_evaluation"]; present {
		return domain.Policy{}, fmt.Errorf("decode policy: field %q was removed; use the %q condition in a rule instead", "deep_evaluation", "llm_classify")
	}
	if err := rejectUnknownFields(raw, reflect.TypeOf(domain.Policy{}), ""); err != nil {
		return domain.Policy{}, fmt.Errorf("decode policy: %w", err)
	}

	js, err := json.Marshal(raw)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("yaml to JSON: %w", err)
	}
	var policy domain.Policy
	decoder := json.NewDecoder(bytes.NewReader(js))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return domain.Policy{}, fmt.Errorf("decode policy: %w", err)
	}

	if _, present := root["schema_version"]; !present {
		policy.SchemaVersion = currentSchemaVersion
	}
	// Unreachable if the pre-decode validation above held (present values
	// are checked there, absent ones defaulted here); kept as a fail-safe
	// invariant guard, not a live code path.
	if policy.SchemaVersion != currentSchemaVersion {
		return domain.Policy{}, fmt.Errorf("unsupported schema_version %d (supported: %d)", policy.SchemaVersion, currentSchemaVersion)
	}
	if policy.Status == "" {
		policy.Status = domain.PolicyStatusApproved
	}
	if policy.Mode == "" {
		policy.Mode = domain.PolicyModeEnforcement
	}
	switch policy.Status {
	case domain.PolicyStatusDraft, domain.PolicyStatusReview, domain.PolicyStatusApproved, domain.PolicyStatusArchived:
	default:
		return domain.Policy{}, fmt.Errorf("policy %q: unknown status %q (must be draft|review|approved|archived)", policy.PolicyID, policy.Status)
	}
	switch policy.Mode {
	case domain.PolicyModeShadow, domain.PolicyModeEnforcement:
	default:
		return domain.Policy{}, fmt.Errorf("policy %q: unknown mode %q (must be shadow|enforcement)", policy.PolicyID, policy.Mode)
	}
	return policy, nil
}

// rejectUnknownFields walks the decoded document against the target
// struct's json tags. Known limitations, deliberate for now: a type
// implementing json.Unmarshaler is not descended into (its unmarshaler
// owns its shape — adding one to a policy type re-opens unknown-field
// bypass at that boundary), and embedded/`json:",inline"` fields are
// not resolved. domain.Policy currently has neither; keep it that way
// or extend this walker first.
func rejectUnknownFields(value any, typ reflect.Type, path string) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Implements(jsonUnmarshalerType) || reflect.PointerTo(typ).Implements(jsonUnmarshalerType) {
		return nil
	}

	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := jsonFields(typ)
		for name, child := range object {
			fieldType, known := fields[name]
			childPath := joinPath(path, name)
			if !known {
				return fmt.Errorf("unknown field %q at %s", name, childPath)
			}
			if err := rejectUnknownFields(child, fieldType, childPath); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		items, ok := value.([]any)
		if !ok {
			return nil
		}
		for i, item := range items {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := rejectUnknownFields(item, typ.Elem(), itemPath); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for key, child := range object {
			if err := rejectUnknownFields(child, typ.Elem(), joinPath(path, key)); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func normalizeYAML(value any) any {
	switch node := value.(type) {
	case map[any]any:
		out := make(map[string]any, len(node))
		for key, child := range node {
			out[fmt.Sprint(key)] = normalizeYAML(child)
		}
		return out
	case map[string]any:
		for key, child := range node {
			node[key] = normalizeYAML(child)
		}
		return node
	case []any:
		for i, child := range node {
			node[i] = normalizeYAML(child)
		}
		return node
	default:
		return value
	}
}
