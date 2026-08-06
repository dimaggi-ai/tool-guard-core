// Package policyload decodes Tool Guard policy files.
package policyload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"gopkg.in/yaml.v3"
)

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

	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return domain.Policy{}, fmt.Errorf("parse policy YAML: %w", err)
	}
	raw = normalizeYAML(raw)
	root, _ := raw.(map[string]any)
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
