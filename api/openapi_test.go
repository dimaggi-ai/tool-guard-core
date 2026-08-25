package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"gopkg.in/yaml.v3"
)

func loadContract(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("OpenAPI YAML is invalid: %v", err)
	}
	return doc
}

func asMap(t *testing.T, value any, where string) map[string]any {
	t.Helper()
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s must be an object, got %T", where, value)
	}
	return m
}

func TestOpenAPI31StructureAndReferences(t *testing.T) {
	doc := loadContract(t)
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi=%v, want 3.1.0", doc["openapi"])
	}
	paths := asMap(t, doc["paths"], "paths")
	components := asMap(t, doc["components"], "components")
	seenIDs := map[string]string{}
	methods := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "options": true, "head": true, "trace": true}
	for path, value := range paths {
		item := asMap(t, value, "paths."+path)
		for method, operationValue := range item {
			if !methods[method] {
				continue
			}
			operation := asMap(t, operationValue, path+" "+method)
			id, ok := operation["operationId"].(string)
			if !ok || id == "" {
				t.Errorf("%s %s has no operationId", method, path)
			} else if previous := seenIDs[id]; previous != "" {
				t.Errorf("duplicate operationId %q at %s and %s", id, previous, path)
			} else {
				seenIDs[id] = path
			}
			responses := asMap(t, operation["responses"], path+" responses")
			if len(responses) == 0 {
				t.Errorf("%s %s has no responses", method, path)
			}
		}
	}
	walkRefs(t, doc, components)
}

func TestEvaluationSchemasAllowOnlyDeclaredComposedProperties(t *testing.T) {
	doc := loadContract(t)
	components := asMap(t, doc["components"], "components")
	schemas := asMap(t, components["schemas"], "components.schemas")
	for _, name := range []string{"EvaluationResult", "EscalatedEvaluation"} {
		schema := asMap(t, schemas[name], "components.schemas."+name)
		if schema["unevaluatedProperties"] != false {
			t.Errorf("%s must close the composed schema with unevaluatedProperties:false", name)
		}
		allOf, ok := schema["allOf"].([]any)
		if !ok || len(allOf) == 0 {
			t.Fatalf("%s must compose EvaluationResultFields", name)
		}
		base := asMap(t, allOf[0], name+".allOf[0]")
		if base["$ref"] != "#/components/schemas/EvaluationResultFields" {
			t.Errorf("%s base ref=%v, want EvaluationResultFields", name, base["$ref"])
		}
	}
	base := asMap(t, schemas["EvaluationResultFields"], "components.schemas.EvaluationResultFields")
	if _, closedTooEarly := base["additionalProperties"]; closedTooEarly {
		t.Fatal("EvaluationResultFields must remain composable; close only the concrete schemas")
	}
}

func TestDecisionReceiptSchemaMatchesWireContract(t *testing.T) {
	doc := loadContract(t)
	components := asMap(t, doc["components"], "components")
	schemas := asMap(t, components["schemas"], "components.schemas")
	receipt := asMap(t, schemas["DecisionReceipt"], "components.schemas.DecisionReceipt")
	if receipt["additionalProperties"] != false {
		t.Fatal("DecisionReceipt must set additionalProperties:false")
	}

	requiredRaw, ok := receipt["required"].([]any)
	if !ok {
		t.Fatal("DecisionReceipt.required must be an array")
	}
	required := map[string]bool{}
	for _, value := range requiredRaw {
		name, _ := value.(string)
		required[name] = true
	}
	wantRequired := []string{
		"receipt_version", "trace_id", "trace_hash", "hash_algorithm",
		"canonical_trace_version", "integrity_model", "decision",
		"action_taken", "timestamp", "receipt_uri",
	}
	for _, name := range wantRequired {
		if !required[name] {
			t.Errorf("DecisionReceipt.required missing %q", name)
		}
	}
	if required["issuer"] {
		t.Error("issuer must remain optional")
	}

	properties := asMap(t, receipt["properties"], "DecisionReceipt.properties")
	for _, name := range append(wantRequired, "issuer") {
		if _, exists := properties[name]; !exists {
			t.Errorf("DecisionReceipt.properties missing %q", name)
		}
	}
	pins := map[string]string{
		"receipt_version":         audit.ReceiptVersion,
		"hash_algorithm":          audit.HashAlgorithmSHA256,
		"canonical_trace_version": audit.CanonicalTraceVersion,
		"integrity_model":         audit.IntegrityModelHashChain,
	}
	for field, want := range pins {
		schema := asMap(t, properties[field], "DecisionReceipt.properties."+field)
		if schema["const"] != want {
			t.Errorf("DecisionReceipt.%s const=%v, want %q", field, schema["const"], want)
		}
	}
	if ref := asMap(t, properties["decision"], "DecisionReceipt.decision")["$ref"]; ref != "#/components/schemas/Decision" {
		t.Errorf("DecisionReceipt.decision ref=%v", ref)
	}
	if ref := asMap(t, properties["action_taken"], "DecisionReceipt.action_taken")["$ref"]; ref != "#/components/schemas/ActionTaken" {
		t.Errorf("DecisionReceipt.action_taken ref=%v", ref)
	}
}

func TestProxyResponseSchemasExposeOptionalReceipts(t *testing.T) {
	doc := loadContract(t)
	components := asMap(t, doc["components"], "components")
	schemas := asMap(t, components["schemas"], "components.schemas")

	fields := asMap(t, schemas["EvaluationResultFields"], "EvaluationResultFields")
	fieldProperties := asMap(t, fields["properties"], "EvaluationResultFields.properties")
	decisionReceipt := asMap(t, fieldProperties["decision_receipt"], "EvaluationResultFields.decision_receipt")
	if decisionReceipt["$ref"] != "#/components/schemas/DecisionReceipt" {
		t.Errorf("decision_receipt ref=%v", decisionReceipt["$ref"])
	}
	for _, required := range fields["required"].([]any) {
		if required == "decision_receipt" {
			t.Error("decision_receipt must be optional when append/receipt creation fails")
		}
	}

	escalation := asMap(t, schemas["Escalation"], "Escalation")
	escalationProperties := asMap(t, escalation["properties"], "Escalation.properties")
	resolutionReceipt := asMap(t, escalationProperties["resolution_receipt"], "Escalation.resolution_receipt")
	if resolutionReceipt["$ref"] != "#/components/schemas/DecisionReceipt" {
		t.Errorf("resolution_receipt ref=%v", resolutionReceipt["$ref"])
	}
	for _, required := range escalation["required"].([]any) {
		if required == "resolution_receipt" {
			t.Error("resolution_receipt must be optional until resolution append succeeds")
		}
	}
}

func walkRefs(t *testing.T, value any, components map[string]any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "$ref" {
				ref, ok := child.(string)
				if !ok || !strings.HasPrefix(ref, "#/components/") {
					t.Errorf("unsupported reference %v", child)
					continue
				}
				parts := strings.Split(strings.TrimPrefix(ref, "#/components/"), "/")
				if len(parts) != 2 {
					t.Errorf("invalid component reference %q", ref)
					continue
				}
				group := asMap(t, components[parts[0]], "components."+parts[0])
				if _, exists := group[parts[1]]; !exists {
					t.Errorf("unresolved reference %q", ref)
				}
			}
			walkRefs(t, child, components)
		}
	case []any:
		for _, child := range node {
			walkRefs(t, child, components)
		}
	}
}

func TestOpenAPICoversProxyMux(t *testing.T) {
	doc := loadContract(t)
	paths := asMap(t, doc["paths"], "paths")
	got := make([]string, 0, len(paths))
	for path, value := range paths {
		item := asMap(t, value, "paths."+path)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			if _, ok := item[method]; ok {
				got = append(got, strings.ToUpper(method)+" "+path)
			}
		}
	}
	sort.Strings(got)
	want := []string{
		"GET /escalations", "GET /escalations/{id}", "GET /healthz", "GET /metrics", "GET /policies", "GET /readyz",
		"POST /escalations/{id}/approve", "POST /escalations/{id}/deny", "POST /evaluate", "POST /reload",
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("documented operations differ\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	source, err := os.ReadFile("../cmd/tg-proxy/main.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(source), -1)
	registered := map[string]bool{}
	for _, match := range matches {
		registered[match[1]] = true
	}
	for _, path := range pathsFromContract(paths) {
		muxPath := path
		if strings.HasPrefix(path, "/escalations/{id}") {
			muxPath = "/escalations/"
		}
		if !registered[muxPath] {
			t.Errorf("documented path %s has no proxy mux registration", path)
		}
	}
	for path := range registered {
		covered := paths[path] != nil || path == "/escalations/"
		if !covered {
			t.Errorf("proxy mux path %s is undocumented", path)
		}
	}
}

func pathsFromContract(paths map[string]any) []string {
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	return result
}
