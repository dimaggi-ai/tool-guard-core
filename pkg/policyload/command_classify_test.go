package policyload

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func TestLoadCommandClassifyYAMLAndJSONRoundTrip(t *testing.T) {
	const source = `policy_id: command-read
rules:
  - rule_id: classify
    effect: deny
    conditions:
      command_classify:
        field: parameters.command
        profile: gh_read
`
	policy, err := loadText(t, source)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(policy.Rules))
	}
	want := &domain.CommandClassify{Field: "parameters.command", Profile: "gh_read"}
	if got := policy.Rules[0].Conditions.CommandClassify; !reflect.DeepEqual(got, want) {
		t.Fatalf("classifier=%+v, want %+v", got, want)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var decoded domain.Policy
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, policy) {
		t.Fatalf("JSON roundtrip changed policy: got %+v, want %+v", decoded, policy)
	}
	loadedJSON, err := loadText(t, string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loadedJSON, policy) {
		t.Fatalf("JSON load changed policy: got %+v, want %+v", loadedJSON, policy)
	}
}

func TestLoadCommandClassifyRejectsUnknownFields(t *testing.T) {
	for _, source := range []string{
		"policy_id: test\nrules:\n  - conditions:\n      command_classify:\n        field: parameters.command\n        profile: gh_read\n        unknown: true\n",
		`{"policy_id":"test","rules":[{"conditions":{"command_classify":{"field":"parameters.command","profile":"gh_read","unknown":true}}}]}`,
	} {
		_, err := loadText(t, source)
		assertErrorContains(t, err, `unknown field "unknown" at rules[0].conditions.command_classify.unknown`)
	}
}
