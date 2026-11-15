package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

const fixtureKeySplit = "{{+}}"

type secretCommandsFixture struct {
	ID     string          `json:"id"`
	Tool   string          `json:"tool"`
	Params json.RawMessage `json:"params"`
	Want   string          `json:"want"` // "hit" or "clean"
	Rule   string          `json:"rule"` // dev set only: a rule that must match
}

func loadSecretCommandsFixtures(t *testing.T, name string) []secretCommandsFixture {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "secretcommands", name))
	if err != nil {
		t.Fatalf("open fixtures: %v", err)
	}
	defer f.Close()
	var out []secretCommandsFixture
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		// Each key-like string is stored in two pieces joined by
		// fixtureKeySplit, so no complete key string is in the repository and
		// secret scanners do not block a push. Join the pieces here.
		line := bytes.ReplaceAll(sc.Bytes(), []byte(fixtureKeySplit), nil)
		var fx secretCommandsFixture
		if err := json.Unmarshal(line, &fx); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		out = append(out, fx)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	return out
}

func loadSecretCommandsPolicy(t *testing.T) domain.Policy {
	t.Helper()
	policy, err := policyload.Load(filepath.Join("..", "..", "policies", "coding_agent_secret_commands.yaml"))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if err := engine.ValidatePolicy(&policy); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	if policy.Mode != domain.PolicyModeShadow {
		t.Fatalf("policy must ship in shadow mode, got %q", policy.Mode)
	}
	return policy
}

// matchedSecretRules returns the IDs of the rules that matched the fixture,
// and the action the engine took.
func matchedSecretRules(t *testing.T, policy domain.Policy, fx secretCommandsFixture) (map[string]bool, domain.ActionTaken) {
	t.Helper()
	group := "filesystem_writes"
	if fx.Tool == "bash" {
		group = "shell"
	}
	env := domain.ActionEnvelope{
		EnvelopeID: "secret-commands-" + fx.ID,
		Timestamp:  time.Now().UTC(),
		ToolName:   fx.Tool,
		ToolGroup:  group,
		Parameters: fx.Params,
	}
	res := engine.NewEvaluator().Evaluate(&env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
	got := map[string]bool{}
	for _, rr := range res.RuleResults {
		if rr.Matched {
			got[rr.RuleID] = true
		}
	}
	return got, res.ActionTaken
}

func TestSecretCommandsPolicyDevSet(t *testing.T) {
	policy := loadSecretCommandsPolicy(t)
	for _, fx := range loadSecretCommandsFixtures(t, "dev.jsonl") {
		t.Run(fx.ID, func(t *testing.T) {
			got, action := matchedSecretRules(t, policy, fx)
			if action == domain.ActionDenied || action == domain.ActionEscalated {
				t.Fatalf("shadow policy changed the action: %s", action)
			}
			switch fx.Want {
			case "hit":
				if !got[fx.Rule] {
					t.Fatalf("want rule %s to match, matched %v", fx.Rule, got)
				}
			case "clean":
				if len(got) != 0 {
					t.Fatalf("want no match, matched %v", got)
				}
			default:
				t.Fatalf("bad want %q", fx.Want)
			}
		})
	}
}

// TestSecretCommandsPolicyHeldOut scores the held-out set. It was written
// before the policy regexes and is not used for tuning, so it reports a
// score instead of failing on each miss. Run it with TG_HELDOUT=1.
func TestSecretCommandsPolicyHeldOut(t *testing.T) {
	if os.Getenv("TG_HELDOUT") != "1" {
		t.Skip("held-out set is scored on request: TG_HELDOUT=1")
	}
	policy := loadSecretCommandsPolicy(t)
	var tp, fp, fn, tn int
	for _, fx := range loadSecretCommandsFixtures(t, "heldout.jsonl") {
		got, _ := matchedSecretRules(t, policy, fx)
		hit := len(got) > 0
		switch {
		case fx.Want == "hit" && hit:
			tp++
		case fx.Want == "hit":
			fn++
			t.Logf("MISS %s", fx.ID)
		case hit:
			fp++
			t.Logf("FALSE MATCH %s %v", fx.ID, got)
		default:
			tn++
		}
	}
	t.Logf("held-out: TP=%d FN=%d FP=%d TN=%d", tp, fn, fp, tn)
}
