package engine

import "testing"

// Commands are classifier inputs only; none is passed to a shell.
func TestReviewMixedReadsClassifyWholeCommand(t *testing.T) {
	for _, command := range []string{
		"ls /dir; gh pr view 1",
		"gh pr view 1; ls /dir",
		"pwd -P && gh issue view 75",
		"gh pr view 1; pwd -P",
	} {
		t.Run(command, func(t *testing.T) {
			if got, reason := ClassifyCommand(command); got != CommandVerifiedRead {
				t.Fatalf("ClassifyCommand(%q) = %s (%s), want verified read", command, got, reason)
			}
			if got, reason := EvalConditionWithDetail(commandReadCondition(), map[string]interface{}{"parameters.command": command}); !got {
				t.Fatalf("gh_read condition unexpectedly ignored mixed read %q: %s", command, reason)
			}
		})
	}
}
