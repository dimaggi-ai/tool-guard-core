package engine

import "testing"

func TestViolatesProtectedPaths_UnresolvedShellPaths(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"assignment before list", "X=/etc; rm $X/passwd", true},
		{"assignment before command", "X=/etc rm $X/passwd", true},
		{"export before list", "export X=/etc; rm $X/f", true},
		{"assignment in subshell", "(X=/etc; rm $X/f)", true},
		{"quoted variable concatenation", `rm "$X"/f`, true},
		{"parameter default", "rm ${X:-/etc}/f", true},
		{"command substitution", "rm $(echo /etc)/f", true},
		{"safe echo variable", "echo $HOME", false},
		{"literal protected path", "rm /protected/f", true},
		{"quoted literal protected path", `rm "/protected/f"`, true},
		{"literal unprotected path", "rm /etc/f", false},
		{"quoted literal unprotected path", `rm "/etc/f"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// /etc is deliberately outside this prefix: expansions must fail
			// closed without evaluating assignments or executing shell text.
			hit, reason := ViolatesProtectedPaths(envCmd("bash", tt.command), []string{"/protected"})
			if hit != tt.wantHit {
				t.Fatalf("ViolatesProtectedPaths(%q) = %v, want %v (reason=%q)", tt.command, hit, tt.wantHit, reason)
			}
			if hit && reason == "" {
				t.Error("protected-path violation must include a reason")
			}
			if !hit && reason != "" {
				t.Errorf("allowed command returned a violation reason: %q", reason)
			}
		})
	}
}
