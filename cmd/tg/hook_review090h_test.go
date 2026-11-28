package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// review090hPatchEvent is the apply_patch call of the round-11 review: 64
// files of lines lines each (the last or the first one is the protected
// file), 8 work directories, and the patch text also under the keys extra.
func review090hPatchEvent(t *testing.T, home string, protectedFirst bool, lines int, extra ...string) string {
	t.Helper()
	line := "+" + strings.Repeat("x", 78) + "\n"
	var names []string
	for i := 0; i < 63; i++ {
		names = append(names, fmt.Sprintf("f%d", i))
	}
	if protectedFirst {
		names = append([]string{".claude/settings.json"}, names...)
	} else {
		names = append(names, ".claude/settings.json")
	}
	var b strings.Builder
	b.WriteString("*** Begin Patch\n")
	for _, n := range names {
		b.WriteString("*** Add File: " + n + "\n" + strings.Repeat(line, lines))
	}
	b.WriteString("*** End Patch")
	ti := map[string]interface{}{"command": b.String()}
	for i := 0; i < 8; i++ {
		ti[fmt.Sprintf("a%d", i)] = map[string]interface{}{"workdir": fmt.Sprintf("d%d", i)}
	}
	for _, k := range extra {
		ti[k] = b.String()
	}
	ev, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": ti, "cwd": home,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(ev)
}

// TestReview090hApplyPatchMemory: round-11 review B3. An apply_patch call
// at the caps (64 files, 8 work directories) with a 900 KB patch. Each of
// about 1,150 envelopes held a copy of the patch, all at once: 4 to 7.6 GB,
// and the process was killed under a 2 GB limit, where 22ed838 denies the
// call with 250 MB. The envelopes are now built one at a time and the check
// stops at the first deny. The call is denied for the protected file, as
// 22ed838 denies it, and the call allocates less than 1 GB in all, which
// bounds its peak heap.
func TestReview090hApplyPatchMemory(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	prot := filepath.Join(home, ".claude", "settings.json")
	if err := os.WriteFile(prot, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := filepath.Abs(filepath.Join("..", "..", "examples", "coding-agent-guard", "policies", "coding_agent_shell.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(home)
	args := []string{"-policy", pol, "-mode", "enforcement", "-fail-closed", "-protect-path", prot}
	cases := []struct {
		name  string
		event string
	}{
		{"protected file last", review090hPatchEvent(t, home, false, 176)},
		{"protected file first", review090hPatchEvent(t, home, true, 176)},
		// Four copies of the patch: each is a quarter of the size, so the
		// call stays under the 1 MiB input limit.
		{"patch also under Content, text, new_string", review090hPatchEvent(t, home, false, 44, "Content", "text", "new_string")},
		{"patch also under CommandLine, script, cmd", review090hPatchEvent(t, home, false, 44, "CommandLine", "script", "cmd")},
	}
	const limit = 1 << 30
	for _, c := range cases {
		var peak atomic.Uint64
		stop := make(chan struct{})
		sampled := make(chan struct{})
		go func() {
			defer close(sampled)
			var m runtime.MemStats
			for {
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
				select {
				case <-stop:
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
		}()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out, code := runHookStr(t, c.event, args...)
		runtime.ReadMemStats(&after)
		close(stop)
		<-sampled
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %d byte event, allocated %d MB, sampled peak heap %d MB", c.name, len(c.event), alloc>>20, peak.Load()>>20)
		if code != 0 {
			t.Errorf("%s: exit code %d, want 0", c.name, code)
		}
		m := permissionDecisionRe.FindStringSubmatch(out)
		if m == nil || m[1] != "deny" || !strings.Contains(out, "protected path: write to") {
			t.Errorf("%s: got %.300s, want the protected-path deny of 22ed838", c.name, out)
		}
		if alloc > limit || peak.Load() > limit {
			t.Errorf("%s: allocated %d MB, peak heap %d MB, want under 1024 MB", c.name, alloc>>20, peak.Load()>>20)
		}
	}
	review090hManyKeysMemory(t, home, args)
}

// TestReview090hManyKeysChild runs one hook call for
// review090hManyKeysMemory in a separate process: the call on stdin, the
// flags in TG_REVIEW090H_CHILD_ARGS. It does nothing in a normal run.
func TestReview090hManyKeysChild(t *testing.T) {
	argv := os.Getenv("TG_REVIEW090H_CHILD_ARGS")
	if argv == "" {
		t.Skip("runs only as the child process of TestReview090hApplyPatchMemory")
	}
	var args []string
	if err := json.Unmarshal([]byte(argv), &args); err != nil {
		t.Fatal(err)
	}
	os.Exit(runHook(args, os.Stdin, os.Stdout))
}

// review090hManyKeysEvent is the call of round-12 review B1: 64 files of one
// line each (the protected file first or last), 8 work directories, and n
// keys "k0" to "k<n-1>" with the value 0.
func review090hManyKeysEvent(t *testing.T, home string, protectedFirst bool, n int) string {
	t.Helper()
	names := []string{}
	for i := 0; i < 63; i++ {
		names = append(names, fmt.Sprintf("f%d", i))
	}
	if protectedFirst {
		names = append([]string{".claude/settings.json"}, names...)
	} else {
		names = append(names, ".claude/settings.json")
	}
	var b strings.Builder
	b.WriteString("*** Begin Patch\n")
	for _, f := range names {
		b.WriteString("*** Add File: " + f + "\n+" + strings.Repeat("x", 78) + "\n")
	}
	b.WriteString("*** End Patch")
	ti := map[string]interface{}{"command": b.String()}
	for i := 0; i < 8; i++ {
		ti[fmt.Sprintf("a%d", i)] = map[string]interface{}{"workdir": fmt.Sprintf("d%d", i)}
	}
	for i := 0; i < n; i++ {
		ti[fmt.Sprintf("k%d", i)] = 0
	}
	ev, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": ti, "cwd": home,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(ev)
}

// review090hManyKeysMemory checks the calls of round-12 review B1. An
// earlier version copied every parameter for each of the about 1,150
// envelopes, so the hook used 462 MB with 2,000 keys and 3.5 GB with 40,000,
// and a 256 MB memory limit killed it before it printed a decision. Each call
// must give the protected-path deny of 22ed838 with a live heap under 256 MB
// in this process (runtime/metrics), and with a peak resident size under
// 256 MB when the tg binary runs it as a separate process.
func review090hManyKeysMemory(t *testing.T, home string, args []string) {
	const limit = 256 << 20
	for _, n := range []int{2000, 10000, 40000} {
		for _, first := range []bool{true, false} {
			name := fmt.Sprintf("%d keys, protected file last", n)
			if first {
				name = fmt.Sprintf("%d keys, protected file first", n)
			}
			event := review090hManyKeysEvent(t, home, first, n)
			sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
			var peak atomic.Uint64
			stop := make(chan struct{})
			sampled := make(chan struct{})
			go func() {
				defer close(sampled)
				s := []metrics.Sample{{Name: sample[0].Name}}
				for {
					metrics.Read(s)
					if v := s[0].Value.Uint64(); v > peak.Load() {
						peak.Store(v)
					}
					select {
					case <-stop:
						return
					case <-time.After(time.Millisecond):
					}
				}
			}()
			runtime.GC()
			out, code := runHookStr(t, event, args...)
			metrics.Read(sample)
			close(stop)
			<-sampled
			if v := sample[0].Value.Uint64(); v > peak.Load() {
				peak.Store(v)
			}
			if code != 0 {
				t.Errorf("%s: exit code %d, want 0", name, code)
			}
			m := permissionDecisionRe.FindStringSubmatch(out)
			if m == nil || m[1] != "deny" || !strings.Contains(out, "protected path: write to") {
				t.Errorf("%s: got %.300s, want the protected-path deny of 22ed838", name, out)
			}
			if peak.Load() > limit {
				t.Errorf("%s: live heap peak %d MB, want under 256 MB", name, peak.Load()>>20)
			}

			// The same call in a separate process: this test binary, running
			// only TestReview090hManyKeysChild.
			argv, _ := json.Marshal(args)
			cmd := exec.Command(os.Args[0], "-test.run=^TestReview090hManyKeysChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "TG_REVIEW090H_CHILD_ARGS="+string(argv))
			cmd.Dir = home
			cmd.Stdin = strings.NewReader(event)
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			err := cmd.Run()
			if err != nil {
				t.Errorf("%s: tg hook process: %v", name, err)
			}
			m = permissionDecisionRe.FindStringSubmatch(stdout.String())
			if m == nil || m[1] != "deny" || !strings.Contains(stdout.String(), "protected path: write to") {
				t.Errorf("%s: tg hook process printed %.300s, want the protected-path deny of 22ed838", name, stdout.String())
			}
			rss, ok := review090hMaxRSS(cmd.ProcessState)
			// A race build adds the shadow memory of the race detector to
			// the resident size, so it is reported and not asserted there.
			if ok && !raceEnabled && rss > limit {
				t.Errorf("%s: tg hook process peak resident size %d MB, want under 256 MB", name, rss>>20)
			}
			t.Logf("%s: %d byte event, live heap peak %d MB, process peak resident size %d MB (measured: %v)", name, len(event), peak.Load()>>20, rss>>20, ok)
		}
	}
}

// TestReview090hProtectViewVerdict: the protected-path check of the files
// of an apply_patch call reads envelopes without the key patch and the keys
// of the content and command alias families (applyPatchPlan.protectEnvelope).
// That gives the verdict of the full envelope only while the check does not
// read these keys for apply_patch. A protected path under each of them is
// allowed; the same path on file_path is denied.
func TestReview090hProtectViewVerdict(t *testing.T) {
	home := t.TempDir()
	prot := filepath.Join(home, ".claude", "settings.json")
	keys := []string{"patch", "new_string", "CommandLine", "File-Content", "Command"}
	for k := range contentAliasNames {
		keys = append(keys, k)
	}
	for k := range commandAliasNames {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, v := range []string{prot, "echo x > " + prot, "*** Begin Patch\n*** Add File: " + prot + "\n+x\n*** End Patch"} {
		for _, k := range keys {
			p, _ := json.Marshal(map[string]string{"file_path": filepath.Join(home, "ok.txt"), k: v})
			env := &domain.ActionEnvelope{ToolName: "apply_patch", ToolGroup: hookToolGroup("apply_patch"), Parameters: p}
			if hit, why := engine.ViolatesProtectedPaths(env, []string{prot}); hit {
				t.Errorf("key %q with %q: denied (%s); the protected-path check reads this key, so the apply_patch view must keep it", k, v, why)
			}
		}
	}
	p, _ := json.Marshal(map[string]string{"file_path": prot})
	env := &domain.ActionEnvelope{ToolName: "apply_patch", ToolGroup: hookToolGroup("apply_patch"), Parameters: p}
	if hit, _ := engine.ViolatesProtectedPaths(env, []string{prot}); !hit {
		t.Errorf("file_path %s: allowed, want deny", prot)
	}

	// The view keeps only the keys of applyPatchProtectKey. A key it drops
	// must not change the verdict, in any form of the value: near misses of
	// the path keys, nested objects and arrays under other keys.
	values := []interface{}{prot, []string{prot}, map[string]string{"file_path": prot},
		[]map[string]string{{"file_path": prot}}, "echo x > " + prot}
	dropped := []string{"File_Path", "filePath", "FilePath", "PATH", "Path", "Target", "TARGET", "Dest", "edit", "Edits",
		"Files", "Changes", "Operations", "nested", "list", "target_file", "targetfile", "abspath", "notebookPath",
		"outPath", "out-path", "notebook-path", "dir", "directory", "root", "workspace", "project_dir", "input", "diff"}
	for _, k := range dropped {
		if applyPatchProtectKey(k) {
			t.Errorf("key %q: the view keeps it; move it to the kept keys below", k)
			continue
		}
		for _, v := range values {
			p, _ := json.Marshal(map[string]interface{}{"file_path": filepath.Join(home, "ok.txt"), k: v})
			env := &domain.ActionEnvelope{ToolName: "apply_patch", ToolGroup: hookToolGroup("apply_patch"), Parameters: p}
			if hit, why := engine.ViolatesProtectedPaths(env, []string{prot}); hit {
				t.Errorf("key %q with %v: denied (%s); the protected-path check reads this key, so the apply_patch view must keep it", k, v, why)
			}
		}
	}
	// Each key the view keeps is one the check reads: one form of the value
	// is denied. A work-directory key is read as the directory of a relative
	// file_path.
	for k := range applyPatchProtectNames {
		if k == "file_path" {
			continue
		}
		denied := false
		for _, v := range values {
			p, _ := json.Marshal(map[string]interface{}{"file_path": filepath.Join(home, "ok.txt"), k: v})
			env := &domain.ActionEnvelope{ToolName: "apply_patch", ToolGroup: hookToolGroup("apply_patch"), Parameters: p}
			if hit, _ := engine.ViolatesProtectedPaths(env, []string{prot}); hit {
				denied = true
			}
		}
		if !denied {
			t.Errorf("key %q: no form of the value is denied; the view keeps a key the check does not read", k)
		}
	}
	for _, k := range []string{"cwd", "workdir", "Work_Dir", "working-directory", "WorkingDir"} {
		if !applyPatchProtectKey(k) {
			t.Errorf("work-directory key %q: the view drops it", k)
		}
		p, _ := json.Marshal(map[string]interface{}{"file_path": "settings.json", k: filepath.Join(home, ".claude")})
		env := &domain.ActionEnvelope{ToolName: "apply_patch", ToolGroup: hookToolGroup("apply_patch"), Parameters: p}
		if hit, _ := engine.ViolatesProtectedPaths(env, []string{prot}); !hit {
			t.Errorf("work-directory key %q: relative file_path under it allowed, want deny", k)
		}
	}
}

// TestReview090hOneDecisionAtTheTimeLimit: round-11 review F1. The decision
// of a call was written under the lock of hookGate, and the call returned
// after the lock was released. A timer that fired in that gap found the call
// not done and wrote the deny of the time limit as a second decision. With a
// budget near the time of a call, every call writes exactly one decision.
func TestReview090hOneDecisionAtTheTimeLimit(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(pol, []byte(hookDenyPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"-policy", pol}
	ev := `{"tool_name":"Bash","tool_input":{"command":"ls"}}`
	old := hookCallBudget
	defer func() { hookCallBudget = old }()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(8))

	// The median time of a call.
	var times []time.Duration
	for i := 0; i < 51; i++ {
		start := time.Now()
		runHookStr(t, ev, args...)
		times = append(times, time.Since(start))
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	median := times[len(times)/2]

	n := 60000
	if raceEnabled {
		n = 10000
	}
	counts := map[int]int{}
	for i := 0; i < n; i++ {
		// Budgets from 0.5 to 1.5 times the median time.
		hookCallBudget = median/2 + median*time.Duration(i%21)/20
		var out strings.Builder
		runHook(args, strings.NewReader(ev), &out)
		dec := json.NewDecoder(strings.NewReader(out.String()))
		objects := 0
		for {
			var v map[string]interface{}
			if err := dec.Decode(&v); err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("output %q: %v", out.String(), err)
			}
			objects++
		}
		counts[objects]++
	}
	t.Logf("median call %s; %d calls; decisions per call: %v", median, n, counts)
	if len(counts) != 1 || counts[1] != n {
		t.Errorf("decisions per call %v, want exactly one in each of %d calls", counts, n)
	}
}
