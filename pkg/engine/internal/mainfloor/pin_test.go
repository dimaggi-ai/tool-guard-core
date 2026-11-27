package mainfloor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mainEngineFiles is the list of non-test .go files of pkg/engine in commit
// 22ed838, in sorted order.
var mainEngineFiles = []string{
	"command_classify.go", "condition.go", "doc.go", "effects.go",
	"evaluator.go", "http_classify.go", "llm_classify.go", "matcher.go",
	"path_classify.go", "protect.go", "protect_mention.go", "regex_cache.go",
	"reversibility.go", "secret_classify.go", "secret_rules_generated.go",
	"shell_classify.go", "shell_tokenize.go", "validate.go", "write_classify.go",
}

// mainEngineHash is the SHA-256 of those files of 22ed838, each written as
// its name, a NUL byte, its content and a NUL byte, in the order above.
// Computed over `git archive 22ed838 pkg/engine`.
const mainEngineHash = "0d7ad044eba2fb9e65a717f7cb20bf5e7a07c88ba4250f93d3678d84246b05b1"

// TestFloorIsMainEngine pins the floor to commit 22ed838: with the package
// clause mapped back to package engine, the non-test files of this directory
// must hash to the pkg/engine files of 22ed838. The only other file is
// floor.go, which must hold no declarations.
func TestFloorIsMainEngine(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") && n != "floor.go" {
			got = append(got, n)
		}
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(mainEngineFiles, " ") {
		t.Fatalf("non-test files %v, want %v", got, mainEngineFiles)
	}
	h := sha256.New()
	for _, n := range mainEngineFiles {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(b, []byte("\npackage mainfloor\n"))
		if bytes.HasPrefix(b, []byte("package mainfloor\n")) {
			i = -1
		} else if i < 0 {
			t.Fatalf("%s: no package mainfloor clause", n)
		}
		b = append(append(append([]byte{}, b[:i+1]...), "package engine\n"...), b[i+1+len("package mainfloor\n"):]...)
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write(b)
		h.Write([]byte{0})
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != mainEngineHash {
		t.Fatalf("the floor differs from pkg/engine of 22ed838: hash %s, want %s", sum, mainEngineHash)
	}
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", "floor.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Decls) != 0 {
		t.Fatalf("floor.go has %d declarations, want 0", len(f.Decls))
	}
}
