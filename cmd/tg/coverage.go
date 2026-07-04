package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// covToolStat accumulates per-tool coverage.
type covToolStat struct {
	Tool     string
	Total    int
	Governed int
	Policies map[string]bool
}

// cmdCoverage answers a question tg simulate does not: of the tool calls an
// agent actually makes, what fraction has ANY governing policy — versus what
// passes only because nothing governs it. Coverage is scope-match: a call is
// "governed" when at least one approved policy's scope selects it. The
// ungoverned remainder is the blind spot (in our own dogfood: file writes and
// http passed ungoverned until 0.3.0).
//
// Input is a JSONL stream where each line is an ActionEnvelope OR a
// DecisionTrace — only the identity fields (agent_id, org_id, tool_name,
// tool_group) are needed, and both shapes carry them — so you can point it
// straight at an existing audit log.
//
// Exit: 0 normally; 3 when -min-coverage is set and coverage is below it (a CI
// gate); 1 internal error; 2 usage error.
func cmdCoverage(args []string) int {
	fs := flag.NewFlagSet("coverage", flag.ExitOnError)
	policyDir := fs.String("policy-dir", "", "directory of *.yaml/*.yml policies (mutually exclusive with -policy)")
	policyFile := fs.String("policy", "", "single policy YAML (mutually exclusive with -policy-dir)")
	callsPath := fs.String("calls", "", "JSONL of ActionEnvelopes or DecisionTraces, one per line (\"-\" reads stdin)")
	asJSON := fs.Bool("json", false, "emit the report as JSON instead of a table")
	minCoverage := fs.Float64("min-coverage", -1, "exit 3 if governed coverage is below this percent (e.g. 80); -1 disables")
	topGaps := fs.Int("top-gaps", 10, "show up to N most-frequent ungoverned tools")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*policyDir == "") == (*policyFile == "") {
		fmt.Fprintln(os.Stderr, "coverage: exactly one of -policy-dir or -policy is required")
		return 2
	}
	if *callsPath == "" {
		fmt.Fprintln(os.Stderr, "coverage: -calls is required")
		return 2
	}

	policies, err := loadPolicySet(*policyDir, *policyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "coverage:", err)
		return 1
	}

	in := os.Stdin
	if *callsPath != "-" {
		f, err := os.Open(*callsPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "coverage:", err)
			return 1
		}
		defer f.Close()
		in = f
	}

	stats := map[string]*covToolStat{}
	var total, governed, malformed int

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var id struct {
			AgentID   string `json:"agent_id"`
			OrgID     string `json:"org_id"`
			ToolName  string `json:"tool_name"`
			ToolGroup string `json:"tool_group"`
		}
		if err := json.Unmarshal([]byte(raw), &id); err != nil || id.ToolName == "" {
			malformed++
			continue
		}
		total++
		env := &domain.ActionEnvelope{
			AgentID: id.AgentID, OrgID: id.OrgID,
			ToolName: id.ToolName, ToolGroup: id.ToolGroup,
		}
		matched := engine.MatchPolicies(env, policies)

		st := stats[id.ToolName]
		if st == nil {
			st = &covToolStat{Tool: id.ToolName, Policies: map[string]bool{}}
			stats[id.ToolName] = st
		}
		st.Total++
		if len(matched) > 0 {
			governed++
			st.Governed++
			for _, p := range matched {
				st.Policies[p.PolicyID] = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "coverage: read calls:", err)
		return 1
	}

	pct := 0.0
	if total > 0 {
		pct = 100 * float64(governed) / float64(total)
	}

	if *asJSON {
		printCoverageJSON(len(policies), total, governed, malformed, pct, stats)
	} else {
		printCoverageTable(len(policies), total, governed, malformed, pct, stats, *topGaps)
	}

	if *minCoverage >= 0 && pct < *minCoverage {
		return 3
	}
	return 0
}

// sortedStats returns per-tool stats ordered by total desc, tool asc.
func sortedStats(stats map[string]*covToolStat) []*covToolStat {
	out := make([]*covToolStat, 0, len(stats))
	for _, s := range stats {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Tool < out[j].Tool
	})
	return out
}

func policyList(s *covToolStat) []string {
	ps := make([]string, 0, len(s.Policies))
	for p := range s.Policies {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

func printCoverageTable(policyCount, total, governed, malformed int, pct float64, stats map[string]*covToolStat, topGaps int) {
	fmt.Printf("Tool Guard coverage — %d policies, %d tool calls", policyCount, total)
	if malformed > 0 {
		fmt.Printf(", %d malformed (skipped)", malformed)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("─", 56))
	fmt.Printf("  GOVERNED   %6d  %5.1f%%\n", governed, pct)
	fmt.Printf("  ungoverned %6d  %5.1f%%\n", total-governed, 100-pct)
	fmt.Println(strings.Repeat("─", 56))
	fmt.Println("  per tool (calls · governed? · policies):")
	rows := sortedStats(stats)
	for _, s := range rows {
		mark := "✗ UNGOVERNED"
		detail := ""
		if s.Governed == s.Total && s.Total > 0 {
			mark = "✓"
			detail = strings.Join(policyList(s), ", ")
		} else if s.Governed > 0 {
			mark = fmt.Sprintf("~ %d/%d", s.Governed, s.Total)
			detail = strings.Join(policyList(s), ", ")
		}
		fmt.Printf("    %-16s %6d  %-12s %s\n", s.Tool, s.Total, mark, detail)
	}

	// Coverage gaps: tools with no governance, biggest first.
	var gaps []*covToolStat
	for _, s := range rows {
		if s.Governed == 0 {
			gaps = append(gaps, s)
		}
	}
	if len(gaps) > 0 {
		fmt.Println(strings.Repeat("─", 56))
		fmt.Println("  coverage gaps (ungoverned tools, most frequent first):")
		for i, s := range gaps {
			if i >= topGaps {
				fmt.Printf("    … and %d more\n", len(gaps)-topGaps)
				break
			}
			fmt.Printf("    %-16s %6d calls with no governing policy\n", s.Tool, s.Total)
		}
	}
}

func printCoverageJSON(policyCount, total, governed, malformed int, pct float64, stats map[string]*covToolStat) {
	tools := make([]map[string]any, 0, len(stats))
	for _, s := range sortedStats(stats) {
		tools = append(tools, map[string]any{
			"tool":     s.Tool,
			"calls":    s.Total,
			"governed": s.Governed,
			"policies": policyList(s),
		})
	}
	out := map[string]any{
		"policies":     policyCount,
		"total":        total,
		"governed":     governed,
		"ungoverned":   total - governed,
		"coverage_pct": pct,
		"malformed":    malformed,
		"tools":        tools,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
