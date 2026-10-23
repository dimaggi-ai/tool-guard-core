// Package commandclassify provides inactive, advisory classification of literal
// command strings. A candidate is never permission to execute a command.
package commandclassify

import (
	"strconv"
	"strings"
)

type Decision string

const (
	ReadOnlyCandidate Decision = "read_only_candidate"
	Escalate          Decision = "escalate"
)

// Result describes syntax only. It does not authenticate the executable, shell,
// CLI configuration, repository, caller, destination or permission to read data.
type Result struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Span     Span     `json:"span"`
	Words    []Word   `json:"words,omitempty"`
	Command  string   `json:"command,omitempty"`
}

type option struct {
	name, value string
	span        Span
}

var aliases = map[string]string{
	"-R": "--repo", "-c": "--comments", "-s": "--state", "-L": "--limit", "-l": "--label",
}
var shapes = map[string]bool{
	"--repo": true, "--comments": false, "--json": true, "--state": true,
	"--limit": true, "--label": true, "--visibility": true,
	"--archived": false, "--no-archived": false, "--fork": false, "--source": false,
}
var allowed = map[string]string{
	"pr view":    " --repo --comments --json ",
	"pr list":    " --repo --json --state --limit --label ",
	"issue view": " --repo --comments --json ",
	"issue list": " --repo --json --state --limit --label ",
	"repo view":  " --json ",
	"repo list":  " --json --limit --visibility --archived --no-archived --fork --source ",
}

// Classify consumes the entire input using a bounded literal grammar. Unknown
// syntax or options escalate. No command is run and no external state is read.
func Classify(input string) Result {
	words, failure := parse(input)
	if failure != nil {
		return Result{Decision: Escalate, Reason: failure.reason, Span: failure.span}
	}
	refuse := func(reason string, span Span) Result {
		return Result{Decision: Escalate, Reason: reason, Span: span, Words: words}
	}
	// A literal executable name is required; paths, wrappers and quoted spellings
	// are intentionally outside this slice. This still cannot identify a binary.
	if words[0].Value != "gh" || input[words[0].Span.Start:words[0].Span.End] != "gh" {
		return refuse("unsupported_executable", words[0].Span)
	}
	var positional []Word
	var options []option
	seen := map[string]bool{}
	for i := 1; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w.Value, "-") {
			positional = append(positional, w)
			continue
		}
		name, value, hasValue := strings.Cut(w.Value, "=")
		if canonical, ok := aliases[name]; ok {
			name = canonical
		}
		takesValue, known := shapes[name]
		if !known {
			return refuse("unsupported_option", w.Span)
		}
		if seen[name] {
			return refuse("repeated_option", w.Span)
		}
		seen[name] = true
		span := w.Span
		if takesValue {
			if !hasValue {
				if i+1 == len(words) || strings.HasPrefix(words[i+1].Value, "-") {
					return refuse("missing_option_value", w.Span)
				}
				i++
				value = words[i].Value
				span.End = words[i].Span.End
			}
			if value == "" {
				return refuse("empty_option_value", span)
			}
		} else if hasValue {
			return refuse("unsupported_boolean_value", span)
		}
		options = append(options, option{name, value, span})
	}
	if len(positional) < 2 {
		return refuse("missing_command", Span{0, len(input)})
	}
	verb := positional[1].Value
	if verb == "ls" {
		verb = "list"
	}
	command := positional[0].Value + " " + verb
	permitted, known := allowed[command]
	if !known {
		return refuse("unsupported_command", Span{positional[0].Span.Start, positional[1].Span.End})
	}
	args := positional[2:]
	validArgs := false
	switch command {
	case "pr view":
		validArgs = len(args) == 0 || len(args) == 1 && positive(args[0].Value, 2147483647)
	case "issue view":
		validArgs = len(args) == 1 && positive(args[0].Value, 2147483647)
	case "repo view":
		validArgs = len(args) == 0 || len(args) == 1 && repository(args[0].Value)
	case "repo list":
		validArgs = len(args) == 0 || len(args) == 1 && owner(args[0].Value)
	default:
		validArgs = len(args) == 0
	}
	if !validArgs {
		span := Span{0, len(input)}
		if len(args) > 0 {
			span = Span{args[0].Span.Start, args[len(args)-1].Span.End}
		}
		return refuse("unsupported_arguments", span)
	}
	for _, o := range options {
		if !strings.Contains(permitted, " "+o.name+" ") {
			return refuse("option_not_supported_for_command", o.span)
		}
		if !shapes[o.name] && o.span.Start < positional[1].Span.Start {
			return refuse("unsupported_boolean_placement", o.span)
		}
		valid := true
		switch o.name {
		case "--repo":
			valid = repository(o.value)
		case "--json":
			valid = jsonFields(command, o.value)
		case "--limit":
			valid = positive(o.value, 1000)
		case "--state":
			valid = o.value == "open" || o.value == "closed" || o.value == "all" || command == "pr list" && o.value == "merged"
		case "--visibility":
			valid = o.value == "public" || o.value == "private" || o.value == "internal"
		case "--label":
			valid = !strings.ContainsAny(o.value, ",\"") && len(o.value) <= 256 && strings.TrimSpace(o.value) == o.value && !strings.HasPrefix(o.value, "-")
		case "--archived", "--no-archived":
			if seen["--archived"] && seen["--no-archived"] {
				return refuse("conflicting_options", o.span)
			}
		case "--fork", "--source":
			if seen["--fork"] && seen["--source"] {
				return refuse("conflicting_options", o.span)
			}
		}
		if !valid {
			return refuse("invalid_option_value", o.span)
		}
	}
	return Result{Decision: ReadOnlyCandidate, Reason: "supported_literal_read_syntax_only", Span: Span{0, len(input)}, Words: words, Command: command}
}

func positive(s string, max uint64) bool {
	if s == "" || s[0] < '1' || s[0] > '9' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n <= max
}
func alnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
func owner(s string) bool {
	if len(s) == 0 || len(s) > 39 || !alnum(s[0]) || !alnum(s[len(s)-1]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !alnum(s[i]) && s[i] != '-' {
			return false
		}
	}
	return !strings.Contains(s, "--")
}
func repository(s string) bool {
	s = strings.TrimPrefix(s, "github.com/")
	org, repo, ok := strings.Cut(s, "/")
	if !ok || !owner(org) || len(repo) == 0 || len(repo) > 100 || !alnum(repo[0]) {
		return false
	}
	for i := 0; i < len(repo); i++ {
		if !alnum(repo[i]) && !strings.ContainsRune("._-", rune(repo[i])) {
			return false
		}
	}
	return true
}
func jsonFields(command, value string) bool {
	seen := map[string]bool{}
	for _, field := range strings.Split(value, ",") {
		if field == "" || seen[field] || !knownField(command, field) {
			return false
		}
		seen[field] = true
	}
	return true
}

func knownField(command, field string) bool {
	for _, candidate := range strings.Fields(fields[command]) {
		if candidate == field {
			return true
		}
	}
	return false
}

// Field sets transcribed from gh 2.57.0 command help; see docs/command-classifier.md.
var fields = map[string]string{
	"pr view":    " additions assignees author autoMergeRequest baseRefName body changedFiles closed closedAt comments commits createdAt deletions files fullDatabaseId headRefName headRefOid headRepository headRepositoryOwner id isCrossRepository isDraft labels latestReviews maintainerCanModify mergeCommit mergeStateStatus mergeable mergedAt mergedBy milestone number potentialMergeCommit projectCards projectItems reactionGroups reviewDecision reviewRequests reviews state statusCheckRollup title updatedAt url ",
	"pr list":    " additions assignees author autoMergeRequest baseRefName body changedFiles closed closedAt comments commits createdAt deletions files fullDatabaseId headRefName headRefOid headRepository headRepositoryOwner id isCrossRepository isDraft labels latestReviews maintainerCanModify mergeCommit mergeStateStatus mergeable mergedAt mergedBy milestone number potentialMergeCommit projectCards projectItems reactionGroups reviewDecision reviewRequests reviews state statusCheckRollup title updatedAt url ",
	"issue view": " assignees author body closed closedAt comments createdAt id isPinned labels milestone number projectCards projectItems reactionGroups state stateReason title updatedAt url ",
	"issue list": " assignees author body closed closedAt comments createdAt id isPinned labels milestone number projectCards projectItems reactionGroups state stateReason title updatedAt url ",
	"repo view":  " assignableUsers codeOfConduct contactLinks createdAt defaultBranchRef deleteBranchOnMerge description diskUsage forkCount fundingLinks hasDiscussionsEnabled hasIssuesEnabled hasProjectsEnabled hasWikiEnabled homepageUrl id isArchived isBlankIssuesEnabled isEmpty isFork isInOrganization isMirror isPrivate isSecurityPolicyEnabled isTemplate isUserConfigurationRepository issueTemplates issues labels languages latestRelease licenseInfo mentionableUsers mergeCommitAllowed milestones mirrorUrl name nameWithOwner openGraphImageUrl owner parent primaryLanguage projects projectsV2 pullRequestTemplates pullRequests pushedAt rebaseMergeAllowed repositoryTopics securityPolicyUrl squashMergeAllowed sshUrl stargazerCount templateRepository updatedAt url usesCustomOpenGraphImage viewerCanAdminister viewerDefaultCommitEmail viewerDefaultMergeMethod viewerHasStarred viewerPermission viewerPossibleCommitEmails viewerSubscription visibility watchers ",
	"repo list":  " assignableUsers codeOfConduct contactLinks createdAt defaultBranchRef deleteBranchOnMerge description diskUsage forkCount fundingLinks hasDiscussionsEnabled hasIssuesEnabled hasProjectsEnabled hasWikiEnabled homepageUrl id isArchived isBlankIssuesEnabled isEmpty isFork isInOrganization isMirror isPrivate isSecurityPolicyEnabled isTemplate isUserConfigurationRepository issueTemplates issues labels languages latestRelease licenseInfo mentionableUsers mergeCommitAllowed milestones mirrorUrl name nameWithOwner openGraphImageUrl owner parent primaryLanguage projects projectsV2 pullRequestTemplates pullRequests pushedAt rebaseMergeAllowed repositoryTopics securityPolicyUrl squashMergeAllowed sshUrl stargazerCount templateRepository updatedAt url usesCustomOpenGraphImage viewerCanAdminister viewerDefaultCommitEmail viewerDefaultMergeMethod viewerHasStarred viewerPermission viewerPossibleCommitEmails viewerSubscription visibility watchers ",
}
