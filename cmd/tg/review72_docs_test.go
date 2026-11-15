package main

import "testing"

func TestSecretEgressOperatorGuidesDiscloseShellCommentCarveOut(t *testing.T) {
	for _, parts := range [][]string{{"examples", "coding-agent-guard", "README.md"}, {"docs", "operating.md"}} {
		requireSentences(t, readRepoFile(t, parts...),
			"In a shell command, a listed URL anywhere in the text satisfies the host carve-out, even inside a comment.",
			"A command can therefore send a known key to an unlisted host while naming a listed host in a comment.")
	}
}
