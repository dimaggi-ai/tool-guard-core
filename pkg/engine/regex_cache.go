package engine

import (
	"regexp"
	"sync"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// regexCache holds compiled patterns keyed by their source string.
// ValidatePolicy pre-warms it at load (where compile errors become
// load errors instead of silent runtime allows). compareRegex looks
// up by string; cache miss falls back to Compile + store so a
// dynamically-built value still works.
//
// sync.Map fits because we have heavy read traffic and rare writes
// (one per distinct pattern over the proxy's lifetime). The cap is a
// hostile-input bound: patterns come from policies (not envelopes)
// but a misconfigured policy bundle with thousands of unique regex
// rules would otherwise pin memory. At the cap, new patterns
// compile-and-return without entering the cache — correctness
// preserved, performance degraded.
var regexCache sync.Map // map[string]*regexp.Regexp

// regexCacheMaxEntries bounds the cache size. 10k distinct patterns
// is comfortably above the largest realistic policy bundle. The cap
// is enforced loosely (post-insert; sync.Map doesn't expose a
// transactional size + insert).
const regexCacheMaxEntries = 10_000

func compiledRegex(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Bound the cache: if we're already at the cap, skip the store so
	// the cache stops growing. The pattern is still compiled and
	// returned, just not memoised — subsequent uses will recompile.
	if regexCacheStats() >= regexCacheMaxEntries {
		return re, nil
	}
	actual, _ := regexCache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), nil
}

// PrewarmRegexCache walks a slice of policies and Compile()s every
// regex it can find: leaf regex operators, shell_classify deny patterns,
// sql_classify policies don't have raw regex (the parser handles SQL),
// path_classify glob prefixes are not Go regex.
//
// Called by the proxy after ValidatePolicy succeeds so the hot path
// is always a sync.Map.Load.
func PrewarmRegexCache(policies []domain.Policy) {
	for i := range policies {
		for j := range policies[i].Rules {
			prewarmCondition(&policies[i].Rules[j].Conditions)
		}
	}
}

func prewarmCondition(c *domain.Condition) {
	for i := range c.And {
		prewarmCondition(&c.And[i])
	}
	for i := range c.Or {
		prewarmCondition(&c.Or[i])
	}
	if c.Not != nil {
		prewarmCondition(c.Not)
	}
	if c.Field != "" && c.Operator == domain.OpRegex {
		if s, ok := c.Value.(string); ok {
			_, _ = compiledRegex(s)
		}
	}
	if c.ShellClassify != nil {
		for _, pat := range c.ShellClassify.Require.ArgvDenyPatterns {
			_, _ = compiledRegex(pat)
		}
	}
}

// regexCacheStats reports the current cache size. Useful for /metrics.
func regexCacheStats() int {
	n := 0
	regexCache.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// CachedRegexCount returns the number of compiled regex patterns
// currently in the global cache. Exposed for /metrics.
func CachedRegexCount() int { return regexCacheStats() }
