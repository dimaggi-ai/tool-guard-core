package sqlguard

import (
	"fmt"
	"sync"
)

// Classifier parses a SQL string into a dialect-neutral Classification.
// Implementations live in dialect subpackages and call Register at init
// time so the engine can look them up by name.
type Classifier interface {
	Classify(sql string) (Classification, error)
	Dialect() string
}

var (
	regMu       sync.RWMutex
	classifiers = map[string]Classifier{}
)

// Register installs a Classifier for a dialect. Safe to call from init().
// A second Register for the same dialect replaces the first; this lets
// tests inject fakes.
func Register(c Classifier) {
	regMu.Lock()
	defer regMu.Unlock()
	classifiers[c.Dialect()] = c
}

// Get returns the Classifier for a dialect, or (nil, false) if no parser
// is linked for it.
func Get(dialect string) (Classifier, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	c, ok := classifiers[dialect]
	return c, ok
}

// Dialects returns the sorted list of registered dialect names. Used by
// the proxy's /policies endpoint and by the lint pass.
func Dialects() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(classifiers))
	for d := range classifiers {
		out = append(out, d)
	}
	return out
}

// Classify is a package-level convenience: looks up the dialect and
// returns ErrUnsupportedDialect when no parser is linked.
func Classify(dialect, sql string) (Classification, error) {
	c, ok := Get(dialect)
	if !ok {
		return Classification{}, fmt.Errorf("%w: %q (linked: %v)", ErrUnsupportedDialect, dialect, Dialects())
	}
	return c.Classify(sql)
}

// ErrUnsupportedDialect is returned by Classify when the requested
// dialect has no registered parser. The engine must treat this as
// fail-closed: a rule that requires SQL classification cannot make a
// safe decision without one.
var ErrUnsupportedDialect = fmt.Errorf("sqlguard: no parser registered for dialect")
