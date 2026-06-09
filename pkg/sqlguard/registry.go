package sqlguard

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Registry classifies function names (and optionally table names) into
// operator-defined risk classes. A policy then matches on class rather
// than on every individual name, which closes the "custom UDF" gap:
// operators add their `cleanup_users()` stored procedure to the
// destructive class instead of every policy author chasing the name
// downstream.
//
// The registry is process-global with a write-once-at-load semantic
// (concurrent reads, infrequent reload via SIGHUP). Empty registry =
// no class lookups available; rules that reference classes deny
// fail-closed when the registry is unset.
type Registry struct {
	// FunctionClass maps a class name to the set of function names
	// that belong to it. Lowercased on load.
	FunctionClass map[string]map[string]struct{}

	// FunctionsInClass returns the class names for a given function
	// (one function may belong to multiple classes).
	functionClasses map[string][]string
}

var (
	regMuFn sync.RWMutex
	regFn   *Registry
)

// SetRegistry installs a function classification registry. Calling
// with nil clears it.
func SetRegistry(r *Registry) {
	regMuFn.Lock()
	regFn = r
	regMuFn.Unlock()
}

// CurrentRegistry returns the active registry or nil.
func CurrentRegistry() *Registry {
	regMuFn.RLock()
	defer regMuFn.RUnlock()
	return regFn
}

// ClassesOf returns the classes a given function name belongs to.
// Match is case-insensitive on the function name.
func (r *Registry) ClassesOf(fn string) []string {
	if r == nil {
		return nil
	}
	return r.functionClasses[strings.ToLower(fn)]
}

// rawRegistry is the on-disk YAML shape.
type rawRegistry struct {
	Functions map[string][]string `yaml:"functions"`
}

// LoadRegistryFile parses a tools.yaml file into a Registry.
func LoadRegistryFile(path string) (*Registry, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseRegistry(body)
}

// ParseRegistry parses YAML bytes into a Registry.
func ParseRegistry(body []byte) (*Registry, error) {
	var raw rawRegistry
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse tools.yaml: %w", err)
	}
	r := &Registry{
		FunctionClass:   make(map[string]map[string]struct{}, len(raw.Functions)),
		functionClasses: make(map[string][]string),
	}
	for class, fns := range raw.Functions {
		class = strings.ToLower(class)
		bag := make(map[string]struct{}, len(fns))
		for _, fn := range fns {
			fn = strings.ToLower(strings.TrimSpace(fn))
			if fn == "" {
				continue
			}
			bag[fn] = struct{}{}
			r.functionClasses[fn] = append(r.functionClasses[fn], class)
		}
		r.FunctionClass[class] = bag
	}
	return r, nil
}

// FunctionInClass reports whether fn is in the given class. Used by
// the engine in the AllowedFunctionClasses / DeniedFunctionClasses
// predicates.
func (r *Registry) FunctionInClass(fn, class string) bool {
	if r == nil {
		return false
	}
	bag := r.FunctionClass[strings.ToLower(class)]
	if bag == nil {
		return false
	}
	_, ok := bag[strings.ToLower(fn)]
	return ok
}
