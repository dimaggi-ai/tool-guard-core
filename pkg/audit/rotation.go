package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// RotationSetOldestFirst lists the size-rotation set for activePath in
// chain order — oldest rotated sibling first, active file last — so a
// caller can concatenate them and replay the hash chain from the
// beginning. Rotated siblings are named "<activePath>.<N>" with
// ascending N as rotation continues, so sorting by N ascending is
// creation order; the active file (the freshest hashes) always comes
// last regardless of its own name.
//
// Shared by `tg verify` and tg-proxy's startup chain-integrity check so
// both walk the exact same file set in the exact same order — two
// independently-maintained copies of this listing logic drifting apart
// would be its own integrity bug.
//
// Returns an error if activePath itself doesn't exist AND no rotated
// siblings exist either (nothing to verify is a caller decision, not
// this function's).
func RotationSetOldestFirst(activePath string) ([]string, error) {
	dir, base := filepath.Split(activePath)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	type rotated struct {
		idx  int
		path string
	}
	var rots []rotated
	prefix := base + "."
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		idx, err := strconv.Atoi(name[len(prefix):])
		if err != nil {
			continue
		}
		rots = append(rots, rotated{idx: idx, path: filepath.Join(dir, name)})
	}
	sort.Slice(rots, func(i, j int) bool { return rots[i].idx < rots[j].idx })

	out := make([]string, 0, len(rots)+1)
	for _, r := range rots {
		out = append(out, r.path)
	}
	if _, err := os.Stat(activePath); err == nil {
		out = append(out, activePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no audit log files found (active %q absent, no rotation siblings)", activePath)
	}
	return out, nil
}
