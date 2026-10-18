package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PruneCheckpoint describes a removed prefix and commits to the retained suffix.
// Its checksum detects corruption, not a rewrite by someone who controls the file.
type PruneCheckpoint struct {
	RecordType               string    `json:"record_type"`
	Version                  int       `json:"version"`
	RemovedCount             int64     `json:"removed_count"`
	LastRemovedIndex         int64     `json:"last_removed_index"`
	LastRemovedHash          string    `json:"last_removed_hash"`
	LastRemovedTimestamp     time.Time `json:"last_removed_timestamp"`
	BoundaryCanonicalVersion string    `json:"boundary_canonical_version"`
	Cutoff                   time.Time `json:"cutoff"`
	RetainedCount            int64     `json:"retained_count"`
	RetainedTailHash         string    `json:"retained_tail_hash"`
	CheckpointHash           string    `json:"checkpoint_hash"`
}

// Hash returns the SHA-256 checksum of the versioned checkpoint fields.
func (c PruneCheckpoint) Hash() string {
	c.CheckpointHash = ""
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validCheckpointHash(s string) bool {
	if !strings.HasPrefix(s, "sha256:") {
		return false
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	return err == nil && len(b) == sha256.Size && s == "sha256:"+hex.EncodeToString(b)
}

// ParsePruneCheckpoint validates the checkpoint format and internal constraints.
func ParsePruneCheckpoint(raw []byte) (*PruneCheckpoint, error) {
	var c PruneCheckpoint
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, err
	}
	if c.RecordType != "prune_checkpoint" || c.Version != 1 {
		return nil, fmt.Errorf("unsupported checkpoint type or version")
	}
	if c.RemovedCount <= 0 || c.LastRemovedIndex != c.RemovedCount || c.RetainedCount < 0 {
		return nil, fmt.Errorf("invalid checkpoint counts or boundary index")
	}
	if c.LastRemovedTimestamp.IsZero() || c.Cutoff.IsZero() || !c.LastRemovedTimestamp.Before(c.Cutoff) {
		return nil, fmt.Errorf("invalid checkpoint timestamp boundary")
	}
	if _, known := canonicalTraceVersionRank(c.BoundaryCanonicalVersion); !known {
		return nil, fmt.Errorf("invalid checkpoint canonical version")
	}
	if !validCheckpointHash(c.LastRemovedHash) || !validCheckpointHash(c.RetainedTailHash) || c.CheckpointHash != c.Hash() {
		return nil, fmt.Errorf("invalid checkpoint hash")
	}
	if c.RetainedCount == 0 && c.RetainedTailHash != c.LastRemovedHash {
		return nil, fmt.Errorf("empty checkpoint suffix has inconsistent tail")
	}
	return &c, nil
}

// IsPruneCheckpoint recognizes the reserved record type. Other extension fields
// keep the same ignored-field behavior as historical decision traces.
func IsPruneCheckpoint(raw []byte) (bool, error) {
	var kind struct {
		RecordType json.RawMessage `json:"record_type"`
	}
	if err := json.Unmarshal(raw, &kind); err != nil {
		return false, err
	}
	var value string
	_ = json.Unmarshal(kind.RecordType, &value)
	return value == "prune_checkpoint", nil
}
