package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func cmdPrune(args []string) int { return runPrune(args, os.Stdout, os.Stderr, time.Now()) }

func runPrune(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("file", "", "closed standalone audit file")
	out := fs.String("out", "", "new output path (must not exist)")
	age := fs.Duration("older-than", 0, "positive retention duration, such as 720h")
	closed := fs.Bool("closed", false, "assert all writers are stopped and the input remains immutable")
	yes := fs.Bool("yes", false, "write the verified output; default is dry-run")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || *out == "" || *age <= 0 || !*closed || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "prune: require -file, -out, positive -older-than and -closed; stop all writers first")
		return 2
	}
	if err := pruneFile(*in, *out, now.Add(-*age).UTC(), *yes, stdout); err != nil {
		fmt.Fprintln(stderr, "prune:", err)
		return 1
	}
	return 0
}

func standalonePrunePath(path string) error {
	paths, err := audit.RotationSetOldestFirst(path)
	if err != nil {
		return err
	}
	if len(paths) != 1 || paths[0] != path {
		return fmt.Errorf("%q has rotation siblings; use a closed standalone chain", path)
	}
	return nil
}

func pruneFile(in, out string, cutoff time.Time, write bool, stdout io.Writer) error {
	if err := rejectPruneRotationSibling(in, out); err != nil {
		return err
	}
	if err := standalonePrunePath(in); err != nil {
		return err
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return fmt.Errorf("output already exists: %s", out)
	}
	// Siblings would make tg verify read more than the published output.
	if paths, err := audit.RotationSetOldestFirst(out); err == nil && len(paths) != 0 {
		return fmt.Errorf("output has rotation siblings")
	}
	st, err := os.Lstat(in)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("input must be a regular file, not a symlink or device")
	}
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(st, opened) {
		return fmt.Errorf("input changed while opening")
	}
	digest := sha256.New()
	report, err := audit.VerifyPrunedChainFromReader(io.TeeReader(io.NewSectionReader(f, 0, st.Size()), digest), "")
	if err != nil {
		return err
	}
	if !report.Intact {
		return fmt.Errorf("input verification failed at line %d: %s", report.FirstFailureAt, report.FailureReason)
	}
	originalDigest := digest.Sum(nil)
	digest.Reset()
	sc := bufio.NewScanner(io.TeeReader(io.NewSectionReader(f, 0, st.Size()), digest))
	sc.Buffer(make([]byte, 0, 1<<20), audit.MaxTraceRecordScanBytes+1)
	sc.Split(pruneRawLines)
	cp := audit.PruneCheckpoint{RecordType: "prune_checkpoint", Version: 1, Cutoff: cutoff, RetainedTailHash: report.Tail}
	var offset, retainOffset, removed int64
	retaining := false
	for sc.Scan() {
		raw := sc.Bytes()
		offset += int64(len(raw))
		if len(bytes.TrimRight(raw, "\r\n")) == 0 {
			continue
		}
		isCheckpoint, err := audit.IsPruneCheckpoint(raw)
		if err != nil {
			return err
		}
		if isCheckpoint {
			prior, err := audit.ParsePruneCheckpoint(raw)
			if err != nil {
				return err
			}
			cp.RemovedCount = prior.RemovedCount
			continue
		}
		var trace domain.DecisionTrace
		if err := json.Unmarshal(raw, &trace); err != nil {
			return err
		}
		if trace.Timestamp.IsZero() {
			return fmt.Errorf("record has no timestamp")
		}
		eligible := trace.Timestamp.Before(cutoff)
		if !retaining && eligible {
			if cp.RemovedCount == math.MaxInt64 {
				return fmt.Errorf("removed count overflow")
			}
			removed++
			cp.RemovedCount++
			cp.LastRemovedHash = trace.TraceHash
			cp.LastRemovedTimestamp = trace.Timestamp
			cp.BoundaryCanonicalVersion = trace.CanonicalVersion
			if cp.BoundaryCanonicalVersion == "" {
				cp.BoundaryCanonicalVersion = "v1"
			}
		} else {
			if !retaining {
				retainOffset = offset - int64(len(raw))
				retaining = true
			}
			cp.RetainedCount++
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !bytes.Equal(originalDigest, digest.Sum(nil)) {
		return fmt.Errorf("input changed during selection")
	}
	if err := pruneInputStable(f, in, st, originalDigest); err != nil {
		return err
	}
	if removed == 0 {
		_, err := fmt.Fprintln(stdout, "No eligible prefix; no output written.")
		return err
	}
	if !retaining {
		retainOffset = offset
	}
	cp.LastRemovedIndex = cp.RemovedCount
	cp.CheckpointHash = cp.Hash()
	if !write {
		_, err := fmt.Fprintf(stdout, "Dry-run: remove %d records; retain %d; cutoff %s; use -yes to write.\n", removed, cp.RetainedCount, cutoff.Format(time.RFC3339Nano))
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(out), ".tg-prune-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if err := json.NewEncoder(temp).Encode(cp); err != nil {
		return err
	}
	if _, err := io.Copy(temp, io.NewSectionReader(f, retainOffset, st.Size()-retainOffset)); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if _, err := temp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	verified, err := audit.VerifyPrunedChainFromReader(temp, "")
	if err != nil {
		return err
	}
	if !verified.Intact {
		return fmt.Errorf("output verification failed: %s", verified.FailureReason)
	}
	if err := pruneInputStable(f, in, st, originalDigest); err != nil {
		return err
	}
	if err := standalonePrunePath(in); err != nil {
		return err
	}
	if paths, err := audit.RotationSetOldestFirst(out); err == nil && len(paths) != 0 {
		return fmt.Errorf("output or rotation siblings appeared")
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := rejectPruneRotationSibling(in, out); err != nil {
		return err
	}
	if err := publishPrunedFile(temp.Name(), out); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Removed %d records from output; retained %d; wrote %s. Input unchanged.\n", removed, cp.RetainedCount, out)
	return err
}

func pruneInputStable(f *os.File, path string, before os.FileInfo, expected []byte) error {
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("input changed; prune requires a closed immutable file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, before.Size()+1)); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), expected) {
		return fmt.Errorf("input contents changed")
	}
	return nil
}

// Keep delimiters so the retained suffix is copied without reserialization.
func pruneRawLines(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i+1], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// rejectPruneRotationSibling uses the same numeric suffix rule as rotation discovery.
func rejectPruneRotationSibling(in, out string) error {
	prefix := filepath.Base(in) + "."
	if !strings.HasPrefix(filepath.Base(out), prefix) {
		return nil
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(out), prefix)); err != nil {
		return nil
	}
	inDir, err := filepath.Abs(filepath.Dir(in))
	if err != nil {
		return err
	}
	outDir, err := filepath.Abs(filepath.Dir(out))
	if err != nil {
		return err
	}
	inInfo, err := os.Stat(inDir)
	if err != nil {
		return err
	}
	same := inDir == outDir
	if outInfo, err := os.Stat(outDir); err == nil {
		same = os.SameFile(inInfo, outInfo)
	}
	if same {
		return fmt.Errorf("output would become a rotation sibling of the input")
	}
	return nil
}
