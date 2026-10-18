# Pruning a closed audit log

`tg prune` replaces an old prefix with a checkpoint in a new file. It never
modifies the input. Preview the operation first:

```bash
tg prune --older-than 720h -file closed.jsonl -out retained.jsonl -closed
```

Add `--yes` to write, then verify the published file:

```bash
tg prune --older-than 720h -file closed.jsonl -out retained.jsonl -closed --yes
tg verify -file retained.jsonl -allow-pruned
```

`--older-than` uses positive Go durations, such as `24h` or `90m`. Calendar
units such as days and months are not supported. The cutoff is the command's
start time minus that duration, expressed in UTC. Only timestamps strictly
before the cutoff are eligible. A timestamp equal to the cutoff is retained.

## Closed input requirement

Stop every writer before using this command. `-closed` asserts that the input
is a standalone immutable file and will remain so until pruning finishes.
The command does not inspect running processes or acquire a writer lock.
The proxy has rotation support but no persisted closed-log marker. Rotated
files may also be reopened during error recovery. A filename alone does not
prove that a log is closed.

Prune rejects symlinks, non-regular input files, and numbered rotation siblings.
For a rotated log, stop the writer and assemble the complete rotation set into
a separate standalone file in chain order: numbered siblings in ascending
order, then the active file. Preserve record delimiters. Verify that file
before pruning. A detached rotation member will fail verification unless it
starts at genesis or has a valid checkpoint.

The command verifies the input before selecting records. It checks file
identity, size, modification time, and a full content digest for changes during
the operation. These checks detect observed changes; they cannot enforce the
operator's assertion or prevent a hostile writer from racing the final check.
Use a directory controlled by the operator for both input and output.

## Prefix selection and publication

Removal stops at the first record whose timestamp is not older than the
cutoff. Later records remain even if their timestamps are older. Records are
never reordered. A missing timestamp is rejected. An empty input or an input
with no eligible prefix produces no output file.

The output begins with a checkpoint, followed by every retained record with
its original bytes, delimiters, and hash. The checkpoint has
`record_type: "prune_checkpoint"` and `version: 1`. Its fields record:

- Cumulative removed count and the last removed record's one-based index.
- Last removed hash, timestamp, and canonical hash version.
- Cutoff, retained record count, and retained tail hash.
- A SHA-256 checksum over the checkpoint fields with `checkpoint_hash` empty.

Pruning an already pruned file replaces its checkpoint and adds the newly
removed prefix to the cumulative count. There is only one checkpoint. If all
remaining records are removed, the output contains only a checkpoint whose
tail equals the last removed hash.

Writing uses a private temporary file in the output directory, syncs it,
verifies it with the opt-in verifier used by `tg verify -allow-pruned`, and
publishes it with an atomic rename that refuses replacement. The output directory is then
synced. Existing output paths, including symlinks, are rejected. Output paths
with numbered rotation siblings are rejected too, as are outputs that would
become rotation siblings of the input.

Publication currently requires Linux and filesystem support for
`renameat2(RENAME_NOREPLACE)`. Other platforms can run the preview but cannot
publish. A directory-sync error after rename reports that the output exists
but its crash durability is uncertain. Inspect and verify that output before
retrying. An interrupted process can leave a private `.tg-prune-*` temporary
file in the output directory; treat it as retained audit data until removed.

## What verification proves

`tg verify` and `tg export` reject pruned chains by default. Use
`-allow-pruned` to accept an unsigned, unpinned checkpoint and verify internal
consistency only. Alternatively, `-checkpoint-hash sha256:<64 lowercase hex>`
requires a checkpoint with that exact hash and implies `-allow-pruned`.
Obtain the pin from a trusted copy stored elsewhere. A trusted external pin
establishes checkpoint identity, not the content of deleted records.

Both commands exit 0 on success and 2 for malformed or explicitly empty pins.
Without opt-in, or with a missing checkpoint or pin mismatch, `tg verify`
prints a JSON failure report and exits 5; `tg export` exits 1 without writing
exported records. Other integrity failures also exit 5 for verify and 1 for
export. Operational failures exit 1 for both commands.

Verification recomputes every retained trace hash and checks each chain link,
starting from the last removed hash in the checkpoint. It checks the checkpoint
checksum, version, boundary constraints, retained count, and retained tail.
It rejects a checkpoint in the middle, multiple checkpoints, a mismatched
anchor, and changed, reordered, missing, or partially truncated retained
records when the checkpoint is unchanged. It also detects removal of complete
records from the retained tail. The report's `records` count excludes the
checkpoint, and `pruned: true` identifies checkpoint-based verification. Original logs without checkpoints retain their existing checks.

The checkpoint is unsigned. Its checksum is not proof of authorship. An
attacker who can rewrite the file can recompute the checkpoint and the chain.
A self-consistent forged checkpoint cannot be distinguished from an authentic
one using this file alone. Verification does not prove deleted content,
removed counts or timestamps as historical facts, or completeness without
independent custody. Preserve a trusted copy of the checkpoint or its hash and
the original chain commitments outside the log if those claims matter.

Pruning does not erase personal data from the source, backups, snapshots,
exports, or temporary files. Deleting originals and backups is a separate
retention operation. Do not use a pruned output as a live proxy audit file:
its checkpoint commits to a fixed suffix. Proxy and hook writers refuse to
resume a pruned chain.

The HTTP OpenAPI contract and Python client do not read audit JSONL files.
Their receipt fields and HTTP response formats are unchanged. `tg export`
requires opt-in to verify a pruned source and omits its checkpoint. The exported
decision traces are not independently verifiable as a complete chain.
