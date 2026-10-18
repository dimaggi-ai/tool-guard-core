# Rebuild Go release artifacts

The Go release check covers `tg`, `tg-proxy`, and their archives for
Linux and macOS on amd64 and arm64, and Windows on amd64. It compares
SHA-256 digests from two clean builds of the same commit.

Use a Linux host with Bash, Git, Python 3, GNU coreutils, Go 1.26.9,
and the official GoReleaser 2.18.3 binary on `PATH`. Use the release
binary of GoReleaser, rather than compiling it with another Go version:
its compression implementation also affects archive bytes.

## Rebuild a tag

Choose a release tag that includes this procedure. Earlier releases do
not have this archive reproducibility contract. Replace `vX.Y.Z` below
with that tag.

```bash
git clone https://github.com/dimaggi-ai/tool-guard-core.git
cd tool-guard-core
git checkout --detach vX.Y.Z
bash scripts/verify-go-reproducible.sh .git/go-reproducible --release
```

The script uses committed source, rejects tracked changes, and requires
an exact tag in release mode. Each build has its own checkout, home,
GOPATH, module cache, build cache, and temporary directory. It downloads
Go 1.26.9 and dependencies as needed. Allow network access to the Go
module proxy and checksum database. No release credentials are needed.

The output directory must be empty. On success it contains both build
logs, `build1.sha256`, `build2.sha256`, source metadata, and the first
build's `dist` directory. Both manifests list every binary and archive.
A missing artifact or a differing digest fails the comparison. Build
processes have a timeout of 30 minutes each.

Download the chosen release's published `checksums.txt` separately.
Keep it outside the rebuilt `dist` directory to avoid replacing the
locally generated checksum file. Then compare the archives:

```bash
cd .git/go-reproducible/dist
sha256sum --check /absolute/path/to/published/checksums.txt
```

All archive entries must report `OK`. The local manifest comparison
alone proves agreement between local builds. Matching the published
checksums also establishes agreement with the release archives.
`checksums.txt` contains archive digests, while the two evidence manifests
also contain individual binary digests. The archive comparison covers
the binaries packaged inside them.

## Fixed inputs

`.goreleaser.yaml` fixes Go 1.26.9, disables CGO, and sets `-trimpath`,
`-buildvcs=false`, and `-mod=readonly`. It clears ambient Go flags and
experiments, disables workspace discovery, and fixes architecture levels.
Version and commit strings keep their existing meanings. `BuildDate`
uses the source commit time, not the wall-clock build time. This was
already the binary timestamp convention before the archive check.

Binary modification times and archive member times also use the commit
time. Archive ownership is root, binary permissions are executable, and
bundled documentation and policy files use mode 0644. GoReleaser fixes
entry ordering and compression behavior. Both workflows pin its version.
The verifier changes source timestamps and documentation permissions in
the second checkout to exercise metadata normalization.

Pull requests run snapshot builds. Snapshots have a different version
string and cannot be compared to tagged release checksums. The release
workflow repeats the comparison in tag mode. Before publication, the
SBOM stage checks each actual release archive against the clean-build
manifest, then runs the existing SBOM generator. A missing manifest or
mismatched archive aborts the release. Both workflows retain checksum
manifests and logs as workflow artifacts for 30 days.

## Scope and limitations

The check does not establish reproducibility of container images, SBOMs,
signatures, attestations, generated release notes, or the Python package.
Python has a separate reproducibility script. The two Go builds run on
the same Linux host with separate directories and caches. They do not
prove agreement across different host operating systems or independently
supplied toolchain binaries.

Provenance identifies where and how an artifact was built.
Reproducibility checks whether rebuilding produces the same bytes.
Neither replaces verifying the release source and toolchain you trust.

The archive settings follow the [GoReleaser archive configuration](https://goreleaser.com/customization/package/archives/).
