#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:?usage: verify-go-reproducible.sh OUTPUT_DIR [--release]}"
mode="${2:---snapshot}"
case "$mode" in
  --snapshot) mode_args=(--snapshot) ;;
  --release) mode_args=() ;;
  *) echo "expected --snapshot or --release" >&2; exit 1 ;;
esac
repo_root="$(git rev-parse --show-toplevel)"
commit="$(git rev-parse HEAD)"
epoch="$(git show -s --format=%ct HEAD)"
if ! git diff --quiet HEAD --; then
  echo "commit tracked changes before verifying a clean rebuild" >&2
  exit 1
fi
if [[ "$mode" == --release ]]; then
  git describe --tags --exact-match HEAD
fi
goreleaser_bin="$(command -v goreleaser)"
goreleaser_bin="$(realpath "$goreleaser_bin")"
if ! "$goreleaser_bin" --version | grep -Eq '^GitVersion: +v?2\.18\.3$'; then
  echo "GoReleaser 2.18.3 official binary is required" >&2
  exit 1
fi
mkdir -p "$output_dir"
output_dir="$(realpath "$output_dir")"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "output directory is not empty: $output_dir" >&2
  exit 1
fi
probe_dir="$(mktemp -d)"
trap 'chmod -R u+w "$probe_dir"; rm -rf "$probe_dir"' EXIT
for run in 1 2; do
  source_dir="$probe_dir/source$run"
  git -c core.autocrlf=false clone --quiet --no-local "$repo_root" "$source_dir"
  git -C "$source_dir" -c core.autocrlf=false checkout --quiet --detach "$commit"
  mkdir -p "$probe_dir/home$run" "$probe_dir/gopath$run" "$probe_dir/cache$run" "$probe_dir/tmp$run"
  echo "Building clean environment $run at $commit"
  (
    cd "$source_dir"
    # Different checkout times and permissions exercise archive normalization.
    if [[ "$run" == 2 ]]; then
      git ls-files -z | xargs -0 touch -d "@$((epoch + 12345))"
      chmod -R go-rwx docs policies
    fi
    env -i PATH="$PATH" HOME="$probe_dir/home$run" \
      TMPDIR="$probe_dir/tmp$run" GOPATH="$probe_dir/gopath$run" \
      GOMODCACHE="$probe_dir/gopath$run/pkg/mod" GOCACHE="$probe_dir/cache$run" \
      GOTOOLCHAIN=go1.26.9 GOENV=off GOWORK=off \
      SOURCE_DATE_EPOCH="$epoch" TZ=UTC LC_ALL=C \
      "$goreleaser_bin" release --clean --timeout=30m --parallelism=2 \
      --skip=publish,announce,docker,sbom,sign "${mode_args[@]}" \
      --release-notes /dev/null
  ) 2>&1 | tee "$output_dir/build$run.log"
  python3 "$repo_root/scripts/go-reproducible-manifest.py" "$source_dir/dist" \
    > "$output_dir/build$run.sha256"
done
diff -u "$output_dir/build1.sha256" "$output_dir/build2.sha256"
cp -a "$probe_dir/source1/dist" "$output_dir/dist"
printf 'commit=%s\nsource_date_epoch=%s\nmode=%s\n' "$commit" "$epoch" "$mode" > "$output_dir/source.txt"
cat "$output_dir/build1.sha256"
echo "OK: all Go binaries and archives are byte-identical across two clean builds"
