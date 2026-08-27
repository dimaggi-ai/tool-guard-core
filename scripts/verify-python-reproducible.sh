#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:?usage: verify-python-reproducible.sh OUTPUT_DIR}"
repo_root="$(git rev-parse --show-toplevel)"
python_bin="${PYTHON_BIN:-python}"
commit="$(git -C "$repo_root" rev-parse HEAD)"
epoch="$(git -C "$repo_root" show -s --format=%ct "$commit")"
probe_dir="$(mktemp -d)"
trap 'rm -rf "$probe_dir"' EXIT

mkdir -p "$output_dir"
if find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "output directory is not empty: $output_dir" >&2
  exit 1
fi

for run in 1 2; do
  git clone --quiet --no-local "$repo_root" "$probe_dir/source$run"
  git -C "$probe_dir/source$run" checkout --quiet --detach "$commit"
  mkdir "$probe_dir/dist$run"
  SOURCE_DATE_EPOCH="$epoch" "$python_bin" -m build \
    --outdir "$probe_dir/dist$run" "$probe_dir/source$run/sdk/python"
  "$python_bin" "$repo_root/scripts/normalize_python_dist.py" \
    "$probe_dir/dist$run" --epoch "$epoch"
done

mapfile -t expected < <(find "$probe_dir/dist1" -maxdepth 1 -type f -printf '%f\n' | sort)
mapfile -t rebuilt < <(find "$probe_dir/dist2" -maxdepth 1 -type f -printf '%f\n' | sort)
if [[ "${expected[*]}" != "${rebuilt[*]}" ]]; then
  echo "distribution filenames differ across clean builds" >&2
  printf 'first:  %s\n' "${expected[*]}" >&2
  printf 'second: %s\n' "${rebuilt[*]}" >&2
  exit 1
fi
for filename in "${expected[@]}"; do
  cmp "$probe_dir/dist1/$filename" "$probe_dir/dist2/$filename"
  install -m 0644 "$probe_dir/dist1/$filename" "$output_dir/$filename"
  sha256sum "$output_dir/$filename"
done
echo "OK: Python distributions are byte-identical across a clean rebuild"
