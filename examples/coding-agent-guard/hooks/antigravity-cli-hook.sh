#!/usr/bin/env bash
# Zero-argument entry point for Antigravity CLI. The harness config file names this
# file by absolute path, so the command needs no shell syntax.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/guard-hook.sh" antigravity
