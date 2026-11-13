#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"
OUT="${2:-.reports}"

python -m secpipeline scan "$ROOT" --out "$OUT" --fail-on high
