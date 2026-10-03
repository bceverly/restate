#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Write a flat status badge as a self-contained SVG.
#
#   scripts/badge.sh LABEL VALUE COLOR OUTPUT.svg
#   scripts/badge.sh coverage 87% green docs/badges/coverage.svg
#
# COLOR is one of the names below, or a #rrggbb literal.
#
# The badges are generated here and committed rather than fetched from
# shields.io, for two reasons: the README then renders correctly with no
# network round trip — including in a source package, where there is none —
# and reading the page does not report a visit to a third party on the
# repository owner's behalf.
#
# Written in shell rather than Python so that regenerating a badge needs
# nothing this project does not already require to build.
set -euo pipefail

LABEL="${1:?usage: badge.sh LABEL VALUE COLOR OUTPUT.svg}"
VALUE="${2:?usage: badge.sh LABEL VALUE COLOR OUTPUT.svg}"
COLOR="${3:?usage: badge.sh LABEL VALUE COLOR OUTPUT.svg}"
OUTPUT="${4:?usage: badge.sh LABEL VALUE COLOR OUTPUT.svg}"

case "$COLOR" in
  green)       FILL="#1e7a46" ;;
  brightgreen) FILL="#3fb950" ;;
  amber)       FILL="#c08a00" ;;
  red)         FILL="#c9302c" ;;
  blue)        FILL="#0a2240" ;;
  navy)        FILL="#1b4b8f" ;;
  gray|grey)   FILL="#7c8697" ;;   # both accepted as input; spelling: ok
  \#*)         FILL="$COLOR" ;;
  *)           echo "badge.sh: unknown color '$COLOR'" >&2; exit 2 ;;
esac

# Verdana at 11px is close enough to 6.6px per character for a badge, with a
# little more for the wider digits. Exactness does not matter: the two halves
# only have to look balanced, and being a few pixels generous never clips.
width_of() {
  local text="$1"
  local chars=${#text}
  echo $(( chars * 7 + 12 ))
}

LABEL_W=$(width_of "$LABEL")
VALUE_W=$(width_of "$VALUE")
TOTAL_W=$(( LABEL_W + VALUE_W ))
LABEL_MID=$(( LABEL_W * 10 / 2 ))
VALUE_MID=$(( LABEL_W * 10 + VALUE_W * 10 / 2 ))
LABEL_LEN=$(( (LABEL_W - 12) * 10 ))
VALUE_LEN=$(( (VALUE_W - 12) * 10 ))

mkdir -p "$(dirname "$OUTPUT")"

# `shape-rendering="crispEdges"` on the rects and a gradient overlay for the
# usual slight sheen. The accessible name is what a screen reader announces
# instead of "image".
cat > "$OUTPUT" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="$TOTAL_W" height="20" role="img" aria-label="$LABEL: $VALUE">
  <title>$LABEL: $VALUE</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="$TOTAL_W" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="$LABEL_W" height="20" fill="#555"/>
    <rect x="$LABEL_W" width="$VALUE_W" height="20" fill="$FILL"/>
    <rect width="$TOTAL_W" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text aria-hidden="true" x="$LABEL_MID" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="$LABEL_LEN">$LABEL</text>
    <text x="$LABEL_MID" y="140" transform="scale(.1)" textLength="$LABEL_LEN">$LABEL</text>
    <text aria-hidden="true" x="$VALUE_MID" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="$VALUE_LEN">$VALUE</text>
    <text x="$VALUE_MID" y="140" transform="scale(.1)" textLength="$VALUE_LEN">$VALUE</text>
  </g>
</svg>
SVG
