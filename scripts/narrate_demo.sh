#!/usr/bin/env bash
# Renders the demo voiceover and muxes it onto a screen recording.
#
#   scripts/narrate_demo.sh <recording.mov> [output.mov]
#
# Beat text and timecodes are parsed out of docs/demo-narration.md so the prose
# stays the single source of truth. Editing the script there changes the audio;
# there is no second copy to keep in sync.
#
# Everything used here ships with macOS. `say` renders each beat, AVFoundation
# places it at its scripted offset and attaches the result to the video.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_md="$repo_root/docs/demo-narration.md"
voice="${ENKSTEIN_NARRATION_VOICE:-Samantha}"
rate="${ENKSTEIN_NARRATION_RATE:-170}"

if [[ $# -lt 1 ]]; then
  echo "usage: $(basename "$0") <recording.mov> [output.mov]" >&2
  exit 2
fi

recording="$1"
output="${2:-${recording%.*}-narrated.mov}"

if [[ ! -f "$recording" ]]; then
  echo "error: no recording at $recording" >&2
  exit 1
fi
if [[ ! -f "$script_md" ]]; then
  echo "error: narration script missing at $script_md" >&2
  exit 1
fi
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# `say` cannot write to /dev/null, so the probe renders a real file.
if ! say -v "$voice" -o "$workdir/probe.aiff" "check" 2>/dev/null; then
  echo "error: voice '$voice' is not installed. Available US English voices:" >&2
  say -v '?' | awk '$2 == "en_US" { print "  " $1 }' >&2
  exit 1
fi

# Each beat is an `## N · Title (m:ss–m:ss)` heading followed by blockquote
# lines holding the spoken words. Screen directions are plain paragraphs and
# are deliberately excluded.
python3 - "$script_md" "$workdir/beats.tsv" <<'PY'
import re
import sys

source, destination = sys.argv[1], sys.argv[2]
heading = re.compile(r"^##\s+(\d+)\s*[·.]\s*(.+?)\s*\((\d+):(\d\d)\s*[–-]")

beats = []
current = None
for line in open(source, encoding="utf-8"):
    match = heading.match(line)
    if match:
        if current:
            beats.append(current)
        current = {
            "number": match.group(1),
            "offset": int(match.group(3)) * 60 + int(match.group(4)),
            "words": [],
        }
    elif current is not None and line.startswith(">"):
        current["words"].append(line.lstrip(">").strip())
    elif current is not None and line.startswith("---"):
        beats.append(current)
        current = None
if current:
    beats.append(current)

beats = [b for b in beats if b["words"]]
if not beats:
    sys.exit("error: no narration beats found; check the heading format")

with open(destination, "w", encoding="utf-8") as handle:
    for beat in beats:
        text = " ".join(word for word in beat["words"] if word)
        handle.write(f"{beat['number']}\t{beat['offset']}\t{text}\n")

print(f"parsed {len(beats)} beats from {source}")
PY

placement=()
while IFS=$'\t' read -r number offset text; do
  clip="$workdir/beat$number.aiff"
  say -v "$voice" -r "$rate" -o "$clip" "$text"
  placement+=("$offset" "$clip")
done < "$workdir/beats.tsv"

echo "rendering narration with $voice at ${rate}wpm"
swift "$repo_root/scripts/assemble_narration.swift" "$workdir/narration.m4a" "${placement[@]}"
swift "$repo_root/scripts/narrate_video.swift" "$recording" "$workdir/narration.m4a" "$output"
