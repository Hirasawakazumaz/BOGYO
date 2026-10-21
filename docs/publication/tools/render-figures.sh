#!/usr/bin/env bash
# Render every ```mermaid block in docs/publication/0*_*.md to a static SVG in
# docs/publication/figures/<doc>-fig<NN>.svg (NN = order of appearance in that doc),
# for print/PDF submission where Mermaid is not rendered.
# Requires Node.js; uses @mermaid-js/mermaid-cli 10.9.1 via npx. Set
# PUPPETEER_EXECUTABLE_PATH to a local Chromium if puppeteer has none.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/figures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

python3 - "$here" "$work" <<'PY'
import glob, os, re, sys
here, work = sys.argv[1], sys.argv[2]
paths = [("", p) for p in glob.glob(os.path.join(here, "0*_*.md"))]
for prefix, path in sorted(paths):
    doc = prefix + os.path.basename(path)[:2]
    text = open(path, encoding="utf-8").read()
    for i, block in enumerate(re.findall(r"```mermaid\n(.*?)```", text, re.S), start=1):
        with open(os.path.join(work, f"{doc}-fig{i:02d}.mmd"), "w", encoding="utf-8") as fh:
            fh.write(block)
PY

cfg="$work/puppeteer.json"
if [ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ]; then
  printf '{"executablePath":"%s","args":["--no-sandbox"]}' "$PUPPETEER_EXECUTABLE_PATH" > "$cfg"
else
  printf '{"args":["--no-sandbox"]}' > "$cfg"
fi

for mmd in "$work"/*.mmd; do
  name="$(basename "$mmd" .mmd)"
  npx --yes @mermaid-js/mermaid-cli@10.9.1 -p "$cfg" -i "$mmd" -o "$out/$name.svg" -q
  echo "rendered figures/$name.svg"
done
