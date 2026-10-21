#!/usr/bin/env bash
# Build standalone HTML for the publication documents into docs/publication/dist/.
# Requires pandoc. Mermaid diagrams render in the browser (mermaid.js from jsDelivr);
# use the browser's "Print -> Save as PDF" for a PDF.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/dist"
mkdir -p "$out"

header="$(mktemp)"
trap 'rm -f "$header"' EXIT
cat > "$header" <<'HTML'
<style>
  body { max-width: 60em; font-family: system-ui, "Segoe UI", Roboto, sans-serif; line-height: 1.7; }
  table { border-collapse: collapse; } th, td { border: 1px solid #999; padding: .3em .6em; }
  pre.mermaid { background: none; text-align: center; }
  blockquote { border-left: 4px solid #c33; margin-left: 0; padding-left: 1em; color: #333; }
  @media print { pre.mermaid { page-break-inside: avoid; } }
</style>
<script type="module">
  import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.esm.min.mjs";
  mermaid.initialize({ startOnLoad: true, securityLevel: "strict" });
</script>
HTML

build() {  # build <source dir> <output dir> <lang>
  mkdir -p "$2"
  for md in "$1"/0*_*.md "$1"/README.md; do
    name="$(basename "$md" .md)"
    [ "$name" = "README" ] && name="index"
    title="$(grep -m1 '^# ' "$md" | sed 's/^# //')"
    pandoc "$md" --from gfm --to html5 --standalone --toc --toc-depth=2 \
      --metadata pagetitle="$title" --metadata lang="$3" --quiet \
      --lua-filter "$here/tools/mermaid-links.lua" \
      --include-in-header "$header" \
      --output "$2/$name.html"
    echo "built ${2#"$here"/}/$name.html"
  done
}

build "$here" "$out" en
