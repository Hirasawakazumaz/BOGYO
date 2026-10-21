-- pandoc filter for docs/publication/build.sh
--  * ```mermaid blocks -> <pre class="mermaid"> rendered in the browser by mermaid.js
--  * links to sibling 0X_*.md -> .html; repo-relative links are re-based for dist/

local function escape(s)
  return (s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"))
end

function CodeBlock(el)
  if el.classes:includes("mermaid") then
    return pandoc.RawBlock("html", '<pre class="mermaid">' .. escape(el.text) .. "</pre>")
  end
end

function Link(el)
  local t = el.target
  if t:match("^%a[%w+.-]*:") or t:match("^#") then
    return el
  end
  local path, frag = t:match("^([^#]*)(#?.*)$")
  if path:match("^0%d_[%w_-]+%.md$") then
    el.target = path:gsub("%.md$", ".html") .. frag
  elseif path == "README.md" then
    el.target = path:gsub("README%.md$", "index.html") .. frag
  elseif path ~= "" then
    el.target = "../" .. path .. frag
  end
  return el
end
