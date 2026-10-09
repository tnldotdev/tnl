# read GitHub release metadata without requiring a JSON tool on the host.
# only root release objects contribute tags; nested data and strings are skipped.
function invalid() { failed = 1; exit 2 }
function space() { while (substr(input, pos, 1) ~ /^[ \t\r\n]$/) pos++ }
function string(    result, c, escape, i) {
  if (substr(input, pos++, 1) != "\"") invalid()
  result = ""
  while (pos <= length(input)) {
    c = substr(input, pos++, 1)
    if (c == "\"") return result
    if (c ~ /[[:cntrl:]]/) invalid()
    if (c == "\\") {
      escape = substr(input, pos++, 1)
      if (escape == "u") {
        for (i = 0; i < 4; i++) if (substr(input, pos + i, 1) !~ /^[0-9a-fA-F]$/) invalid()
        result = result "\\u" substr(input, pos, 4)
        pos += 4
      } else {
        if (escape !~ /^["\\\/bfnrt]$/) invalid()
        result = result "\\" escape
      }
    } else result = result c
  }
  invalid()
}
function value(depth, release,    c, token) {
  if (depth > 64) invalid()
  space()
  c = substr(input, pos, 1)
  if (c == "{") { object(depth + 1, release); return "object" }
  if (c == "[") { array(depth + 1); return "array" }
  if (c == "\"") { atom = string(); return "string" }
  token = substr(input, pos)
  if (match(token, /^(true|false|null)/)) {
    atom = substr(token, 1, RLENGTH)
    pos += RLENGTH
    return atom
  }
  if (match(token, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) {
    pos += RLENGTH
    return "number"
  }
  invalid()
}
function object(depth, release,    key, type, tag, draft, prerelease, published, seen_tag, seen_draft, seen_prerelease, seen_published, c) {
  pos++
  space()
  if (substr(input, pos, 1) == "}") { pos++; return }
  while (1) {
    space()
    key = string()
    space()
    if (substr(input, pos++, 1) != ":") invalid()
    type = value(depth, 0)
    if (release) {
      if (key == "tag_name") {
        if (seen_tag++ || type != "string") invalid()
        tag = atom
      } else if (key == "draft") {
        if (seen_draft++ || (type != "true" && type != "false")) invalid()
        draft = type
      } else if (key == "prerelease") {
        if (seen_prerelease++ || (type != "true" && type != "false")) invalid()
        prerelease = type
      } else if (key == "published_at") {
        if (seen_published++ || (type != "string" && type != "null")) invalid()
        published = type == "string" ? atom : ""
      }
    }
    space()
    c = substr(input, pos++, 1)
    if (c == "}") break
    if (c != ",") invalid()
  }
  # older mawk releases do not implement interval expressions such as {4}.
  if (!release || draft != "false" || !seen_prerelease || published !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/) return
  if (mode == "stable" && prerelease == "false" && tag ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) best = tag
  if (mode == "candidate" && prerelease == "true" && tag ~ /^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$/ && published > newest) {
    best = tag
    newest = published
  }
}
function array(depth,    c) {
  pos++
  space()
  if (substr(input, pos, 1) == "]") { pos++; return }
  while (1) {
    value(depth, depth == 1 && mode == "candidate")
    space()
    c = substr(input, pos++, 1)
    if (c == "]") return
    if (c != ",") invalid()
  }
}
{ input = input $0 "\n" }
END {
  if (failed) exit 2
  pos = 1
  space()
  if ((mode == "stable" && substr(input, pos, 1) != "{") || (mode == "candidate" && substr(input, pos, 1) != "[")) invalid()
  value(0, mode == "stable")
  space()
  if (pos <= length(input) || best == "") invalid()
  print best
}
