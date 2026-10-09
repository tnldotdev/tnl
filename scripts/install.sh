#!/bin/sh
# generated from scripts/install.sh.in and internal/clioutput; do not edit install.sh.
# curl -fsSL https://tnl.dev/install | sh
# TNL_VERSION selects an exact release; otherwise prefer stable, then a release candidate.
# TNL_INSTALL selects the binary directory (default: ~/.local/bin).
# release legal files are kept in <binary directory>/tnl-notices.

tnl_frame() (
  export TNL_FRAME_COMMAND="$1" TNL_FRAME_STATE="$2" TNL_FRAME_FOOTER="$3"
  shift 3
  count=0
  while [ "$#" -ge 2 ]; do
    count=$((count + 1))
    export "TNL_FRAME_LABEL_$count=$1" "TNL_FRAME_VALUE_$count=$2"
    shift 2
  done
  [ "$#" -eq 0 ] || exit 2
  export TNL_FRAME_COUNT="$count"
  LC_ALL=C awk -v default_width=64 -v max_width=72 -v padding=2 \
    -v top_format='+--[ %s ]-- %s ' -v footer_format='+-- %s ' '# the bootstrap backend supports one field block and uses the Go frame constants.
function repeat(value, count,    result, i) {
  result = ""
  for (i = 0; i < count; i++) result = result value
  return result
}

function sanitize(value,    result, i, b, b2, n, code, j, valid) {
  result = ""
  for (i = 1; i <= length(value); i++) {
    b = ord[substr(value, i, 1)]
    if (b >= 32 && b <= 126) {
      result = result substr(value, i, 1)
      continue
    }
    n = b >= 194 && b <= 223 ? 2 : b >= 224 && b <= 239 ? 3 : b >= 240 && b <= 244 ? 4 : 0
    valid = n > 0 && i + n - 1 <= length(value)
    code = b % (n == 2 ? 32 : n == 3 ? 16 : 8)
    for (j = 1; valid && j < n; j++) {
      b2 = ord[substr(value, i + j, 1)]
      valid = b2 >= 128 && b2 <= 191
      code = code * 64 + b2 - 128
    }
    valid = valid && code >= (n == 2 ? 128 : n == 3 ? 2048 : 65536) && code <= 1114111 && !(code >= 55296 && code <= 57343)
    if (valid) {
      result = result sprintf(code <= 65535 ? "\\u%04x" : "\\U%08x", code)
      i += n - 1
    } else {
      result = result sprintf("\\x%02x", b)
    }
  }
  return result
}

function wrap(value, width,    count, cut, i, line) {
  for (i in lines) delete lines[i]
  count = 0
  while (length(value) > width) {
    cut = 0
    for (i = 1; i <= width + 1; i++) if (substr(value, i, 1) == " ") cut = i - 1
    if (cut <= 0) cut = width
    line = substr(value, 1, cut)
    sub(/ +$/, "", line)
    lines[++count] = line
    value = substr(value, cut + 1)
    sub(/^ +/, "", value)
  }
  lines[++count] = value
  return count
}

function body(value) {
  printf "|%s%s%s%s|\n", repeat(" ", padding), value, repeat(" ", width - 2 - 2 * padding - length(value)), repeat(" ", padding)
}

BEGIN {
  for (i = 1; i <= 255; i++) ord[sprintf("%c", i)] = i
  command = ENVIRON["TNL_FRAME_COMMAND"]
  state = ENVIRON["TNL_FRAME_STATE"]
  footer = ENVIRON["TNL_FRAME_FOOTER"]
  if (command ~ /[\r\n]/ || state ~ /[\r\n]/ || footer ~ /[\r\n]/) exit 2
  command = sanitize(command)
  state = sanitize(state)
  footer = sanitize(footer)
  if (command == "" || state == "") exit 2
  top = sprintf(top_format, command, state)
  bottom = footer == "" ? "" : sprintf(footer_format, footer)
  width = default_width
  if (length(top) + 2 > width) width = length(top) + 2
  if (length(bottom) + 2 > width) width = length(bottom) + 2
  if (width > max_width) exit 2
  content_width = width - 2 - 2 * padding
  count = ENVIRON["TNL_FRAME_COUNT"] + 0
  label_width = 0
  for (i = 1; i <= count; i++) {
    labels[i] = sanitize(ENVIRON["TNL_FRAME_LABEL_" i])
    values[i] = sanitize(ENVIRON["TNL_FRAME_VALUE_" i])
    if (length(labels[i]) > label_width) label_width = length(labels[i])
  }
  print top repeat("-", width - length(top) - 1) "+"
  body("")
  for (i = 1; i <= count; i++) {
    if (label_width + 2 >= content_width) {
      size = wrap(labels[i], content_width)
      for (j = 1; j <= size; j++) body(lines[j])
      size = wrap(values[i], content_width - 2)
      for (j = 1; j <= size; j++) body("  " lines[j])
    } else {
      prefix = label_width == 0 ? "" : labels[i] repeat(" ", label_width - length(labels[i])) "  "
      size = wrap(values[i], content_width - length(prefix))
      for (j = 1; j <= size; j++) body((j == 1 ? prefix : repeat(" ", length(prefix))) lines[j])
    }
  }
  body("")
  print (footer == "" ? "+" repeat("-", width - 2) : bottom repeat("-", width - length(bottom) - 1)) "+"
}
' </dev/null
)


tnl_release_tag() {
  LC_ALL=C awk -v mode="$1" '# read GitHub release metadata without requiring a JSON tool on the host.
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
' "$2"
}

tnl_install() (
  set -eu
  command -v awk >/dev/null 2>&1 || {
    printf '%s' '+--[ tnl install ]-- failed -----------------------------------+
|                                                              |
|  error   awk is required to install tnl                      |
|  action  install awk and run the installer again             |
|                                                              |
+--------------------------------------------------------------+
' >&2
    exit 1
  }

  step=setup
  tmp=
  staged=
  present() {
    tnl_frame 'tnl install' "$@"
    printf '\n'
  }
  fail() {
    present failed '' step "$step" error "$1" action "$2" >&2
    exit 1
  }
  cleanup() {
    [ -z "$tmp" ] || rm -rf "$tmp"
    [ -z "$staged" ] || rm -rf "$staged"
    return 0
  }
  trap cleanup 0
  trap 'fail "installation interrupted" "run the installer again"' HUP INT TERM

  for tool in curl tar uname mktemp mkdir cp mv chmod rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "$tool is required to install tnl" "install $tool and run the installer again"
  done
  if command -v sha256sum >/dev/null 2>&1; then
    checksum=sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    checksum=shasum
  else
    fail 'a SHA-256 tool is required' 'install sha256sum or shasum and run the installer again'
  fi

  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) fail 'this operating system is not supported' 'use macOS or Linux to install tnl' ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) fail 'this architecture is not supported' 'use an amd64 or arm64 machine to install tnl' ;;
  esac
  [ -n "${TNL_INSTALL:-}" ] || [ -n "${HOME:-}" ] || fail 'the home directory is not set' 'set HOME or TNL_INSTALL before running the installer'
  dir=${TNL_INSTALL:-${HOME:-}/.local/bin}
  # absolute paths keep cleanup and option handling independent of the working directory.
  case "$dir" in /*) ;; *) dir="$(pwd)/$dir" ;; esac
  version=${TNL_VERSION:-}
  if [ -n "$version" ]; then
    version=${version#v}
    printf '%s\n' "$version" | LC_ALL=C awk '
      NR != 1 || $0 !~ /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/ { exit 1 }
    ' || fail 'TNL_VERSION must name a released version' 'set TNL_VERSION to a version such as 0.1.0-rc.40'
  fi
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/tnl-install.XXXXXXXX" 2>/dev/null) || fail 'could not create a temporary directory' 'check that the temporary directory is writable'
  repo=https://github.com/tnldotdev/tnl
  api=https://api.github.com/repos/tnldotdev/tnl/releases

  fetch() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 15 --max-time 300 --output "$2" "$1" 2>"$tmp/curl-error"
  }

  if [ -z "$version" ]; then
    step='select release'
    # only a missing stable release permits the release-candidate fallback.
    status=$(curl --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 15 --max-time 60 --output "$tmp/release.json" \
      --write-out '%{http_code}' "$api/latest" 2>"$tmp/curl-error") || fail 'could not select a release' 'check access to api.github.com and run the installer again'
    case "$status" in
      200) tag=$(tnl_release_tag stable "$tmp/release.json") || fail 'stable release metadata is invalid' 'set TNL_VERSION to an exact release or try again later' ;;
      404)
        fetch "$api?per_page=100" "$tmp/release.json" || fail 'could not find a release candidate' 'check access to api.github.com or set TNL_VERSION to an exact release'
        tag=$(tnl_release_tag candidate "$tmp/release.json") || fail 'no published release candidate was found' 'set TNL_VERSION to an exact release or try again later'
        ;;
      *) fail 'GitHub could not select a release' 'try again later or set TNL_VERSION to an exact release' ;;
    esac
    version=${tag#v}
  fi

  archive="tnl_${version}_${os}_${arch}.tar.gz"
  base="$repo/releases/download/v$version"
  step=download
  present downloading '' version "$version" platform "$os/$arch" >&2
  fetch "$base/$archive" "$tmp/$archive" || fail 'could not download the release archive' 'check the version and access to github.com, then run the installer again'
  fetch "$base/checksums.txt" "$tmp/checksums.txt" || fail 'could not download the release checksums' 'check access to github.com and run the installer again'

  step='verify checksum'
  present verifying '' archive "$archive" >&2
  expected=$(LC_ALL=C awk -v name="$archive" '
    $2 == name {
      count++
      if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/) invalid = 1
      hash = $1
    }
    END { if (count != 1 || invalid) exit 1; print hash }
  ' "$tmp/checksums.txt") || fail 'the release checksum is missing or invalid' 'run the installer again or select another release with TNL_VERSION'
  if [ "$checksum" = sha256sum ]; then
    actual=$(sha256sum <"$tmp/$archive" 2>"$tmp/checksum-error") || fail 'could not check the archive checksum' 'run the installer again'
  else
    actual=$(shasum -a 256 <"$tmp/$archive" 2>"$tmp/checksum-error") || fail 'could not check the archive checksum' 'run the installer again'
  fi
  actual=${actual%% *}
  [ "$actual" = "$expected" ] || fail 'the archive checksum does not match' 'run the installer again to download a fresh archive'

  step=extract
  tar -xzf "$tmp/$archive" -C "$tmp" tnl LICENSE NOTICE THIRD_PARTY_LICENSES.txt 2>"$tmp/tar-error" || fail 'could not extract the release archive' 'run the installer again or select another release with TNL_VERSION'
  for file in tnl LICENSE NOTICE THIRD_PARTY_LICENSES.txt; do
    [ -f "$tmp/$file" ] && [ ! -L "$tmp/$file" ] || fail 'the release archive is missing a regular installation file' 'select another release with TNL_VERSION'
  done

  step=install
  mkdir -p "$dir" 2>"$tmp/install-error" || fail 'could not create the installation directory' 'set TNL_INSTALL to a writable directory'
  [ ! -d "$dir/tnl" ] || fail 'the binary path is a directory' 'set TNL_INSTALL to another directory'
  staged=$(mktemp -d "$dir/.tnl-install.XXXXXXXX" 2>"$tmp/install-error") || fail 'could not stage the installation' 'set TNL_INSTALL to a writable directory'
  cp "$tmp/tnl" "$staged/tnl" 2>"$tmp/install-error" || fail 'could not copy the binary' 'check free space and permissions in TNL_INSTALL'
  chmod 755 "$staged/tnl" 2>"$tmp/install-error" || fail 'could not set executable permissions' 'check permissions in TNL_INSTALL'
  mkdir -p "$dir/tnl-notices" 2>"$tmp/install-error" || fail 'could not create the notices directory' 'check permissions in TNL_INSTALL'
  cp "$tmp/LICENSE" "$tmp/NOTICE" "$tmp/THIRD_PARTY_LICENSES.txt" "$dir/tnl-notices/" 2>"$tmp/install-error" || fail 'could not retain release notices' 'check free space and permissions in TNL_INSTALL'
  mv -f "$staged/tnl" "$dir/tnl" 2>"$tmp/install-error" || fail 'could not install the binary' 'check permissions in TNL_INSTALL'

  # quote the entire PATH addition as data; do not expand a custom path as shell code.
  case ":${PATH:-}:" in
    *":$dir:"*)
      present installed 'start with: tnl publish 3000' version "$version" platform "$os/$arch" binary "$dir/tnl"
      ;;
    *)
      quoted=$(printf '%s' "$dir" | awk '{
        if (NR > 1) printf "\n"
        for (i = 1; i <= length($0); i++) {
          c = substr($0, i, 1)
          if (c == "\047") printf "\047\\\047\047"
          else printf "%s", c
        }
      }' 2>"$tmp/format-error") || fail 'could not format the PATH action' 'add TNL_INSTALL to PATH before running tnl'
      present installed 'start with: tnl publish 3000' version "$version" platform "$os/$arch" binary "$dir/tnl" action "export PATH='$quoted':\"\$PATH\""
      ;;
  esac
)

# execution starts only after the complete script has been parsed.
tnl_install
