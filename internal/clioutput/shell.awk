# the bootstrap backend supports one field block and uses the Go frame constants.
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
