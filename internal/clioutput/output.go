// Package clioutput renders plain, copyable CLI results.
package clioutput

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const defaultWidth = 80

// Message holds the lines of one result or diagnostic.
type Message struct {
	Blocks []Block
}

// Block is content rendered inside a message.
type Block interface {
	render(int) []row
}

// Field is one label and value in an aligned field list.
type Field struct {
	Label string
	Value string
	// prose may wrap at spaces. other values are printed intact.
	Prose bool
}

type row struct {
	text string
}

type textBlock string
type literalBlock string
type fieldBlock []Field
type tableBlock struct {
	head []string
	rows [][]string
}

type sectionBlock struct {
	title  string
	blocks []Block
}

type commandError struct {
	command string
	err     error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }

// CommandTitle returns a canonical command title without argument placeholders.
func CommandTitle(program, path string) string {
	parts := []string{program}
	for _, part := range strings.Fields(path) {
		if strings.HasPrefix(part, "<") && strings.HasSuffix(part, ">") {
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

// WrapCommand attaches command context to err.
func WrapCommand(command string, err error) error {
	if err == nil {
		return nil
	}
	return &commandError{command: command, err: err}
}

// CommandOf returns the nearest attached command context from a non-nil wrapper.
func CommandOf(err error) (string, bool) {
	contextual, ok := errors.AsType[*commandError](err)
	if !ok || contextual == nil {
		return "", false
	}
	return contextual.command, true
}

// Text renders wrapped prose.
func Text(value string) Block { return textBlock(value) }

// Literal prints one copyable value on its own line.
func Literal(value string) Block { return literalBlock(value) }

// Line prints one logical row. only the terminal may wrap it.
func Line(value string) Block { return literalBlock(value) }

func (b literalBlock) render(int) []row { return []row{{text: sanitize(string(b))}} }

// Fields renders aligned label-value pairs.
func Fields(values ...Field) Block { return fieldBlock(values) }

// Table aligns comparable records without splitting their values.
func Table(head []string, rows [][]string, empty string) Block {
	if len(rows) == 0 {
		return Text(empty)
	}
	return tableBlock{head, rows}
}

func (b tableBlock) render(int) []row {
	data := make([][]string, 0, len(b.rows)+1)
	widths := make([]int, len(b.head))
	for _, cells := range append([][]string{b.head}, b.rows...) {
		values := make([]string, len(cells))
		for i, cell := range cells {
			values[i] = sanitize(cell)
			if i < len(widths) {
				widths[i] = max(widths[i], len(values[i]))
			}
		}
		data = append(data, values)
	}
	result := make([]row, 0, len(data))
	for _, values := range data {
		var line strings.Builder
		for len(values) > 0 && values[len(values)-1] == "" {
			values = values[:len(values)-1]
		}
		for i, value := range values {
			line.WriteString(value)
			if i+1 < len(values) && i < len(widths) {
				line.WriteString(strings.Repeat(" ", widths[i]-len(value)+2))
			}
		}
		result = append(result, row{text: line.String()})
	}
	return result
}

// Section places a title above its content.
func Section(title string, blocks ...Block) Block {
	return sectionBlock{title: title, blocks: blocks}
}

// Write emits one newline-terminated result.
func Write(output io.Writer, message Message) error {
	text, err := render(message, TerminalWidth(output, 0))
	if err != nil {
		return err
	}
	written, err := io.WriteString(output, text)
	if err == nil && written != len(text) {
		err = io.ErrShortWrite
	}
	return err
}

// Render returns newline-terminated plain text.
func Render(message Message) (string, error) {
	return render(message, 0)
}

// TerminalWidth uses the destination's terminal size, or fallback for pipes and files.
func TerminalWidth(output io.Writer, fallback int) int {
	if file, ok := output.(interface{ Fd() uintptr }); ok {
		if width, _, err := term.GetSize(int(file.Fd())); err == nil && width > 0 {
			return width
		}
	}
	return fallback
}

func render(message Message, columns int) (string, error) {
	width := defaultWidth
	if columns > 0 {
		width = min(width, columns)
	}
	var result strings.Builder
	for _, block := range message.Blocks {
		if err := validateBlock(block); err != nil {
			return "", err
		}
		for _, r := range block.render(width) {
			result.WriteString(r.text)
			result.WriteByte('\n')
		}
	}
	return result.String(), nil
}

func (b textBlock) render(width int) []row {
	lines := wrap(string(b), width)
	result := make([]row, len(lines))
	for index, line := range lines {
		result[index].text = line
	}
	return result
}

func (b fieldBlock) render(width int) []row {
	labelWidth := 0
	for _, field := range b {
		labelWidth = max(labelWidth, len(sanitize(field.Label)))
	}
	var result []row
	for _, field := range b {
		label := sanitize(field.Label)
		value := sanitize(field.Value)
		if labelWidth+2 >= width || !field.Prose && labelWidth+2+len(value) > width {
			result = append(result, row{text: label})
			if field.Prose {
				result = append(result, textBlock(field.Value).render(width)...)
			} else {
				result = append(result, row{text: value})
			}
			continue
		}
		valueWidth := width
		prefix := ""
		if labelWidth > 0 {
			prefix = label + strings.Repeat(" ", labelWidth-len(label)) + "  "
			valueWidth -= len(prefix)
		}
		lines := wrap(field.Value, valueWidth)
		for index, line := range lines {
			if index == 0 {
				result = append(result, row{text: prefix + line})
				continue
			}
			result = append(result, row{text: strings.Repeat(" ", len(prefix)) + line})
		}
	}
	return result
}

func (b sectionBlock) render(width int) []row {
	result := []row{{text: sanitize(b.title) + ":"}}
	for _, block := range b.blocks {
		result = append(result, block.render(width)...)
	}
	return result
}

func wrap(value string, width int) []string {
	value = sanitize(value)
	if value == "" {
		return []string{""}
	}
	if width < 1 {
		return []string{value}
	}
	var result []string
	for len(value) > width {
		cut := strings.LastIndexByte(value[:width+1], ' ')
		if cut <= 0 {
			next := strings.IndexByte(value[width:], ' ')
			if next < 0 {
				break
			}
			cut = width + next
		}
		result = append(result, strings.TrimRight(value[:cut], " "))
		value = strings.TrimLeft(value[cut:], " ")
	}
	return append(result, value)
}

func sanitize(value string) string {
	var result strings.Builder
	for len(value) > 0 {
		character, size := utf8.DecodeRuneInString(value)
		if character == utf8.RuneError && size == 1 {
			fmt.Fprintf(&result, `\x%02x`, value[0])
			value = value[1:]
			continue
		}
		value = value[size:]
		switch {
		case character >= 0x20 && character <= 0x7e:
			result.WriteRune(character)
		case character < 0x20 || character == 0x7f:
			fmt.Fprintf(&result, `\x%02x`, character)
		case character <= 0xffff:
			fmt.Fprintf(&result, `\u%04x`, character)
		default:
			fmt.Fprintf(&result, `\U%08x`, character)
		}
	}
	return result.String()
}

func validateBlock(block Block) error {
	if block == nil {
		return errors.New("clioutput: nil block")
	}
	section, ok := block.(sectionBlock)
	if !ok {
		return nil
	}
	for _, child := range section.blocks {
		if err := validateBlock(child); err != nil {
			return err
		}
	}
	return nil
}
