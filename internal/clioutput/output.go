// Package clioutput renders stable human-readable CLI diagrams.
package clioutput

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const (
	defaultWidth = 64
	maxWidth     = 72
	framePadding = 2
)

// Frame is one complete human-readable command result or diagnostic.
type Frame struct {
	Command string
	State   string
	Blocks  []Block
	Footer  string
}

// Block is content rendered inside a Frame.
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

// FlowNode is one node in a vertical flow. Detail and Failure describe the
// connection from this node to the next node.
type FlowNode struct {
	Label   string
	Detail  string
	Failure bool
}

// TreeNode is one node in an ASCII tree.
type TreeNode struct {
	Label    string
	Value    string
	Children []TreeNode
}

type row struct {
	text    string
	section bool
	plain   bool
}

type textBlock string
type literalBlock string
type fieldBlock []Field
type flowBlock []FlowNode
type treeBlock TreeNode

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

// Literal prints one copyable line without a border or padding.
func Literal(value string) Block { return literalBlock(value) }

func (b literalBlock) render(int) []row { return []row{{text: sanitize(string(b)), plain: true}} }

// Fields renders aligned label-value pairs.
func Fields(values ...Field) Block { return fieldBlock(values) }

// Flow renders nodes connected vertically by v or x markers.
func Flow(nodes ...FlowNode) Block { return flowBlock(nodes) }

// Transition renders one healthy transition between two values.
func Transition(from, detail, to string) Block {
	return Flow(FlowNode{Label: from, Detail: detail}, FlowNode{Label: to})
}

// Tree renders a hierarchy with ASCII branches.
func Tree(root TreeNode) Block { return treeBlock(root) }

// Section renders a titled divider followed by content.
func Section(title string, blocks ...Block) Block {
	return sectionBlock{title: title, blocks: blocks}
}

// Write renders frame to output with a blank line after its closing rail.
func Write(output io.Writer, frame Frame) error {
	text, err := render(frame, TerminalWidth(output, 0))
	if err != nil {
		return err
	}
	text += "\n"
	written, err := io.WriteString(output, text)
	if err == nil && written != len(text) {
		err = io.ErrShortWrite
	}
	return err
}

// Render returns a complete frame ending in one newline.
func Render(frame Frame) (string, error) {
	return render(frame, 0)
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

func render(frame Frame, columns int) (string, error) {
	if hasLineBreak(frame.Command) || hasLineBreak(frame.State) || hasLineBreak(frame.Footer) {
		return "", errors.New("clioutput: frame rails must be single-line values")
	}
	command := sanitize(frame.Command)
	state := sanitize(frame.State)
	footer := sanitize(frame.Footer)
	if command == "" || state == "" {
		return "", errors.New("clioutput: command and state are required")
	}

	topPrefix := "+--[ " + command + " ]-- " + state + " "
	bottomPrefix := ""
	if footer != "" {
		bottomPrefix = "+-- " + footer + " "
	}
	if len(topPrefix)+2 > maxWidth {
		return "", fmt.Errorf("clioutput: frame rail exceeds %d columns", maxWidth)
	}
	// redirected output keeps the compact frame, expanding for short rails.
	width := min(maxWidth, max(12, columns))
	if columns == 0 {
		width = min(maxWidth, max(defaultWidth, len(topPrefix)+2, len(bottomPrefix)+2))
	}
	contentWidth := width - 2 - 2*framePadding
	var rows []row
	plain := len(topPrefix)+2 > width || len(bottomPrefix)+2 > width
	for index, block := range frame.Blocks {
		if err := validateBlock(block); err != nil {
			return "", err
		}
		if index > 0 {
			rows = append(rows, row{})
		}
		for _, rendered := range block.render(contentWidth) {
			plain = plain || rendered.plain || len(rendered.text) > contentWidth
			rows = append(rows, rendered)
		}
	}
	var result strings.Builder
	if len(topPrefix)+2 <= width {
		result.WriteString(topPrefix)
		result.WriteString(strings.Repeat("-", width-len(topPrefix)-1))
		result.WriteString("+\n")
	} else {
		fmt.Fprintf(&result, "%s\n%s\n", command, state)
	}
	if plain {
		// use an open layout for this result. the terminal can soft-wrap values;
		// copying or redirecting them gets the original logical line.
		for _, r := range rows {
			result.WriteString(r.text)
			if r.section {
				result.WriteByte(':')
			}
			result.WriteByte('\n')
		}
		if footer != "" {
			if len(bottomPrefix)+2 <= width {
				result.WriteString(bottomPrefix + strings.Repeat("-", width-len(bottomPrefix)-1) + "+\n")
			} else {
				result.WriteString(footer + "\n")
			}
		}
		return strings.TrimRight(result.String(), "\n") + "\n", nil
	}
	writeBodyRow(&result, width, "")
	for _, r := range rows {
		if r.section {
			writeSectionRow(&result, width, r.text)
		} else {
			writeBodyRow(&result, width, r.text)
		}
	}
	writeBodyRow(&result, width, "")
	if footer == "" {
		result.WriteByte('+')
		result.WriteString(strings.Repeat("-", width-2))
		result.WriteString("+\n")
		return result.String(), nil
	}
	result.WriteString(bottomPrefix)
	result.WriteString(strings.Repeat("-", width-len(bottomPrefix)-1))
	result.WriteString("+\n")
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
				result = append(result, row{text: value, plain: true})
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

func (b flowBlock) render(width int) []row {
	var result []row
	for index, node := range b {
		lines := []string{sanitize(node.Label)}
		for _, line := range lines {
			// short labels sit beneath the fixed connector at content column three.
			if len(lines) == 1 && len(line) > 0 && len(line) < 7 {
				line = strings.Repeat(" ", (7-len(line))/2) + line
			}
			result = append(result, row{text: line})
		}
		if index == len(b)-1 {
			continue
		}
		result = append(result, row{text: "   |"})
		marker := "   v"
		if node.Failure {
			marker = "   x"
		}
		if node.Detail == "" {
			result = append(result, row{text: marker})
			continue
		}
		prefix := marker + "  "
		detail := wrap(node.Detail, width-len(prefix))
		for detailIndex, line := range detail {
			if detailIndex == 0 {
				result = append(result, row{text: prefix + line})
				continue
			}
			result = append(result, row{text: strings.Repeat(" ", len(prefix)) + line})
		}
	}
	return result
}

func (b treeBlock) render(width int) []row {
	root := TreeNode(b)
	result := make([]row, 0)
	for _, line := range treeLines(root, width) {
		result = append(result, row{text: line})
	}
	return appendTreeChildren(result, root.Children, "", width)
}

func (b sectionBlock) render(width int) []row {
	title := wrap(b.title, width-2)
	result := []row{{text: title[0], section: true}}
	for _, continuation := range title[1:] {
		result = append(result, row{text: continuation})
	}
	for index, block := range b.blocks {
		if index > 0 {
			result = append(result, row{})
		}
		result = append(result, block.render(width)...)
	}
	return result
}

func appendTreeChildren(result []row, children []TreeNode, parentPrefix string, width int) []row {
	for index, child := range children {
		last := index == len(children)-1
		branch := "|-- "
		childPrefix := parentPrefix + "|   "
		if last {
			branch = "`-- "
			childPrefix = parentPrefix + "    "
		}
		maxParentWidth := max(0, width-len(branch)-1)
		if len(parentPrefix) > maxParentWidth {
			parentPrefix = parentPrefix[:maxParentWidth]
		}
		prefix := parentPrefix + branch
		lines := treeLines(child, width-len(prefix))
		for lineIndex, line := range lines {
			if lineIndex == 0 {
				result = append(result, row{text: prefix + line})
				continue
			}
			result = append(result, row{text: strings.Repeat(" ", len(prefix)) + line})
		}
		if len(childPrefix) > maxParentWidth {
			childPrefix = childPrefix[:maxParentWidth]
		}
		result = appendTreeChildren(result, child.Children, childPrefix, width)
	}
	return result
}

func treeLines(node TreeNode, width int) []string {
	if node.Value == "" {
		return wrap(node.Label, width)
	}
	label, value := sanitize(node.Label), sanitize(node.Value)
	if len(label)+2+len(value) <= width {
		return []string{label + "  " + value}
	}
	return append(wrap(node.Label, width), value)
}

func writeBodyRow(output *strings.Builder, width int, text string) {
	output.WriteString("|  ")
	output.WriteString(text)
	output.WriteString(strings.Repeat(" ", width-6-len(text)))
	output.WriteString("  |\n")
}

func writeSectionRow(output *strings.Builder, width int, title string) {
	prefix := "|-- " + title + " "
	output.WriteString(prefix)
	output.WriteString(strings.Repeat("-", width-len(prefix)-1))
	output.WriteString("|\n")
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

func hasLineBreak(value string) bool { return strings.ContainsAny(value, "\r\n") }

func validateBlock(block Block) error {
	if block == nil {
		return errors.New("clioutput: frame contains a nil block")
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
