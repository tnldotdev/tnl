// package runtimetrace owns the fixture-only native flight recorder's pipe
// protocol and resource lifetime. the tagged CLI and daemon test adapter depend
// on this leaf; it imports neither owner nor the production observability stack.
// runtime/trace is process-global, unlike the existing request/span observers.
package runtimetrace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const (
	CommandFDFlag = "-tnl-native-trace-command-fd"
	ReplyFDFlag   = "-tnl-native-trace-reply-fd"
	DirectoryFlag = "-tnl-native-trace-directory"
	MaxFrameBytes = 4096
	MaxCommands   = 4
	TraceLimit    = 16 << 20
	PostTrigger   = time.Second
)

type Kind string

const (
	Arm     Kind = "ARM"
	Trigger Kind = "TRIGGER"
	Export  Kind = "EXPORT"
)

// trigger fields are visitor offsets, not native-process timestamps.
type Event struct {
	Slot                           int
	Kind                           string
	Started, Completed, Observed   time.Duration
	TriggerLag                     time.Duration
	MarkerStarted, MarkerCompleted time.Duration
	MarkerEmitted                  bool
}

type Command struct {
	ID        int
	Kind      Kind
	Phase     string        `json:",omitempty"`
	Component string        `json:",omitempty"`
	Start     time.Time     `json:",omitzero"`
	Duration  time.Duration `json:",omitempty"`
	Event     *Event        `json:",omitempty"`
}

type Reply struct {
	ID      int
	Kind    Kind
	Error   string   `json:",omitempty"`
	Receipt *Receipt `json:",omitempty"`
}

func SimpleName(s string) bool {
	if len(s) == 0 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (c Command) Validate() error {
	if c.ID < 1 || c.ID > MaxCommands {
		return errors.New("invalid command ID")
	}
	if c.Kind != Arm && (c.Phase != "" || c.Component != "" || !c.Start.IsZero() || c.Duration != 0) {
		return errors.New("unexpected arm fields")
	}
	switch c.Kind {
	case Arm:
		if !SimpleName(c.Phase) || !SimpleName(c.Component) || c.Start.IsZero() || c.Duration <= 0 || c.Duration > 5*time.Minute || c.Event != nil {
			return errors.New("invalid arm fields")
		}
	case Trigger:
		e := c.Event
		if e == nil || e.Slot < 0 || e.Slot > 1<<31-1 || (e.Kind != "query" && e.Kind != "callback") || e.Started < 0 || e.Completed < e.Started || e.Observed < e.Completed || e.Observed > 10*time.Minute || e.TriggerLag < 0 || e.TriggerLag > 10*time.Minute || e.MarkerStarted < 0 || e.MarkerCompleted < e.MarkerStarted || e.MarkerCompleted > 10*time.Minute {
			return errors.New("invalid trigger fields")
		}
	case Export:
		if c.Event != nil {
			return errors.New("unexpected trigger fields")
		}
	default:
		return errors.New("invalid command kind")
	}
	return nil
}

// decoder bounds allocation and rejects unknown fields without echoing input.
type Decoder struct{ scanner *bufio.Scanner }

func NewDecoder(r io.Reader) *Decoder {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, MaxFrameBytes+1), MaxFrameBytes+1)
	return &Decoder{scanner: s}
}

func (d *Decoder) Read(value any) error {
	if !d.scanner.Scan() {
		if d.scanner.Err() != nil {
			return errors.New("read frame failed or frame too large")
		}
		return io.EOF
	}
	if len(d.scanner.Bytes())+1 > MaxFrameBytes {
		return errors.New("frame too large")
	}
	j := json.NewDecoder(bytes.NewReader(d.scanner.Bytes()))
	j.DisallowUnknownFields()
	if j.Decode(value) != nil || j.Decode(new(any)) != io.EOF {
		return errors.New("invalid JSON frame")
	}
	return nil
}

func WriteFrame(w io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil || len(b)+1 > MaxFrameBytes {
		return errors.New("encode frame failed or frame too large")
	}
	b = append(b, '\n')
	n, err := w.Write(b)
	if err != nil {
		return errors.New("write frame failed")
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

// consume only the private fixture flags; no flags means no recorder work.
func ConsumeArgs(args []string) (remaining []string, directory string, enabled bool, err error) {
	remaining = make([]string, 0, len(args))
	values := make(map[string]string, 3)
	for _, arg := range args {
		name, value, equal := strings.Cut(arg, "=")
		if name != CommandFDFlag && name != ReplyFDFlag && name != DirectoryFlag {
			remaining = append(remaining, arg)
			continue
		}
		if _, found := values[name]; found || !equal {
			return nil, "", false, errors.New("invalid private trace flags")
		}
		values[name] = value
	}
	if len(values) == 0 {
		return remaining, "", false, nil
	}
	if len(values) != 3 || values[CommandFDFlag] != "3" || values[ReplyFDFlag] != "4" || !filepath.IsAbs(values[DirectoryFlag]) || filepath.Clean(values[DirectoryFlag]) != values[DirectoryFlag] || values[DirectoryFlag] == string(filepath.Separator) {
		return nil, "", false, errors.New("invalid private trace flags")
	}
	return remaining, values[DirectoryFlag], true, nil
}
