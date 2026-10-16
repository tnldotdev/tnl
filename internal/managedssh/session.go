package managedssh

import (
	"context"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxCommandBytes = 64 << 10

func (s *Server) serveSession(ctx context.Context, conn *ssh.ServerConn, incoming ssh.NewChannel) {
	if len(incoming.ExtraData()) != 0 {
		_ = incoming.Reject(ssh.Prohibited, "invalid session channel")
		return
	}
	channel, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	closeIO := context.AfterFunc(life, func() { _ = channel.Close() })
	defer closeIO()
	request := Request{Username: conn.User()}
	resize := make(chan Window, 1)
	defer close(resize)
	signals := make(chan string, 16)
	defer close(signals)
	type outcome struct {
		code   int
		err    error
		signal string
	}
	var finished chan outcome
	var inputDone chan struct{}
	// cancellation closes channel I/O before joining the child runner.
	defer func() {
		// keep the SSH mux draining while joining the stdin reader. a client may
		// send no-reply requests after exit; filling its request queue otherwise
		// prevents the mux from processing close acknowledgments or disconnects.
		requestsDone := make(chan struct{})
		go func() { ssh.DiscardRequests(requests); close(requestsDone) }()
		_ = channel.Close()
		if finished != nil {
			cancel()
			_ = channel.Close()
			<-finished
		}
		if inputDone != nil {
			<-inputDone
		}
		<-requestsDone
	}()
	for {
		select {
		case <-life.Done():
			return
		case result := <-finished:
			finished = nil
			if result.err != nil {
				result.code = 255
				_, _ = io.WriteString(channel.Stderr(), "SSH session could not run\n")
			}
			_ = channel.CloseWrite()
			if result.signal != "" {
				_, _ = channel.SendRequest("exit-signal", false, ssh.Marshal(struct {
					Signal            string
					CoreDumped        bool
					Message, Language string
				}{Signal: result.signal}))
			} else {
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(result.code)}))
			}
			return
		case msg, ok := <-requests:
			if !ok {
				return
			}
			accepted := false
			switch msg.Type {
			case "pty-req":
				if finished == nil && request.Term == "" {
					var p struct {
						Term                                   string
						Width, Height, PixelWidth, PixelHeight uint32
						Modes                                  string
					}
					if len(msg.Payload) <= 4096 && ssh.Unmarshal(msg.Payload, &p) == nil && validTerm(p.Term) && p.Width <= 65535 && p.Height <= 65535 {
						if modes, ok := parseTerminalModes(p.Modes); ok {
							request.Term, request.Modes = p.Term, modes
							request.Window = Window{Width: int(p.Width), Height: int(p.Height)}
							accepted = true
						}
					}
				}
			case "window-change":
				var p struct{ Width, Height, PixelWidth, PixelHeight uint32 }
				if request.Term != "" && ssh.Unmarshal(msg.Payload, &p) == nil && p.Width <= 65535 && p.Height <= 65535 {
					// keep the latest size without blocking other channel requests.
					select {
					case <-resize:
					default:
					}
					if p.Width != 0 {
						request.Window.Width = int(p.Width)
					}
					if p.Height != 0 {
						request.Window.Height = int(p.Height)
					}
					resize <- request.Window
					accepted = true
				}
			case "shell", "exec", "subsystem":
				if finished == nil && canStartWork(life) {
					candidate := request
					var value struct{ Value string }
					valid := len(msg.Payload) <= maxCommandBytes+4
					if msg.Type == "shell" {
						valid = len(msg.Payload) == 0
						candidate.Kind, candidate.Command = "shell", ""
					} else {
						valid = valid && ssh.Unmarshal(msg.Payload, &value) == nil && !strings.ContainsRune(value.Value, 0)
						candidate.Kind, candidate.Command = "command", value.Value
						if msg.Type == "subsystem" {
							valid = valid && value.Value == "sftp" && request.Term == ""
							candidate.Kind, candidate.Command = "sftp", ""
						}
					}
					if valid {
						request = candidate
						if msg.Reply(true, nil) != nil {
							return
						}
						finished = make(chan outcome, 1)
						input, inputWriter := io.Pipe()
						inputDone = make(chan struct{})
						go func() { defer close(inputDone); _, _ = io.Copy(inputWriter, channel); _ = inputWriter.Close() }()
						go func(req Request, done chan<- outcome) {
							defer input.Close()
							var signal string
							code, runErr := s.runner.Run(life, req, Streams{Stdin: input, CloseInput: func() { _ = inputWriter.Close() }, Stdout: channel, Stderr: channel.Stderr(), Resize: resize, Signals: signals, ExitSignal: func(name string) { signal = name }})
							done <- outcome{code: code, err: runErr, signal: signal}
						}(request, finished)
						continue
					}
				}
			case "signal":
				var payload struct{ Signal string }
				if finished != nil && request.Kind != "sftp" && len(msg.Payload) <= 32 && ssh.Unmarshal(msg.Payload, &payload) == nil && validSignal(payload.Signal) {
					select {
					case signals <- payload.Signal:
						accepted = true
					default:
					}
				}
			}
			// no env, agent, X11, or arbitrary subsystem requests.
			if msg.Reply(accepted, nil) != nil {
				return
			}
		}
	}
}

func validTerm(term string) bool {
	if len(term) == 0 || len(term) > 128 {
		return false
	}
	for _, c := range term {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._+-", c)) {
			return false
		}
	}
	return true
}
