package managedssh

import (
	"context"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxCommandBytes = 64 << 10

func (s *Server) serveSession(ctx context.Context, conn *ssh.ServerConn, incoming ssh.NewChannel) {
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
	type outcome struct {
		code int
		err  error
	}
	var finished chan outcome
	// cancellation closes channel I/O before joining the child runner.
	defer func() {
		if finished != nil {
			cancel()
			_ = channel.Close()
			<-finished
		}
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
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(result.code)}))
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
						request.Term = p.Term
						request.Window = Window{Width: int(p.Width), Height: int(p.Height)}
						accepted = true
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
					resize <- Window{Width: int(p.Width), Height: int(p.Height)}
					accepted = true
				}
			case "shell", "exec", "subsystem":
				if finished == nil {
					var value struct{ Value string }
					valid := len(msg.Payload) <= maxCommandBytes+4
					if msg.Type == "shell" {
						valid = len(msg.Payload) == 0
						request.Kind = "shell"
					} else {
						valid = valid && ssh.Unmarshal(msg.Payload, &value) == nil && !strings.ContainsRune(value.Value, 0)
						request.Kind, request.Command = "command", value.Value
						if msg.Type == "subsystem" {
							valid = valid && value.Value == "sftp" && request.Term == ""
							request.Kind, request.Command = "sftp", ""
						}
					}
					if valid {
						accepted = true
						finished = make(chan outcome, 1)
						go func(req Request, done chan<- outcome) {
							code, runErr := s.runner.Run(life, req, Streams{Stdin: channel, Stdout: channel, Stderr: channel.Stderr(), Resize: resize})
							done <- outcome{code, runErr}
						}(request, finished)
					}
				}
			}
			// no env, agent, X11, signal, or arbitrary subsystem requests.
			_ = msg.Reply(accepted, nil)
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
