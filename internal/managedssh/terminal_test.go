package managedssh

import (
	"context"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ssh"
)

func modeBytes(op byte, value uint32) string {
	data := []byte{op, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(data[1:], value)
	return string(data)
}

func TestTerminalModeWireValidation(t *testing.T) {
	for _, value := range []string{"", string([]byte{ssh.ECHO}), modeBytes(ssh.ECHO, 0), modeBytes(ssh.VINTR, 256) + "\x00", modeBytes(ssh.CS7, 1) + modeBytes(ssh.CS8, 1) + "\x00", "\x00extra"} {
		if _, ok := parseTerminalModes(value); ok {
			t.Fatalf("accepted malformed terminal modes %q", value)
		}
	}
	modes, ok := parseTerminalModes(modeBytes(ssh.ECHO, 0) + modeBytes(159, 17) + modeBytes(ssh.VINTR, 2) + "\x00")
	if !ok || modes[ssh.VINTR] != 2 || modes[159] != 17 {
		t.Fatalf("terminal modes = %v %v", modes, ok)
	}
	if _, ok := parseTerminalModes("\xa0extension"); !ok {
		t.Fatal("did not stop at an extension opcode")
	}
}

func TestSSHInvalidRequestsDoNotMutateSession(t *testing.T) {
	ran := make(chan Request, 1)
	client, done := protocolServer(t, protocolConfig(t), protocolRunner{run: func(_ context.Context, req Request, _ Streams) (int, error) { ran <- req; return 0, nil }})
	if channel, _, err := client.OpenChannel("session", []byte("unexpected channel setup")); err == nil {
		channel.Close()
		t.Fatal("accepted invalid session channel data")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, modes := range []string{"bad", modeBytes(ssh.VINTR, 256) + "\x00"} {
		ok, err := session.SendRequest("pty-req", true, ssh.Marshal(struct {
			Term                  string
			Width, Height, WP, HP uint32
			Modes                 string
		}{"xterm", 80, 24, 0, 0, modes}))
		if err != nil || ok {
			t.Fatalf("invalid pty = %v %v", ok, err)
		}
	}
	if ok, err := session.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"bad\x00command"})); err != nil || ok {
		t.Fatalf("invalid exec = %v %v", ok, err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	req := awaitProtocol(t, ran)
	if req.Kind != "shell" || req.Command != "" || req.Term != "" {
		t.Fatalf("rejected request contaminated shell: %#v", req)
	}
	_ = session.Wait()
	_ = client.Close()
	awaitProtocol(t, done)
}
