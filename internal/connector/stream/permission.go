package stream

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func nativePermission(signer Signer, session, visitor, runID string, runNumber, revision uint64, token string, initial []byte) (tunnelv1.NativeVisitorPermission, error) {
	message, err := visitortoken.NativeProofMessage(visitortoken.Token(token), session, visitor, runID, runNumber, revision, initial)
	if err != nil || signer.Sign == nil {
		return tunnelv1.NativeVisitorPermission{}, ErrServiceConnection
	}
	signature := signer.Sign(message)
	if !ed25519.Verify(signer.PublicKey, message, signature) {
		return tunnelv1.NativeVisitorPermission{}, ErrServiceConnection
	}
	return tunnelv1.NativeVisitorPermission{Token: token, PublicKey: base64.RawURLEncoding.EncodeToString(signer.PublicKey), Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

// renewNativePermission reads prepared state only. the stream keeps its original
// session, visitor ID and metadata; a renewal cannot move it to another run or
// replace its subject. closing joins the writer before releasing its path slot.
func renewNativePermission(ctx context.Context, raw net.Conn, writer *tunnel.NativeRequestWriter, prepared *preparedSelection, signer Signer, session, visitor string, run Run) func() error {
	life, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		last := run.Permission.VisitorToken
		currentDeadline := run.Permission.ExpiresAt
		for {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
			}
			next, err := prepared.current()
			if err != nil || next.TrustRevision != run.TrustRevision || next.ServiceID != run.ServiceID || !sameEndpoint(next.Endpoint, run.Endpoint) {
				_ = raw.Close()
				return
			}
			if next.Permission.VisitorToken == last {
				continue
			}
			permission, err := nativePermission(signer, session, visitor, run.ServiceRunID, run.RunNumber, uint64(run.TrustRevision), next.Permission.VisitorToken, nil)
			if err != nil {
				_ = raw.Close()
				return
			}
			// a blocked application upload holds the writer lock. the existing
			// permission, not a short write timeout, bounds how long it may wait.
			write, finish := context.WithDeadline(life, currentDeadline)
			closed := make(chan struct{})
			stop := context.AfterFunc(write, func() { _ = raw.Close(); close(closed) })
			err = writer.Renew(permission)
			if err == nil {
				err = write.Err()
			}
			if !stop() {
				<-closed
			}
			finish()
			if err != nil {
				_ = raw.Close()
				return
			}
			last = next.Permission.VisitorToken
			currentDeadline = next.Permission.ExpiresAt
		}
	}()
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() { cancel(); result = raw.Close(); <-done })
		return result
	}
}
