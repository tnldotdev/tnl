// Package sourceauth authenticates edge-supplied source metadata to a publisher.
package sourceauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/proxyproto"
)

type Purpose byte

const (
	PurposeApplication Purpose = 1
	PurposeACME        Purpose = 2

	requestMagic  = "TNLSRC1Q"
	responseMagic = "TNLSRC1R"
	domain        = "tnl/source-auth/v1\x00"
)

type Claim struct {
	Purpose Purpose
	Header  proxyproto.Header
}

func Client(connection io.ReadWriter, key [32]byte, purpose Purpose, header proxyproto.Header) error {
	if connection == nil || zeroKey(key) || !validPurpose(purpose) {
		return errors.New("sourceauth: invalid client configuration")
	}
	request := make([]byte, len(requestMagic)+32)
	if _, err := io.ReadFull(connection, request); err != nil {
		return err
	}
	if string(request[:len(requestMagic)]) != requestMagic {
		return errors.New("sourceauth: invalid challenge")
	}
	encoded, err := proxyproto.Encode(header)
	if err != nil {
		return err
	}
	prefix := make([]byte, len(responseMagic)+3+len(encoded))
	copy(prefix, responseMagic)
	prefix[len(responseMagic)] = byte(purpose)
	binary.BigEndian.PutUint16(prefix[len(responseMagic)+1:], uint16(len(encoded)))
	copy(prefix[len(responseMagic)+3:], encoded)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(request[len(requestMagic):])
	_, _ = mac.Write(prefix[len(responseMagic):])
	return writeAll(connection, append(prefix, mac.Sum(nil)...))
}

func Server(connection io.ReadWriter, key [32]byte) (Claim, error) {
	if connection == nil || zeroKey(key) {
		return Claim{}, errors.New("sourceauth: invalid server configuration")
	}
	request := make([]byte, len(requestMagic)+32)
	copy(request, requestMagic)
	if _, err := rand.Read(request[len(requestMagic):]); err != nil {
		return Claim{}, err
	}
	if err := writeAll(connection, request); err != nil {
		return Claim{}, err
	}
	fixed := make([]byte, len(responseMagic)+3)
	if _, err := io.ReadFull(connection, fixed); err != nil {
		return Claim{}, err
	}
	if string(fixed[:len(responseMagic)]) != responseMagic {
		return Claim{}, errors.New("sourceauth: invalid response")
	}
	purpose := Purpose(fixed[len(responseMagic)])
	headerLength := int(binary.BigEndian.Uint16(fixed[len(responseMagic)+1:]))
	if !validPurpose(purpose) || headerLength != 28 && headerLength != 52 {
		return Claim{}, errors.New("sourceauth: invalid response metadata")
	}
	rest := make([]byte, headerLength+sha256.Size)
	if _, err := io.ReadFull(connection, rest); err != nil {
		return Claim{}, err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(request[len(requestMagic):])
	_, _ = mac.Write(fixed[len(responseMagic):])
	_, _ = mac.Write(rest[:headerLength])
	if !hmac.Equal(rest[headerLength:], mac.Sum(nil)) {
		return Claim{}, errors.New("sourceauth: invalid response authentication")
	}
	encoded := rest[:headerLength]
	header, _, err := proxyproto.Decode(bytes.NewReader(encoded))
	if err != nil {
		return Claim{}, err
	}
	canonical, err := proxyproto.Encode(header)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Claim{}, errors.New("sourceauth: noncanonical source metadata")
	}
	return Claim{Purpose: purpose, Header: header}, nil
}

func validPurpose(purpose Purpose) bool {
	return purpose == PurposeApplication || purpose == PurposeACME
}

func zeroKey(key [32]byte) bool {
	return key == [32]byte{}
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		value = value[written:]
	}
	return nil
}
