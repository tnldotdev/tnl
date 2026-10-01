package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	MaxClientHelloBytes    = 64 * 1024
	MaxClientHelloRecords  = 8
	ClientHelloReadTimeout = 5 * time.Second
	maxTLSPlaintext        = 16 * 1024
)

const (
	handshakeRecord = 22
	clientHelloType = 1
	serverNameExt   = 0
	alpnExt         = 16
	acmeTLSALPN     = "acme-tls/1"
)

type ClientHelloErrorCode string

const (
	ErrorMalformedClientHello ClientHelloErrorCode = "malformed_client_hello"
	ErrorClientHelloTooLarge  ClientHelloErrorCode = "client_hello_too_large"
	ErrorTooManyTLSRecords    ClientHelloErrorCode = "too_many_tls_records"
	ErrorMissingSNI           ClientHelloErrorCode = "missing_sni"
	ErrorDuplicateSNI         ClientHelloErrorCode = "duplicate_sni"
	ErrorUnexpectedTLSRecord  ClientHelloErrorCode = "unexpected_tls_record"
	ErrorClientHelloTimeout   ClientHelloErrorCode = "client_hello_timeout"
)

type ClientHelloError struct {
	Code ClientHelloErrorCode
}

func (e *ClientHelloError) Error() string {
	return string(e.Code)
}

type ClientHello struct {
	ServerName  string
	ACMETLSALPN bool
	Prefix      []byte
	Remainder   io.Reader
}

// Replay returns the inspected prefix followed by the unread connection. the
// prefix can be replayed independently until a visitor byte is committed.
func (h ClientHello) Replay() io.Reader {
	return io.MultiReader(bytes.NewReader(h.Prefix), h.Remainder)
}

func InspectClientHello(connection net.Conn) (ClientHello, error) {
	if err := connection.SetReadDeadline(time.Now().Add(ClientHelloReadTimeout)); err != nil {
		return ClientHello{}, clientHelloError(ErrorMalformedClientHello)
	}
	defer connection.SetReadDeadline(time.Time{})
	return inspectClientHello(connection)
}

func inspectClientHello(reader io.Reader) (ClientHello, error) {
	var buffered bytes.Buffer
	var handshake []byte
	handshakeLength := -1

	for range MaxClientHelloRecords {
		var header [5]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return ClientHello{}, clientHelloReadError(err)
		}
		if header[0] != handshakeRecord {
			return ClientHello{}, clientHelloError(ErrorUnexpectedTLSRecord)
		}

		recordLength := int(binary.BigEndian.Uint16(header[3:]))
		if recordLength > maxTLSPlaintext || buffered.Len()+len(header)+recordLength > MaxClientHelloBytes {
			return ClientHello{}, clientHelloError(ErrorClientHelloTooLarge)
		}

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return ClientHello{}, clientHelloReadError(err)
		}
		buffered.Write(header[:])
		buffered.Write(payload)
		handshake = append(handshake, payload...)

		if handshakeLength < 0 && len(handshake) >= 4 {
			if handshake[0] != clientHelloType {
				return ClientHello{}, clientHelloError(ErrorMalformedClientHello)
			}
			handshakeLength = 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if handshakeLength > MaxClientHelloBytes {
				return ClientHello{}, clientHelloError(ErrorClientHelloTooLarge)
			}
		}
		if handshakeLength < 0 || len(handshake) < handshakeLength {
			continue
		}

		serverName, acmeTLSALPN, err := parseClientHello(handshake[4:handshakeLength])
		if err != nil {
			return ClientHello{}, err
		}
		return ClientHello{
			ServerName:  serverName,
			ACMETLSALPN: acmeTLSALPN,
			Prefix:      bytes.Clone(buffered.Bytes()),
			Remainder:   reader,
		}, nil
	}
	return ClientHello{}, clientHelloError(ErrorTooManyTLSRecords)
}

func parseClientHello(body []byte) (string, bool, error) {
	cursor := cryptobyte.String(body)
	var sessionID, cipherSuites, compressionMethods cryptobyte.String
	if !cursor.Skip(2+32) ||
		!cursor.ReadUint8LengthPrefixed(&sessionID) || len(sessionID) > 32 ||
		!cursor.ReadUint16LengthPrefixed(&cipherSuites) || len(cipherSuites) < 2 || len(cipherSuites)%2 != 0 ||
		!cursor.ReadUint8LengthPrefixed(&compressionMethods) || len(compressionMethods) == 0 {
		return "", false, clientHelloError(ErrorMalformedClientHello)
	}
	if cursor.Empty() {
		return "", false, clientHelloError(ErrorMissingSNI)
	}

	var extensions cryptobyte.String
	if !cursor.ReadUint16LengthPrefixed(&extensions) || !cursor.Empty() {
		return "", false, clientHelloError(ErrorMalformedClientHello)
	}

	var serverName string
	acmeTLSALPN := false
	seenSNI := false
	seenALPN := false
	for !extensions.Empty() {
		var extensionType uint16
		var extension cryptobyte.String
		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&extension) {
			return "", false, clientHelloError(ErrorMalformedClientHello)
		}

		switch extensionType {
		case serverNameExt:
			if seenSNI {
				return "", false, clientHelloError(ErrorDuplicateSNI)
			}
			seenSNI = true
			parsedServerName, err := parseServerName(extension)
			if err != nil {
				return "", false, err
			}
			serverName = parsedServerName
		case alpnExt:
			if seenALPN {
				return "", false, clientHelloError(ErrorMalformedClientHello)
			}
			seenALPN = true
			parsedACMETLSALPN, err := parseALPN(extension)
			if err != nil {
				return "", false, err
			}
			acmeTLSALPN = parsedACMETLSALPN
		}
	}

	if serverName == "" {
		return "", false, clientHelloError(ErrorMissingSNI)
	}
	return serverName, acmeTLSALPN, nil
}

func parseServerName(data cryptobyte.String) (string, error) {
	var names cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&names) || !data.Empty() {
		return "", clientHelloError(ErrorMalformedClientHello)
	}

	var serverName string
	for !names.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) || name.Empty() {
			return "", clientHelloError(ErrorMalformedClientHello)
		}
		if nameType == 0 {
			if serverName != "" {
				return "", clientHelloError(ErrorDuplicateSNI)
			}
			serverName = string(name)
		}
	}
	if serverName == "" {
		return "", clientHelloError(ErrorMissingSNI)
	}
	return serverName, nil
}

func parseALPN(data cryptobyte.String) (bool, error) {
	var protocols cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&protocols) || !data.Empty() || protocols.Empty() {
		return false, clientHelloError(ErrorMalformedClientHello)
	}

	count := 0
	onlyACME := false
	for !protocols.Empty() {
		var protocol cryptobyte.String
		if !protocols.ReadUint8LengthPrefixed(&protocol) || protocol.Empty() {
			return false, clientHelloError(ErrorMalformedClientHello)
		}
		count++
		onlyACME = bytes.Equal(protocol, []byte(acmeTLSALPN))
	}
	return count == 1 && onlyACME, nil
}

func clientHelloError(code ClientHelloErrorCode) error {
	return &ClientHelloError{Code: code}
}

func clientHelloReadError(err error) error {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return clientHelloError(ErrorClientHelloTimeout)
	}
	return clientHelloError(ErrorMalformedClientHello)
}
