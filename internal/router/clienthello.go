package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
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
	echExt          = 0xfe0d
	acmeTLSALPN     = "acme-tls/1"
)

type ClientHelloErrorCode string

const (
	ErrorMalformedClientHello ClientHelloErrorCode = "malformed_client_hello"
	ErrorClientHelloTooLarge  ClientHelloErrorCode = "client_hello_too_large"
	ErrorTooManyTLSRecords    ClientHelloErrorCode = "too_many_tls_records"
	ErrorMissingSNI           ClientHelloErrorCode = "missing_sni"
	ErrorDuplicateSNI         ClientHelloErrorCode = "duplicate_sni"
	ErrorECHUnsupported       ClientHelloErrorCode = "ech_unsupported"
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
	ServerName        string
	OffersACMETLSALPN bool
	Replay            io.Reader
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

		serverName, offersACME, err := parseClientHello(handshake[4:handshakeLength])
		if err != nil {
			return ClientHello{}, err
		}
		return ClientHello{
			ServerName:        serverName,
			OffersACMETLSALPN: offersACME,
			Replay:            io.MultiReader(bytes.NewReader(buffered.Bytes()), reader),
		}, nil
	}
	return ClientHello{}, clientHelloError(ErrorTooManyTLSRecords)
}

func parseClientHello(body []byte) (string, bool, error) {
	cursor := byteCursor(body)
	if !cursor.skip(2 + 32) {
		return "", false, clientHelloError(ErrorMalformedClientHello)
	}
	sessionID, sessionOK := cursor.vector8()
	cipherSuites, ciphersOK := cursor.vector16()
	compressionMethods, compressionOK := cursor.vector8()
	if !sessionOK || len(sessionID) > 32 ||
		!ciphersOK || len(cipherSuites) < 2 || len(cipherSuites)%2 != 0 ||
		!compressionOK || len(compressionMethods) == 0 {
		return "", false, clientHelloError(ErrorMalformedClientHello)
	}
	if len(cursor) == 0 {
		return "", false, clientHelloError(ErrorMissingSNI)
	}

	extensions, ok := cursor.vector16()
	if !ok || len(cursor) != 0 {
		return "", false, clientHelloError(ErrorMalformedClientHello)
	}

	var serverName string
	offersACME := false
	seenSNI := false
	seenALPN := false
	for len(extensions) > 0 {
		extensionType, typeOK := extensions.uint16()
		extension, extensionOK := extensions.vector16()
		if !typeOK || !extensionOK {
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
			parsedOffersACME, err := parseALPN(extension)
			if err != nil {
				return "", false, err
			}
			offersACME = parsedOffersACME
		case echExt:
			return "", false, clientHelloError(ErrorECHUnsupported)
		}
	}

	if serverName == "" {
		return "", false, clientHelloError(ErrorMissingSNI)
	}
	return serverName, offersACME, nil
}

func parseServerName(data byteCursor) (string, error) {
	names, ok := data.vector16()
	if !ok || len(data) != 0 {
		return "", clientHelloError(ErrorMalformedClientHello)
	}

	var serverName string
	for len(names) > 0 {
		nameType, ok := names.uint8()
		if !ok {
			return "", clientHelloError(ErrorMalformedClientHello)
		}
		name, ok := names.vector16()
		if !ok || len(name) == 0 {
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

func parseALPN(data byteCursor) (bool, error) {
	protocolsData, ok := data.vector16()
	if !ok || len(data) != 0 || len(protocolsData) == 0 {
		return false, clientHelloError(ErrorMalformedClientHello)
	}

	offersACME := false
	for len(protocolsData) > 0 {
		protocol, ok := protocolsData.vector8()
		if !ok || len(protocol) == 0 {
			return false, clientHelloError(ErrorMalformedClientHello)
		}
		offersACME = offersACME || bytes.Equal(protocol, []byte(acmeTLSALPN))
	}
	return offersACME, nil
}

type byteCursor []byte

func (c *byteCursor) take(length int) (byteCursor, bool) {
	if length < 0 || len(*c) < length {
		return nil, false
	}
	value := (*c)[:length]
	*c = (*c)[length:]
	return value, true
}

func (c *byteCursor) skip(length int) bool {
	_, ok := c.take(length)
	return ok
}

func (c *byteCursor) uint8() (uint8, bool) {
	value, ok := c.take(1)
	if !ok {
		return 0, false
	}
	return value[0], true
}

func (c *byteCursor) uint16() (uint16, bool) {
	value, ok := c.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(value), true
}

func (c *byteCursor) vector8() (byteCursor, bool) {
	length, ok := c.uint8()
	if !ok {
		return nil, false
	}
	return c.take(int(length))
}

func (c *byteCursor) vector16() (byteCursor, bool) {
	length, ok := c.uint16()
	if !ok {
		return nil, false
	}
	return c.take(int(length))
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
