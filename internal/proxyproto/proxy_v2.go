package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"

	proxy "github.com/pires/go-proxyproto"
)

const (
	v1Signature = "PROXY"
	v2Signature = "\r\n\r\n\x00\r\nQUIT\n"
	ipv4Length  = 12
	ipv6Length  = 36
)

type ErrorCode string

const (
	ErrorInvalidSignature     ErrorCode = "invalid_signature"
	ErrorUnsupportedVersion   ErrorCode = "unsupported_version"
	ErrorUnsupportedCommand   ErrorCode = "unsupported_command"
	ErrorUnsupportedTransport ErrorCode = "unsupported_transport"
	ErrorInvalidLength        ErrorCode = "invalid_length"
	ErrorTruncatedHeader      ErrorCode = "truncated_header"
	ErrorInvalidAddress       ErrorCode = "invalid_address"
	ErrorDuplicateHeader      ErrorCode = "duplicate_header"
)

type ProtocolError struct {
	Code ErrorCode
}

func (e *ProtocolError) Error() string {
	return string(e.Code)
}

type Header struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func Encode(header Header) ([]byte, error) {
	header, ok := normalize(header)
	if !ok {
		return nil, protocolError(ErrorInvalidAddress)
	}

	source := tcpAddress(header.Source)
	destination := tcpAddress(header.Destination)
	encoded := proxy.HeaderProxyFromAddrs(2, source, destination)
	if encoded.Version != 2 || encoded.Command != proxy.PROXY ||
		encoded.TransportProtocol != proxy.TCPv4 && encoded.TransportProtocol != proxy.TCPv6 {
		return nil, protocolError(ErrorInvalidAddress)
	}
	bytes, err := encoded.Format()
	if err != nil {
		return nil, protocolError(ErrorInvalidAddress)
	}
	return bytes, nil
}

func Decode(reader io.Reader) (Header, io.Reader, error) {
	buffered := bufio.NewReaderSize(reader, 64)
	fixed, err := buffered.Peek(16)
	if err != nil {
		return Header{}, nil, protocolError(ErrorTruncatedHeader)
	}
	if !bytes.Equal(fixed[:len(v2Signature)], []byte(v2Signature)) {
		return Header{}, nil, protocolError(ErrorInvalidSignature)
	}
	if fixed[12]>>4 != 2 {
		return Header{}, nil, protocolError(ErrorUnsupportedVersion)
	}
	if fixed[12]&0x0f != 1 {
		return Header{}, nil, protocolError(ErrorUnsupportedCommand)
	}

	family := fixed[13]
	addressLength := int(binary.BigEndian.Uint16(fixed[14:]))
	switch family {
	case byte(proxy.TCPv4):
		if addressLength != ipv4Length {
			return Header{}, nil, protocolError(ErrorInvalidLength)
		}
	case byte(proxy.TCPv6):
		if addressLength != ipv6Length {
			return Header{}, nil, protocolError(ErrorInvalidLength)
		}
	default:
		return Header{}, nil, protocolError(ErrorUnsupportedTransport)
	}
	if _, err := buffered.Peek(16 + addressLength); err != nil {
		return Header{}, nil, protocolError(ErrorTruncatedHeader)
	}

	parsed, err := proxy.Read(buffered)
	if err != nil {
		return Header{}, nil, proxyReadError(err)
	}
	source, destination, ok := parsed.TCPAddrs()
	if !ok {
		return Header{}, nil, protocolError(ErrorInvalidAddress)
	}
	header, ok := headerFromTCP(family, source, destination)
	if !ok {
		return Header{}, nil, protocolError(ErrorInvalidAddress)
	}
	return header, &duplicateGuard{reader: buffered}, nil
}

type duplicateGuard struct {
	reader  *bufio.Reader
	checked bool
}

func (g *duplicateGuard) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if !g.checked {
		first, err := g.reader.Peek(1)
		if err != nil {
			return 0, err
		}
		var signature string
		switch first[0] {
		case v1Signature[0]:
			signature = v1Signature
		case v2Signature[0]:
			signature = v2Signature
		}
		if signature != "" {
			candidate, _ := g.reader.Peek(len(signature))
			if bytes.Equal(candidate, []byte(signature)) {
				return 0, protocolError(ErrorDuplicateHeader)
			}
		}
		g.checked = true
	}
	return g.reader.Read(destination)
}

func tcpAddress(endpoint netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port())}
}

func headerFromTCP(family byte, source, destination *net.TCPAddr) (Header, bool) {
	sourceAddress, sourceOK := netip.AddrFromSlice(source.IP)
	destinationAddress, destinationOK := netip.AddrFromSlice(destination.IP)
	if !sourceOK || !destinationOK || source.Port < 1 || source.Port > 65535 ||
		destination.Port < 1 || destination.Port > 65535 {
		return Header{}, false
	}
	switch family {
	case byte(proxy.TCPv4):
		if !sourceAddress.Is4() || !destinationAddress.Is4() {
			return Header{}, false
		}
	case byte(proxy.TCPv6):
		if sourceAddress.Is4In6() || destinationAddress.Is4In6() {
			return Header{}, false
		}
	}
	return normalize(Header{
		Source:      netip.AddrPortFrom(sourceAddress, uint16(source.Port)),
		Destination: netip.AddrPortFrom(destinationAddress, uint16(destination.Port)),
	})
}

func normalize(header Header) (Header, bool) {
	if !validEndpoint(header.Source) || !validEndpoint(header.Destination) {
		return Header{}, false
	}
	source := header.Source.Addr().Unmap()
	destination := header.Destination.Addr().Unmap()
	if source.Is4() != destination.Is4() {
		return Header{}, false
	}
	return Header{
		Source:      netip.AddrPortFrom(source, header.Source.Port()),
		Destination: netip.AddrPortFrom(destination, header.Destination.Port()),
	}, true
}

func validEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	return address.IsValid() && address.Zone() == "" && !address.IsUnspecified() && endpoint.Port() != 0
}

func proxyReadError(err error) error {
	switch {
	case errors.Is(err, proxy.ErrInvalidLength):
		return protocolError(ErrorInvalidLength)
	case errors.Is(err, proxy.ErrInvalidAddress), errors.Is(err, proxy.ErrInvalidPortNumber):
		return protocolError(ErrorInvalidAddress)
	default:
		return protocolError(ErrorTruncatedHeader)
	}
}

func protocolError(code ErrorCode) error {
	return &ProtocolError{Code: code}
}
