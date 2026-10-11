package publisher

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
)

const mysqlAuthenticationPacketLimit = 1 << 20

// mysql has a server-first greeting. advertise TLS to the visiting client
// without changing the private server's challenge or authentication plugin.
func advertiseMySQLTLS(packet []byte) ([]byte, error) {
	if len(packet) < 5 || packet[4] != 10 {
		return nil, errors.New("publisher: invalid MySQL target greeting")
	}
	versionEnd := bytes.IndexByte(packet[5:], 0)
	if versionEnd < 0 {
		return nil, errors.New("publisher: invalid MySQL target version")
	}
	capabilities := 5 + versionEnd + 1 + 4 + 8 + 1
	if len(packet) < capabilities+2+1+2+2+1+10 {
		return nil, errors.New("publisher: incomplete MySQL target greeting")
	}
	authLength := int(packet[capabilities+2+1+2+2])
	challenge := capabilities + 2 + 1 + 2 + 2 + 1 + 10
	if len(packet) < challenge+max(13, authLength-8) {
		return nil, errors.New("publisher: incomplete MySQL target challenge")
	}
	scramble := append([]byte(nil), packet[capabilities-9:capabilities-1]...)
	scramble = append(scramble, packet[challenge:challenge+max(13, authLength-8)]...)
	if len(scramble) < 20 {
		return nil, errors.New("publisher: invalid MySQL target challenge")
	}
	binary.LittleEndian.PutUint16(packet[capabilities:capabilities+2],
		binary.LittleEndian.Uint16(packet[capabilities:capabilities+2])|mysqlClientSSL)
	return scramble[:20], nil
}

// the visitor's SSLRequest adds a packet the private server has not seen.
// translate authentication packet numbers until OK or ERR; command packets
// have their own sequence starting at zero and can then be copied unchanged.
func forwardMySQLAuthentication(visitor, backend net.Conn, scramble []byte, clientFlags *uint32) error {
	visitorSequence, backendSequence := byte(2), byte(1)
	for step := 0; step < 32; step++ {
		if step == 0 {
			response, err := readMySQLPacket(visitor, mysqlAuthenticationPacketLimit)
			if err != nil {
				return err
			}
			if response[3] != visitorSequence || len(response) < 8 {
				return errors.New("publisher: invalid MySQL visitor login packet")
			}
			visitorSequence++
			flags := binary.LittleEndian.Uint32(response[4:8])
			*clientFlags = flags
			binary.LittleEndian.PutUint32(response[4:8], flags&^mysqlClientSSL)
			response[3] = backendSequence
			backendSequence++
			if _, err := io.Copy(backend, bytes.NewReader(response)); err != nil {
				return err
			}
		}
		response, err := readMySQLPacket(backend, mysqlAuthenticationPacketLimit)
		if err != nil {
			return err
		}
		if response[3] != backendSequence {
			return errors.New("publisher: invalid MySQL target authentication sequence")
		}
		backendSequence++
		if len(response) < 5 {
			return errors.New("publisher: empty MySQL target authentication packet")
		}
		if response[4] == 1 && len(response) == 6 && response[5] == 4 {
			// caching_sha2_password requires an RSA-encrypted password when the
			// target is plaintext. fetch its public key without exposing the
			// extra exchange to the TLS-protected visiting client.
			request := encodeMySQLPacket(backendSequence, []byte{2})
			backendSequence++
			if _, err := io.Copy(backend, bytes.NewReader(request)); err != nil {
				return err
			}
			key, err := readMySQLPacket(backend, 16<<10)
			if err != nil {
				return err
			}
			if key[3] != backendSequence || len(key) < 6 || key[4] != 1 {
				return errors.New("publisher: invalid MySQL target public key response")
			}
			backendSequence++
			response[3] = visitorSequence
			visitorSequence++
			if _, err := io.Copy(visitor, bytes.NewReader(response)); err != nil {
				return err
			}
			password, err := readMySQLPacket(visitor, 512)
			if err != nil {
				return err
			}
			if password[3] != visitorSequence || len(password) < 5 || password[len(password)-1] != 0 {
				return errors.New("publisher: invalid MySQL visitor password response")
			}
			visitorSequence++
			ciphertext, err := encryptMySQLPassword(password[4:], scramble, key[5:])
			clear(password)
			if err != nil {
				return err
			}
			login := encodeMySQLPacket(backendSequence, ciphertext)
			backendSequence++
			if _, err := io.Copy(backend, bytes.NewReader(login)); err != nil {
				return err
			}
			continue
		}
		response[3] = visitorSequence
		visitorSequence++
		if _, err := io.Copy(visitor, bytes.NewReader(response)); err != nil {
			return err
		}
		if response[4] == 0 || response[4] == 0xff {
			return nil
		}
		if response[4] == 1 && len(response) == 6 && response[5] == 3 {
			continue // fast authentication succeeded; wait for the server's OK.
		}
		login, err := readMySQLPacket(visitor, mysqlAuthenticationPacketLimit)
		if err != nil {
			return err
		}
		if login[3] != visitorSequence {
			return errors.New("publisher: invalid MySQL visitor authentication sequence")
		}
		visitorSequence++
		login[3] = backendSequence
		backendSequence++
		if _, err := io.Copy(backend, bytes.NewReader(login)); err != nil {
			return err
		}
	}
	return errors.New("publisher: MySQL authentication exchange exceeded its limit")
}

func encodeMySQLPacket(sequence byte, payload []byte) []byte {
	packet := make([]byte, len(payload)+4)
	packet[0], packet[1], packet[2], packet[3] = byte(len(payload)), byte(len(payload)>>8), byte(len(payload)>>16), sequence
	copy(packet[4:], payload)
	return packet
}

func encryptMySQLPassword(password, scramble, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil || len(scramble) == 0 {
		return nil, errors.New("publisher: invalid MySQL target public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("publisher: MySQL target public key is not RSA")
	}
	plain := make([]byte, len(password))
	copy(plain, password)
	defer clear(plain)
	for index := range plain {
		plain[index] ^= scramble[index%len(scramble)]
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, key, plain, nil)
}
