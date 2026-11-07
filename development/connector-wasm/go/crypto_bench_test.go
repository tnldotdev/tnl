package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var cryptoBenchmarkAlgorithms = []struct {
	name    string
	keySize int
	newAEAD func([]byte) (cipher.AEAD, error)
}{
	{"ChaCha20Poly1305", chacha20poly1305.KeySize, chacha20poly1305.New},
	{"AES128GCM", 16, cryptoBenchmarkGCM},
	{"AES256GCM", 32, cryptoBenchmarkGCM},
}

var cryptoBenchmarkSizes = [...]int{128, 1200, 16384}

func cryptoBenchmarkGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func TestCryptoAEADRoundTrip(t *testing.T) {
	for _, algorithm := range cryptoBenchmarkAlgorithms {
		for _, size := range cryptoBenchmarkSizes {
			t.Run(fmt.Sprintf("%s/%d", algorithm.name, size), func(t *testing.T) {
				aead, err := algorithm.newAEAD(make([]byte, algorithm.keySize))
				if err != nil {
					t.Fatal(err)
				}
				plaintext := bytes.Repeat([]byte{0x42}, size)
				nonce := make([]byte, aead.NonceSize())
				aad := []byte{23, 3, 3, 0, 0}
				ciphertext := aead.Seal(nil, nonce, plaintext, aad)
				opened, err := aead.Open(nil, nonce, ciphertext, aad)
				if err != nil || !bytes.Equal(opened, plaintext) {
					t.Fatalf("round trip failed: %v", err)
				}
				ciphertext[len(ciphertext)-1] ^= 1
				if _, err := aead.Open(nil, nonce, ciphertext, aad); err == nil {
					t.Fatal("modified authentication tag accepted")
				}
			})
		}
	}
}

// these primitive-only measurements use public synthetic keys and data, not
// production tls records. the five-byte aad models a record header's size only.
// buffers are reused, and each timed seal gets a different nonce. opening the
// same fixture repeatedly does not perform additional encryption.
func BenchmarkCryptoAEAD(b *testing.B) {
	for _, algorithm := range cryptoBenchmarkAlgorithms {
		for _, size := range cryptoBenchmarkSizes {
			for _, operation := range []string{"seal", "open"} {
				b.Run(fmt.Sprintf("%s/%d/%s", algorithm.name, size, operation), func(b *testing.B) {
					aead, err := algorithm.newAEAD(make([]byte, algorithm.keySize))
					if err != nil {
						b.Fatal(err)
					}
					plaintext := bytes.Repeat([]byte{0x42}, size)
					nonce := make([]byte, aead.NonceSize())
					aad := []byte{23, 3, 3, 0, 0}
					ciphertext := aead.Seal(nil, nonce, plaintext, aad)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					if operation == "seal" {
						var sequence uint64
						for b.Loop() {
							sequence++
							binary.LittleEndian.PutUint64(nonce[len(nonce)-8:], sequence)
							ciphertext = aead.Seal(ciphertext[:0], nonce, plaintext, aad)
						}
					} else {
						for b.Loop() {
							plaintext, err = aead.Open(plaintext[:0], nonce, ciphertext, aad)
							if err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		}
	}
}
