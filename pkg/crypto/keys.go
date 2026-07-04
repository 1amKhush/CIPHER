package crypto

import (
	"crypto/rand"
	"io"
)

// GenerateChunkKey generates a cryptographically random 32-byte key.
func GenerateChunkKey() ([32]byte, error) {
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}
