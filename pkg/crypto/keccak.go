package crypto

import (
	"encoding/binary"
	"golang.org/x/crypto/sha3"
)

// Keccak256 computes the EVM-native keccak256 hash.
// Uses golang.org/x/crypto/sha3.NewLegacyKeccak256.
func Keccak256(data ...[]byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hash.Write(d)
	}
	var out [32]byte
	hash.Sum(out[:0])
	return out
}

// HResp computes the v5 response commitment: keccak256(K ∥ C_plaintext)
func HResp(key [32]byte, plaintext []byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(key[:])
	hash.Write(plaintext)
	var out [32]byte
	hash.Sum(out[:0])
	return out
}

// MerkleLeaf computes: keccak256(FileID ∥ ChunkIndex ∥ Length ∥ C_plaintext)
func MerkleLeaf(fileID [32]byte, index uint64, length uint32, plaintext []byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()

	// FileID
	hash.Write(fileID[:])

	// ChunkIndex (8 bytes, BigEndian)
	var idxBytes [8]byte
	binary.BigEndian.PutUint64(idxBytes[:], index)
	hash.Write(idxBytes[:])

	// Length (4 bytes, BigEndian)
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], length)
	hash.Write(lenBytes[:])

	// C_plaintext
	hash.Write(plaintext)

	var out [32]byte
	hash.Sum(out[:0])
	return out
}
