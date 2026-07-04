package engine

import (
	"errors"
	"fmt"
	"github.com/1amKhush/CIPHER/pkg/chunker"
	"github.com/1amKhush/CIPHER/pkg/crypto"
	"github.com/1amKhush/CIPHER/pkg/wire"
)

// VerifyResponse checks ciphertext bounds but defers Merkle proof until key reveal.
func VerifyResponse(resp *wire.ChunkResponse) error {
	if len(resp.Ciphertext) < 40 {
		return errors.New("ciphertext too short")
	}
	return nil
}

// VerifyReveal decrypts with K, checks HResp, and verifies Merkle proof.
func VerifyReveal(reveal *wire.KeyReveal, resp *wire.ChunkResponse, merkleRoot, fileID [32]byte, chunkIndex uint64) ([]byte, error) {
	plaintext, err := crypto.Decrypt(reveal.Key, resp.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt chunk: %w", err)
	}

	hresp := crypto.HResp(reveal.Key, plaintext)
	if hresp != resp.HResp {
		return nil, errors.New("HResp verification failed: commitment mismatch")
	}

	length := uint32(len(plaintext))
	leaf := crypto.MerkleLeaf(fileID, chunkIndex, length, plaintext)
	if !chunker.VerifyProof(merkleRoot, leaf, int(chunkIndex), resp.MerkleProof) {
		return nil, errors.New("merkle proof verification failed")
	}

	return plaintext, nil
}
