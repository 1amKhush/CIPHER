package chunker

import (
	"crypto/rand"
	"testing"
)

func TestChunkBytes(t *testing.T) {
	// 100 KB data
	data := make([]byte, 100*1024)
	rand.Read(data)

	chunks := ChunkBytes(data)

	// 100 KB / 32 KB = 3 chunks of 32 KB, 1 chunk of 4 KB
	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}

	if len(chunks[0].Data) != ChunkSize {
		t.Errorf("expected first chunk to be %d bytes, got %d", ChunkSize, len(chunks[0].Data))
	}
	if len(chunks[3].Data) != 100*1024-(3*ChunkSize) {
		t.Errorf("expected last chunk to be 4096 bytes, got %d", len(chunks[3].Data))
	}
}

func TestMerkleTree(t *testing.T) {
	// 5 leaves
	var leaves [][32]byte
	for i := 0; i < 5; i++ {
		var leaf [32]byte
		rand.Read(leaf[:])
		leaves = append(leaves, leaf)
	}

	tree := NewMerkleTree(leaves)

	for i := 0; i < 5; i++ {
		proof, err := tree.Proof(i)
		if err != nil {
			t.Fatalf("failed to generate proof for leaf %d: %v", i, err)
		}

		if !VerifyProof(tree.Root, leaves[i], i, proof) {
			t.Errorf("failed to verify proof for leaf %d", i)
		}
	}
}
