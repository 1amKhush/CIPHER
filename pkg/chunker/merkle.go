package chunker

import (
	"errors"

	"github.com/1amKhush/CIPHER/pkg/crypto"
)

// MerkleTree represents a Keccak256 Merkle tree.
type MerkleTree struct {
	Leaves [][32]byte
	Root   [32]byte
	layers [][][32]byte
}

// NewMerkleTree builds a Merkle tree from leaf hashes.
// For MVP, simple binary tree. If odd number of leaves, duplicate last leaf.
func NewMerkleTree(leaves [][32]byte) *MerkleTree {
	if len(leaves) == 0 {
		return &MerkleTree{}
	}

	tree := &MerkleTree{
		Leaves: make([][32]byte, len(leaves)),
	}
	copy(tree.Leaves, leaves)

	currentLayer := tree.Leaves
	tree.layers = append(tree.layers, currentLayer)

	for len(currentLayer) > 1 {
		var nextLayer [][32]byte
		for i := 0; i < len(currentLayer); i += 2 {
			left := currentLayer[i]
			right := left
			if i+1 < len(currentLayer) {
				right = currentLayer[i+1]
			}
			nextLayer = append(nextLayer, crypto.Keccak256(left[:], right[:]))
		}
		tree.layers = append(tree.layers, nextLayer)
		currentLayer = nextLayer
	}

	tree.Root = currentLayer[0]
	return tree
}

// Proof returns the Merkle proof (sibling hashes) for the leaf at index.
// The proof is ordered from bottom (leaf's sibling) to top.
func (t *MerkleTree) Proof(index int) ([][32]byte, error) {
	if index < 0 || index >= len(t.Leaves) {
		return nil, errors.New("index out of bounds")
	}

	var proof [][32]byte
	currIdx := index

	for _, layer := range t.layers[:len(t.layers)-1] { // Stop before root
		siblingIdx := currIdx ^ 1 // Flip last bit to get sibling
		if siblingIdx < len(layer) {
			proof = append(proof, layer[siblingIdx])
		} else {
			// If odd number, sibling is the node itself (duplicated)
			proof = append(proof, layer[currIdx])
		}
		currIdx /= 2 // Move up to parent
	}

	return proof, nil
}

// VerifyProof checks a Merkle proof against a root.
func VerifyProof(root, leaf [32]byte, index int, proof [][32]byte) bool {
	curr := leaf
	currIdx := index

	for _, sibling := range proof {
		if currIdx%2 == 0 {
			// curr is left, sibling is right
			curr = crypto.Keccak256(curr[:], sibling[:])
		} else {
			// sibling is left, curr is right
			curr = crypto.Keccak256(sibling[:], curr[:])
		}
		currIdx /= 2
	}

	return curr == root
}

// ComputeFileID returns keccak256(MerkleRoot ∥ originalFileHash)
func ComputeFileID(merkleRoot, fileHash [32]byte) [32]byte {
	return crypto.Keccak256(merkleRoot[:], fileHash[:])
}
