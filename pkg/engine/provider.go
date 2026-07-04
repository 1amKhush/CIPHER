package engine

import (
	"errors"
	"fmt"
	"github.com/1amKhush/CIPHER/pkg/chunker"
	"github.com/1amKhush/CIPHER/pkg/crypto"
	"github.com/1amKhush/CIPHER/pkg/wire"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

type ChunkStore struct {
	FileID     [32]byte
	Chunks     []chunker.Chunk
	MerkleTree *chunker.MerkleTree
}

func (s *ChunkStore) HandleRequest(req *wire.ChunkRequest) (*wire.ChunkResponse, [32]byte, error) {
	if req.ChunkIndex >= uint64(len(s.Chunks)) {
		return nil, [32]byte{}, fmt.Errorf("chunk index %d out of bounds", req.ChunkIndex)
	}
	if req.FileID != s.FileID {
		return nil, [32]byte{}, errors.New("file ID mismatch")
	}

	chunk := s.Chunks[req.ChunkIndex]
	key, err := crypto.GenerateChunkKey()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to generate key: %w", err)
	}

	ciphertext, err := crypto.Encrypt(key, chunk.Data)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to encrypt chunk: %w", err)
	}

	hresp := crypto.HResp(key, chunk.Data)
	proof, err := s.MerkleTree.Proof(int(req.ChunkIndex))
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to generate proof: %w", err)
	}

	resp := &wire.ChunkResponse{
		Version:     wire.Version,
		MsgType:     wire.TypeResponse,
		Ciphertext:  ciphertext,
		HResp:       hresp,
		MerkleProof: proof,
	}

	return resp, key, nil
}

func (s *ChunkStore) HandleTicket(ticket *wire.LotteryTicket, key [32]byte, pubKey p2pcrypto.PubKey) (*wire.KeyReveal, error) {
	if pubKey != nil {
		ok, err := pubKey.Verify(ticket.DataToSign(), ticket.Signature)
		if err != nil || !ok {
			return nil, errors.New("invalid ticket signature")
		}
	}

	reveal := &wire.KeyReveal{
		Version: wire.Version,
		MsgType: wire.TypeReveal,
		Key:     key,
	}
	return reveal, nil
}
