package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"


	"github.com/1amKhush/CIPHER/pkg/logger"
	"github.com/1amKhush/CIPHER/pkg/p2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	providerAddr := flag.String("provider", "", "Provider multiaddr")
	rootHex := flag.String("root", "", "Merkle root in hex")
	chunkIdx := flag.Uint64("chunk", 0, "Chunk index to request")
	flag.Parse()

	if *providerAddr == "" || *rootHex == "" {
		logger.Fatal().Msg("-provider and -root flags are required")
	}

	rootBytes, err := hex.DecodeString(*rootHex)
	if err != nil || len(rootBytes) != 32 {
		logger.Fatal().Err(err).Msg("Invalid merkle root")
	}
	var merkleRoot [32]byte
	copy(merkleRoot[:], rootBytes)

	maddr, err := multiaddr.NewMultiaddr(*providerAddr)
	if err != nil {
		logger.Fatal().Err(err).Msg("Invalid multiaddr")
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to extract peer info")
	}

	opts := p2p.HostOptions{
		ListenPort:  0,
		PrivKeyPath: "client_key.key",
		EnableMDNS:  true,
	}
	h, err := p2p.NewHost(context.Background(), opts)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to start host")
	}
	defer h.Close()

	if err := h.Connect(context.Background(), *info); err != nil {
		logger.Fatal().Err(err).Msg("Failed to connect to provider")
	}
	logger.Info().Msgf("Connected to provider %s", info.ID)

	privKey := p2p.GetHostPrivateKey(h)

	var fileID [32]byte // zeroed
	plaintext, err := p2p.RequestChunk(context.Background(), h, info.ID, fileID, merkleRoot, *chunkIdx, privKey)
	if err != nil {
		logger.Fatal().Err(err).Msg("Chunk request failed")
	}

	logger.Info().Msgf("Successfully received and verified chunk %d! Size: %d bytes", *chunkIdx, len(plaintext))
	
	// Dump first few bytes to verify it's random data and not nil
	fmt.Printf("Chunk head: %x\n", plaintext[:32])
}
