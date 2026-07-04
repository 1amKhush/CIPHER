package main

import (
	"context"
	"encoding/hex"
	"flag"
	"os"

	"github.com/1amKhush/CIPHER/pkg/logger"
	"github.com/1amKhush/CIPHER/pkg/p2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	providerAddr := flag.String("provider", "", "Provider multiaddr")
	rootHex := flag.String("root", "", "Merkle root in hex")
	chunksCount := flag.Uint64("chunks", 4, "Number of chunks to download")
	relayAddr := flag.String("relay", "", "Relay multiaddr to connect to (optional)")
	verbose := flag.Bool("verbose", false, "Enable verbose debug logging")
	flag.Parse()

	cfg := logger.DefaultConfig()
	if *verbose {
		cfg.Level = "debug"
	}
	logger.Init(cfg)

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
		RelayAddr:   *relayAddr,
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

	outFile, err := os.Create("downloaded_file.txt")
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create output file")
	}
	defer outFile.Close()

	for i := uint64(0); i < *chunksCount; i++ {
		plaintext, err := p2p.RequestChunk(context.Background(), h, info.ID, fileID, merkleRoot, i, privKey)
		if err != nil {
			logger.Fatal().Err(err).Msgf("Failed to request chunk %d", i)
		}

		if _, err := outFile.Write(plaintext); err != nil {
			logger.Fatal().Err(err).Msgf("Failed to write chunk %d to file", i)
		}

		logger.Info().Msgf("Successfully downloaded chunk %d (%d bytes)", i, len(plaintext))
	}

	logger.Info().Msg("File download complete!")
}
