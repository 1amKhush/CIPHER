package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/1amKhush/CIPHER/pkg/chunker"
	"github.com/1amKhush/CIPHER/pkg/crypto"
	"github.com/1amKhush/CIPHER/pkg/engine"
	"github.com/1amKhush/CIPHER/pkg/logger"
	"github.com/1amKhush/CIPHER/pkg/p2p"
)

func main() {
	port := flag.Int("port", 9000, "Port to listen on")
	relayAddr := flag.String("relay", "", "Relay multiaddr to connect to (optional)")
	verbose := flag.Bool("verbose", false, "Enable verbose debug logging")
	flag.Parse()

	cfg := logger.DefaultConfig()
	if *verbose {
		cfg.Level = "debug"
	}
	logger.Init(cfg)

	// 1. Create a dummy file for MVP if it doesn't exist
	fileName := "test_file.txt"
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		dummyData := make([]byte, 100*1024) // 100 KB
		rand.Read(dummyData)
		os.WriteFile(fileName, dummyData, 0644)
		logger.Info().Msgf("Created dummy file %s (100KB)", fileName)
	} else {
		logger.Info().Msgf("Using existing file %s", fileName)
	}

	// 2. Chunk the file
	chunks, err := chunker.ChunkFile(fileName)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to chunk file")
	}

	// 3. Create Merkle Tree
	var leaves [][32]byte
	for _, c := range chunks {
		var fileID [32]byte // zeroed
		length := uint32(len(c.Data))
		leaf := crypto.MerkleLeaf(fileID, c.Index, length, c.Data)
		leaves = append(leaves, leaf)
	}
	tree := chunker.NewMerkleTree(leaves)

	var fileID [32]byte // zeroed
	store := &engine.ChunkStore{
		FileID:     fileID,
		Chunks:     chunks,
		MerkleTree: tree,
	}

	rootHex := hex.EncodeToString(tree.Root[:])
	logger.Info().Msgf("File processed. Chunks: %d, Root: %s", len(chunks), rootHex)

	// 4. Start libp2p host
	opts := p2p.HostOptions{
		ListenPort:  *port,
		PrivKeyPath: "provider_key.key",
		EnableMDNS:  true,
		RelayAddr:   *relayAddr,
	}
	h, err := p2p.NewHost(context.Background(), opts)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to start host")
	}
	defer h.Close()

	// 5. Register Handler
	h.SetStreamHandler(p2p.ProtocolID, p2p.ProviderStreamHandler(store))

	// 6. Wait for sigint
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	fmt.Println("Shutting down...")
}
