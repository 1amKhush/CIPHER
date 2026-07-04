package p2p

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/1amKhush/CIPHER/pkg/logger"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

const ProtocolID = "/cipher/v5/chunk/1.0.0"

// HostOptions configures the libp2p host.
type HostOptions struct {
	ListenPort  int
	PrivKeyPath string
	EnableMDNS  bool
}

// NewHost creates a new libp2p host for CIPHER.
func NewHost(ctx context.Context, opts HostOptions) (host.Host, error) {
	privKey, err := loadOrGeneratePrivateKey(opts.PrivKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate private key: %w", err)
	}

	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", opts.ListenPort)

	libp2pOpts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(listenAddr),
	}

	h, err := libp2p.New(libp2pOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	if opts.EnableMDNS {
		if err := setupMDNS(h, ProtocolID); err != nil {
			logger.Warn().Err(err).Msg("Failed to setup mDNS discovery")
		} else {
			logger.Info().Msg("mDNS discovery enabled")
		}
	}

	return h, nil
}

// loadOrGeneratePrivateKey loads an Ed25519 private key from a file,
// or generates a new one and saves it if the file doesn't exist.
func loadOrGeneratePrivateKey(path string) (crypto.PrivKey, error) {
	if path == "" {
		// Generate an ephemeral key if no path provided
		priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
		return priv, err
	}

	keyData, err := os.ReadFile(path)
	if err == nil {
		// Try parsing as base64 first
		decoded, decodeErr := base64.StdEncoding.DecodeString(string(keyData))
		if decodeErr == nil {
			keyData = decoded
		}
		
		priv, err := crypto.UnmarshalPrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse existing key file: %w", err)
		}
		return priv, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Generate new key
	logger.Info().Str("path", path).Msg("Generating new libp2p private key")
	priv, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Save as base64
	b64Key := base64.StdEncoding.EncodeToString(keyBytes)
	if err := os.WriteFile(path, []byte(b64Key), 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}

	return priv, nil
}

// GetHostPrivateKey returns the private key for the given host.
func GetHostPrivateKey(h host.Host) crypto.PrivKey {
	return h.Peerstore().PrivKey(h.ID())
}

type discoveryNotifee struct {
	h host.Host
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.h.ID() {
		return
	}
	logger.Debug().Str("peer", pi.ID.String()).Msg("Discovered peer via mDNS")
	// Connect proactively in background
	go func() {
		ctx := context.Background()
		if err := n.h.Connect(ctx, pi); err != nil {
			logger.Debug().Err(err).Str("peer", pi.ID.String()).Msg("Failed to connect to discovered peer")
		} else {
			logger.Info().Str("peer", pi.ID.String()).Msg("Connected to discovered peer")
		}
	}()
}

func setupMDNS(h host.Host, rendezvous string) error {
	svc := mdns.NewMdnsService(h, rendezvous, &discoveryNotifee{h: h})
	return svc.Start()
}
