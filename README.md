# CIPHER

CDNs are owned by a handful of companies. CIPHER is the alternative - a decentralized content delivery protocol where math replaces the middleman.

## CIPHER v5 MVP - Zero-Cost P2P Transport

This MVP demonstrates a direct, end-to-end encrypted file transfer between two isolated peers (behind NATs/firewalls) using Libp2p's circuit relay and hole-punching mechanisms, verified by a Merkle Tree.

### Demo Instructions

To run the demo, you will need two separate terminal windows. For a true test of hole-punching, run them on two different networks (e.g., your home Wi-Fi and a mobile hotspot).

**1. Start the Provider**
The provider will create a dummy 100KB file (`test_file.txt`), chunk it, encrypt it, build a Merkle tree, and connect to the public relay to await requests.

```bash
go run ./cmd/provider -relay /dns4/relay-torrentium-3zok.onrender.com/tcp/443/wss/p2p/12D3KooWEBxhvkASAJtmdeKWiWWhdXCzwXEVvSMpjuY8YrDAi68Z -verbose
```

Wait for it to output the `Root` hash and the `Successfully reserved slot on relay: ...` message. It will also print its Peer ID (e.g., `12D3KooW...`).

**2. Start the Client**
In another terminal (or on another machine), run the client. You need to pass the provider's full relay multiaddress and the Merkle root hash.

Construct the provider multiaddress by appending `/p2p-circuit/p2p/<PROVIDER_PEER_ID>` to the relay address.

```bash
go run ./cmd/client \
  -provider /dns4/relay-torrentium-3zok.onrender.com/tcp/443/wss/p2p/12D3KooWEBxhvkASAJtmdeKWiWWhdXCzwXEVvSMpjuY8YrDAi68Z/p2p-circuit/p2p/<PROVIDER_PEER_ID> \
  -root <MERKLE_ROOT_HASH> \
  -chunks 4 \
  -verbose
```

**Example:**
```bash
go run ./cmd/client -provider /dns4/relay-torrentium-3zok.onrender.com/tcp/443/wss/p2p/12D3KooWEBxhvkASAJtmdeKWiWWhdXCzwXEVvSMpjuY8YrDAi68Z/p2p-circuit/p2p/12D3KooWRLLKMNyUgQADWFivKBCRBprPM9BmeA8mV1i5XcwXeqFE -root e8a5757c212a4f78667a2dd306c4cae63bd281816947f9cacc55ff7fa3e5db50 -chunks 4 -verbose
```

The client will connect through the relay, negotiate a hole-punch if possible, request the chunks, decrypt them, verify them against the Merkle root, and save the result as `downloaded_file.txt`.

### Architecture Features
* **Chunking & Encryption**: AES-256-GCM symmetric encryption for every 32KB chunk.
* **Merkle Integrity**: Keccak256-based Merkle tree ensures that every decrypted byte belongs to the original file.
* **Transport**: QUIC, TCP, and Secure WebSockets over Libp2p.
* **Hole-Punching**: Libp2p `circuitv2` relay bootstrapping with automatic DCUtR (Direct Connection Upgrade through Relay).
