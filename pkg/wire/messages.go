package wire

import (
	"encoding/binary"
	"errors"
)

const (
	Version      = 0x01
	TypeRequest  = 0x01
	TypeResponse = 0x02
	TypeTicket   = 0x03
	TypeReveal   = 0x04
)

// ChunkRequest is sent by client to provider. (74 bytes)
type ChunkRequest struct {
	Version    uint8
	MsgType    uint8
	ChunkIndex uint64
	Nonce      [32]byte
	FileID     [32]byte
}

func (m *ChunkRequest) Marshal() []byte {
	buf := make([]byte, 74)
	buf[0] = m.Version
	buf[1] = m.MsgType
	binary.BigEndian.PutUint64(buf[2:10], m.ChunkIndex)
	copy(buf[10:42], m.Nonce[:])
	copy(buf[42:74], m.FileID[:])
	return buf
}

func (m *ChunkRequest) Unmarshal(data []byte) error {
	if len(data) < 74 {
		return errors.New("ChunkRequest too short")
	}
	if data[0] != Version || data[1] != TypeRequest {
		return errors.New("unexpected ChunkRequest version or type")
	}
	m.Version = data[0]
	m.MsgType = data[1]
	m.ChunkIndex = binary.BigEndian.Uint64(data[2:10])
	copy(m.Nonce[:], data[10:42])
	copy(m.FileID[:], data[42:74])
	return nil
}

// ChunkResponse is sent by provider to client. (Variable length)
type ChunkResponse struct {
	Version     uint8
	MsgType     uint8
	Ciphertext  []byte // Variable length
	HResp       [32]byte
	MerkleProof [][32]byte // Variable depth
}

func (m *ChunkResponse) Marshal() []byte {
	cLen := len(m.Ciphertext)
	pLen := len(m.MerkleProof)
	totalLen := 1 + 1 + 4 + cLen + 32 + 4 + (pLen * 32)
	buf := make([]byte, totalLen)

	buf[0] = m.Version
	buf[1] = m.MsgType

	binary.BigEndian.PutUint32(buf[2:6], uint32(cLen))
	offset := 6
	copy(buf[offset:offset+cLen], m.Ciphertext)
	offset += cLen

	copy(buf[offset:offset+32], m.HResp[:])
	offset += 32

	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(pLen))
	offset += 4

	for _, hash := range m.MerkleProof {
		copy(buf[offset:offset+32], hash[:])
		offset += 32
	}

	return buf
}

func (m *ChunkResponse) Unmarshal(data []byte) error {
	if len(data) < 42 { // Min length: version+type(2) + clen(4) + hresp(32) + plen(4)
		return errors.New("ChunkResponse too short")
	}
	if data[0] != Version || data[1] != TypeResponse {
		return errors.New("unexpected ChunkResponse version or type")
	}
	m.Version = data[0]
	m.MsgType = data[1]

	cLen := int(binary.BigEndian.Uint32(data[2:6]))
	offset := 6

	if len(data) < offset+cLen+36 {
		return errors.New("ChunkResponse missing ciphertext or trailing data")
	}

	m.Ciphertext = make([]byte, cLen)
	copy(m.Ciphertext, data[offset:offset+cLen])
	offset += cLen

	copy(m.HResp[:], data[offset:offset+32])
	offset += 32

	pLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if len(data) < offset+(pLen*32) {
		return errors.New("ChunkResponse missing merkle proof hashes")
	}

	m.MerkleProof = make([][32]byte, pLen)
	for i := 0; i < pLen; i++ {
		copy(m.MerkleProof[i][:], data[offset:offset+32])
		offset += 32
	}

	return nil
}

// LotteryTicket is sent by client to provider. (Variable length for sig)
type LotteryTicket struct {
	Version      uint8
	MsgType      uint8
	ChannelID    [32]byte
	ProviderAddr [20]byte // Note: ETH address
	HResp        [32]byte
	TargetBlock  uint64
	WinProb      uint32
	Signature    []byte
}

func (m *LotteryTicket) Marshal() []byte {
	sigLen := len(m.Signature)
	totalLen := 1 + 1 + 32 + 20 + 32 + 8 + 4 + 4 + sigLen // +4 for sig length prefix
	buf := make([]byte, totalLen)

	buf[0] = m.Version
	buf[1] = m.MsgType
	offset := 2

	copy(buf[offset:offset+32], m.ChannelID[:])
	offset += 32

	copy(buf[offset:offset+20], m.ProviderAddr[:])
	offset += 20

	copy(buf[offset:offset+32], m.HResp[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], m.TargetBlock)
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:offset+4], m.WinProb)
	offset += 4

	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(sigLen))
	offset += 4

	copy(buf[offset:offset+sigLen], m.Signature)

	return buf
}

// DataToSign returns the portion of the ticket that is signed
func (m *LotteryTicket) DataToSign() []byte {
	// Sign everything before the signature prefix (96 bytes total)
	buf := make([]byte, 32+20+32+8+4)
	offset := 0

	copy(buf[offset:offset+32], m.ChannelID[:])
	offset += 32

	copy(buf[offset:offset+20], m.ProviderAddr[:])
	offset += 20

	copy(buf[offset:offset+32], m.HResp[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], m.TargetBlock)
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:offset+4], m.WinProb)
	return buf
}

func (m *LotteryTicket) Unmarshal(data []byte) error {
	if len(data) < 102 { // 2 + 32 + 20 + 32 + 8 + 4 + 4
		return errors.New("LotteryTicket too short")
	}
	m.Version = data[0]
	m.MsgType = data[1]
	offset := 2

	copy(m.ChannelID[:], data[offset:offset+32])
	offset += 32

	copy(m.ProviderAddr[:], data[offset:offset+20])
	offset += 20

	copy(m.HResp[:], data[offset:offset+32])
	offset += 32

	m.TargetBlock = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	m.WinProb = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	sigLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	if len(data) < offset+sigLen {
		return errors.New("LotteryTicket missing signature data")
	}

	m.Signature = make([]byte, sigLen)
	copy(m.Signature, data[offset:offset+sigLen])

	return nil
}

// KeyReveal is sent by provider to client. (34 bytes)
type KeyReveal struct {
	Version uint8
	MsgType uint8
	Key     [32]byte
}

func (m *KeyReveal) Marshal() []byte {
	buf := make([]byte, 34)
	buf[0] = m.Version
	buf[1] = m.MsgType
	copy(buf[2:34], m.Key[:])
	return buf
}

func (m *KeyReveal) Unmarshal(data []byte) error {
	if len(data) < 34 {
		return errors.New("KeyReveal too short")
	}
	m.Version = data[0]
	m.MsgType = data[1]
	copy(m.Key[:], data[2:34])
	return nil
}
