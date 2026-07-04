package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteMsg writes a length-prefixed message to a stream.
func WriteMsg(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}
	
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write message body: %w", err)
	}
	
	return nil
}

// ReadMsg reads a length-prefixed message from a stream.
func ReadMsg(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}
	
	msgLen := binary.BigEndian.Uint32(lenBuf)
	// Add arbitrary sanity limit to avoid OOM
	if msgLen > 50*1024*1024 { // 50MB
		return nil, fmt.Errorf("message too large: %d bytes", msgLen)
	}
	
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(r, msgBuf); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}
	
	return msgBuf, nil
}
