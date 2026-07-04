package chunker

import (
	"bytes"
	"io"
	"os"
)

const ChunkSize = 32768 // 32 KB

type Chunk struct {
	Index uint64
	Data  []byte
}

// ChunkFile reads a file and splits it into 32 KB chunks.
func ChunkFile(path string) ([]Chunk, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ChunkBytes(data), nil
}

// ChunkBytes splits a byte slice into 32 KB chunks.
func ChunkBytes(data []byte) []Chunk {
	var chunks []Chunk
	var index uint64
	buf := bytes.NewBuffer(data)

	for {
		chunkData := make([]byte, ChunkSize)
		n, err := io.ReadFull(buf, chunkData)
		if n > 0 {
			chunks = append(chunks, Chunk{
				Index: index,
				Data:  chunkData[:n],
			})
			index++
		}
		if err != nil {
			break
		}
	}
	return chunks
}
