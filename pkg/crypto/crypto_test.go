package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateChunkKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("hello world, this is a test chunk")
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text %s does not match original %s", string(decrypted), string(plaintext))
	}
}

func TestKeccak256(t *testing.T) {
	// A simple test to ensure Keccak256 works
	got := Keccak256([]byte("test"))
	expected := [32]byte{0x9c, 0x22, 0xff, 0x5f, 0x21, 0xf0, 0xb8, 0x1b, 0x11, 0x3e, 0x63, 0xf7, 0xdb, 0x6d, 0xa9, 0x4f, 0xed, 0xef, 0x11, 0xb2, 0x11, 0x9b, 0x40, 0x88, 0xb8, 0x96, 0x64, 0xfb, 0x9a, 0x3c, 0xb6, 0x58}
	if got != expected {
		t.Fatalf("unexpected keccak256(\"test\"): got %x expected %x", got, expected)
	}
}
