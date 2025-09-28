package krypto

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChaCha20KeySize   = chacha20poly1305.KeySize
	ChaCha20NonceSize = chacha20poly1305.NonceSizeX
)

type ChaCha20Crypto struct {
	cipher cipher.AEAD
}

// New creates a new XChaCha20-Poly1305 cipher with the given key.
func NewChaCha20Crypto(key []byte) (*ChaCha20Crypto, error) {
	if key == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}

	if len(key) != ChaCha20KeySize {
		return nil, fmt.Errorf("key size must be %d bytes, got %d", ChaCha20KeySize, len(key))
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create chacha20poly1305 cipher: %w", err)
	}

	return &ChaCha20Crypto{
		cipher: cipher,
	}, nil
}

// Encrypts the plaintext with a XChaCha20-Poly1305 cipher.
// The additionalData parameter is optional and is used for additional authenticated data (AAD).
func (c *ChaCha20Crypto) Encrypt(ctx context.Context, plainText []byte, additionalData []byte) (cipherText []byte, nonce []byte, err error) {
	if plainText == nil {
		return nil, nil, fmt.Errorf("plaintext cannot be nil")
	}

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	nonce = make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("random nonce: %w", err)
	}

	ciphertext := c.cipher.Seal(nil, nonce, plainText, additionalData)

	return ciphertext, nonce, nil
}

// Decrypts the plaintext with a XChaCha20-Poly1305 cipher.
// The additionalData parameter is optional and is used for additional authenticated data (AAD).
func (c *ChaCha20Crypto) Decrypt(ctx context.Context, cipherText []byte, nonce []byte, additionalData []byte) (plainText []byte, err error) {
	if cipherText == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}

	if nonce == nil {
		return nil, fmt.Errorf("nonce cannot be nil")
	}

	if len(nonce) != c.cipher.NonceSize() {
		return nil, fmt.Errorf("nonce size size must be %d bytes, got %d", c.cipher.NonceSize(), len(nonce))
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	plaintext, err := c.cipher.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
