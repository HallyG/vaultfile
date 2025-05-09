package chacha

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/HallyG/vaultfile/internal/krypto"
	"golang.org/x/crypto/chacha20poly1305"
)

var _ krypto.Krypto = (*ChaCha20Crypto)(nil)

const (
	KeySize   = chacha20poly1305.KeySize
	NonceSize = chacha20poly1305.NonceSizeX
)

type ChaCha20Crypto struct {
	cipher cipher.AEAD
}

// New creates a new XChaCha20-Poly1305 cipher with the given key.
func New(key []byte) (*ChaCha20Crypto, error) {
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return &ChaCha20Crypto{
		cipher: cipher,
	}, nil
}

// Encrypts the plaintext with a XChaCha20-Poly1305 cipher.
// The additionalData parameter is optional and is used for additional authenticated data (AAD).
func (c *ChaCha20Crypto) Encrypt(ctx context.Context, plainText []byte, additionalData []byte) (cipherText []byte, nonce []byte, err error) {
	nonce = make([]byte, c.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := c.cipher.Seal(nil, nonce, plainText, additionalData)

	return ciphertext, nonce, nil
}

// Decrypts the plaintext with a XChaCha20-Poly1305 cipher.
// The additionalData parameter is optional and is used for additional authenticated data (AAD).
func (c *ChaCha20Crypto) Decrypt(ctx context.Context, cipherText []byte, nonce []byte, additionalData []byte) (plainText []byte, err error) {
	plaintext, err := c.cipher.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
