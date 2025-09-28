package krypto_test

import (
	"context"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keySize = chacha20poly1305.KeySize
)

func TestNewChaCha20Crypto(t *testing.T) {
	t.Parallel()

	t.Run("returns error when key too short", func(t *testing.T) {
		t.Parallel()

		_, err := krypto.NewChaCha20Crypto(make([]byte, 1))
		require.ErrorContains(t, err, "key size must be 32 bytes, got 1")
	})

	t.Run("returns error when nil key", func(t *testing.T) {
		t.Parallel()

		_, err := krypto.NewChaCha20Crypto(nil)
		require.ErrorContains(t, err, "key cannot be nil")
	})

	t.Run("implements krypto.Krypto interface", func(t *testing.T) {
		t.Parallel()

		var _ krypto.Krypto = (*krypto.ChaCha20Crypto)(nil)
	})
}

func TestChaCha20CryptoEncrypt(t *testing.T) {
	t.Parallel()

	t.Run("returns error when nil plaintext", func(t *testing.T) {
		t.Parallel()

		authData := []byte("auth-data")
		cipher := setupCipher(t)

		cipherText, nonce, err := cipher.Encrypt(t.Context(), nil, authData)
		require.ErrorContains(t, err, "plaintext cannot be nil")
		require.Nil(t, cipherText)
		require.Nil(t, nonce)
	})

	t.Run("returns error when context canceled", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("Hello, World!")
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		cipherText, nonce, err := cipher.Encrypt(ctx, plainText, authData)
		require.ErrorContains(t, err, "context canceled")
		require.Nil(t, cipherText)
		require.Nil(t, nonce)
	})
}

func TestChaCha20CryptoDecrypt(t *testing.T) {
	t.Parallel()

	t.Run("returns error when nil ciphertext", func(t *testing.T) {
		t.Parallel()

		nonce := make([]byte, krypto.ChaCha20NonceSize)
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ciphertext, err := cipher.Decrypt(t.Context(), nil, nonce, authData)
		require.ErrorContains(t, err, "ciphertext cannot be nil")
		require.Nil(t, ciphertext)

	})

	t.Run("returns error when nil nonce", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("Hello, World!")
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		cipherText, err := cipher.Decrypt(ctx, cipherText, nil, authData)
		require.ErrorContains(t, err, "nonce cannot be nil")
		require.Nil(t, cipherText)
	})

	t.Run("returns error when unexpected nonce length", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("Hello, World!")
		nonce := []byte("nonce")
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		cipherText, err := cipher.Decrypt(ctx, cipherText, nonce, authData)
		require.ErrorContains(t, err, "nonce size size must be 24 bytes, got 5")
		require.Nil(t, cipherText)
	})

	t.Run("returns error when context canceled", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("Hello, World!")
		nonce := make([]byte, krypto.ChaCha20NonceSize)
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		cipherText, err := cipher.Decrypt(ctx, cipherText, nonce, authData)
		require.ErrorContains(t, err, "context canceled")
		require.Nil(t, cipherText)
	})
}

func TestChaCha20Crypto(t *testing.T) {
	t.Parallel()

	t.Run("can decrypt encrypted plaintext", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("Hello, World!")
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ciphertext, nonce, err := cipher.Encrypt(t.Context(), plainText, authData)
		require.NoError(t, err)

		decrypted, err := cipher.Decrypt(t.Context(), ciphertext, nonce, authData)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
	})

	t.Run("returns error when decrypt with different additional auth data", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("Hello, World!")
		authData := []byte("auth-data")
		cipher := setupCipher(t)

		ciphertext, nonce, err := cipher.Encrypt(t.Context(), plainText, authData)
		require.NoError(t, err)

		_, err = cipher.Decrypt(t.Context(), ciphertext, nonce, []byte("different-auth-data"))
		require.ErrorContains(t, err, "decrypt: chacha20poly1305: message authentication failed")
	})

}

func setupCipher(t *testing.T) krypto.Krypto {
	t.Helper()

	password := []byte("securepassword")
	salt := []byte("randomsaltrandomsalt")
	params := krypto.Argon2idParams{
		MemoryKiB:     1,
		NumIterations: 1,
		NumThreads:    1,
	}

	key, err := krypto.DeriveKeyFromPassword(t.Context(), password, salt, params, keySize)
	require.NoError(t, err)

	cipher, err := krypto.NewChaCha20Crypto(key)
	require.NoError(t, err)

	return cipher
}
