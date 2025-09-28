package krypto_test

import (
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

	t.Run("error when key too short", func(t *testing.T) {
		t.Parallel()

		_, err := krypto.NewChaCha20Crypto(make([]byte, 0))
		require.ErrorContains(t, err, "chacha20poly1305: bad key length")
	})

	t.Run("implements krypto.Krypto interface", func(t *testing.T) {
		t.Parallel()

		var _ krypto.Krypto = (*krypto.ChaCha20Crypto)(nil)
	})
}

func TestChaCha20Crypto(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) krypto.Krypto {
		t.Helper()

		password := []byte("securepassword")
		salt := []byte("randomsaltrandomsalt")

		key, err := krypto.DeriveKeyFromPassword(t.Context(), password, salt, krypto.DefaultArgon2idParams(), keySize)
		require.NoError(t, err)

		cipher, err := krypto.NewChaCha20Crypto(key)
		require.NoError(t, err)

		return cipher
	}

	t.Run("encrypt and decrypt successfully", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("Hello, World!")
		authData := []byte("auth-data")
		cipher := setup(t)

		ciphertext, nonce, err := cipher.Encrypt(t.Context(), plaintext, authData)
		require.NoError(t, err)

		decrypted, err := cipher.Decrypt(t.Context(), ciphertext, nonce, authData)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)
	})

	t.Run("error when invalid auth data", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("Hello, World!")
		authData := []byte("auth-data")
		cipher := setup(t)

		ciphertext, nonce, err := cipher.Encrypt(t.Context(), plaintext, authData)
		require.NoError(t, err)

		_, err = cipher.Decrypt(t.Context(), ciphertext, nonce, []byte("different-auth-data"))
		require.ErrorContains(t, err, "decryption failed: chacha20poly1305: message authentication failed")
	})
}
