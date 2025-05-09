package chacha_test

import (
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto/chacha"
	"github.com/HallyG/vaultfile/internal/krypto/key"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keySize = chacha20poly1305.KeySize
)

func TestNewChaCha20Crypto(t *testing.T) {
	t.Run("error when key too short", func(t *testing.T) {
		t.Parallel()

		_, err := chacha.New(make([]byte, 0))
		require.ErrorContains(t, err, "chacha20poly1305: bad key length")
	})
}

func TestChaCha20Crypto(t *testing.T) {
	password := []byte("securepassword")
	salt := []byte("randomsaltrandomsalt")

	key, err := key.DeriveKeyFromPassword(t.Context(), password, salt, key.DefaultArgon2idParams(), keySize)
	require.NoError(t, err)

	cipher, err := chacha.New(key)
	require.NoError(t, err)

	t.Run("encrypt and decrypt successfully", func(t *testing.T) {
		t.Parallel()

		plaintext := []byte("Hello, World!")
		authData := []byte("auth-data")

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

		ciphertext, nonce, err := cipher.Encrypt(t.Context(), plaintext, authData)
		require.NoError(t, err)

		_, err = cipher.Decrypt(t.Context(), ciphertext, nonce, []byte("different-auth-data"))
		require.ErrorContains(t, err, "decryption failed: chacha20poly1305: message authentication failed")
	})
}
