package vault_test

import (
	"bytes"
	"context"
	"math"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*

	password := []byte("some-long-password")
	v := setupVault(t)

	var buf bytes.Buffer
	err := v.Encrypt(t.Context(), &buf, password, plainText)
	require.NoError(t, err)

	return v, buf.Bytes(), plainText, password

*/

func TestV1Format(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (*vault.Vault, []byte) {
		t.Helper()

		password := []byte("some-long-password")
		v := setupVault(t)

		return v, password
	}

	t.Run("version is v1", func(t *testing.T) {
		t.Parallel()

		v := setupVault(t)
		require.Equal(t, format.VersionV1, v.Version())
	})

	t.Run("returns error when nil writer", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		err := v.Encrypt(t.Context(), nil, password, plainText)
		require.ErrorContains(t, err, "output writer cannot be nil")
	})

	t.Run("returns error when nil reader", func(t *testing.T) {
		t.Parallel()

		v, password := setup(t)

		_, err := v.Decrypt(t.Context(), nil, password)
		require.ErrorContains(t, err, "input reader cannot be nil")
	})

	t.Run("successful encrypt and decrypt", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), password)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
	})

	t.Run("successful encrypt and decrypt when empty plaintext", func(t *testing.T) {
		t.Parallel()

		plainText := []byte{}
		v, password := setup(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), password)
		require.NoError(t, err)
		require.Empty(t, decrypted)
	})

	t.Run("returns error when decrypt with wrong password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), []byte("wrong-password"))
		require.ErrorContains(t, err, "invalid HMAC")
		require.Empty(t, decrypted)
	})

	t.Run("returns error when encrypt with empty password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, []byte{}, plainText)
		require.ErrorContains(t, err, "hmac key derivation failed: password length must be at least 1 characters, got 0")
	})

	t.Run("returns error when encrypt with output ciphertext too big", func(t *testing.T) {
		t.Parallel()

		v, password := setup(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, make([]byte, math.MaxUint16))
		require.ErrorContains(t, err, "ciphertext must be smaller than 65535 bytes")

	})

	t.Run("returns error when decrypt with truncated ciphertext", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()[0:len(cipherText.Bytes())-2]), password)
		require.Nil(t, decrypted)
		require.ErrorContains(t, err, "file truncated: expected 29 bytes, read 27: unexpected EOF")

	})

	t.Run("encrypt respects context", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		plainText := []byte("hello, world!")
		v, password := setup(t)

		var buf bytes.Buffer
		err := v.Encrypt(ctx, &buf, password, plainText)
		assert.NoError(t, err)
	})

	t.Run("returns error when encrypt with output writer failure", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		err := v.Encrypt(t.Context(), &failingWriter{}, password, plainText)
		assert.Error(t, err)
	})

	t.Run("different passwords produce different ciphertexts", func(t *testing.T) {
		t.Parallel()

		v := setupVault(t)

		plainText := []byte("same plaintext")
		password1 := []byte("password1")
		password2 := []byte("password2")

		var buf1, buf2 bytes.Buffer
		err := v.Encrypt(t.Context(), &buf1, password1, plainText)
		require.NoError(t, err)
		err = v.Encrypt(t.Context(), &buf2, password2, plainText)
		require.NoError(t, err)

		assert.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})

	t.Run("same input produces different ciphertexts (due to random nonce)", func(t *testing.T) {
		t.Parallel()

		v := setupVault(t)

		plainText := []byte("same plaintext")
		password := []byte("same password")

		var buf1, buf2 bytes.Buffer
		err := v.Encrypt(t.Context(), &buf1, password, plainText)
		require.NoError(t, err)
		err = v.Encrypt(t.Context(), &buf2, password, plainText)
		require.NoError(t, err)

		assert.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})
}

func setupVault(tb testing.TB) *vault.Vault {
	tb.Helper()

	v, err := vault.New(
		// Use minimal KDF Params so we don't unnecessarily slow down tests
		vault.WithKDFParams(krypto.Argon2idParams{
			MemoryKiB:     1024,
			NumIterations: 1,
			NumThreads:    1,
		}),
	)
	require.NoError(tb, err)

	return v
}

type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, assert.AnError
}
