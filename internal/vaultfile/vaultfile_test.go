package vaultfile

import (
	"bytes"
	"math"
	"testing"

	"github.com/HallyG/vaultfile/internal/format"
	"github.com/HallyG/vaultfile/internal/testlog"
	"github.com/stretchr/testify/require"
)

func TestV1Format(t *testing.T) {
	setup := func(t *testing.T, plainText []byte) (*Vault, []byte, []byte, []byte) {
		t.Helper()

		password := []byte("some-long-password")
		vault, err := New(
			WithLogger(testlog.New(t)),
		)
		require.NoError(t, err)

		var buf bytes.Buffer
		err = vault.Encrypt(t.Context(), &buf, password, plainText)
		require.NoError(t, err)

		return vault, buf.Bytes(), plainText, password
	}

	t.Run("error when nil writer", func(t *testing.T) {
		t.Parallel()

		vault, err := New()
		require.NoError(t, err)

		err = vault.Encrypt(t.Context(), nil, []byte("password"), []byte("test"))
		require.ErrorIs(t, err, ErrNilWriter)
	})

	t.Run("error when nil reader", func(t *testing.T) {
		t.Parallel()

		vault, err := New()
		require.NoError(t, err)

		_, err = vault.Decrypt(t.Context(), nil, []byte("password"))
		require.ErrorIs(t, err, ErrNilReader)
	})

	t.Run("version is v1", func(t *testing.T) {
		t.Parallel()
		vault, err := New()
		require.NoError(t, err)

		require.Equal(t, format.VersionV1, vault.Version())
	})

	t.Run("successful encrypt and decrypt", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, plainText, password := setup(t, []byte("hello, world!"))

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
	})

	t.Run("success encrypt and decrypt when empty plaintext", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, password := setup(t, []byte{})

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.NoError(t, err)
		require.Empty(t, decrypted)
	})

	t.Run("error when decrypt with wrong password", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, _ := setup(t, []byte("hello, world!"))

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), []byte("wrong-password"))
		require.ErrorContains(t, err, "invalid HMAC")
		require.Empty(t, decrypted)
	})

	t.Run("error on encrypt with empty password", func(t *testing.T) {
		t.Parallel()

		vault, err := New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = vault.Encrypt(t.Context(), &buf, []byte{}, []byte("test"))
		require.ErrorContains(t, err, "password must be at least 1 characters long")
	})

	t.Run("error on encrypt when ciphertext too big", func(t *testing.T) {
		t.Parallel()

		password := []byte("some-long-password")
		vault, err := New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = vault.Encrypt(t.Context(), &buf, password, make([]byte, math.MaxUint16))
		require.ErrorContains(t, err, "ciphertext must be smaller than 65535 bytes")

	})

	t.Run("error on decrypt when ciphertext truncated", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, password := setup(t, []byte("hello, world!"))

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText[0:len(cipherText)-2]), password)
		require.Nil(t, decrypted)
		require.ErrorContains(t, err, "file truncated: expected 29 bytes, read 27: unexpected EOF")

	})
}
