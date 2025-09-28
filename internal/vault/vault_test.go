package vault_test

import (
	"bytes"
	"context"
	"math"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV1Format(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, plainText []byte) (*vault.Vault, []byte, []byte, []byte) {
		t.Helper()

		password := []byte("some-long-password")
		v, err := vault.New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = v.Encrypt(t.Context(), &buf, password, plainText)
		require.NoError(t, err)

		return v, buf.Bytes(), plainText, password
	}

	t.Run("version is v1", func(t *testing.T) {
		t.Parallel()
		v, err := vault.New()
		require.NoError(t, err)

		require.Equal(t, format.VersionV1, v.Version())
	})

	t.Run("successful encrypt and decrypt", func(t *testing.T) {
		t.Parallel()

		v, cipherText, plainText, password := setup(t, []byte("hello, world!"))

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
	})

	t.Run("successful encrypt and decrypt when empty plaintext", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, password := setup(t, []byte{})

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.NoError(t, err)
		require.Empty(t, decrypted)
	})

	t.Run("returns error when nil writer", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		err = v.Encrypt(t.Context(), nil, []byte("password"), []byte("test"))
		require.ErrorContains(t, err, "output writer cannot be nil")
	})

	t.Run("returns error when nil reader", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		_, err = v.Decrypt(t.Context(), nil, []byte("password"))
		require.ErrorContains(t, err, "input reader cannot be nil")
	})

	t.Run("returns error when decrypt with wrong password", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, _ := setup(t, []byte("hello, world!"))

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), []byte("wrong-password"))
		require.ErrorContains(t, err, "invalid HMAC")
		require.Empty(t, decrypted)
	})

	t.Run("returns error on encrypt with empty password", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = v.Encrypt(t.Context(), &buf, []byte{}, []byte("test"))
		require.ErrorContains(t, err, "password must be at least 1 characters long")
	})

	t.Run("returns error on encrypt when ciphertext too big", func(t *testing.T) {
		t.Parallel()

		password := []byte("some-long-password")
		v, err := vault.New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = v.Encrypt(t.Context(), &buf, password, make([]byte, math.MaxUint16))
		require.ErrorContains(t, err, "ciphertext must be smaller than 65535 bytes")

	})

	t.Run("returns error on decrypt when ciphertext truncated", func(t *testing.T) {
		t.Parallel()

		v, cipherText, _, password := setup(t, []byte("hello, world!"))

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText[0:len(cipherText)-2]), password)
		require.Nil(t, decrypted)
		require.ErrorContains(t, err, "file truncated: expected 29 bytes, read 27: unexpected EOF")

	})

	t.Run("encrypt respects context", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		ctx := context.Background()
		var buf bytes.Buffer
		err = v.Encrypt(ctx, &buf, []byte("password"), []byte("test"))
		assert.NoError(t, err)
	})

	t.Run("large plaintext encryption and decryption", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		largeText := make([]byte, 32768)
		for i := range largeText {
			largeText[i] = byte(i % 256)
		}

		password := []byte("test-password-for-large-data")
		var buf bytes.Buffer
		err = v.Encrypt(context.Background(), &buf, password, largeText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(context.Background(), bytes.NewReader(buf.Bytes()), password)
		require.NoError(t, err)
		assert.Equal(t, largeText, decrypted)
	})

	t.Run("error on decrypt when header is corrupted", func(t *testing.T) {
		t.Parallel()

		v, cipherText, _, password := setup(t, []byte("hello, world!"))

		corruptedData := make([]byte, len(cipherText))
		copy(corruptedData, cipherText)
		corruptedData[10] ^= 0xFF

		decrypted, err := v.Decrypt(context.Background(), bytes.NewReader(corruptedData), password)
		assert.Nil(t, decrypted)
		assert.ErrorContains(t, err, "invalid HMAC")
	})

	t.Run("error on encrypt when output writer fails", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		failingWriter := &failingWriter{}
		err = v.Encrypt(context.Background(), failingWriter, []byte("password"), []byte("test"))
		assert.Error(t, err)
	})

	t.Run("different passwords produce different ciphertexts", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		plainText := []byte("same plaintext")
		password1 := []byte("password1")
		password2 := []byte("password2")

		var buf1, buf2 bytes.Buffer
		err = v.Encrypt(context.Background(), &buf1, password1, plainText)
		require.NoError(t, err)
		err = v.Encrypt(context.Background(), &buf2, password2, plainText)
		require.NoError(t, err)

		assert.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})

	t.Run("same input produces different ciphertexts due to random nonce", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)

		plainText := []byte("same plaintext")
		password := []byte("same password")

		var buf1, buf2 bytes.Buffer
		err = v.Encrypt(context.Background(), &buf1, password, plainText)
		require.NoError(t, err)
		err = v.Encrypt(context.Background(), &buf2, password, plainText)
		require.NoError(t, err)

		assert.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})
}

type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, assert.AnError
}
