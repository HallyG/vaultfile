package vault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"math"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	t.Run("version is v1", func(t *testing.T) {
		t.Parallel()

		v, err := vault.New()
		require.NoError(t, err)
		require.Equal(t, format.VersionV1, v.Version())
	})
}

func TestV1FormatDecrypt(t *testing.T) {
	t.Parallel()

	t.Run("returns error when nil password", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("some fake ciphertext")
		v, _ := setupVault(t)

		_, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText), nil)
		require.EqualError(t, err, "password cannot be nil")
	})

	t.Run("returns error when nil reader", func(t *testing.T) {
		t.Parallel()

		v, password := setupVault(t)

		_, err := v.Decrypt(t.Context(), nil, password)
		require.EqualError(t, err, "input reader cannot be nil")
	})
}

func TestV1FormatEncrypt(t *testing.T) {
	t.Parallel()

	t.Run("returns error when nil writer", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t)

		err := v.Encrypt(t.Context(), nil, password, plainText)
		require.EqualError(t, err, "output writer cannot be nil")
	})

	t.Run("returns error when nil password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, _ := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, nil, plainText)
		require.EqualError(t, err, "password cannot be nil")
	})

	t.Run("returns error when nil plaintext", func(t *testing.T) {
		t.Parallel()

		v, password := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, nil)
		require.EqualError(t, err, "plaintext cannot be nil")
	})

	t.Run("returns error when encrypt with empty password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, _ := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, []byte{}, plainText)
		require.EqualError(t, err, "hmac key derivation failed: password length must be at least 1 characters, got 0")
	})

	t.Run("returns error when ciphertext too big", func(t *testing.T) {
		t.Parallel()

		v, password := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, make([]byte, math.MaxUint16))
		require.EqualError(t, err, "ciphertext exceeds maximum of 65431 bytes, got 65535")
	})

	t.Run("returns error when context cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(ctx, &buf, password, plainText)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("returns error when output writer failure", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t)

		err := v.Encrypt(t.Context(), &failingWriter{}, password, plainText)
		require.Error(t, err)
	})

	t.Run("returns error when invalid KDF parameters", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t,
			vault.WithKDFParams(krypto.Argon2idParams{
				MemoryKiB:     0,
				NumIterations: 1,
				NumThreads:    1,
			}),
		)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.EqualError(t, err, "ciphertext key derivation failed: invalid Argon2id parameters: MemoryKiB: cannot be blank.")
	})

	t.Run("different ciphertexts when different passwords", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		password2 := []byte("password2")
		v, password1 := setupVault(t)

		var buf1, buf2 bytes.Buffer

		err := v.Encrypt(t.Context(), &buf1, password1, plainText)
		require.NoError(t, err)

		err = v.Encrypt(t.Context(), &buf2, password2, plainText)
		require.NoError(t, err)

		require.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})

	t.Run("different ciphertext with same plaintext input", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t)

		var buf1, buf2 bytes.Buffer
		err := v.Encrypt(t.Context(), &buf1, password, plainText)
		require.NoError(t, err)

		err = v.Encrypt(t.Context(), &buf2, password, plainText)
		require.NoError(t, err)

		require.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})

	t.Run("encrypt plaintext at maximum length", func(t *testing.T) {
		t.Parallel()

		plainText := make([]byte, vault.MaxCipherTextSize)
		v, password := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, plainText)
		require.NoError(t, err)
	})
}

func TestV1FormatEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tests := map[string]struct {
		plaintext []byte
	}{
		"empty":         {plaintext: []byte{}},
		"single byte":   {plaintext: []byte{0x42}},
		"null bytes":    {plaintext: make([]byte, 100)},
		"random small":  {plaintext: generateRandomBytes(t, 50)},
		"random medium": {plaintext: generateRandomBytes(t, 1000)},
		"random large":  {plaintext: generateRandomBytes(t, 10000)},
		"all 0xFF":      {plaintext: bytes.Repeat([]byte{0xFF}, 500)},
		"unicode text":  {plaintext: []byte("Hello 世界! 🚀 Testing Unicode")},
		"binary data":   {plaintext: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			v, password := setupVault(t)

			var cipherText bytes.Buffer
			err := v.Encrypt(t.Context(), &cipherText, password, test.plaintext)
			require.NoError(t, err)

			decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), password)
			require.NoError(t, err)

			if len(test.plaintext) == 0 {
				require.Empty(t, decrypted)
			} else {
				require.Equal(t, test.plaintext, decrypted)
			}
		})
	}

	t.Run("returns error when decrypt with wrong password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), []byte("wrong-password"))
		require.EqualError(t, err, "validate header: computed HMAC does not match header HMAC")
		require.Empty(t, decrypted)
	})

	t.Run("returns error when decrypt with truncated ciphertext", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setupVault(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		truncated := cipherText.Bytes()[0 : len(cipherText.Bytes())-2]
		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(truncated), password)
		require.Nil(t, decrypted)
		require.EqualError(t, err, "read ciphertext: truncated: expected 29 bytes, read 27: unexpected EOF")

	})
}

func setupVault(tb testing.TB, opts ...vault.Option) (*vault.Vault, []byte) {
	tb.Helper()

	password := []byte("some-long-password")
	if opts == nil {
		opts = append(opts, vault.WithKDFParams(krypto.Argon2idParams{
			MemoryKiB:     1,
			NumIterations: 1,
			NumThreads:    1,
		}))
	}

	v, err := vault.New(opts...)
	require.NoError(tb, err)

	return v, password
}

func generateRandomBytes(tb testing.TB, length int) []byte {
	tb.Helper()

	data := make([]byte, length)
	_, err := rand.Read(data)
	require.NoError(tb, err)

	return data
}

type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, assert.AnError
}
