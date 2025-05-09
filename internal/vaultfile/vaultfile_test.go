package vaultfile

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestV1Format(t *testing.T) {
	t.Run("version is v1", func(t *testing.T) {
		t.Parallel()
		vault, err := New()
		require.NoError(t, err)

		require.Equal(t, VersionV1, vault.Version())
	})

	setup := func(t *testing.T, plainText []byte) (*Vault, []byte, []byte, []byte) {
		t.Helper()

		password := []byte("some-long-password")
		vault, err := New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = vault.Encrypt(t.Context(), &buf, password, plainText)
		require.NoError(t, err)

		return vault, buf.Bytes(), plainText, password
	}

	t.Run("successful encrypt and decrypt", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, plainText, password := setup(t, []byte("hello, world!"))

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
	})

	t.Run("error when decrypt with wrong password", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, _ := setup(t, []byte("hello, world!"))

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), []byte("wrong-password"))
		require.ErrorContains(t, err, "invalid HMAC")
		require.Empty(t, decrypted)
	})

	t.Run("empty plaintext", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, _, password := setup(t, []byte{})

		decrypted, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.NoError(t, err)
		require.Empty(t, decrypted)
	})

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
}

func TestV1FormatInvalidHeader(t *testing.T) {
	setup := func(t *testing.T) (*Vault, []byte, []byte) {
		t.Helper()

		plainText := []byte("hello, world!")
		password := []byte("some-long-password")
		vault, err := New()
		require.NoError(t, err)

		var buf bytes.Buffer
		err = vault.Encrypt(t.Context(), &buf, password, plainText)
		require.NoError(t, err)

		return vault, buf.Bytes(), password
	}

	t.Run("error when header field is tampered", func(t *testing.T) {
		fields := map[string]struct {
			modifier func(t *testing.T, vault *Vault, password []byte, header []byte) []byte
		}{
			"salt": {
				modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
					start := versionV1LenMagicNumber + versionV1LenVersion
					header[start] ^= 0xFF
					return header
				},
			},
			"nonce": {
				modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
					start := versionV1LenMagicNumber + versionV1LenVersion + versionV1LenSalt
					header[start] ^= 0xFF
					return header
				},
			},
			"kdfParams": {
				modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
					start := versionV1LenMagicNumber + versionV1LenVersion + versionV1LenSalt + versionV1LenNonce
					header[start] ^= 0xFF
					return header
				},
			},
			"totalFileLength": {
				modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
					start := versionV1LenMagicNumber + versionV1LenVersion + versionV1LenSalt + versionV1LenNonce + versionV1LenKDF
					binary.BigEndian.PutUint16(header[start:start+versionV1LenTotalFileLength], uint16(versionV1LenHeader-1))
					return header
				},
			},
		}
		for name, test := range fields {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				vault, cipherText, password := setup(t)
				modifiedData := test.modifier(t, vault, password, cipherText)

				_, err := vault.Decrypt(t.Context(), bytes.NewReader(modifiedData), password)
				require.ErrorContains(t, err, "invalid HMAC")
			})
		}
	})

	tests := map[string]struct {
		modifier    func(t *testing.T, vault *Vault, password []byte, header []byte) []byte
		errContains string
	}{
		"error when invalid magic number": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				header[0] = 'X'
				return header
			},
			errContains: `expected "HGVF", got "XGVF"`,
		},
		"error when invalid version": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				header[versionV1LenMagicNumber] = 99
				return header
			},
			errContains: "expected version 1, got 99",
		},
		"error when invalid HMAC": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				start := versionV1LenHeader - versionV1LenHMAC
				header[start] ^= 0xFF // Flip a bit in HMAC
				return header
			},
			errContains: "invalid HMAC",
		},
		"error when tampered salt": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				start := versionV1LenMagicNumber + versionV1LenVersion
				header[start] ^= 0xFF // Modify salt, HMAC will be invalid
				return header
			},
			errContains: "invalid HMAC",
		},
		"error when truncated header": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				return header[:versionV1LenHeader-1]
			},
			errContains: "incomplete header",
		},
		"error when truncated ciphertext": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				return header[:versionV1LenHeader+5] // Partial ciphertext
			},
			errContains: "incomplete ciphertext",
		},
		"error when invalid totalFileLength (too small)": {
			modifier: func(t *testing.T, vault *Vault, password []byte, header []byte) []byte {
				t.Helper()

				start := versionV1LenMagicNumber + versionV1LenVersion + versionV1LenSalt + versionV1LenNonce + versionV1LenKDF
				binary.BigEndian.PutUint16(header[start:start+versionV1LenTotalFileLength], uint16(999))

				headerData, err := vault.readHeader(t.Context(), bytes.NewReader(header))
				require.NoError(t, err)

				newHMAC, err := vault.computeHMAC(t.Context(), password, headerData)
				require.NoError(t, err)

				result := make([]byte, len(header))
				copy(result, header)
				copy(result[versionV1LenHeader-versionV1LenHMAC:], newHMAC)
				return result
			},
			errContains: "incomplete ciphertext",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			vault, cipherText, password := setup(t)
			modifiedData := test.modifier(t, vault, password, cipherText)

			plaintext, err := vault.Decrypt(t.Context(), bytes.NewReader(modifiedData), password)
			require.ErrorContains(t, err, test.errContains)
			require.Nil(t, plaintext)
		})
	}

	t.Run("invalid KDF parameters", func(t *testing.T) {
		t.Parallel()

		vault, cipherText, password := setup(t)
		start := versionV1LenMagicNumber + versionV1LenVersion + versionV1LenSalt + versionV1LenNonce

		binary.BigEndian.PutUint32(cipherText[start:start+4], 0) // Set MemoryKiB to 0

		_, err := vault.Decrypt(t.Context(), bytes.NewReader(cipherText), password)
		require.ErrorContains(t, err, "invalid KDF parameters")
	})
}
