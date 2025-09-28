package vault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"math"
	mathrand "math/rand"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
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
		require.ErrorContains(t, err, "plaintext exceeds maximum of 65471 bytes, got 65535")
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
		require.NoError(t, err)
	})

	t.Run("returns error when encrypt with output writer failure", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		err := v.Encrypt(t.Context(), &failingWriter{}, password, plainText)
		require.Error(t, err)
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

		require.NotEqual(t, buf1.Bytes(), buf2.Bytes())
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

		require.NotEqual(t, buf1.Bytes(), buf2.Bytes())
	})

	t.Run("returns error when encrypt with nil password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v := setupVault(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, nil, plainText)
		require.ErrorContains(t, err, "password cannot be nil")
	})

	t.Run("returns error when encrypt with nil plaintext", func(t *testing.T) {
		t.Parallel()

		v, password := setup(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, nil)
		require.ErrorContains(t, err, "plaintext cannot be nil")
	})

	t.Run("returns error when decrypt with nil password", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v := setupVault(t)
		password := []byte("test-password")

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		_, err = v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), nil)
		require.ErrorContains(t, err, "password cannot be nil")
	})

	t.Run("returns error when encrypt with plaintext at maximum boundary", func(t *testing.T) {
		t.Parallel()

		v, password := setup(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, make([]byte, format.MaxCipherTextSize-15))
		require.ErrorContains(t, err, "plaintext exceeds maximum")
	})

	t.Run("successful encrypt with plaintext just under boundary", func(t *testing.T) {
		t.Parallel()

		v, password := setup(t)

		var buf bytes.Buffer
		err := v.Encrypt(t.Context(), &buf, password, make([]byte, format.MaxCipherTextSize-17))
		require.NoError(t, err)
	})

	t.Run("returns error when decrypt with invalid KDF parameters", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		t.Parallel()

		plainText := []byte("hello, world!")
		password := []byte("test-password")

		v, err := vault.New(
			vault.WithKDFParams(krypto.Argon2idParams{
				MemoryKiB:     0,
				NumIterations: 1,
				NumThreads:    1,
			}),
		)
		require.NoError(t, err)

		var cipherText bytes.Buffer
		err = v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.ErrorContains(t, err, "invalid Argon2id parameters")
	})

	t.Run("encrypt respects context cancellation", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		var buf bytes.Buffer
		err := v.Encrypt(ctx, &buf, password, plainText)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("decrypt respects context cancellation", func(t *testing.T) {
		t.Parallel()

		plainText := []byte("hello, world!")
		v, password := setup(t)

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = v.Decrypt(ctx, bytes.NewReader(cipherText.Bytes()), password)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("concurrent encrypt operations are safe", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		t.Parallel()

		v := setupVault(t)
		password := []byte("test-password")
		plainText := []byte("concurrent test")

		const numGoroutines = 10
		results := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				var buf bytes.Buffer
				err := v.Encrypt(context.Background(), &buf, password, plainText)
				results <- err
			}()
		}

		for i := 0; i < numGoroutines; i++ {
			err := <-results
			require.NoError(t, err)
		}
	})

	t.Run("encrypt and decrypt with maximum valid password length", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		t.Parallel()

		plainText := []byte("hello, world!")
		v := setupVault(t)
		password := make([]byte, krypto.MaxPasswordLength)
		for i := range password {
			password[i] = 'a'
		}

		var cipherText bytes.Buffer
		err := v.Encrypt(t.Context(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(t.Context(), bytes.NewReader(cipherText.Bytes()), password)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
	})

	t.Run("memory stress test with large KDF parameters", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		t.Parallel()

		plainText := []byte("stress test")
		password := []byte("test-password")

		v, err := vault.New(
			vault.WithKDFParams(krypto.Argon2idParams{
				MemoryKiB:     1024 * 10,
				NumIterations: 2,
				NumThreads:    2,
			}),
		)
		require.NoError(t, err)

		var cipherText bytes.Buffer
		err = v.Encrypt(context.Background(), &cipherText, password, plainText)
		require.NoError(t, err)

		decrypted, err := v.Decrypt(context.Background(), bytes.NewReader(cipherText.Bytes()), password)
		require.NoError(t, err)
		require.Equal(t, plainText, decrypted)
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

func TestFuzzEncryptDecrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzzing test in short mode")
	}

	v := setupVault(t)
	password := []byte("fuzz-test-password")

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x42}},
		{"null bytes", make([]byte, 100)},
		{"random small", generateRandomBytes(t, 50)},
		{"random medium", generateRandomBytes(t, 1000)},
		{"random large", generateRandomBytes(t, 10000)},
		{"all 0xFF", bytes.Repeat([]byte{0xFF}, 500)},
		{"unicode text", []byte("Hello 世界! 🚀 Testing Unicode")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var cipherText bytes.Buffer
			err := v.Encrypt(context.Background(), &cipherText, password, tc.plaintext)
			require.NoError(t, err)

			decrypted, err := v.Decrypt(context.Background(), bytes.NewReader(cipherText.Bytes()), password)
			require.NoError(t, err)
			if len(tc.plaintext) == 0 {
				require.Empty(t, decrypted)
			} else {
				require.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

func TestSecurityProperties(t *testing.T) {
	t.Run("MAC validation is constant time resistant", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		t.Parallel()

		v := setupVault(t)
		password := []byte("security-test")
		plaintext := []byte("secret data")

		var cipherText bytes.Buffer
		err := v.Encrypt(context.Background(), &cipherText, password, plaintext)
		require.NoError(t, err)

		original := cipherText.Bytes()

		macStartIndex := 56
		corruptions := []struct {
			name string
			data []byte
		}{
			{"HMAC first byte", corruptAtIndex(original, macStartIndex)},
			{"HMAC middle byte", corruptAtIndex(original, macStartIndex+16)},
			{"HMAC last byte", corruptAtIndex(original, macStartIndex+31)},
		}

		for _, corruption := range corruptions {
			t.Run(corruption.name, func(t *testing.T) {
				_, err := v.Decrypt(context.Background(), bytes.NewReader(corruption.data), password)
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid HMAC")
			})
		}
	})

	t.Run("different passwords produce cryptographically different outputs", func(t *testing.T) {
		t.Parallel()

		v := setupVault(t)
		plaintext := []byte("same plaintext for all")

		passwords := [][]byte{
			[]byte("password1"),
			[]byte("password2"),
			[]byte("PASSWORD1"),
			[]byte("password1 "),
			[]byte("äpassword1"),
		}

		var outputs [][]byte
		for _, pwd := range passwords {
			var buf bytes.Buffer
			err := v.Encrypt(context.Background(), &buf, pwd, plaintext)
			require.NoError(t, err)
			outputs = append(outputs, buf.Bytes())
		}

		for i := 0; i < len(outputs); i++ {
			for j := i + 1; j < len(outputs); j++ {
				require.NotEqual(t, outputs[i], outputs[j],
					"outputs for passwords %q and %q should be different", passwords[i], passwords[j])
			}
		}
	})

	t.Run("error messages don't leak sensitive information", func(t *testing.T) {
		t.Parallel()

		v := setupVault(t)

		errorTests := []struct {
			name     string
			testFunc func() error
		}{
			{
				"nil output writer",
				func() error { return v.Encrypt(context.Background(), nil, []byte("pwd"), []byte("data")) },
			},
			{
				"nil input reader",
				func() error { _, err := v.Decrypt(context.Background(), nil, []byte("pwd")); return err },
			},
		}

		for _, test := range errorTests {
			t.Run(test.name, func(t *testing.T) {
				err := test.testFunc()
				require.Error(t, err)

				errMsg := err.Error()
				require.NotContains(t, errMsg, "secret")
				require.NotContains(t, errMsg, "private")
				require.NotContains(t, errMsg, "credential")
			})
		}
	})
}

func TestHelperFunctions(t *testing.T) {
	t.Run("createVaultWithLargeKDF creates vault with specified parameters", func(t *testing.T) {
		v := createVaultWithLargeKDF(t)
		require.NotNil(t, v)
		require.Equal(t, format.VersionV1, v.Version())
	})

	t.Run("createInvalidHeader creates corrupted headers", func(t *testing.T) {
		testCases := []string{
			"magic",
			"version",
			"salt",
			"nonce",
			"kdf",
			"length",
			"hmac",
		}

		for _, corruption := range testCases {
			t.Run(corruption, func(t *testing.T) {
				data := createInvalidHeader(t, corruption)
				require.NotNil(t, data)
				require.Greater(t, len(data), 0)
			})
		}
	})
}

func createVaultWithLargeKDF(tb testing.TB) *vault.Vault {
	tb.Helper()

	v, err := vault.New(
		vault.WithKDFParams(krypto.Argon2idParams{
			MemoryKiB:     8192,
			NumIterations: 3,
			NumThreads:    4,
		}),
	)
	require.NoError(tb, err)
	return v
}

func createInvalidHeader(tb testing.TB, corruption string) []byte {
	tb.Helper()

	v := setupVault(tb)
	password := []byte("test-password")
	plaintext := []byte("test data")

	var buf bytes.Buffer
	err := v.Encrypt(context.Background(), &buf, password, plaintext)
	require.NoError(tb, err)

	data := buf.Bytes()

	switch corruption {
	case "magic":
		copy(data[0:4], []byte("XXXX"))
	case "version":
		data[4] = 99
	case "salt":
		for i := 5; i < 5+16; i++ {
			data[i] = 0xFF
		}
	case "nonce":
		for i := 21; i < 21+24; i++ {
			data[i] = 0x00
		}
	case "kdf":
		for i := 45; i < 45+9; i++ {
			data[i] = 0xFF
		}
	case "length":
		data[54] = 0xFF
		data[55] = 0xFF
	case "hmac":
		for i := 56; i < 56+32; i++ {
			data[i] = 0x00
		}
	}

	return data
}

func generateRandomBytes(tb testing.TB, length int) []byte {
	tb.Helper()

	data := make([]byte, length)
	_, err := rand.Read(data)
	require.NoError(tb, err)
	return data
}

func corruptAtIndex(data []byte, index int) []byte {
	corrupted := make([]byte, len(data))
	copy(corrupted, data)
	corrupted[index] ^= 0xFF
	return corrupted
}

func corruptRandomly(tb testing.TB, data []byte) []byte {
	tb.Helper()

	corrupted := make([]byte, len(data))
	copy(corrupted, data)

	index := mathrand.Intn(len(corrupted))
	corrupted[index] ^= 0xFF

	return corrupted
}
