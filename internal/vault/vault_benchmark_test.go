package vault_test

import (
	"bytes"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/stretchr/testify/require"
)

func BenchmarkEncryptV1(b *testing.B) {
	v, password, plainText := setupBenchmark(b)

	for b.Loop() {
		var buf bytes.Buffer

		err := v.Encrypt(b.Context(), &buf, password, plainText)
		require.NoError(b, err)
	}
}

func BenchmarkDecryptV1(b *testing.B) {
	v, password, plainText := setupBenchmark(b)

	var buf bytes.Buffer
	err := v.Encrypt(b.Context(), &buf, password, plainText)
	require.NoError(b, err)

	cipherText := bytes.NewReader(buf.Bytes())

	for b.Loop() {
		_, err := v.Decrypt(b.Context(), cipherText, password)
		require.NoError(b, err)
	}
}

func setupBenchmark(b *testing.B) (*vault.Vault, []byte, []byte) {
	b.Helper()

	v := setupVault(b)

	password := []byte("benchmark-password")
	plainText := []byte("hello, world!")

	return v, password, plainText
}
