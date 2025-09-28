package vault_test

import (
	"bytes"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/stretchr/testify/require"
)

func BenchmarkEncrypt(b *testing.B) {
	v, password, plainText := setupBenchmark(b)

	for b.Loop() {
		var buf bytes.Buffer

		err := v.Encrypt(b.Context(), &buf, password, plainText)
		require.NoError(b, err)
	}
}

func BenchmarkDecrypt(b *testing.B) {
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

	v, err := vault.New()
	require.NoError(b, err)

	password := []byte("benchmark-password")
	plainText := make([]byte, 1024)
	for i := range plainText {
		plainText[i] = byte(i % 256)
	}

	return v, password, plainText
}
