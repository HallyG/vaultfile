package format

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version  Version
		expected string
	}{
		{VersionUnknown, "v0"},
		{VersionV1, "v1"},
		{Version(5), "v5"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.expected, test.version.String())
		})
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()

	require.Equal(t, "HGVF", MagicNumber)
	require.Equal(t, 4, MagicNumberLen)
	require.Equal(t, 2, TotalPayloadLengthLen)
	require.Equal(t, 1, VersionLen)
	require.Equal(t, 32, HMACLen)
	require.Equal(t, 9, KDFParamsLen)
	require.Equal(t, 16, SaltLen)
	require.Equal(t, 24, NonceLen)
	require.Equal(t, 88, TotalHeaderLen)
	require.Equal(t, 65535, MaxCipherTextSize)
}

func TestReadCipherText(t *testing.T) {
	t.Parallel()

	t.Run("reads cipher text successfully", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("test ciphertext data")
		header := &Header{
			TotalPayloadLength: uint16(TotalHeaderLen + len(cipherText)),
		}

		result, err := ReadCipherText(bytes.NewReader(cipherText), header)
		require.NoError(t, err)
		require.Equal(t, cipherText, result)
	})

	t.Run("returns error when total payload length too small", func(t *testing.T) {
		t.Parallel()

		header := &Header{
			TotalPayloadLength: uint16(TotalHeaderLen - 1),
		}

		result, err := ReadCipherText(bytes.NewReader(nil), header)
		require.Nil(t, result)
		require.EqualError(t, err, "total payload length 87 is smaller than header length 88")
	})

	t.Run("returns error when ciphertext truncated", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("short")
		header := &Header{
			TotalPayloadLength: uint16(TotalHeaderLen + 20),
		}

		result, err := ReadCipherText(bytes.NewReader(cipherText), header)
		require.Nil(t, result)
		require.EqualError(t, err, "truncated: expected 20 bytes, read 5: unexpected EOF")
	})
}
