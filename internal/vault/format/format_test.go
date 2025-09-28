package format_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/require"
)

func TestVersionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version  format.Version
		expected string
	}{
		{format.VersionUnknown, "v0"},
		{format.VersionV1, "v1"},
		{format.Version(5), "v5"},
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

	require.Equal(t, "HGVF", format.MagicNumber)
	require.Equal(t, 4, format.MagicNumberLen)
	require.Equal(t, 2, format.TotalPayloadLengthLen)
	require.Equal(t, 1, format.VersionLen)
	require.Equal(t, 32, format.HMACLen)
	require.Equal(t, 9, format.KDFParamsLen)
	require.Equal(t, 16, format.SaltLen)
	require.Equal(t, 24, format.NonceLen)
	require.Equal(t, 88, format.TotalHeaderLen)
	require.Equal(t, 65535, format.MaxCipherTextSize)
}

func TestReadCipherText(t *testing.T) {
	t.Parallel()

	t.Run("reads cipher text successfully", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("test ciphertext data")
		header := &format.Header{
			TotalPayloadLength: uint16(format.TotalHeaderLen + len(cipherText)),
		}

		result, err := format.ReadCipherText(bytes.NewReader(cipherText), header)
		require.NoError(t, err)
		require.Equal(t, cipherText, result)
	})

	t.Run("returns error when total payload length too small", func(t *testing.T) {
		t.Parallel()

		header := &format.Header{
			TotalPayloadLength: uint16(format.TotalHeaderLen - 1),
		}

		result, err := format.ReadCipherText(bytes.NewReader(nil), header)
		require.Nil(t, result)
		require.EqualError(t, err, "total payload length 87 is smaller than header length 88")
	})

	t.Run("returns error when ciphertext truncated", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("short")
		header := &format.Header{
			TotalPayloadLength: uint16(format.TotalHeaderLen + 20),
		}

		result, err := format.ReadCipherText(bytes.NewReader(cipherText), header)
		require.Nil(t, result)
		require.EqualError(t, err, "truncated: expected 20 bytes, read 5: unexpected EOF")
	})
}

func TestParseHeader(t *testing.T) {
	t.Parallel()

	t.Run("returns error when input reader is nil", func(t *testing.T) {
		t.Parallel()

		header, reader, err := format.ParseHeader(nil)
		require.Nil(t, header)
		require.Nil(t, reader)
		require.EqualError(t, err, "input reader cannot be nil")
	})

	t.Run("returns error when header is truncated", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen-1)
		copy(data, []byte(format.MagicNumber))

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		require.Nil(t, header)
		require.Nil(t, reader)
		require.EqualError(t, err, "read header: truncated: expected 88 bytes, read 87: unexpected EOF")
	})

	t.Run("returns error when header is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen)
		copy(data, []byte(format.MagicNumber))
		data[format.MagicNumberLen] = 99

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		require.Nil(t, header)
		require.Nil(t, reader)
		require.ErrorContains(t, err, "unmarshal header: invalid:")
	})

	t.Run("parses header", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen)
		copy(data, []byte(format.MagicNumber))
		data[format.MagicNumberLen] = 99

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		require.Nil(t, header)
		require.Nil(t, reader)
		require.ErrorContains(t, err, "unmarshal header: invalid:")
	})
}

func TestEncodeHeader(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (*bytes.Buffer, hash.Hash, [format.SaltLen]byte, [format.NonceLen]byte, format.KDFParams, uint16) {
		t.Helper()

		var buf bytes.Buffer
		mac := hmac.New(sha256.New, []byte("test-key"))

		salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		kdfParams := format.KDFParams{
			MemoryKiB:     1,
			NumIterations: 1,
			NumThreads:    1,
		}

		return &buf, mac, salt, nonce, kdfParams, 100
	}

	t.Run("returns error when input reader is nil", func(t *testing.T) {
		t.Parallel()

		_, mac, salt, nonce, kdfParams, cipherTextLen := setup(t)

		err := format.EncodeHeader(nil, mac, salt, nonce, kdfParams, cipherTextLen)
		require.EqualError(t, err, "output writer cannot be nil")
	})

	t.Run("returns error when hmac hash is nil", func(t *testing.T) {
		t.Parallel()

		writer, _, salt, nonce, kdfParams, cipherTextLen := setup(t)

		err := format.EncodeHeader(writer, nil, salt, nonce, kdfParams, cipherTextLen)
		require.EqualError(t, err, "hmac hash cannot be nil")
	})

	t.Run("encodes header", func(t *testing.T) {
		t.Parallel()

		buf, mac, salt, nonce, kdfParams, cipherTextLen := setup(t)

		err := format.EncodeHeader(buf, mac, salt, nonce, kdfParams, cipherTextLen)
		require.NoError(t, err)

		data := buf.Bytes()
		require.Len(t, data, format.TotalHeaderLen)
		require.Equal(t, []byte(format.MagicNumber), data[:format.MagicNumberLen])
		require.Equal(t, byte(format.VersionV1), data[format.MagicNumberLen])
		require.Equal(t, salt[:], data[format.MagicNumberLen+format.VersionLen:format.MagicNumberLen+format.VersionLen+format.SaltLen])
	})
}

func TestEncodeParseHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("encoded header can be parsed", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		mac := hmac.New(sha256.New, []byte("test-key"))

		salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		kdfParams := format.KDFParams{
			MemoryKiB:     1,
			NumIterations: 2,
			NumThreads:    3,
		}
		cipherTextLen := uint16(1024)

		err := format.EncodeHeader(&buf, mac, salt, nonce, kdfParams, cipherTextLen)
		require.NoError(t, err)
		require.Len(t, buf.Bytes(), format.TotalHeaderLen)

		header, reader, err := format.ParseHeader(&buf)
		require.NoError(t, err)
		require.NotNil(t, header)
		require.NotNil(t, reader)

		require.Equal(t, salt, header.Salt)
		require.Equal(t, nonce, header.Nonce)
		require.Equal(t, kdfParams.MemoryKiB, header.KDFParams.MemoryKiB)
		require.Equal(t, kdfParams.NumIterations, header.KDFParams.NumIterations)
		require.Equal(t, kdfParams.NumThreads, header.KDFParams.NumThreads)
		require.Equal(t, cipherTextLen+uint16(format.TotalHeaderLen), header.TotalPayloadLength)
	})
}
