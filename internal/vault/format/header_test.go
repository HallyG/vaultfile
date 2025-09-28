package format_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHeader(t *testing.T) {
	t.Parallel()

	t.Run("returns error when input reader is nil", func(t *testing.T) {
		t.Parallel()

		header, reader, err := format.ParseHeader(nil)
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, "input reader cannot be nil")
	})

	t.Run("returns error when header is truncated", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen-1)
		copy(data, []byte(format.MagicNumber))

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, "read header: truncated: expected 88 bytes, read 87: unexpected EOF")
	})

	t.Run("returns error when magic number is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen)
		copy(data, []byte("XXXX"))
		data[format.MagicNumberLen] = byte(format.VersionV1)

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, `unmarshal header: invalid: magic number: expected \"HGVF\", got \"XXXX\"`)
	})

	t.Run("returns error when version is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen) // TODO: convert to header nad marshal
		copy(data, []byte(format.MagicNumber))
		data[format.MagicNumberLen] = 99

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, "invalid version: expected version v1, got v99")
	})

	t.Run("returns successful parse with valid header", func(t *testing.T) {
		t.Parallel()

		data := []byte{} //createValidHeaderData(t)

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		require.NoError(t, err)
		require.NotNil(t, header)
		require.NotNil(t, reader)

		assert.Equal(t, [4]byte{'H', 'G', 'V', 'F'}, header.MagicNumber)
		assert.Equal(t, format.VersionV1, header.Version)
		assert.Equal(t, uint32(1024), header.CipherTextKeyKDFParams.MemoryKiB)
		assert.Equal(t, uint32(1), header.CipherTextKeyKDFParams.NumIterations)
		assert.Equal(t, uint8(1), header.CipherTextKeyKDFParams.NumThreads)
	})
}

func TestEncodeHeader(t *testing.T) {
	t.Parallel()

	t.Run("successful encode header", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		mac := hmac.New(sha256.New, []byte("test-key"))

		salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		kdfParams := format.KDFParams{
			MemoryKiB:     1,
			NumIterations: 1,
			NumThreads:    1,
		}

		err := format.EncodeHeader(&buf, mac, salt, nonce, kdfParams, 100)
		require.NoError(t, err)

		data := buf.Bytes()
		assert.Len(t, data, format.TotalHeaderLen)

		assert.Equal(t, []byte(format.MagicNumber), data[:format.MagicNumberLen])
		assert.Equal(t, byte(format.VersionV1), data[format.MagicNumberLen])
		assert.Equal(t, salt[:], data[format.MagicNumberLen+format.VersionLen:format.MagicNumberLen+format.VersionLen+format.SaltLen])
	})
}

// func createValidHeaderData(tb testing.TB) []byte {
// 	tb.Helper()

// 	data := make([]byte, TotalHeaderLen)
// 	offset := 0

// 	copy(data[offset:], []byte(MagicNumber))
// 	offset += MagicNumberLen

// 	data[offset] = byte(VersionV1)
// 	offset += VersionLen

// 	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
// 	copy(data[offset:], salt[:])
// 	offset += SaltLen

// 	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
// 	copy(data[offset:], nonce[:])
// 	offset += NonceLen

// 	kdfParams := KDFParams{
// 		MemoryKiB:     1,
// 		NumIterations: 1,
// 		NumThreads:    1,
// 	}

// 	kdfBytes, err := kdfParams.MarshalBinary()
// 	require.NoError(tb, err)
// 	copy(data[offset:], kdfBytes[:])
// 	offset += KDFParamsLen

// 	binary.BigEndian.PutUint16(data[offset:], uint16(TotalHeaderLen+100))
// 	offset += TotalPayloadLengthLen

// 	mac := hmac.New(sha256.New, []byte("test-key"))
// 	mac.Write(data[:offset])
// 	hmacSum := mac.Sum(nil)
// 	copy(data[offset:], hmacSum)

// 	return data
// }
