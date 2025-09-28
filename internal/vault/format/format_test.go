package format

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var kdfParams = KDFParams{
	MemoryKiB:     1024,
	NumIterations: 1,
	NumThreads:    1,
}

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
	require.Equal(t, 9, KDFParamsLen)
	require.Equal(t, 16, SaltLen)
	require.Equal(t, 24, NonceLen)
	require.Equal(t, 88, TotalHeaderLen)
	require.Equal(t, 65535, MaxCipherTextSize)
}

func TestParseHeader(t *testing.T) {
	t.Parallel()

	t.Run("error when input reader is nil", func(t *testing.T) {
		t.Parallel()

		header, reader, err := ParseHeader(nil)
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, "input reader cannot be nil")
	})

	t.Run("error when header is truncated", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, TotalHeaderLen-1)
		copy(data, []byte(MagicNumber))

		header, reader, err := ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.ErrorContains(t, err, "truncated header")
	})

	t.Run("error when magic number is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, TotalHeaderLen)
		copy(data, []byte("XXXX"))
		data[magicNumberLen] = byte(VersionV1)

		header, reader, err := ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.ErrorContains(t, err, `invalid magic number: expected "HGVF", got "XXXX"`)
	})

	t.Run("error when version is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, TotalHeaderLen)
		copy(data, []byte(MagicNumber))
		data[magicNumberLen] = 99

		header, reader, err := ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.ErrorContains(t, err, "invalid version: expected version v1, got v99")
	})

	t.Run("successful parse with valid header", func(t *testing.T) {
		t.Parallel()

		data := createValidHeaderData(t)

		header, reader, err := ParseHeader(bytes.NewReader(data))
		require.NoError(t, err)
		require.NotNil(t, header)
		require.NotNil(t, reader)

		assert.Equal(t, [4]byte{'H', 'G', 'V', 'F'}, header.MagicNumber)
		assert.Equal(t, VersionV1, header.Version)
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

		err := EncodeHeader(&buf, mac, salt, nonce, kdfParams, 100)
		require.NoError(t, err)

		data := buf.Bytes()
		assert.Len(t, data, TotalHeaderLen)

		assert.Equal(t, []byte(MagicNumber), data[:magicNumberLen])
		assert.Equal(t, byte(VersionV1), data[magicNumberLen])
		assert.Equal(t, salt[:], data[magicNumberLen+versionLen:magicNumberLen+versionLen+SaltLen])
	})
}

func TestValidateMAC(t *testing.T) {
	t.Parallel()

	createHeader := func() *Header {
		return &Header{
			MagicNumber:               [4]byte{'H', 'G', 'V', 'F'},
			Version:                   VersionV1,
			CipherTextKeySalt:         [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			CipherTextKeyNonce:        [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
			cipherTextKeyKDFParamsRaw: [9]byte{0, 1, 0, 0, 0, 0, 0, 3, 4},
			TotalPayloadLength:        200,
		}
	}

	t.Run("valid MAC", func(t *testing.T) {
		t.Parallel()

		header := createHeader()
		mac := hmac.New(sha256.New, []byte("test-key"))
		computedMAC, err := ComputeMAC(header, mac)
		require.NoError(t, err)
		assert.Len(t, computedMAC, sha256.Size)

		copy(header.HMAC[:], computedMAC)

		mac = hmac.New(sha256.New, []byte("test-key"))
		err = ValidateMAC(header, mac)
		assert.NoError(t, err)
	})

	t.Run("error when invalid MAC", func(t *testing.T) {
		t.Parallel()

		header := createHeader()
		header.HMAC = [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

		mac := hmac.New(sha256.New, []byte("test-key"))
		err := ValidateMAC(header, mac)
		assert.EqualError(t, err, "invalid HMAC")
	})
}

func TestReadCipherText(t *testing.T) {
	t.Parallel()

	t.Run("successful read", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("test ciphertext data")
		header := &Header{
			TotalPayloadLength: uint16(TotalHeaderLen + len(cipherText)),
		}

		result, err := ReadCipherText(bytes.NewReader(cipherText), header)
		require.NoError(t, err)
		assert.Equal(t, cipherText, result)
	})

	t.Run("error when total payload length too small", func(t *testing.T) {
		t.Parallel()

		header := &Header{
			TotalPayloadLength: uint16(TotalHeaderLen - 1),
		}

		result, err := ReadCipherText(bytes.NewReader(nil), header)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "total payload length")
		assert.ErrorContains(t, err, "is smaller than header length")
	})

	t.Run("error when ciphertext truncated", func(t *testing.T) {
		t.Parallel()

		cipherText := []byte("short")
		header := &Header{
			TotalPayloadLength: uint16(TotalHeaderLen + 20),
		}

		result, err := ReadCipherText(bytes.NewReader(cipherText), header)
		assert.Nil(t, result)
		assert.ErrorContains(t, err, "file truncated")
	})
}

func createValidHeaderData(tb testing.TB) []byte {
	tb.Helper()

	data := make([]byte, TotalHeaderLen)
	offset := 0

	copy(data[offset:], []byte(MagicNumber))
	offset += magicNumberLen

	data[offset] = byte(VersionV1)
	offset += versionLen

	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	copy(data[offset:], salt[:])
	offset += SaltLen

	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	copy(data[offset:], nonce[:])
	offset += NonceLen

	kdfBytes, err := kdfParams.MarshalBinary()
	require.NoError(tb, err)
	copy(data[offset:], kdfBytes[:])
	offset += KDFParamsLen

	binary.BigEndian.PutUint16(data[offset:], uint16(TotalHeaderLen+100))
	offset += totalFileLengthLen

	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write(data[:offset])
	hmacSum := mac.Sum(nil)
	copy(data[offset:], hmacSum)

	return data
}
