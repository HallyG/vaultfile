package format_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/require"
)

func TestValidateHMAC(t *testing.T) {
	t.Parallel()

	createHeader := func() *format.Header {
		return &format.Header{
			MagicNumber: [4]byte{'H', 'G', 'V', 'F'},
			Version:     format.VersionV1,
			Salt:        [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Nonce:       [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
			// CipherTextKeyKDFParamsRaw: [9]byte{0, 1, 0, 0, 0, 0, 0, 3, 4},
			TotalPayloadLength: 200,
		}
	}

	t.Run("valid MAC", func(t *testing.T) {
		t.Parallel()

		header := createHeader()
		mac := hmac.New(sha256.New, []byte("test-key"))
		computedMAC, err := format.ComputeHMAC(header, mac)
		require.NoError(t, err)
		require.Len(t, computedMAC, sha256.Size)

		copy(header.HMAC[:], computedMAC)

		mac = hmac.New(sha256.New, []byte("test-key"))
		err = format.ValidateHMAC(header, mac)
		require.NoError(t, err)
	})

	t.Run("error when invalid MAC", func(t *testing.T) {
		t.Parallel()

		header := createHeader()
		header.HMAC = [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

		mac := hmac.New(sha256.New, []byte("test-key"))
		err := format.ValidateHMAC(header, mac)
		require.EqualError(t, err, "invalid HMAC")
	})
}
