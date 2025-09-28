package format_test

import (
	"testing"

	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/require"
)

func TestHeaderValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		expectedErr string
		header      format.Header
	}{
		"returns error when invalid magic number": {
			expectedErr: `magic number: expected "HGVF", got "XXXX"`,
			header: format.Header{
				MagicNumber: [4]byte{'X', 'X', 'X', 'X'},
			},
		},
		"returns error when invalid version": {
			expectedErr: "version: expected v1, got v0",
			header: format.Header{
				MagicNumber: [4]byte{'H', 'G', 'V', 'F'},
			},
		},
		"returns error when zero payload length": {
			expectedErr: "total payload length must be at least 88 bytes, got 0",
			header: format.Header{
				MagicNumber: [4]byte{'H', 'G', 'V', 'F'},
				Version:     format.VersionV1,
			},
		},
		"returns error when invalid payload length": {
			expectedErr: "total payload length must be at least 88 bytes, got 87",
			header: format.Header{
				MagicNumber:        [4]byte{'H', 'G', 'V', 'F'},
				Version:            format.VersionV1,
				TotalPayloadLength: uint16(format.TotalHeaderLen) - 1,
			},
		},
		"valid header with no payload": {
			header: format.Header{
				MagicNumber:        [4]byte{'H', 'G', 'V', 'F'},
				Version:            format.VersionV1,
				TotalPayloadLength: uint16(format.TotalHeaderLen),
			},
		},
		"valid header with payload": {
			header: format.Header{
				MagicNumber:        [4]byte{'H', 'G', 'V', 'F'},
				Version:            format.VersionV1,
				TotalPayloadLength: uint16(format.TotalHeaderLen) + 1,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := test.header.Validate()

			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHeaderUnmarshalBinary(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		expectedErr string
		data        []byte
	}{
		"returns error when data too long": {
			data:        make([]byte, format.TotalHeaderLen+1),
			expectedErr: "invalid length: got 89, expected 88",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var header format.Header
			err := header.UnmarshalBinary(test.data)

			if test.expectedErr != "" {
				require.EqualError(t, err, test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
