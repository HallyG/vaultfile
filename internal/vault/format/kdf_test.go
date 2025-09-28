package format_test

import (
	"encoding/binary"
	"testing"

	"github.com/HallyG/vaultfile/internal/vault/format"
	"github.com/stretchr/testify/require"
)

func TestKDFParams(t *testing.T) {
	t.Parallel()

	t.Run("unmarshal binary", func(t *testing.T) {
		t.Parallel()

		data := [9]byte{}
		binary.BigEndian.PutUint32(data[0:4], 65536)
		binary.BigEndian.PutUint32(data[4:8], 3)
		data[8] = 4

		var params format.KDFParams
		err := params.UnmarshalBinary(data[:])

		require.NoError(t, err)
		require.Equal(t, uint32(65536), params.MemoryKiB)
		require.Equal(t, uint32(3), params.NumIterations)
		require.Equal(t, uint8(4), params.NumThreads)
	})

	t.Run("returns error when invalid length during unmarshal binary", func(t *testing.T) {
		t.Parallel()

		data := [10]byte{}
		binary.BigEndian.PutUint32(data[0:4], 65536)
		binary.BigEndian.PutUint32(data[4:8], 3)
		data[8] = 4

		var params format.KDFParams
		err := params.UnmarshalBinary(data[:])

		require.EqualError(t, err, "invalid length: got 10, expected 9")
	})

	t.Run("marshal binary", func(t *testing.T) {
		t.Parallel()

		kdfParams := format.KDFParams{
			MemoryKiB:     1024,
			NumIterations: 2,
			NumThreads:    1,
		}

		data, err := kdfParams.MarshalBinary()
		require.NoError(t, err)

		expected := [9]byte{}
		binary.BigEndian.PutUint32(expected[0:4], 1024)
		binary.BigEndian.PutUint32(expected[4:8], 2)
		expected[8] = 1

		require.Equal(t, expected[:], data)
	})

	t.Run("roundtrip encoding and parsing", func(t *testing.T) {
		t.Parallel()

		kdfParams := format.KDFParams{
			MemoryKiB:     1024,
			NumIterations: 2,
			NumThreads:    1,
		}

		data, err := kdfParams.MarshalBinary()
		require.NoError(t, err)

		var params format.KDFParams
		err = params.UnmarshalBinary(data[:])
		require.NoError(t, err)

		require.Equal(t, kdfParams, params)
	})
}
