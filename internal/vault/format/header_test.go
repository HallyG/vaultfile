package format_test

/*

	t.Run("returns error when magic number is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen)
		copy(data, []byte("XXXX"))
		data[format.MagicNumberLen] = byte(format.VersionV1)

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, `unmarshal header: invalid: magic number: expected "HGVF", got "XXXX"`)
	})

	t.Run("returns error when version is invalid", func(t *testing.T) {
		t.Parallel()

		data := make([]byte, format.TotalHeaderLen)
		copy(data, []byte(format.MagicNumber))
		data[format.MagicNumberLen] = 99

		header, reader, err := format.ParseHeader(bytes.NewReader(data))
		assert.Nil(t, header)
		assert.Nil(t, reader)
		assert.EqualError(t, err, "unmarshal header: invalid: version: expected v1, got v99")
	})
*/

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
