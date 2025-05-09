package key_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto/key"
	"github.com/stretchr/testify/require"
)

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name         string
		saltLength   uint32
		expectedErr  error
		expectedSalt []byte
	}{
		{
			name:         "valid salt length",
			saltLength:   32,
			expectedErr:  nil,
			expectedSalt: make([]byte, 32),
		},
		{
			name:         "minimum salt length",
			saltLength:   key.MinSaltLength,
			expectedErr:  nil,
			expectedSalt: make([]byte, key.MinSaltLength),
		},
		{
			name:         "maximum salt length",
			saltLength:   key.MaxSaltLength,
			expectedErr:  nil,
			expectedSalt: make([]byte, key.MaxSaltLength),
		},
		{
			name:         "error when salt length too long",
			saltLength:   key.MaxSaltLength + 1,
			expectedErr:  errors.New("salt length exceeds maximum of 255 bytes"),
			expectedSalt: nil,
		},
		{
			name:         "error when salt length too short",
			saltLength:   key.MinSaltLength - 1,
			expectedErr:  errors.New("salt must be at least 16 bytes long"),
			expectedSalt: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			salt, err := key.GenerateSalt(test.saltLength)
			if test.expectedErr != nil {
				require.ErrorContains(t, err, test.expectedErr.Error())
				require.Nil(t, salt)
				return
			}

			require.NoError(t, err)
			require.Len(t, salt, int(test.saltLength))
		})
	}
}

func TestDeriveKeyFromPassword(t *testing.T) {
	defaultParams := &key.Argon2idParams{
		MemoryKiB:     1,
		NumIterations: 1,
		NumThreads:    1,
	}

	validSalt := make([]byte, 32)
	maxSalt := make([]byte, key.MaxSaltLength)
	minSalt := make([]byte, key.MinSaltLength)

	tests := []struct {
		name           string
		password       string
		salt           []byte
		params         *key.Argon2idParams
		keyLength      uint32
		expectedKeyLen int
		expectedErr    error
	}{
		{
			name:           "valid input",
			password:       "securepassword123",
			salt:           validSalt,
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		{
			name:           "minimum password length",
			password:       "123456789101", // Exactly key.MinPasswordLength
			salt:           validSalt,
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		{
			name:           "minimum salt length",
			password:       "securepassword123",
			salt:           minSalt,
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		{
			name:           "maximum salt length",
			password:       "securepassword123",
			salt:           maxSalt,
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		{
			name:           "error when key length too short",
			password:       "securepassword123",
			salt:           validSalt,
			params:         defaultParams,
			keyLength:      15, // Exactly key.MinKeyLength - 1
			expectedKeyLen: 0,
			expectedErr:    errors.New("key length must be at least 16 bytes"),
		},
		{
			name:           "different key length",
			password:       "securepassword123",
			salt:           validSalt,
			params:         defaultParams,
			keyLength:      64,
			expectedKeyLen: 64,
			expectedErr:    nil,
		},
		{
			name:           "error when password too short",
			password:       "", // key.MinPasswordLength - 1
			salt:           validSalt,
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    fmt.Errorf("password must be at least %d characters long", key.MinPasswordLength),
		},
		{
			name:           "error when invalid UTF-8 password",
			password:       string([]byte{0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd}),
			salt:           validSalt,
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    key.ErrInvalidUTF8,
		},
		{
			name:           "error when salt too short",
			password:       "securepassword123",
			salt:           make([]byte, key.MinSaltLength-1),
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    fmt.Errorf("salt must be at least %d bytes long", key.MinSaltLength),
		},
		{
			name:           "error when salt too long",
			password:       "securepassword123",
			salt:           make([]byte, key.MaxSaltLength+1),
			params:         defaultParams,
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    fmt.Errorf("salt length exceeds maximum of %d bytes", key.MaxSaltLength),
		},
		{
			name:           "error when zero iterations",
			password:       "securepassword123",
			salt:           validSalt,
			params:         &key.Argon2idParams{MemoryKiB: 128 * 1024, NumIterations: 0, NumThreads: 4},
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    errors.New("invalid Argon2id parameters: NumIterations: cannot be blank."),
		},
		{
			name:           "error when zero memory",
			password:       "securepassword123",
			salt:           validSalt,
			params:         &key.Argon2idParams{MemoryKiB: 0, NumIterations: 4, NumThreads: 4},
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    errors.New("invalid Argon2id parameters: MemoryKiB: cannot be blank."),
		},
		{
			name:           "error when zero threads",
			password:       "securepassword123",
			salt:           validSalt,
			params:         &key.Argon2idParams{MemoryKiB: 128 * 1024, NumIterations: 4, NumThreads: 0},
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    errors.New("invalid Argon2id parameters: NumThreads: cannot be blank."),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			key, err := key.DeriveKeyFromPassword(t.Context(), []byte(test.password), test.salt, test.params, test.keyLength)
			if test.expectedErr != nil {
				require.ErrorContains(t, err, test.expectedErr.Error())
				require.Nil(t, key)
			} else {
				require.NoError(t, err)
				require.NotNil(t, key)
				require.Len(t, key, test.expectedKeyLen)
			}
		})
	}

	t.Run("same input should produce same key", func(t *testing.T) {
		t.Parallel()

		password := []byte("securepassword123")

		key1, err := key.DeriveKeyFromPassword(t.Context(), password, validSalt, defaultParams, 32)
		require.NoError(t, err)

		key2, err := key.DeriveKeyFromPassword(t.Context(), password, validSalt, defaultParams, 32)
		require.NoError(t, err)

		require.Equal(t, key1, key2)
	})
}

func TestDefaultArgon2idParams(t *testing.T) {
	t.Parallel()

	params := key.DefaultArgon2idParams()

	require.Equal(t, key.DefaultArgon2idMemoryKiB, params.MemoryKiB)
	require.Equal(t, key.DefaultArgon2idNumIterations, params.NumIterations)
	require.Equal(t, key.DefaultArgon2idNumThreads, params.NumThreads)
}
