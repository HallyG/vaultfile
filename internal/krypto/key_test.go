package krypto_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/stretchr/testify/require"
)

func TestArgon2idParams(t *testing.T) {
	t.Parallel()

	t.Run("default argon2id returns expected values", func(t *testing.T) {
		t.Parallel()

		params := krypto.DefaultArgon2idParams()

		require.Equal(t, krypto.DefaultArgon2idMemoryKiB, params.MemoryKiB)
		require.Equal(t, krypto.DefaultArgon2idNumIterations, params.NumIterations)
		require.Equal(t, krypto.DefaultArgon2idNumThreads, params.NumThreads)
	})
}

func TestGenerateSalt(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		saltLength   uint32
		expectedErr  error
		expectedSalt []byte
	}{
		"valid salt length": {
			saltLength:   32,
			expectedErr:  nil,
			expectedSalt: make([]byte, 32),
		},
		"minimum salt length": {
			saltLength:   krypto.MinSaltLength,
			expectedErr:  nil,
			expectedSalt: make([]byte, krypto.MinSaltLength),
		},
		"maximum salt length": {
			saltLength:   krypto.MaxSaltLength,
			expectedErr:  nil,
			expectedSalt: make([]byte, krypto.MaxSaltLength),
		},
		"returns error when salt length too long": {
			saltLength:   krypto.MaxSaltLength + 1,
			expectedErr:  errors.New("salt size exceeds maximum of 255 bytes, got 25"),
			expectedSalt: nil,
		},
		"returns error when salt length too short": {
			saltLength:   krypto.MinSaltLength - 1,
			expectedErr:  errors.New("salt size must be at least 16 bytes, got 15"),
			expectedSalt: nil,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			salt, err := krypto.GenerateSalt(test.saltLength)
			if test.expectedErr != nil {
				require.ErrorContains(t, err, test.expectedErr.Error())
				require.Nil(t, salt)
			} else {
				require.NoError(t, err)
				require.Len(t, salt, int(test.saltLength))
			}
		})
	}
}

func TestDeriveKeyFromPassword(t *testing.T) {
	t.Parallel()

	password := []byte("securepassword123")
	salt := []byte(strings.Repeat("s", 32))
	kdfParams := krypto.Argon2idParams{
		MemoryKiB:     1,
		NumIterations: 1,
		NumThreads:    1,
	}

	tests := map[string]struct {
		password       []byte
		salt           []byte
		params         krypto.Argon2idParams
		keyLen         uint32
		expectedKeyLen int
		expectedErr    error
	}{
		"valid input": {
			password:       password,
			salt:           salt,
			params:         kdfParams,
			keyLen:         32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"minimum password length": {
			password:       []byte(strings.Repeat("1", krypto.MinPasswordLength)),
			salt:           salt,
			params:         kdfParams,
			keyLen:         32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"returns error when nil password": {
			password:    nil,
			salt:        salt,
			params:      kdfParams,
			keyLen:      32,
			expectedErr: errors.New("password cannot be nil"),
		},
		"returns error when password too short": {
			password:    []byte(strings.Repeat("1", krypto.MinPasswordLength-1)),
			salt:        salt,
			params:      kdfParams,
			keyLen:      32,
			expectedErr: errors.New("password length must be at least 1 characters, got 0"),
		},
		"returns error when password too long": {
			password:    []byte(strings.Repeat("1", krypto.MaxPasswordLength+1)),
			salt:        salt,
			params:      kdfParams,
			keyLen:      32,
			expectedErr: errors.New("password exceeds maximum length of 256 characters, got 257"),
		},
		"returns error when invalid UTF-8 password": {
			password:    []byte{0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd},
			salt:        salt,
			params:      kdfParams,
			keyLen:      32,
			expectedErr: krypto.ErrInvalidUTF8,
		},
		"minimum salt length": {
			password:       password,
			salt:           make([]byte, krypto.MinSaltLength),
			params:         kdfParams,
			keyLen:         32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"maximum salt length": {
			password:       password,
			salt:           make([]byte, krypto.MaxSaltLength),
			params:         kdfParams,
			keyLen:         32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"returns error when nil salt": {
			password:    password,
			salt:        nil,
			params:      kdfParams,
			keyLen:      32,
			expectedErr: errors.New("salt cannot be nil"),
		},
		"returns error when salt too short": {
			password:    password,
			salt:        make([]byte, krypto.MinSaltLength-1),
			params:      kdfParams,
			keyLen:      32,
			expectedErr: errors.New("salt size must be at least 16 bytes, got 15"),
		},
		"returns error when salt too long": {
			password:    password,
			salt:        make([]byte, krypto.MaxSaltLength+1),
			params:      kdfParams,
			keyLen:      32,
			expectedErr: errors.New("salt size exceeds maximum of 255 bytes, got 256"),
		},
		"returns error when key too short": {
			password:    password,
			salt:        salt,
			params:      kdfParams,
			keyLen:      krypto.MinKeyLength - 1,
			expectedErr: errors.New("key length must be at least 16 bytes, got 1"),
		},
		"returns error when key too long": {
			password:    password,
			salt:        salt,
			params:      kdfParams,
			keyLen:      krypto.MaxKeyLength + 1,
			expectedErr: errors.New("key length exceeds maximum of 64 bytes, got 65"),
		},
		"different key length": {
			password:       password,
			salt:           salt,
			params:         kdfParams,
			keyLen:         64,
			expectedKeyLen: 64,
			expectedErr:    nil,
		},
		"error when zero iterations": {
			password:    password,
			salt:        salt,
			params:      krypto.Argon2idParams{MemoryKiB: 1, NumIterations: 0, NumThreads: 1},
			keyLen:      32,
			expectedErr: errors.New("invalid Argon2id parameters: NumIterations: cannot be blank."),
		},
		"returns error when zero memory": {
			password:    password,
			salt:        salt,
			params:      krypto.Argon2idParams{MemoryKiB: 0, NumIterations: 1, NumThreads: 1},
			keyLen:      32,
			expectedErr: errors.New("invalid Argon2id parameters: MemoryKiB: cannot be blank."),
		},
		"returns error when zero threads": {
			password:    password,
			salt:        salt,
			params:      krypto.Argon2idParams{MemoryKiB: 1, NumIterations: 1, NumThreads: 0},
			keyLen:      32,
			expectedErr: errors.New("invalid Argon2id parameters: NumThreads: cannot be blank."),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := krypto.DeriveKeyFromPassword(t.Context(), []byte(test.password), test.salt, test.params, test.keyLen)
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

	t.Run("returns error when context cancelled", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		key, err := krypto.DeriveKeyFromPassword(ctx, password, salt, kdfParams, 32)
		require.ErrorContains(t, err, "context canceled")
		require.Nil(t, key)
	})

	t.Run("same input should produce same key", func(t *testing.T) {
		t.Parallel()

		key1, err := krypto.DeriveKeyFromPassword(t.Context(), password, salt, kdfParams, 32)
		require.NoError(t, err)
		require.NotNil(t, key1)

		key2, err := krypto.DeriveKeyFromPassword(t.Context(), password, salt, kdfParams, 32)
		require.NoError(t, err)
		require.NotNil(t, key2)

		require.Equal(t, key1, key2)
	})
}
