package krypto_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/stretchr/testify/require"
)

func TestDefaultArgon2idParams(t *testing.T) {
	t.Run("default argon2id returns expected values", func(t *testing.T) {
		t.Parallel()

		params := krypto.DefaultArgon2idParams()

		require.Equal(t, krypto.DefaultArgon2idMemoryKiB, params.MemoryKiB)
		require.Equal(t, krypto.DefaultArgon2idNumIterations, params.NumIterations)
		require.Equal(t, krypto.DefaultArgon2idNumThreads, params.NumThreads)
	})
}

func TestGenerateSalt(t *testing.T) {
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
		"error when salt length too long": {
			saltLength:   krypto.MaxSaltLength + 1,
			expectedErr:  errors.New("salt length exceeds maximum of 255 bytes"),
			expectedSalt: nil,
		},
		"error when salt length too short": {
			saltLength:   krypto.MinSaltLength - 1,
			expectedErr:  errors.New("salt must be at least 16 bytes long"),
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
	basicArgonParams := func() *krypto.Argon2idParams {
		return &krypto.Argon2idParams{
			MemoryKiB:     1,
			NumIterations: 1,
			NumThreads:    1,
		}
	}

	validSalt := func() []byte {
		return make([]byte, 32)
	}

	tests := map[string]struct {
		password       string
		salt           []byte
		params         *krypto.Argon2idParams
		keyLength      uint32
		expectedKeyLen int
		expectedErr    error
	}{
		"valid input": {
			password:       "securepassword123",
			salt:           validSalt(),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"minimum password length": {
			password:       "123456789101", // Exactly key.MinPasswordLength
			salt:           validSalt(),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"minimum salt length": {
			password:       "securepassword123",
			salt:           make([]byte, krypto.MinSaltLength),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"maximum salt length": {
			password:       "securepassword123",
			salt:           make([]byte, krypto.MaxSaltLength),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 32,
			expectedErr:    nil,
		},
		"error when key length too short": {
			password:       "securepassword123",
			salt:           validSalt(),
			params:         basicArgonParams(),
			keyLength:      15, // Exactly key.MinKeyLength - 1
			expectedKeyLen: 0,
			expectedErr:    errors.New("key length must be at least 16 bytes"),
		},
		"different key length": {
			password:       "securepassword123",
			salt:           validSalt(),
			params:         basicArgonParams(),
			keyLength:      64,
			expectedKeyLen: 64,
			expectedErr:    nil,
		},
		"error when password too short": {
			password:       "", // key.MinPasswordLength - 1
			salt:           validSalt(),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    fmt.Errorf("password must be at least %d characters long", krypto.MinPasswordLength),
		},
		"error when invalid UTF-8 password": {
			password:       string([]byte{0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd, 0xff, 0xfe, 0xfd}),
			salt:           validSalt(),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    krypto.ErrInvalidUTF8,
		},
		"error when salt too short": {
			password:       "securepassword123",
			salt:           make([]byte, krypto.MinSaltLength-1),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    fmt.Errorf("salt must be at least %d bytes long", krypto.MinSaltLength),
		},
		"error when salt too long": {
			password:       "securepassword123",
			salt:           make([]byte, krypto.MaxSaltLength+1),
			params:         basicArgonParams(),
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    fmt.Errorf("salt length exceeds maximum of %d bytes", krypto.MaxSaltLength),
		},
		"error when zero iterations": {
			password:       "securepassword123",
			salt:           validSalt(),
			params:         &krypto.Argon2idParams{MemoryKiB: 128 * 1024, NumIterations: 0, NumThreads: 4},
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    errors.New("invalid Argon2id parameters: NumIterations: cannot be blank."),
		},
		"error when zero memory": {
			password:       "securepassword123",
			salt:           validSalt(),
			params:         &krypto.Argon2idParams{MemoryKiB: 0, NumIterations: 4, NumThreads: 4},
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    errors.New("invalid Argon2id parameters: MemoryKiB: cannot be blank."),
		},
		"error when zero threads": {
			password:       "securepassword123",
			salt:           validSalt(),
			params:         &krypto.Argon2idParams{MemoryKiB: 128 * 1024, NumIterations: 4, NumThreads: 0},
			keyLength:      32,
			expectedKeyLen: 0,
			expectedErr:    errors.New("invalid Argon2id parameters: NumThreads: cannot be blank."),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := krypto.DeriveKeyFromPassword(t.Context(), []byte(test.password), test.salt, test.params, test.keyLength)
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
		salt := make([]byte, 32)
		params := &krypto.Argon2idParams{
			MemoryKiB:     1,
			NumIterations: 1,
			NumThreads:    1,
		}

		key1, err := krypto.DeriveKeyFromPassword(t.Context(), password, salt, params, 32)
		require.NoError(t, err)

		key2, err := krypto.DeriveKeyFromPassword(t.Context(), password, salt, params, 32)
		require.NoError(t, err)

		require.Equal(t, key1, key2)
	})
}
