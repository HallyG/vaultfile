package krypto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"unicode/utf8"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"golang.org/x/crypto/argon2"
)

const (
	MinPasswordLength                   = 1
	MaxPasswordLength                   = 256
	MinKeyLength                        = 16
	MaxKeyLength                        = 64
	MinSaltLength                       = 16
	MaxSaltLength                       = 255
	DefaultArgon2idMemoryKiB     uint32 = 128 * 1024
	MaxArgon2idMemoryKiB         uint32 = 8 * 1024 * 1024
	DefaultArgon2idNumIterations uint32 = 4
	MaxArgon2idNumIterations     uint32 = 100
	DefaultArgon2idNumThreads    uint8  = 4
	MaxArgon2idNumThreads        uint8  = 32
)

var (
	ErrInvalidUTF8 = errors.New("password contains invalid UTF-8 characters")
)

type Argon2idParams struct {
	MemoryKiB     uint32
	NumIterations uint32
	NumThreads    uint8
}

func (a Argon2idParams) Validate(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, &a,
		validation.Field(&a.MemoryKiB, validation.Required, validation.Min(uint32(1)), validation.Max(MaxArgon2idMemoryKiB)),
		validation.Field(&a.NumIterations, validation.Required, validation.Min(uint32(1)), validation.Max(MaxArgon2idNumIterations)),
		validation.Field(&a.NumThreads, validation.Required, validation.Min(uint8(1)), validation.Max(MaxArgon2idNumThreads)),
	)
}

func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		MemoryKiB:     DefaultArgon2idMemoryKiB,
		NumIterations: DefaultArgon2idNumIterations,
		NumThreads:    DefaultArgon2idNumThreads,
	}
}

func GenerateSalt(length uint32) ([]byte, error) {
	if length < MinSaltLength {
		return nil, fmt.Errorf("salt size must be at least %d bytes, got %d", MinSaltLength, length)
	}

	if length > MaxSaltLength {
		return nil, fmt.Errorf("salt size exceeds maximum of %d bytes, got %d", MaxSaltLength, length)
	}

	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("random salt: %w", err)
	}

	return salt, nil
}

// DeriveKeyFromPassword derives a key using Argon2id.
func DeriveKeyFromPassword(ctx context.Context, utf8Password []byte, salt []byte, params Argon2idParams, keyLengthInBytes uint32) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if salt == nil {
		return nil, errors.New("salt cannot be nil")
	}

	if len(salt) < MinSaltLength {
		return nil, fmt.Errorf("salt size must be at least %d bytes, got %d", MinSaltLength, len(salt))
	}

	if len(salt) > MaxSaltLength {
		return nil, fmt.Errorf("salt size exceeds maximum of %d bytes, got %d", MaxSaltLength, len(salt))
	}

	if keyLengthInBytes < MinKeyLength {
		return nil, fmt.Errorf("key length must be at least %d bytes, got %d", MinKeyLength, keyLengthInBytes)
	}

	if keyLengthInBytes > MaxKeyLength {
		return nil, fmt.Errorf("key length exceeds maximum of %d bytes, got %d", MaxKeyLength, keyLengthInBytes)
	}

	if utf8Password == nil {
		return nil, errors.New("password cannot be nil")
	}

	if len(utf8Password) < MinPasswordLength {
		return nil, fmt.Errorf("password length must be at least %d characters, got %d", MinPasswordLength, len(utf8Password))
	}

	if len(utf8Password) > MaxPasswordLength {
		return nil, fmt.Errorf("password exceeds maximum length of %d characters, got %d", MaxPasswordLength, len(utf8Password))
	}

	if !utf8.Valid(utf8Password) {
		return nil, ErrInvalidUTF8
	}

	if err := params.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid Argon2id parameters: %w", err)
	}

	return argon2.IDKey(utf8Password, salt, params.NumIterations, params.MemoryKiB, params.NumThreads, keyLengthInBytes), nil
}
