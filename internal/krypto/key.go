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
	MinKeyLength                        = 16
	MinSaltLength                       = 16
	MaxSaltLength                       = 255
	DefaultArgon2idMemoryKiB     uint32 = 128 * 1024
	DefaultArgon2idNumIterations uint32 = 4
	DefaultArgon2idNumThreads    uint8  = 4
)

var (
	ErrInvalidUTF8 = errors.New("password contains invalid UTF-8 characters")
)

type Argon2idParams struct {
	MemoryKiB     uint32
	NumIterations uint32
	NumThreads    uint8
}

// TODO: Enforce secure minimum values for MemoryKiB, NumIterations, and NumThreads.
func (a Argon2idParams) Validate(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, &a,
		validation.Field(&a.MemoryKiB, validation.Required, validation.Min(uint32(1))),
		validation.Field(&a.NumIterations, validation.Required, validation.Min(uint32(1))),
		validation.Field(&a.NumThreads, validation.Required, validation.Min(uint8(1))),
	)
}

func DefaultArgon2idParams() *Argon2idParams {
	return &Argon2idParams{
		MemoryKiB:     DefaultArgon2idMemoryKiB,
		NumIterations: DefaultArgon2idNumIterations,
		NumThreads:    DefaultArgon2idNumThreads,
	}
}

func GenerateSalt(length uint32) ([]byte, error) {
	if length < MinSaltLength {
		return nil, fmt.Errorf("salt must be at least %d bytes long", MinSaltLength)
	}

	if length > MaxSaltLength {
		return nil, fmt.Errorf("salt length exceeds maximum of %d bytes", MaxSaltLength)
	}

	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}

// DeriveKeyFromPassword derives a key using Argon2id.
func DeriveKeyFromPassword(ctx context.Context, utf8Password []byte, salt []byte, params *Argon2idParams, keyLengthInBytes uint32) ([]byte, error) {
	if len(utf8Password) < MinPasswordLength {
		return nil, fmt.Errorf("password must be at least %d characters long", MinPasswordLength)
	}

	if !utf8.Valid(utf8Password) {
		return nil, ErrInvalidUTF8
	}

	if len(salt) < MinSaltLength {
		return nil, fmt.Errorf("salt must be at least %d bytes long", MinSaltLength)
	}

	if len(salt) > MaxSaltLength {
		return nil, fmt.Errorf("salt length exceeds maximum of %d bytes", MaxSaltLength)
	}

	if keyLengthInBytes < MinKeyLength {
		return nil, fmt.Errorf("key length must be at least %d bytes", MinKeyLength)
	}

	if params == nil {
		params = DefaultArgon2idParams()
	}

	if err := params.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid Argon2id parameters: %w", err)
	}

	return argon2.IDKey(utf8Password, salt, params.NumIterations, params.MemoryKiB, params.NumThreads, keyLengthInBytes), nil
}
