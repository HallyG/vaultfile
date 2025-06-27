package vaultfile

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/HallyG/vaultfile/internal/format"
	"github.com/HallyG/vaultfile/internal/krypto"
)

type Version uint8

func (v Version) String() string {
	return fmt.Sprintf("v%d", v)
}

const (
	VersionUnknown Version = 0
)

var (
	ErrInvalidHeader       = errors.New("invalid header format")
	ErrFileTruncated       = errors.New("file truncated")
	ErrInvalidHeaderHMAC   = errors.New("invalid HMAC")
	ErrInvalidKDFParams    = errors.New("invalid KDF parameters")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrKeyDerivationFailed = errors.New("key derivation failed")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrNilWriter           = errors.New("writer is nil")
	ErrNilReader           = errors.New("reader is nil")
	ErrCipherTextTooLarge  = fmt.Errorf("ciphertext must be smaller than %d bytes", versionV1MaxCipherTextSize)
)

type VaultFileError struct {
	Err   error
	Field string
	Value any
}

func (e *VaultFileError) Error() string {
	return fmt.Sprintf("vault error: %s (field: %s, value: %v)", e.Err, e.Field, e.Value)
}

func (e *VaultFileError) Unwrap() error {
	return e.Err
}

type Vault struct {
	logger    *slog.Logger
	kdfParams *krypto.Argon2idParams
}

func WithLogger(logger *slog.Logger) func(*Vault) {
	return func(v *Vault) {
		v.logger = logger
	}
}

func New(opts ...func(*Vault)) (*Vault, error) {
	v := &Vault{
		kdfParams: krypto.DefaultArgon2idParams(),
	}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	v.logger = v.logger.
		WithGroup("vault").
		With(slog.String("version", VersionV1.String()))
	return v, nil
}

func (v *Vault) Version() Version {
	return VersionV1
}

func (v *Vault) Encrypt(ctx context.Context, w io.Writer, password []byte, plainText []byte) error {
	if w == nil {
		return &VaultFileError{
			Err:   ErrNilWriter,
			Field: "writer",
			Value: nil,
		}
	}

	v.logger.Debug("encrypting data", slog.Int("plaintext.size", len(plainText)))
	v.logger.Debug("generating salt", slog.Int("salt.size", krypto.MinSaltLength))

	salt, err := krypto.GenerateSalt(krypto.MinSaltLength)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to generate salt: %w", err),
			Field: "salt",
			Value: nil,
		}
	}

	cipher, err := v.deriveEncryptionKey(ctx, password, salt, v.kdfParams, krypto.ChaCha20KeySize)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "encryption_key",
			Value: nil,
		}
	}

	hmacKey, err := v.deriveHMACKey(ctx, password, salt, krypto.ChaCha20KeySize)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "hmac_key",
			Value: nil,
		}
	}

	v.logger.Debug("encrypting plaintext")
	cipherText, nonce, err := cipher.Encrypt(ctx, plainText, nil)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("encryption failed: %w", err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	if len(cipherText) > versionV1MaxCipherTextSize {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: ciphertext size %d exceeds maximum %d", ErrCipherTextTooLarge, len(cipherText), versionV1MaxCipherTextSize),
			Field: "ciphertext",
			Value: len(cipherText),
		}
	}

	v.logger.Debug("encrypted plaintext", slog.Int("nonce.size", len(nonce)), slog.Int("ciphertext.size", len(cipherText)))
	return v.writeBinary(w, salt, nonce, v.kdfParams, cipherText, hmacKey)
}

func (v *Vault) Decrypt(ctx context.Context, input io.Reader, password []byte) ([]byte, error) {
	if input == nil {
		return nil, &VaultFileError{Err: ErrNilReader, Field: "reader", Value: nil}
	}

	v.logger.Debug("decrypting data")

	header, r, err := format.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	// Parse KDF params using format package
	kdfParams, err := header.ParseKDFParams()
	if err != nil {
		return nil, &VaultFileError{Err: err, Field: "kdf_params", Value: nil}
	}

	// Convert to internal KDF params type if needed
	internalKDFParams := &krypto.Argon2idParams{
		MemoryKiB:     kdfParams.MemoryKiB,
		NumIterations: kdfParams.NumIterations,
		NumThreads:    kdfParams.NumThreads,
	}

	// Validate KDF params
	if err := internalKDFParams.Validate(ctx); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrInvalidKDFParams, err),
			Field: "argon2id_params",
			Value: fmt.Sprintf("memory=%d, iterations=%d, threads=%d",
				kdfParams.MemoryKiB, kdfParams.NumIterations, kdfParams.NumThreads),
		}
	}

	// Derive HMAC key and validate
	hmacKey, err := v.deriveHMACKey(ctx, password, header.CipherTextKeySalt[:], krypto.ChaCha20KeySize)
	if err != nil {
		return nil, err
	}

	// Use format package for HMAC validation
	if err := format.ValidateMAC(header, hmac.New(sha256.New, hmacKey)); err != nil {
		return nil, &VaultFileError{Err: ErrInvalidHeaderHMAC, Field: "hmac", Value: nil}
	}

	// Use format package to read ciphertext
	cipherText, err := format.ReadCipherText(r, header)
	if err != nil {
		return nil, &VaultFileError{Err: err, Field: "ciphertext", Value: nil}
	}

	// Validate total file length
	totalLen := len(cipherText) + versionV1LenHeader
	if uint16(totalLen) != header.TotalPayloadLength {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: expected %d bytes, read %d", ErrFileTruncated, header.TotalPayloadLength, totalLen),
			Field: "total_file_length",
			Value: totalLen,
		}
	}

	// Decrypt
	plainText, err := v.decrypt(ctx, password, header.CipherTextKeySalt[:], header.CipherTextKeyNonce[:], internalKDFParams, cipherText, krypto.ChaCha20KeySize)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrDecryptionFailed, err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return plainText, nil
}
