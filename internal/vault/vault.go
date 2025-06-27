package vaultfile

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/HallyG/vaultfile/internal/vault/format"
)

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

	return v, nil
}

func (v *Vault) Version() format.Version {
	return format.VersionV1
}

func (v *Vault) Encrypt(ctx context.Context, output io.Writer, password []byte, plainText []byte) error {
	if output == nil {
		return errors.New("output writer cannot be nil")
	}

	salt, err := krypto.GenerateSalt(krypto.MinSaltLength)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	hmacKey, err := v.deriveHMACKey(ctx, password, salt, krypto.ChaCha20KeySize)
	if err != nil {
		return fmt.Errorf("hmac key derivation failed: %w", err)
	}

	key, err := v.deriveEncryptionKey(ctx, password, salt, v.kdfParams, krypto.ChaCha20KeySize)
	if err != nil {
		return fmt.Errorf("ciphertext key derivation failed: %w", err)
	}

	cipher, err := krypto.NewChaCha20Crypto(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	v.logger.Debug("encrypting plaintext", slog.Int("plaintext.size", len(plainText)))

	cipherText, nonce, err := cipher.Encrypt(ctx, plainText, nil)
	if err != nil {
		return fmt.Errorf("plaintext encryption: %w", err)
	}

	v.logger.Debug("encrypted plaintext", slog.Int("plaintext.size", len(plainText)), slog.Int("ciphertext.size", len(cipherText)))

	if len(cipherText) > format.MaxCipherTextSize {
		return fmt.Errorf("ciphertext must be smaller than %d bytes", format.MaxCipherTextSize)
	}

	if err := format.EncodeHeader(
		output,
		hmac.New(sha256.New, hmacKey),
		[16]byte(salt),
		[24]byte(nonce),
		format.KDFParams{
			MemoryKiB:     v.kdfParams.MemoryKiB,
			NumIterations: v.kdfParams.NumIterations,
			NumThreads:    v.kdfParams.NumThreads,
		},
		uint16(len(cipherText)),
	); err != nil {
		return err
	}

	if _, err := output.Write(cipherText); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	return nil
}

func (v *Vault) Decrypt(ctx context.Context, input io.Reader, password []byte) ([]byte, error) {
	if input == nil {
		return nil, errors.New("input reader cannot be nil")
	}

	v.logger.Debug("parsing header")

	header, r, err := format.ParseHeader(input)
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	internalKDFParams := &krypto.Argon2idParams{
		MemoryKiB:     header.CipherTextKeyKDFParams.MemoryKiB,
		NumIterations: header.CipherTextKeyKDFParams.NumIterations,
		NumThreads:    header.CipherTextKeyKDFParams.NumThreads,
	}
	if err := internalKDFParams.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid KDF parameters: %w", err)
	}

	hmacKey, err := v.deriveHMACKey(ctx, password, header.CipherTextKeySalt[:], krypto.ChaCha20KeySize)
	if err != nil {
		return nil, fmt.Errorf("hmac key derivation failed: %w", err)
	}

	if err := format.ValidateMAC(header, hmac.New(sha256.New, hmacKey)); err != nil {
		return nil, err
	}

	key, err := v.deriveEncryptionKey(ctx, password, header.CipherTextKeySalt[:], internalKDFParams, krypto.ChaCha20KeySize)
	if err != nil {
		return nil, fmt.Errorf("ciphertext key derivation failed: %w", err)
	}

	cipher, err := krypto.NewChaCha20Crypto(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	cipherText, err := format.ReadCipherText(r, header)
	if err != nil {
		return nil, err
	}

	v.logger.Debug("decrypting ciphertext", slog.Int("ciphertext.size", len(cipherText)))

	plainText, err := cipher.Decrypt(ctx, cipherText, header.CipherTextKeyNonce[:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plainText, nil
}

func (v *Vault) deriveHMACKey(ctx context.Context, password []byte, salt []byte, keySize uint32) ([]byte, error) {
	// We use a predefined argon2id params so prevent a resource exhaustion attack where we'd need to generate the password from header values before we verify them
	kdfParams := krypto.DefaultArgon2idParams()
	return krypto.DeriveKeyFromPassword(ctx, password, salt, kdfParams, keySize)
}

func (v *Vault) deriveEncryptionKey(ctx context.Context, password []byte, salt []byte, kdfParams *krypto.Argon2idParams, keySize uint32) ([]byte, error) {
	return krypto.DeriveKeyFromPassword(ctx, password, salt, kdfParams, keySize)
}
