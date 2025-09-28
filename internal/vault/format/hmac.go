package format

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

func ValidateHMAC(header *Header, mac hash.Hash) error {
	computedHMAC, err := ComputeHMAC(header, mac)
	if err != nil {
		return fmt.Errorf("compute HMAC: %w", err)
	}

	if subtle.ConstantTimeCompare(computedHMAC, header.HMAC[:]) != 1 {
		return errors.New("invalid HMAC")
	}

	return nil
}

func ComputeHMAC(header *Header, mac hash.Hash) ([]byte, error) {
	if _, err := mac.Write(header.MagicNumber[:]); err != nil {
		return nil, fmt.Errorf("magic number: %w", err)
	}

	if _, err := mac.Write([]byte{byte(header.Version)}); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}

	if _, err := mac.Write(header.CipherTextKeySalt[:]); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	if _, err := mac.Write(header.CipherTextKeyNonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	if _, err := mac.Write(header.cipherTextKeyKDFParamsRaw[:]); err != nil {
		return nil, fmt.Errorf("KDF params: %w", err)
	}

	if err := binary.Write(mac, binary.BigEndian, header.TotalPayloadLength); err != nil {
		return nil, fmt.Errorf("payload length: %w", err)
	}

	return mac.Sum(nil), nil
}
