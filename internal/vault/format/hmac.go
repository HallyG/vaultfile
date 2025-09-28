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
		return errors.New("computed HMAC does not match header HMAC")
	}

	return nil
}

func ComputeHMAC(header *Header, mac hash.Hash) ([]byte, error) {
	mac.Reset() // incase we try to reuse the mac

	mac.Write(header.MagicNumber[:])
	mac.Write([]byte{byte(header.Version)})
	mac.Write(header.Salt[:])
	mac.Write(header.Nonce[:])

	kdfParamsBytes, err := header.KDFParams.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal KDF params: %w", err)
	}
	mac.Write(kdfParamsBytes)

	if err := binary.Write(mac, binary.BigEndian, header.TotalPayloadLength); err != nil {
		return nil, fmt.Errorf("total payload length: %w", err)
	}

	return mac.Sum(nil), nil
}
