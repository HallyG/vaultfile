package format

import (
	"fmt"
	"io"
)

type Version uint8

func (v Version) String() string {
	return fmt.Sprintf("v%d", v)
}

const (
	VersionUnknown Version = 0
)

type Header struct {
	MagicNumber            []byte
	Version                Version
	CipherTextKeySalt      []byte
	CipherTextKeyNonce     []byte
	CipherTextKeyKDFParams []byte
	TotalPayloadLength     uint16
	HMAC                   []byte
}

func Parse(src io.Reader) (*Header, io.Reader, error) {

	return nil, nil, nil
}
