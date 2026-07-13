package jwt

import (
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var (
	ErrMLDSA87Verification = errors.New("mldsa87: verification error")
)

type SigningMethodMLDSA struct {
	alg string
}

var _ SigningMethod = (*SigningMethodMLDSA)(nil)

func (m *SigningMethodMLDSA) Alg() string {
	return m.alg
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an ed25519.PublicKey
func (m *SigningMethodMLDSA) Verify(signingString string, sig []byte, key interface{}) error {
	var mldsa87Key *mldsa87.PublicKey
	var ok bool

	if mldsa87Key, ok = key.(*mldsa87.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	if len(mldsa87Key.Bytes()) != mldsa87.PublicKeySize {
		return ErrInvalidKey
	}

	// Verify the signature
	if !mldsa87.Verify(mldsa87Key, []byte(signingString), nil, sig) {
		return ErrMLDSA87Verification
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an mldsa87.PrivateKey
func (m *SigningMethodMLDSA) Sign(signingString string, key interface{}) ([]byte, error) {
	var mldsa87Key crypto.Signer
	var ok bool

	if mldsa87Key, ok = key.(crypto.Signer); !ok {
		return nil, ErrInvalidKeyType
	}

	if _, ok := mldsa87Key.Public().(*mldsa87.PublicKey); !ok {
		return nil, ErrInvalidKey
	}

	// Sign the string and return the encoded result
	// ed25519 performs a two-pass hash as part of its algorithm. Therefore, we need to pass a non-prehashed message into the Sign function, as indicated by crypto.Hash(0)
	sig, err := mldsa87Key.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

var SigningMethodMLDSA87 = &SigningMethodMLDSA{
	alg: "MLDSA87",
}
