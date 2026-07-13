package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// SigningMethodRSA implements the RSA family of signing methods.
// Expects *rsa.PrivateKey for signing and *rsa.PublicKey for validation
type SigningMethodRSA struct {
	alg  string
	hash crypto.Hash
}

var _ SigningMethod = (*SigningMethodRSA)(nil)

var SigningMethodRS256 = &SigningMethodRSA{
	alg:  "RS256",
	hash: crypto.SHA256,
}

var SigningMethodRS384 = &SigningMethodRSA{
	alg:  "RS384",
	hash: crypto.SHA384,
}

var SigningMethodRS512 = &SigningMethodRSA{
	alg:  "RS512",
	hash: crypto.SHA512,
}

func (m *SigningMethodRSA) Alg() string {
	return m.alg
}

// Verify implements token verification for the SigningMethod
// For this signing method, must be an *rsa.PublicKey structure.
func (m *SigningMethodRSA) Verify(signingString string, sig []byte, key interface{}) error {
	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	// Create hasher
	if !m.hash.Available() {
		return ErrHashUnavailable
	}
	hasher := m.hash.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, m.hash, hasher.Sum(nil), sig)
}

// Sign implements token signing for the SigningMethod
// For this signing method, must be an *rsa.PrivateKey structure.
func (m *SigningMethodRSA) Sign(signingString string, key interface{}) ([]byte, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	// Validate type of key
	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return nil, ErrInvalidKeyType
	}

	// Create the hasher
	if !m.hash.Available() {
		return nil, ErrHashUnavailable
	}

	hasher := m.hash.New()
	hasher.Write([]byte(signingString))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, m.hash, hasher.Sum(nil)); err == nil {
		return sigBytes, nil
	} else {
		return nil, err
	}
}
