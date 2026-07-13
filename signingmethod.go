package jwt

type SigningMethod interface {
	Alg() string

	Verify(signingString string, sig []byte, key interface{}) error
	Sign(signingString string, key interface{}) ([]byte, error)
}
