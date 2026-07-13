package jwt

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/assert"
)

func TestSignParseTokenMLDSA87(t *testing.T) {
	publicKey, privateKey, err := mldsa87.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	signer := NewSigner(
		SignerWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		SignerWithSigningMethods[*StdHeader, *StdClaims](SigningMethodMLDSA87),
		SignerWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	parser := NewParser(
		ParserWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return publicKey, nil
		}),
		ParserWithSigningMethods[*StdHeader, *StdClaims](SigningMethodMLDSA87),
		ParserWithAudience[*StdHeader, *StdClaims]("testaudience"),
		ParserWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	token := NewStdToken()
	token.Header.Alg = SigningMethodMLDSA87.Alg()
	token.Claims.IssuedAt = NewNumericDate(time.Now())
	token.Claims.NotBefore = NewNumericDate(time.Now())
	token.Claims.ExpirationTime = NewNumericDate(time.Now().Add(10 * time.Second))
	token.Claims.Audience = []string{"testaudience"}
	token.Claims.Subject = "usr-01"

	signedToken, err := signer.Sign(token)
	assert.NoError(t, err)

	parsedToken := NewStdToken()

	err = parser.Parse(signedToken, parsedToken)
	assert.NoError(t, err)
	assert.Equal(t, "usr-01", parsedToken.Claims.Subject)
}
