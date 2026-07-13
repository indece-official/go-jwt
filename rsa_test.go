package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignParseTokenRSA512(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)

	publicKey := privateKey.Public()

	signer := NewSigner(
		SignerWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		SignerWithSigningMethods[*StdHeader, *StdClaims](SigningMethodRS512),
		SignerWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	parser := NewParser(
		ParserWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return publicKey, nil
		}),
		ParserWithSigningMethods[*StdHeader, *StdClaims](SigningMethodRS512),
		ParserWithAudience[*StdHeader, *StdClaims]("testaudience"),
		ParserWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	token := NewStdToken()
	token.Header.Alg = SigningMethodRS512.Alg()
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
