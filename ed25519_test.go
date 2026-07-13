package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignParseTokenEdDSA(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	signer := NewSigner(
		SignerWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		SignerWithSigningMethods[*StdHeader, *StdClaims](SigningMethodEdDSA),
		SignerWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	parser := NewParser(
		ParserWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return publicKey, nil
		}),
		ParserWithSigningMethods[*StdHeader, *StdClaims](SigningMethodEdDSA),
		ParserWithAudience[*StdHeader, *StdClaims]("testaudience"),
		ParserWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	token := NewStdToken()
	token.Header.Alg = SigningMethodEdDSA.Alg()
	token.Claims.IssuedAt = NewNumericDate(time.Now())
	token.Claims.NotBefore = NewNumericDate(time.Now())
	token.Claims.ExpirationTime = NewNumericDate(time.Now().Add(10 * time.Second))
	token.Claims.Audience = []string{"testaudience"}
	token.Claims.Subject = "usr-01"

	signedToken, err := signer.Sign(token)
	assert.NoError(t, err)
	tokenParts := strings.Split(signedToken, ".")
	assert.Len(t, tokenParts, 3)
	assert.Len(t, tokenParts[2], 86)

	parsedToken := NewStdToken()

	err = parser.Parse(signedToken, parsedToken)
	assert.NoError(t, err)
	assert.Equal(t, "EdDSA", parsedToken.Header.Alg)
	assert.Equal(t, "usr-01", parsedToken.Claims.Subject)
}
