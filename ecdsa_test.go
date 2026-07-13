package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignParseTokenES256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	signer := NewSigner(
		SignerWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		SignerWithSigningMethods[*StdHeader, *StdClaims](SigningMethodES256),
		SignerWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	parser := NewParser(
		ParserWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return &privateKey.PublicKey, nil
		}),
		ParserWithSigningMethods[*StdHeader, *StdClaims](SigningMethodES256),
		ParserWithAudience[*StdHeader, *StdClaims]("testaudience"),
		ParserWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	token := NewStdToken()
	token.Header.Alg = SigningMethodES256.Alg()
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
	assert.Equal(t, "ES256", parsedToken.Header.Alg)
	assert.Equal(t, "usr-01", parsedToken.Claims.Subject)
}

func TestSignParseTokenES384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	signer := NewSigner(
		SignerWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		SignerWithSigningMethods[*StdHeader, *StdClaims](SigningMethodES384),
		SignerWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	parser := NewParser(
		ParserWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return &privateKey.PublicKey, nil
		}),
		ParserWithSigningMethods[*StdHeader, *StdClaims](SigningMethodES384),
		ParserWithAudience[*StdHeader, *StdClaims]("testaudience"),
		ParserWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	token := NewStdToken()
	token.Header.Alg = SigningMethodES384.Alg()
	token.Claims.IssuedAt = NewNumericDate(time.Now())
	token.Claims.NotBefore = NewNumericDate(time.Now())
	token.Claims.ExpirationTime = NewNumericDate(time.Now().Add(10 * time.Second))
	token.Claims.Audience = []string{"testaudience"}
	token.Claims.Subject = "usr-01"

	signedToken, err := signer.Sign(token)
	assert.NoError(t, err)
	tokenParts := strings.Split(signedToken, ".")
	assert.Len(t, tokenParts, 3)
	assert.Len(t, tokenParts[2], 128)

	parsedToken := NewStdToken()

	err = parser.Parse(signedToken, parsedToken)
	assert.NoError(t, err)
	assert.Equal(t, "ES384", parsedToken.Header.Alg)
	assert.Equal(t, "usr-01", parsedToken.Claims.Subject)
}

func TestSignParseTokenES512(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NoError(t, err)

	signer := NewSigner(
		SignerWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		SignerWithSigningMethods[*StdHeader, *StdClaims](SigningMethodES512),
		SignerWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	parser := NewParser(
		ParserWithKeyFunc(func(t *Token[*StdHeader, *StdClaims]) (interface{}, error) {
			return &privateKey.PublicKey, nil
		}),
		ParserWithSigningMethods[*StdHeader, *StdClaims](SigningMethodES512),
		ParserWithAudience[*StdHeader, *StdClaims]("testaudience"),
		ParserWithIssuer[*StdHeader, *StdClaims]("testissuer"),
	)

	token := NewStdToken()
	token.Header.Alg = SigningMethodES512.Alg()
	token.Claims.IssuedAt = NewNumericDate(time.Now())
	token.Claims.NotBefore = NewNumericDate(time.Now())
	token.Claims.ExpirationTime = NewNumericDate(time.Now().Add(10 * time.Second))
	token.Claims.Audience = []string{"testaudience"}
	token.Claims.Subject = "usr-01"

	signedToken, err := signer.Sign(token)
	assert.NoError(t, err)
	tokenParts := strings.Split(signedToken, ".")
	assert.Len(t, tokenParts, 3)
	assert.Len(t, tokenParts[2], 176)

	parsedToken := NewStdToken()

	err = parser.Parse(signedToken, parsedToken)
	assert.NoError(t, err)
	assert.Equal(t, "ES512", parsedToken.Header.Alg)
	assert.Equal(t, "usr-01", parsedToken.Claims.Subject)
}
