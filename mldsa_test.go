package jwt

import (
	"crypto/rand"
	"fmt"
	"strings"
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
	tokenParts := strings.Split(signedToken, ".")
	assert.Len(t, tokenParts, 3)
	assert.Len(t, tokenParts[2], 6170)

	parsedToken := NewStdToken()

	err = parser.Parse(signedToken, parsedToken)
	assert.NoError(t, err)
	assert.Equal(t, "MLDSA87", parsedToken.Header.Alg)
	assert.Equal(t, "usr-01", parsedToken.Claims.Subject)
}

func TestSignParseTokenMLDSA87InvalidSignature(t *testing.T) {
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
	tokenParts := strings.Split(signedToken, ".")
	assert.Len(t, tokenParts, 3)
	assert.Len(t, tokenParts[2], 6170)

	parsedToken := NewStdToken()
	corruptedSignature := fmt.Sprintf("%sA%s", tokenParts[2][0:99], tokenParts[2][100:])
	corruptedSignedToken := fmt.Sprintf("%s.%s.%s", tokenParts[0], tokenParts[1], corruptedSignature)

	err = parser.Parse(corruptedSignedToken, parsedToken)
	assert.ErrorIs(t, err, ErrMLDSA87Verification)
}
