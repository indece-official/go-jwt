# go-jwt
JWT Parser, Signer and JWKS-Loader with support for post-quantum-cryptography (PQC)

## Supported algorithms
| Algorithm | PQC | `alg` header | Signatur size (base64 encoded) |
| --- | --- | --- |
| RSA 256 | No | `RS256` | 683 b (4096 bit key) | 
| RSA 384 | No | `RS384` | 683 b (4096 bit key) | 
| RSA 512 | No | `RS512` | 683 b (4096 bit key) | 
| ECDSA 256 | No | `ES256` | 86 b |
| ECDSA 384 | No | `ES384` | 128 b |
| ECDSA 512 | No | `ES512` | 176 b | 
| Ed25519 | No | `EdDSA` | 86 b |
| ML-DSA-87 | Yes | `MLDSA87` | 6170 b |

## Usage

Example with signer & loader for MLDSA87
```

import (
    "fmt"

    "github.com/cloudflare/circl/sign/mldsa/mldsa87"
    jwt "github.com/indece-official/go-jwt"
)

func example() error {
    publicKey, privateKey, err := mldsa87.GenerateKey(rand.Reader)
    if err != nil {
        return fmt.Errorf("generaring key failed: %s", err)
    }

	signer := jwt.NewSigner(
		jwt.SignerWithKeyFunc(func(t *jwt.Token[*jwt.StdHeader, *jwt.StdClaims]) (interface{}, error) {
			return privateKey, nil
		}),
		jwt.SignerWithSigningMethods[*jwt.StdHeader, *jwt.StdClaims](jwt.SigningMethodMLDSA87),
		jwt.SignerWithIssuer[*jwt.StdHeader, *jwt.StdClaims]("testissuer"),
	)

	parser := jwt.NewParser(
		jwt.ParserWithKeyFunc(func(t *jwt.Token[*jwt.StdHeader, *jwt.StdClaims]) (interface{}, error) {
			return publicKey, nil
		}),
		jwt.ParserWithSigningMethods[*jwt.StdHeader, *jwt.StdClaims](jwt.SigningMethodMLDSA87),
		jwt.ParserWithAudience[*jwt.StdHeader, *jwt.StdClaims]("testaudience"),
		jwt.ParserWithIssuer[*jwt.StdHeader, *jwt.StdClaims]("testissuer"),
	)

	token := jwt.NewStdToken()
	token.Header.Alg = jwt.SigningMethodMLDSA87.Alg()
	token.Claims.IssuedAt = jwt.NewNumericDate(time.Now())
	token.Claims.NotBefore = jwt.NewNumericDate(time.Now())
	token.Claims.ExpirationTime = jwt.NewNumericDate(time.Now().Add(10 * time.Second))
	token.Claims.Audience = []string{"testaudience"}
	token.Claims.Subject = "usr-01"

	signedToken, err := signer.Sign(token)
    if err != nil {
        return err
    }

	parsedToken := jwt.NewStdToken()

	err = parser.Parse(signedToken, parsedToken)
    if err != nil {
        return err
    }

    return nil
}
```

Inspired by github.com/golang-jwt/jwt
