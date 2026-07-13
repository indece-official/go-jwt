package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

type Signer[H Header, C Claims] struct {
	keyFunc        KeyFunc[H, C]
	signingMethods map[string]SigningMethod
	issuer         string
}

var ErrNoIssuerConfigured = errors.New("no issuer configured")

func (s *Signer[H, C]) Sign(token *Token[H, C]) (string, error) {
	if s.issuer == "" {
		return "", ErrNoIssuerConfigured
	}

	token.Claims.SetIssuer(s.issuer)

	// TODO: Pre-validate token

	encoding := base64.RawURLEncoding

	headerRaw, err := json.Marshal(token.Header)
	if err != nil {
		return "", err
	}

	claimsRaw, err := json.Marshal(token.Claims)
	if err != nil {
		return "", err
	}

	token.SignedString = fmt.Sprintf(
		"%s.%s",
		encoding.EncodeToString(headerRaw),
		encoding.EncodeToString(claimsRaw),
	)

	signingMethod := s.signingMethods[token.Header.GetAlg()]
	if signingMethod == nil {
		return "", fmt.Errorf("invalid alg %s", token.Header.GetAlg())
	}

	key, err := s.keyFunc(token)
	if err != nil {
		return "", err
	}

	signatureRaw, err := signingMethod.Sign(token.SignedString, key)
	if err != nil {
		return "", err
	}

	token.Signature = signatureRaw

	signedToken := fmt.Sprintf(
		"%s.%s",
		token.SignedString,
		encoding.EncodeToString(signatureRaw),
	)

	return signedToken, nil
}

type SignerOption[H Header, C Claims] func(*Signer[H, C])

func SignerWithKeyFunc[H Header, C Claims](keyFunc KeyFunc[H, C]) SignerOption[H, C] {
	return func(p *Signer[H, C]) {
		p.keyFunc = keyFunc
	}
}

func SignerWithSigningMethods[H Header, C Claims](signingMethods ...SigningMethod) SignerOption[H, C] {
	return func(p *Signer[H, C]) {
		p.signingMethods = map[string]SigningMethod{}

		for _, signingMethod := range signingMethods {
			p.signingMethods[signingMethod.Alg()] = signingMethod
		}
	}
}

func SignerWithIssuer[H Header, C Claims](issuer string) SignerOption[H, C] {
	return func(p *Signer[H, C]) {
		p.issuer = issuer
	}
}

func NewSigner[H Header, C Claims](options ...SignerOption[H, C]) *Signer[H, C] {
	signer := &Signer[H, C]{
		signingMethods: map[string]SigningMethod{
			SigningMethodES256.Alg():   SigningMethodES256,
			SigningMethodES384.Alg():   SigningMethodES384,
			SigningMethodES512.Alg():   SigningMethodES512,
			SigningMethodRS256.Alg():   SigningMethodRS256,
			SigningMethodRS384.Alg():   SigningMethodRS384,
			SigningMethodRS512.Alg():   SigningMethodRS512,
			SigningMethodEdDSA.Alg():   SigningMethodEdDSA,
			SigningMethodMLDSA87.Alg(): SigningMethodMLDSA87,
		},
		keyFunc: func(t *Token[H, C]) (interface{}, error) {
			return nil, ErrInvalidKeyType
		},
		issuer: "",
	}

	for _, option := range options {
		option(signer)
	}

	return signer
}
