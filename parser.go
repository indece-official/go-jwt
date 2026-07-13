package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

func splitToken(token string) ([]string, bool) {
	parts := make([]string, 3)
	header, remain, ok := strings.Cut(token, ".")
	if !ok {
		return nil, false
	}
	parts[0] = header
	claims, remain, ok := strings.Cut(remain, ".")
	if !ok {
		return nil, false
	}
	parts[1] = claims
	// One more cut to ensure the signature is the last part of the token and there are no more
	// delimiters. This avoids an issue where malicious input could contain additional delimiters
	// causing unecessary overhead parsing tokens.
	signature, _, unexpected := strings.Cut(remain, ".")
	if unexpected {
		return nil, false
	}
	parts[2] = signature

	return parts, true
}

type KeyFunc[H Header, C Claims] func(*Token[H, C]) (interface{}, error)

type Parser[H Header, C Claims] struct {
	// leeway is an optional leeway that can be provided to account for clock skew.
	leeway               time.Duration
	decodePaddingAllowed bool
	decodeStrict         bool
	// Fallback to use iat if nbf is not set (e.g. keycloak does not set nbf)
	fallbackNbfIat        bool
	keyFunc               KeyFunc[H, C]
	signingMethods        map[string]SigningMethod
	expectedAudiences     []string
	expectedIssuers       []string
	expectAllAudiences    bool
	expectMatchingIssuer  bool
	expectMatchingSubject bool
	expectedSubjects      []string
}

func (p *Parser[H, C]) DecodeSegment(seg string) ([]byte, error) {
	encoding := base64.RawURLEncoding

	if p.decodePaddingAllowed {
		if l := len(seg) % 4; l > 0 {
			seg += strings.Repeat("=", 4-l)
		}
		encoding = base64.URLEncoding
	}

	if p.decodeStrict {
		encoding = encoding.Strict()
	}

	return encoding.DecodeString(seg)
}

func (p *Parser[H, C]) verifyExpiresAt(claims Claims) error {
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return err
	}

	if exp == nil {
		return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "exp")
	}

	cmp := time.Now()

	if cmp.After(exp.Add(+p.leeway)) {
		return ErrTokenExpired
	}

	return nil
}

func (p *Parser[H, C]) verifyNotBefore(claims Claims) error {
	nbf, err := claims.GetNotBefore()
	if err != nil {
		return err
	}

	if nbf == nil {
		if p.fallbackNbfIat {
			nbf, err = claims.GetIssuedAt()
			if err != nil {
				return err
			}

			if nbf == nil {
				return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "nbf")
			}
		} else {
			return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "nbf")
		}
	}

	cmp := time.Now()

	if cmp.Before(nbf.Add(-p.leeway)) {
		return ErrTokenNotValidYet
	}

	return nil
}

func (p *Parser[H, C]) verifyAudience(claims Claims) error {
	aud, err := claims.GetAudience()
	if err != nil {
		return err
	}

	if len(aud) == 0 {
		return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "aud")
	}

	matching := map[string]bool{}
	for _, expected := range p.expectedAudiences {
		matching[expected] = false
	}

	// TODO: Seems odd

	var stringClaims string
	for _, a := range aud {
		a := a
		_, ok := matching[a]
		if ok {
			matching[a] = true
		}

		stringClaims = stringClaims + a
	}

	// check if all expected auds are present
	result := true
	for _, match := range matching {
		if !p.expectAllAudiences && match {
			break
		} else if !match {
			result = false
		}
	}

	// case where "" is sent in one or many aud claims
	if stringClaims == "" {
		return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "aud")
	}

	if !result {
		return ErrTokenInvalidAudience
	}

	return nil
}

func (p *Parser[H, C]) verifyIssuer(claims Claims) error {
	iss, err := claims.GetIssuer()
	if err != nil {
		return err
	}

	if iss == "" {
		return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "iss")
	}

	if p.expectMatchingIssuer && !slices.Contains(p.expectedIssuers, iss) {
		return ErrTokenInvalidIssuer
	}

	return nil
}

func (p *Parser[H, C]) verifySubject(claims Claims) error {
	sub, err := claims.GetSubject()
	if err != nil {
		return err
	}

	if sub == "" {
		return ErrTokenRequiredClaimMissing // TODO? errorIfRequired(required, "sub")
	}

	if p.expectMatchingSubject && !slices.Contains(p.expectedSubjects, sub) {
		return ErrTokenInvalidSubject
	}

	return nil
}

func (p *Parser[H, C]) Validate(token *Token[H, C]) error {
	if p.signingMethods[token.Header.GetAlg()] == nil {
		return ErrTokenUnverifiable
	}

	key, err := p.keyFunc(token)
	if err != nil {
		return err
	}

	err = p.signingMethods[token.Header.GetAlg()].Verify(token.SignedString, token.Signature, key)
	if err != nil {
		return err
	}

	err = p.verifyExpiresAt(token.Claims)
	if err != nil {
		return err
	}

	err = p.verifyNotBefore(token.Claims)
	if err != nil {
		return err
	}

	err = p.verifyAudience(token.Claims)
	if err != nil {
		return err
	}

	err = p.verifyIssuer(token.Claims)
	if err != nil {
		return err
	}

	err = p.verifySubject(token.Claims)
	if err != nil {
		return err
	}

	return nil
}

func (p *Parser[H, C]) Parse(tokenStr string, token *Token[H, C]) error {
	token.Valid = false

	tokenParts, valid := splitToken(tokenStr)
	if !valid {
		return ErrTokenMalformed
	}

	token.SignedString = fmt.Sprintf("%s.%s", tokenParts[0], tokenParts[1])

	headerRaw, err := p.DecodeSegment(tokenParts[0])
	if err != nil {
		return ErrTokenMalformed
	}

	err = json.Unmarshal(headerRaw, token.Header)
	if err != nil {
		return ErrTokenMalformed
	}

	claimsRaw, err := p.DecodeSegment(tokenParts[1])
	if err != nil {
		return ErrTokenMalformed
	}

	err = json.Unmarshal(claimsRaw, token.Claims)
	if err != nil {
		return ErrTokenMalformed
	}

	token.Signature, err = p.DecodeSegment(tokenParts[2])
	if err != nil {
		return ErrTokenMalformed
	}

	err = p.Validate(token)
	if err != nil {
		return err
	}

	token.Valid = true

	return nil
}

type ParserOption[H Header, C Claims] func(*Parser[H, C])

func ParserWithAudience[H Header, C Claims](aud ...string) ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.expectedAudiences = aud
		p.expectAllAudiences = false
	}
}

func ParserWithAllAudience[H Header, C Claims](aud ...string) ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.expectedAudiences = aud
		p.expectAllAudiences = true
	}
}

func ParserWithIssuer[H Header, C Claims](iss ...string) ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.expectedIssuers = iss
	}
}

func ParserWithoutIssuerValidation[H Header, C Claims]() ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.expectMatchingIssuer = false
	}
}

func ParserWithKeyFunc[H Header, C Claims](keyFunc KeyFunc[H, C]) ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.keyFunc = keyFunc
	}
}

func ParserWithFallbackNbfIat[H Header, C Claims](fallbackNbfIat bool) ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.fallbackNbfIat = fallbackNbfIat
	}
}

func ParserWithSigningMethods[H Header, C Claims](signingMethods ...SigningMethod) ParserOption[H, C] {
	return func(p *Parser[H, C]) {
		p.signingMethods = map[string]SigningMethod{}

		for _, signingMethod := range signingMethods {
			p.signingMethods[signingMethod.Alg()] = signingMethod
		}
	}
}

func NewParser[H Header, C Claims](options ...ParserOption[H, C]) *Parser[H, C] {
	parser := &Parser[H, C]{
		signingMethods: map[string]SigningMethod{
			SigningMethodES256.Alg(): SigningMethodES256,
			SigningMethodES384.Alg(): SigningMethodES384,
			SigningMethodES512.Alg(): SigningMethodES512,
			SigningMethodRS256.Alg(): SigningMethodRS256,
			SigningMethodRS384.Alg(): SigningMethodRS384,
			SigningMethodRS512.Alg(): SigningMethodRS512,
			SigningMethodEdDSA.Alg(): SigningMethodEdDSA,
		},
		keyFunc: func(t *Token[H, C]) (interface{}, error) {
			return nil, ErrInvalidKeyType
		},
		expectMatchingIssuer: true,
		fallbackNbfIat:       true,
	}

	for _, option := range options {
		option(parser)
	}

	return parser
}
