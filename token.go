package jwt

type Header interface {
	GetAlg() string
}

type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	SetIssuer(issuer string)
	GetSubject() (string, error)
	GetAudience() (ClaimStrings, error)
}

type Token[H Header, C Claims] struct {
	Header       H
	Claims       C
	SignedString string
	Signature    []byte
	Valid        bool
}

type StdHeader struct {
	Alg string `json:"alg"`
}

func (h *StdHeader) GetAlg() string {
	return h.Alg
}

var _ Header = (*StdHeader)(nil)

type StdClaims struct {
	ExpirationTime *NumericDate `json:"exp"`
	IssuedAt       *NumericDate `json:"iat"`
	NotBefore      *NumericDate `json:"nbf"`
	Issuer         string       `json:"iss"`
	Subject        string       `json:"sub"`
	Audience       ClaimStrings `json:"aud"`
}

func (h *StdClaims) GetExpirationTime() (*NumericDate, error) {
	return h.ExpirationTime, nil
}

func (h *StdClaims) GetIssuedAt() (*NumericDate, error) {
	return h.IssuedAt, nil
}

func (h *StdClaims) GetNotBefore() (*NumericDate, error) {
	return h.NotBefore, nil
}

func (h *StdClaims) GetIssuer() (string, error) {
	return h.Issuer, nil
}

func (h *StdClaims) SetIssuer(issuer string) {
	h.Issuer = issuer
}

func (h *StdClaims) GetSubject() (string, error) {
	return h.Subject, nil
}

func (h *StdClaims) GetAudience() (ClaimStrings, error) {
	return h.Audience, nil
}

var _ Claims = (*StdClaims)(nil)

func NewToken[H Header, C Claims](header H, claims C) *Token[H, C] {
	return &Token[H, C]{
		Header: header,
		Claims: claims,
	}
}

func NewStdToken() *Token[*StdHeader, *StdClaims] {
	return &Token[*StdHeader, *StdClaims]{
		Header: &StdHeader{},
		Claims: &StdClaims{},
	}
}
