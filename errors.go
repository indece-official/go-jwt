package jwt

import "errors"

var (
	ErrTokenMalformed            = errors.New("token is malformed")
	ErrTokenUnverifiable         = errors.New("token is unverifiable")
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrTokenNotValidYet          = errors.New("token is not valid yet")
	ErrInvalidType               = errors.New("invalid type for claim")
	ErrInvalidKey                = errors.New("key is invalid")
	ErrInvalidKeyType            = errors.New("key is of invalid type")
	ErrTokenInvalidAudience      = errors.New("token has invalid audience")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("token has invalid subject")
	ErrHashUnavailable           = errors.New("the requested hash function is unavailable")
)
