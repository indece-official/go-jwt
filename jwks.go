package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type JWKSKeyKty string

const (
	JWKSKeyKtyEC  JWKSKeyKty = "EC"
	JWKSKeyKtyOKP JWKSKeyKty = "OKP"
	JWKSKeyKtyRSA JWKSKeyKty = "RSA"
	JWKSKeyKtyOct JWKSKeyKty = "oct"
)

type JWKSKeyUse string

const (
	JWKSKeyUseEnc JWKSKeyUse = "enc"
	JWKSKeyUseSig JWKSKeyUse = "sig"
)

type JWKSKey struct {
	Alg string     `json:"alg"`
	E   string     `json:"e"`
	N   string     `json:"n"`
	K   string     `json:"k"`
	Kid string     `json:"kid"`
	Kty JWKSKeyKty `json:"kty"`
	Use JWKSKeyUse `json:"use"`
}

func (j *JWKSKey) LoadPublicKey() (any, error) {
	switch j.Kty {
	case JWKSKeyKtyRSA:
		rawN, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, fmt.Errorf("error parsing n from jwks: %s", err)
		}

		rawE, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, fmt.Errorf("error parsing e from jwks: %s", err)
		}

		n := big.NewInt(0)
		n.SetBytes(rawN)

		e := big.NewInt(0)
		e.SetBytes(rawE)

		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case JWKSKeyKtyOct:
		switch j.Alg {
		case "MLDSA87":
			pubKey := &mldsa87.PublicKey{}

			raw, err := base64.RawURLEncoding.DecodeString(j.K)
			if err != nil {
				return nil, fmt.Errorf("error parsing k from jwks: %s", err)
			}

			err = pubKey.UnmarshalBinary(raw)
			if err != nil {
				return nil, fmt.Errorf("error loading k from jwks as mldsa87 public key: %s", err)
			}

			return pubKey, nil
		default:
			return nil, fmt.Errorf("unsupported alg %s for kty %s", j.Alg, j.Kty)
		}
	default:
		return nil, fmt.Errorf("unsupported kty %s", j.Kty)
	}
}

type JWKSCerts struct {
	Keys []*JWKSKey `json:"keys"`
}

type KidHeader interface {
	Header

	GetKid() string
}

type StdKidHeader struct {
	StdHeader

	Kid string `json:"kid"`
}

func (h *StdKidHeader) GetKid() string {
	return h.Kid
}

var _ KidHeader = (*StdKidHeader)(nil)

type JWKSLoader[H KidHeader, C Claims] struct {
	ctx             context.Context
	uriJwks         string
	client          *http.Client
	lastRefresh     *time.Time
	refreshInterval time.Duration
	keys            []*JWKSKey
}

type JWKSLoaderOption[H KidHeader, C Claims] func(*JWKSLoader[H, C])

func WithJWKSUri[H KidHeader, C Claims](uriJwks string) JWKSLoaderOption[H, C] {
	return func(l *JWKSLoader[H, C]) {
		l.uriJwks = uriJwks
	}
}

func WithJWKSHttpClient[H KidHeader, C Claims](client *http.Client) JWKSLoaderOption[H, C] {
	return func(l *JWKSLoader[H, C]) {
		l.client = client
	}
}

func WithJWKSRefreshInterval[H KidHeader, C Claims](refreshInterval time.Duration) JWKSLoaderOption[H, C] {
	return func(l *JWKSLoader[H, C]) {
		l.refreshInterval = refreshInterval
	}
}

// New creates a new Keyfunc.
func NewJWKSLoader[H KidHeader, C Claims](ctx context.Context, options ...JWKSLoaderOption[H, C]) (*JWKSLoader[H, C], error) {
	loader := &JWKSLoader[H, C]{
		ctx:             ctx,
		uriJwks:         "",
		client:          http.DefaultClient,
		lastRefresh:     nil,
		refreshInterval: time.Hour,
		keys:            []*JWKSKey{},
	}

	for _, option := range options {
		option(loader)
	}

	err := loader.load(loader.ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading jwks: %s", err)
	}

	if loader.refreshInterval > 0 {
		go func() {
			tickerRefresh := time.NewTicker(loader.refreshInterval)

			for {
				<-tickerRefresh.C

				err := loader.load(loader.ctx)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error reloading jwks: %s", err)
				}
			}
		}()
	}

	return loader, nil
}

func (k *JWKSLoader[H, C]) load(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.uriJwks, nil)
	if err != nil {
		return fmt.Errorf("error creating http request for jwks: %s", err)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("error executing http request for jwks: %s", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response of http request for jwks: %s", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("http status code %d: %s", resp.StatusCode, body)
	}

	jwksKeys := &JWKSCerts{}

	err = json.Unmarshal(body, jwksKeys)
	if err != nil {
		return fmt.Errorf("error parsing response of http request for jwks: %s", err)
	}

	k.keys = jwksKeys.Keys

	lastRefresh := time.Now()

	k.lastRefresh = &lastRefresh

	return nil
}

func (k *JWKSLoader[H, C]) KeyfuncCtx(ctx context.Context) KeyFunc[H, C] {
	return func(token *Token[H, C]) (any, error) {
		kid := token.Header.GetKid()
		alg := token.Header.GetAlg()

		var foundKey *JWKSKey

		for _, key := range k.keys {
			if key.Kid == kid && key.Alg == alg {
				foundKey = key

				break
			}
		}

		if foundKey == nil {
			return nil, fmt.Errorf("no matching key found in jwks")
		}

		key, err := foundKey.LoadPublicKey()
		if err != nil {
			return nil, fmt.Errorf("error loading key from jwks: %s", err)
		}

		return key, nil
	}
}

func (k *JWKSLoader[H, C]) KeyFunc(token *Token[H, C]) (any, error) {
	keyF := k.KeyfuncCtx(k.ctx)
	return keyF(token)
}
