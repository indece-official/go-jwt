package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStdTokenUnmarshalBody(t *testing.T) {
	raw := []byte(`{
		"iss": "https://sso.indece.com/oauth/",
		"sub": "USR-01",
		"aud": [
			"oauth"
		],
		"exp": 1750451383,
		"nbf": 1750451263,
		"iat": 1750451263,
		"azp": "portal_testcloud",
		"typ": "access",
		"sid": "SID-01",
		"user_uid": "USR-01",
		"name": "Tester",
		"email": "tester@indece.com",
		"groups": [
			"indece:oauth2:loggedin",
			"indece:oauth2:self:change-password"
		],
		"attrs": {},
		"orgs": [
			{
				"uid": "ORG-01",
				"name": "Testorg",
				"role": "owner"
			}
		]
	}`)

	token := NewStdToken()

	err := json.Unmarshal(raw, token.Claims)
	assert.NoError(t, err)
	assert.Equal(t, time.Unix(1750451383, 0), token.Claims.ExpirationTime.Time)
}
