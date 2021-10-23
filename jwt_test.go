package auth

import (
	"testing"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJWTEncode(t *testing.T) {

	jwtAuth := NewJWTAuth(nil, JWTAuthConfig{
		SessionKey: "randomsecret",
		TTL:        time.Hour,
		Issuer:     "telehealth.nexlab",
		Algorithm:  jose.HS256,
	})

	uid := uuid.New().String()
	tokenResult, err := jwtAuth.EncodeToken(uid)
	assert.NoError(t, err)
	payload, err := jwtAuth.VerifyToken(tokenResult.AccessToken)
	assert.NoError(t, err)

	assert.Equal(t, uid, payload.ProviderUserID)
	assert.Equal(t, uid, *payload.AccountID)
	assert.Equal(t, string(AuthJWT), payload.Name)
}
