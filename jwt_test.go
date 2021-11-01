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
		RefreshTTL: 2 * time.Hour,
		Issuer:     "telehealth.nexlab",
		Algorithm:  jose.HS256,
	})

	uid := uuid.New().String()
	tokenResult, err := jwtAuth.EncodeToken(uid)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenResult.RefreshToken)

	testVerifyToken := func(tok string) {
		payload, err := jwtAuth.VerifyToken(tok)
		assert.NoError(t, err)

		assert.Equal(t, uid, payload.ProviderUserID)
		assert.Equal(t, uid, *payload.AccountID)
		assert.Equal(t, string(AuthJWT), payload.Name)
	}

	testVerifyToken(tokenResult.AccessToken)

	refreshToken, err := jwtAuth.RefreshToken(tokenResult.RefreshToken, tokenResult.AccessToken)
	assert.NoError(t, err)

	_, err = jwtAuth.RefreshToken(tokenResult.RefreshToken, refreshToken.AccessToken)
	assert.EqualError(t, err, ErrCodeTokenMismatched)

	testVerifyToken(refreshToken.AccessToken)
}
