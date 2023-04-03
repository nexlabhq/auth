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
		Issuer:     "https://nexlab.tech",
		Algorithm:  jose.HS256,
	})

	uid := uuid.New().String()
	tokenResult, err := jwtAuth.EncodeToken(&AccountProvider{
		ProviderUserID: uid,
	}, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenResult.RefreshToken)

	testVerifyToken := func(tok string) {
		payload, claims, err := jwtAuth.VerifyToken(tok)
		assert.NoError(t, err)

		assert.Equal(t, uid, payload.ProviderUserID)
		assert.Equal(t, uid, *payload.AccountID)
		assert.Equal(t, string(AuthJWT), payload.Name)
		assert.Nil(t, claims)
	}

	testVerifyToken(tokenResult.AccessToken)

	refreshToken, err := jwtAuth.RefreshToken(tokenResult.RefreshToken)
	assert.NoError(t, err)

	_, _, err = jwtAuth.VerifyToken(tokenResult.RefreshToken)
	assert.EqualError(t, err, ErrCodeTokenAudienceMismatched)

	testVerifyToken(refreshToken.AccessToken)
}
