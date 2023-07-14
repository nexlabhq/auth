package auth

import (
	"testing"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJWT_encodeToken(t *testing.T) {

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
	}, []AuthScope{ScopeOpenID, ScopeOfflineAccess})
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

func TestJWT_encodeTokenWithClaims(t *testing.T) {

	jwtAuth := NewJWTAuth(nil, JWTAuthConfig{
		SessionKey: "randomsecret",
		TTL:        time.Hour,
		RefreshTTL: 2 * time.Hour,
		Issuer:     "https://nexlab.tech",
		Algorithm:  jose.HS256,
	})

	fixtures := []struct {
		UserID string
		Claims map[string]interface{}
	}{
		{
			uuid.NewString(),
			map[string]interface{}{
				"foo":    "bar",
				"active": false,
			},
		},
		{
			uuid.NewString(),
			map[string]interface{}{
				"x-hasura-user-id": "1",
				"x-hasura-role":    "admin",
			},
		},
	}

	for i, f := range fixtures {
		tokenResult, err := jwtAuth.EncodeToken(&AccountProvider{
			ProviderUserID: f.UserID,
		}, []AuthScope{ScopeOpenID, ScopeOfflineAccess}, NewTokenClaims(f.Claims))
		assert.NoError(t, err, "%d", i)
		assert.NotEmpty(t, tokenResult.AccessToken, "%d", i)
		assert.NotEmpty(t, tokenResult.RefreshToken, "%d", i)
		decodedToken, err := jwtAuth.decodeToken(tokenResult.AccessToken)
		assert.NoError(t, err, "%d", i)
		assert.Equal(t, f.UserID, decodedToken.Subject, "%d", i)
		assert.Equal(t, f.Claims, decodedToken.CustomClaims, "%d", i)
	}

}
