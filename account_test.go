package auth

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hasura/go-graphql-client"
	"github.com/stretchr/testify/assert"
)

// hasuraTransport transport for Hasura GraphQL Client
type hasuraTransport struct {
	// keep a reference to the client's original transport
	rt http.RoundTripper
}

// RoundTrip set header data before executing http request
func (t *hasuraTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	adminSecret := os.Getenv("HASURA_GRAPHQL_ADMIN_SECRET")

	r.Header.Set("x-hasura-admin-secret", adminSecret)
	return t.rt.RoundTrip(r)
}

func createHasuraClient() *graphql.Client {
	httpClient := &http.Client{
		Transport: &hasuraTransport{
			rt: http.DefaultTransport,
		},
		Timeout: time.Minute,
	}

	return graphql.NewClient(os.Getenv("DATA_URL"), httpClient)
}

func TestJWTAuthProvider(t *testing.T) {
	manager, err := NewAccountManager(AccountManagerConfig{
		GQLClient: createHasuraClient(),
		JWT: &JWTAuthConfig{
			SessionKey: "random",
			TTL:        time.Hour,
		},
		DefaultRole:     "user",
		DefaultProvider: "jwt",
		CreateFromToken: true,
	})
	assert.NoError(t, err)

	_, err = manager.EncodeToken("user1")
	assert.NoError(t, err)

	// acc1, err := manager.VerifyToken(token1.AccessToken)
	// assert.NoError(t, err)

	// assert.Equal(t, "user1", acc1.ID)
}
