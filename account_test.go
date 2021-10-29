// go:build integration
//go:build integration
// +build integration

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	firebase "firebase.google.com/go/v4"
	"github.com/hasura/go-graphql-client"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
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

func setupHasuraClient() *graphql.Client {
	httpClient := &http.Client{
		Transport: &hasuraTransport{
			rt: http.DefaultTransport,
		},
		Timeout: time.Minute,
	}

	return graphql.NewClient(os.Getenv("DATA_URL"), httpClient)
}

func setupFirebaseApp() *firebase.App {
	app, err := firebase.NewApp(context.Background(), nil, option.WithCredentialsJSON([]byte(os.Getenv("GOOGLE_CREDENTIALS"))))

	if err != nil {
		panic(err)
	}

	return app
}

func getFirebaseIdToken(token string) (string, error) {
	client := http.DefaultClient
	url := fmt.Sprintf("https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=%s", os.Getenv("FIREBASE_API_KEY"))
	resp, err := client.Post(url, "application/json", bytes.NewBuffer([]byte(fmt.Sprintf(`{
		"token": "%s",
		"returnSecureToken": true
	}`, token))))

	if err != nil {
		return "", err
	}

	var result struct {
		IDToken string `json:"idToken"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return "", err
	}

	return result.IDToken, nil
}

func TestAuthMangerAs(t *testing.T) {
	manager, err := NewAccountManager(AccountManagerConfig{
		GQLClient: setupHasuraClient(),
		JWT: &JWTAuthConfig{
			SessionKey: "random",
			TTL:        time.Hour,
		},
		DefaultRole:     "user",
		DefaultProvider: "jwt",
		CreateFromToken: true,
	})
	assert.NoError(t, err)

	managerFirebase := manager.As("firebase")
	assert.Equal(t, manager.createFromToken, managerFirebase.createFromToken)
	assert.Equal(t, manager.defaultRole, managerFirebase.defaultRole)
	assert.Equal(t, AuthFirebase, managerFirebase.providerType)
}

func TestParseJson(t *testing.T) {
	env := os.Getenv("TEST_JSON")
	log.Printf("TEST_JSON: %s", env)

	var testObject struct {
		Foo string `json:"foo"`
	}

	err := json.Unmarshal([]byte(env), &testObject)
	assert.NoError(t, err)
}

func TestJWTAuthProvider(t *testing.T) {
	manager, err := NewAccountManager(AccountManagerConfig{
		GQLClient: setupHasuraClient(),
		JWT: &JWTAuthConfig{
			SessionKey: "random",
			TTL:        time.Hour,
		},
		DefaultRole:     "user",
		DefaultProvider: "jwt",
		CreateFromToken: true,
	})
	assert.NoError(t, err)

	token1, err := manager.EncodeToken("user1")
	assert.NoError(t, err)

	acc1, err := manager.VerifyToken(token1.AccessToken)
	assert.Error(t, err)
	assert.Nil(t, acc1)
}

func TestFirebaseAuthProvider(t *testing.T) {
	fbApp := setupFirebaseApp()
	provider := NewFirebaseAuth(fbApp)
	email := "firebase@example.com"
	manager, err := NewAccountManager(AccountManagerConfig{
		GQLClient:       setupHasuraClient(),
		FirebaseApp:     fbApp,
		DefaultRole:     "user",
		DefaultProvider: "firebase",
		CreateFromToken: true,
	})
	assert.NoError(t, err)

	// cleanup data first
	user1, err := provider.GetUserByEmail(email)
	assert.NoError(t, err)

	if user1 != nil {
		err = provider.DeleteUser(user1.AccountProviders[0].ProviderUserID)
		assert.NoError(t, err)

		u, err := manager.findAccountByProviderUser(user1.AccountProviders[0].ProviderUserID)
		assert.NoError(t, err)

		if u != nil {
			err = manager.DeleteUser(u.ID)
			assert.NoError(t, err)
		}
	}

	user1, err = provider.CreateUser(&CreateAccountInput{
		DisplayName:  "Jon Snow",
		Email:        email,
		EmailEnabled: true,
		PhoneEnabled: true,
		PhoneCode:    84,
		PhoneNumber:  "0123456789",
		Password:     "random_password",
	})
	assert.NoError(t, err)

	customToken, err := provider.EncodeToken(user1.ID)
	assert.NoError(t, err)

	idToken, err := getFirebaseIdToken(customToken.AccessToken)
	assert.NoError(t, err)

	acc1, err := manager.VerifyToken(idToken)
	assert.NoError(t, err)
	assert.Equal(t, user1.ID, acc1.AccountProviders[0].ProviderUserID)

	acc1g, err := manager.FindAccountByID(acc1.ID)
	assert.NoError(t, err)
	assert.Equal(t, acc1.ID, acc1g.ID)
	assert.Equal(t, acc1.DisplayName, acc1g.DisplayName)
	assert.Equal(t, acc1.Email, acc1g.Email)
	assert.Equal(t, acc1.PhoneCode, acc1g.PhoneCode)
	assert.Equal(t, acc1.PhoneNumber, acc1g.PhoneNumber)
	assert.Equal(t, "user", acc1g.Role)

	err = manager.DeleteUser(acc1.ID)
	assert.NoError(t, err)
}
