//go:build integration
// +build integration

package auth

import (
	"log"
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

func setupHasuraClient() *graphql.Client {
	httpClient := &http.Client{
		Transport: &hasuraTransport{
			rt: http.DefaultTransport,
		},
		Timeout: time.Minute,
	}

	return graphql.NewClient(os.Getenv("DATA_URL"), httpClient)
}

func deleteUserByEmail(am *AccountManager, email string) error {
	user, err := am.FindAccountByEmail(email)
	if err != nil {
		return err
	}

	if user == nil {
		return nil
	}

	return am.DeleteUser(user.ID, false)
}

func account_cleanup(t *testing.T, am *AccountManager) {
	_, err := am.DeleteUsers(map[string]interface{}{}, true)
	assert.NoError(t, err)
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

	token1, err := manager.EncodeToken(&AccountProvider{
		ProviderUserID: "user1",
	}, nil)
	assert.NoError(t, err)

	acc1, claims1, err := manager.VerifyToken(token1.AccessToken, nil)
	assert.Error(t, err)
	assert.Nil(t, acc1)
	assert.Nil(t, claims1)
}

func TestJWTAuthProviderChecksum(t *testing.T) {
	manager, err := NewAccountManager(AccountManagerConfig{
		GQLClient: setupHasuraClient(),
		JWT: &JWTAuthConfig{
			SessionKey:  "random",
			TTL:         3 * time.Second,
			RefreshTTL:  10 * time.Second,
			HasChecksum: true,
		},
		DefaultRole:     "user",
		DefaultProvider: "jwt",
		CreateFromToken: true,
	})
	assert.NoError(t, err)

	email := "jwt-test@example.com"
	password := "123456"
	err = deleteUserByEmail(manager, email)
	assert.Nil(t, err)

	user, err := manager.CreateAccountWithProvider(&CreateAccountInput{
		Email:    &email,
		Password: &password,
		Verified: getPtr(true),
	}, nil)
	assert.Nil(t, err)
	assert.NotNil(t, user)

	testClaims := map[string]interface{}{
		"foo": "bar",
	}
	doVerify := func(token string) {
		acc, claims, err := manager.VerifyToken(token, nil)
		assert.Nil(t, err)

		assert.Equal(t, user.ID, acc.ID)
		assert.Equal(t, testClaims, claims)
	}

	token1, err := manager.EncodeToken(&user.AccountProviders[0], []AuthScope{ScopeOpenID, ScopeOfflineAccess}, NewTokenClaims(testClaims))
	assert.NoError(t, err)

	doVerify(token1.AccessToken)

	// test token expired
	time.Sleep(3 * time.Second)

	_, _, err = manager.VerifyToken(token1.AccessToken, nil)
	assert.EqualError(t, err, ErrCodeTokenExpired)

	newToken1, err := manager.RefreshToken(token1.RefreshToken, NewTokenClaims(testClaims))
	assert.Nil(t, err)
	doVerify(newToken1.AccessToken)

	newPassword := "password_changed"
	err = manager.ChangePassword(user.ID, password, newPassword, false)
	assert.Nil(t, err)

	_, _, err = manager.VerifyToken(newToken1.AccessToken, nil)
	assert.EqualError(t, err, ErrCodeTokenExpired)

	userAfterChanged, err := manager.FindAccountByID(user.ID)
	assert.Nil(t, err)
	assert.Equal(t, user.ID, userAfterChanged.ID)

	tokenAfterChanged, err := manager.EncodeToken(&userAfterChanged.AccountProviders[0], []AuthScope{ScopeOpenID, ScopeOfflineAccess}, NewTokenClaims(testClaims))
	assert.Nil(t, err)
	doVerify(tokenAfterChanged.AccessToken)

	deleteUserByEmail(manager, user.Email)
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

		u, err := manager.findAccountByProviderUser(user1.AccountProviders[0].ProviderUserID, nil)
		assert.NoError(t, err)

		if u != nil {
			err = manager.DeleteUser(u.ID, false)
			assert.NoError(t, err)
		}
	}

	user1, err = provider.CreateUser(&CreateAccountInput{
		DisplayName:  getPtr("Jon Snow"),
		Email:        &email,
		EmailEnabled: getPtr(true),
		PhoneEnabled: getPtr(true),
		PhoneCode:    getPtr(84),
		PhoneNumber:  getPtr("0123456789"),
		Password:     getPtr("random_password"),
	})
	assert.NoError(t, err)

	customToken, err := provider.EncodeToken(&AccountProvider{
		ProviderUserID: user1.ID,
	}, nil)
	assert.NoError(t, err)

	idToken, err := getFirebaseIdToken(customToken.AccessToken)
	assert.NoError(t, err)

	acc1, _, err := manager.VerifyToken(idToken)
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

	err = manager.DeleteUser(acc1.ID, false)
	assert.NoError(t, err)
}

func TestJWTAuthOTP(t *testing.T) {
	manager, err := NewAccountManager(AccountManagerConfig{
		GQLClient: setupHasuraClient(),
		JWT: &JWTAuthConfig{
			SessionKey: "random",
			TTL:        time.Hour,
		},
		DefaultRole:     "user",
		DefaultProvider: "jwt",
		CreateFromToken: true,
		Enabled2FA:      true,
		OTP: AuthOTPConfig{
			Enabled:           true,
			DevMode:           true,
			DevOTPCode:        "123456",
			OTPLength:         6,
			LoginLimit:        2,
			LoginDisableLimit: 3,
			LoginLockDuration: time.Second,
			TTL:               time.Minute,
		},
	})
	assert.NoError(t, err)

	defer account_cleanup(t, manager)

	phoneNumber := "0900000000"

	otp := manager.GenerateOTP(nil, 84, phoneNumber)
	assert.Equal(t, "", otp.Error)
	assert.Equal(t, 6, len(otp.Code))

	otp2 := manager.GenerateOTP(nil, 84, phoneNumber)
	assert.Equal(t, ErrCodeOTPAlreadySent, otp2.Error)

	tok1, err := manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         otp.Code,
	})
	assert.NoError(t, err)
	assert.NotNil(t, tok1)

	_, err = manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         otp.Code,
	})
	assert.EqualError(t, err, ErrCodeInvalidOTP)

	// test 2fa otp
	log.Println(otp.AccountID)
	otp2fa := manager.Generate2FaOTP(nil, otp.AccountID, 0, "")
	assert.Equal(t, "", otp2fa.Error)
	assert.Equal(t, 6, len(otp2fa.Code))

	err = manager.Verify2FaOTP(nil, otp.AccountID, otp2fa.Code, Auth2FASms)
	assert.NoError(t, err)

	// test failure otp
	opt4 := manager.GenerateOTP(nil, 84, phoneNumber)
	assert.Equal(t, "", opt4.Error)
	assert.Equal(t, 6, len(opt4.Code))

	_, err = manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         "111111",
	})
	assert.EqualError(t, err, ErrCodeInvalidOTP)

	_, err = manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         "111111",
	})
	assert.EqualError(t, err, ErrCodeInvalidOTP)

	_, err = manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         "111111",
	})
	assert.EqualError(t, err, ErrCodeInvalidOTP)

	otp5 := manager.GenerateOTP(nil, 84, phoneNumber)
	assert.Equal(t, ErrCodeAccountTemporarilyLocked, otp5.Error)

	assert.EqualError(t, err, ErrCodeInvalidOTP)
	time.Sleep(2 * time.Second)

	_, err = manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         "111111",
	})
	assert.EqualError(t, err, ErrCodeInvalidOTP)

	otp6 := manager.GenerateOTP(nil, 84, phoneNumber)
	assert.Equal(t, ErrCodeAccountDisabled, otp6.Error)
	_, err = manager.VerifyOTP(nil, VerifyOTPInput{
		PhoneCode:   84,
		PhoneNumber: phoneNumber,
		OTP:         "111111",
	})
	assert.EqualError(t, err, ErrCodeAccountDisabled)
}
