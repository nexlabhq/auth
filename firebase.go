package auth

import (
	"context"
	"errors"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

// FirebaseAuth implements the AuthProvider interface for Firebase authentication
type FirebaseAuth struct {
	*firebase.App
	roleAnonymous string
}

// NewFirebaseAuth creates a FirebaseAuth instance
func NewFirebaseAuth(app *firebase.App) *FirebaseAuth {
	return &FirebaseAuth{App: app, roleAnonymous: "anonymous"}
}

// GetName gets the authentication provider type enum
func (fa FirebaseAuth) GetName() AuthProviderType {
	return AuthFirebase
}

func (fa *FirebaseAuth) CreateUser(input *CreateAccountInput) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)

	if err != nil {
		return nil, err
	}
	params := (&auth.UserToCreate{})

	if input.EmailEnabled {
		params = params.Email(input.Email).
			EmailVerified(input.Verified)
	}

	if input.DisplayName != "" {
		params = params.DisplayName(input.DisplayName)
	}
	if input.Password != "" {
		params = params.Password(input.Password)
	}

	if input.ID == "" {
		input.ID = genID()
	}
	params = params.UID((input.ID))

	if input.PhoneNumber != "" && input.PhoneEnabled {
		params = params.PhoneNumber(formatI18nPhoneNumber(input.PhoneCode, input.PhoneNumber))
	}

	u, err := authClient.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	return &Account{
		BaseAccount: BaseAccount{
			ID:          input.ID,
			Email:       input.Email,
			DisplayName: input.DisplayName,
			PhoneCode:   input.PhoneCode,
			PhoneNumber: input.PhoneNumber,
			Role:        input.Role,
			Verified:    input.Verified,
		},
		AccountProviders: []AccountProvider{
			{
				Name:           string(AuthFirebase),
				ProviderUserID: u.UID,
			},
		},
	}, nil
}

func (fa *FirebaseAuth) GetUserByID(id string) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, err
	}
	return fa.applyUser(authClient.GetUser(ctx, id))
}

func (fa *FirebaseAuth) GetUserByEmail(email string) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, err
	}
	return fa.applyUser(authClient.GetUserByEmail(ctx, email))
}

func (fa *FirebaseAuth) applyUser(u *auth.UserRecord, err error) (*Account, error) {

	if err != nil {
		if !auth.IsUserNotFound(err) {
			return nil, err
		}
		return nil, nil
	}

	var baseAccount BaseAccount
	// anonymous user
	if len(u.ProviderUserInfo) == 0 {
		baseAccount = BaseAccount{
			Role: fa.roleAnonymous,
		}
	} else {
		phoneCode := 0
		phoneNumber := ""
		if u.PhoneNumber != "" {
			phoneCode, phoneNumber, err = parseI18nPhoneNumber(u.PhoneNumber, 0)
			if err != nil {
				return nil, err
			}
		}
		baseAccount = BaseAccount{
			Email:       u.Email,
			DisplayName: u.DisplayName,
			PhoneCode:   phoneCode,
			PhoneNumber: phoneNumber,
			Verified:    u.EmailVerified,
		}
	}

	return &Account{
		BaseAccount: baseAccount,
		AccountProviders: []AccountProvider{
			{
				Name:           string(AuthFirebase),
				ProviderUserID: u.UID,
			},
		},
	}, nil
}

func (fa *FirebaseAuth) SetCustomClaims(uid string, input map[string]interface{}) error {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return err
	}

	return authClient.SetCustomUserClaims(ctx, uid, input)
}

// VerifyToken verifies the id token
func (fa *FirebaseAuth) VerifyToken(token string) (*AccountProvider, map[string]interface{}, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, nil, err
	}

	authToken, err := authClient.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	return &AccountProvider{
		Name:           string(AuthFirebase),
		ProviderUserID: authToken.UID,
	}, authToken.Claims, nil
}

// ChangePassword change  the password of user
func (fa *FirebaseAuth) ChangePassword(uid string, newPassword string) error {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return err
	}

	_, err = authClient.UpdateUser(ctx, uid, (&auth.UserToUpdate{}).Password(newPassword))
	if err != nil {
		return err
	}

	return nil
}

func (fa *FirebaseAuth) DeleteUser(uid string) error {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return err
	}

	err = authClient.DeleteUser(ctx, uid)
	if err == nil || auth.IsUserNotFound(err) {
		return nil
	}

	return err
}

// EncodeToken encodes the custom ID Token from Firebase Auth
func (fa *FirebaseAuth) EncodeToken(cred *AccountProvider, options ...AccessTokenOption) (*AccessToken, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, err
	}

	tok, err := authClient.CustomToken(ctx, cred.ProviderUserID)
	if err != nil {
		return nil, err
	}

	return &AccessToken{
		TokenType:   string(AuthFirebase),
		AccessToken: tok,
	}, nil
}

func (fa *FirebaseAuth) SignInWithEmailAndPassword(email string, password string) (*Account, error) {
	return nil, errors.New(ErrCodeUnsupported)
}

func (fa *FirebaseAuth) SignInWithPhoneAndPassword(phoneCode int, phoneNumber string, password string) (*Account, error) {
	return nil, errors.New(ErrCodeUnsupported)
}

func (fa *FirebaseAuth) VerifyPassword(providerUserId string, password string) error {
	return errors.New(ErrCodeUnsupported)
}

// RefreshToken verifies and refreshes user token.
// Firebase Auth doesn't support this
func (fa *FirebaseAuth) RefreshToken(refreshToken string, options ...AccessTokenOption) (*AccessToken, error) {
	return nil, errors.New(ErrCodeUnsupported)
}

// GetOrCreateUserByPhone get or create user by phone number
func (fa *FirebaseAuth) GetOrCreateUserByPhone(input *CreateAccountInput) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)

	if err != nil {
		return nil, err
	}

	phoneNumber := formatI18nPhoneNumber(input.PhoneCode, input.PhoneNumber)
	user, err := authClient.GetUserByPhoneNumber(context.TODO(), phoneNumber)

	if err != nil && !auth.IsUserNotFound(err) {
		return nil, err
	}

	if user == nil {
		params := (&auth.UserToCreate{})

		if input.EmailEnabled {
			params = params.Email(input.Email).
				EmailVerified(input.Verified)
		}

		if input.DisplayName != "" {
			params = params.DisplayName(input.DisplayName)
		}
		if input.Password != "" {
			params = params.Password(input.Password)
		}

		if input.ID == "" {
			input.ID = genID()
		}
		params = params.UID(input.ID)

		if input.PhoneNumber != "" && input.PhoneEnabled {
			params = params.PhoneNumber(phoneNumber)
		}

		user, err = authClient.CreateUser(ctx, params)
		if err != nil {
			return nil, err
		}
	}

	return &Account{
		BaseAccount: BaseAccount{
			ID:          input.ID,
			Email:       input.Email,
			DisplayName: input.DisplayName,
			PhoneCode:   input.PhoneCode,
			PhoneNumber: input.PhoneNumber,
			Role:        input.Role,
			Verified:    input.Verified,
		},
		AccountProviders: []AccountProvider{
			{
				Name:           string(AuthFirebase),
				ProviderUserID: user.UID,
			},
		},
	}, nil
}

func (fa *FirebaseAuth) UpdateUser(uid string, input UpdateAccountInput) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, err
	}

	u, err := authClient.GetUser(context.Background(), uid)
	if err != nil {
		if !auth.IsUserNotFound(err) {
			return nil, err
		}
		return fa.CreateUser(&CreateAccountInput{
			ID:               uid,
			DisplayName:      input.DisplayName,
			Email:            input.Email,
			EmailEnabled:     input.EmailEnabled,
			PhoneCode:        input.PhoneCode,
			PhoneNumber:      input.PhoneNumber,
			PhoneEnabled:     input.PhoneEnabled,
			AuthProviderType: fa.GetName(),
			Password:         input.Password,
			Verified:         input.Verified,
		})
	}

	shouldUpdate := false
	data := &auth.UserToUpdate{}
	if input.Password != "" {
		data = data.Password(input.Password)
		shouldUpdate = true
	}

	if input.PhoneNumber != "" {
		i18nPhone := formatI18nPhoneNumber(input.PhoneCode, input.PhoneNumber)
		if i18nPhone != u.PhoneNumber {
			data = data.PhoneNumber(i18nPhone)
			shouldUpdate = true
		}
	}
	if input.Email != "" && input.Email != u.Email {
		data = data.Email(input.Email).EmailVerified(input.EmailEnabled)
		shouldUpdate = true
	}

	acc := &Account{
		BaseAccount: BaseAccount{
			ID:          uid,
			Email:       input.Email,
			DisplayName: input.DisplayName,
			PhoneCode:   input.PhoneCode,
			PhoneNumber: input.PhoneNumber,
			Verified:    input.Verified,
		},
		AccountProviders: []AccountProvider{
			{
				Name:           string(AuthFirebase),
				ProviderUserID: u.UID,
			},
		},
	}

	if !shouldUpdate {
		return acc, nil
	}

	_, err = authClient.UpdateUser(ctx, uid, data)
	if err != nil {
		return nil, err
	}

	return acc, nil
}
