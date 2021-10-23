package auth

import (
	"context"
	"errors"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

type FirebaseAuth struct {
	*firebase.App
}

func NewFirebaseAuth(app *firebase.App) *FirebaseAuth {
	return &FirebaseAuth{app}
}

func (fa FirebaseAuth) GetName() AuthProviderType {
	return AuthFirebase
}

func (fa *FirebaseAuth) CreateUser(input CreateAccountInput) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)

	if err != nil {
		return nil, err
	}
	params := (&auth.UserToCreate{}).
		Email(input.Email).
		EmailVerified(input.Verified)

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
		params = params.PhoneNumber(getI18nPhoneNumber(input.PhoneCode, input.PhoneNumber))
	}

	u, err := authClient.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}

	return &Account{
		ID:          input.ID,
		Email:       input.Email,
		DisplayName: input.DisplayName,
		PhoneCode:   input.PhoneCode,
		PhoneNumber: input.PhoneNumber,
		Verified:    input.Verified,
		AccountProviders: []AccountProvider{
			{
				Name:           string(AuthFirebase),
				ProviderUserID: u.UID,
			},
		},
	}, nil
}

func (fa *FirebaseAuth) GetUserByEmail(email string) (*Account, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, err
	}
	u, err := authClient.GetUserByEmail(ctx, email)
	if err != nil {
		if !auth.IsUserNotFound(err) {
			return nil, err
		}
		return nil, nil
	}

	return &Account{
		ID:          u.UID,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Verified:    u.EmailVerified,
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

func (fa *FirebaseAuth) VerifyToken(token string) (*AccountProvider, error) {
	ctx := context.Background()
	authClient, err := fa.App.Auth(ctx)
	if err != nil {
		return nil, err
	}

	authToken, err := authClient.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, err
	}

	return &AccountProvider{
		Name:           string(AuthFirebase),
		ProviderUserID: authToken.UID,
	}, nil
}

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

func (fa *FirebaseAuth) EncodeToken(uid string) (*AccessToken, error) {
	return nil, errors.New(ErrorCodeUnsupported)
}

func (fa *FirebaseAuth) SignInWithEmailAndPassword(email string, password string) (*Account, error) {
	return nil, errors.New(ErrorCodeUnsupported)
}

func (fa *FirebaseAuth) SignInWithPhoneAndPassword(phoneCode int, phoneNumber string, password string) (*Account, error) {
	return nil, errors.New(ErrorCodeUnsupported)
}

func (fa *FirebaseAuth) VerifyPassword(providerUserId string, password string) error {
	return errors.New(ErrorCodeUnsupported)
}
