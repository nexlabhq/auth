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

	phoneCode := 0
	phoneNumber := ""
	if u.PhoneNumber != "" {
		phoneCode, phoneNumber, err = parseI18nPhoneNumber(u.PhoneNumber, 0)
		if err != nil {
			return nil, err
		}
	}

	return &Account{
		BaseAccount: BaseAccount{
			Email:       u.Email,
			DisplayName: u.DisplayName,
			PhoneCode:   phoneCode,
			PhoneNumber: phoneNumber,
			Verified:    u.EmailVerified,
		},
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

func (fa *FirebaseAuth) RefreshToken(refreshToken string, accessToken string, options ...AccessTokenOption) (*AccessToken, error) {
	return nil, errors.New(ErrCodeUnsupported)
}

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
