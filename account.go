package auth

import (
	"context"
	"errors"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	gql "github.com/hasura/go-graphql-client"
)

const ()

// AccountManagerConfig config options for AccountManager
type AccountManagerConfig struct {
	FirebaseApp     *firebase.App
	DefaultProvider AuthProviderType
	GQLClient       *gql.Client
	JWT             *JWTAuthConfig
}

// AccountManager account business method
type AccountManager struct {
	providers    map[AuthProviderType]AuthProvider
	gqlClient    *gql.Client
	providerType AuthProviderType
}

// NewAccountManager create new AccountManager instance
func NewAccountManager(config AccountManagerConfig) (*AccountManager, error) {
	if config.DefaultProvider == "" {
		return nil, errors.New("DefaultProvider is required")
	}

	switch config.DefaultProvider {
	case AuthFirebase:
		if config.FirebaseApp == nil {
			return nil, errors.New("FirebaseApp is required")
		}
	case AuthJWT:
		if config.FirebaseApp == nil {
			return nil, errors.New("JWTAuthConfig is required")
		}
	}

	providers := make(map[AuthProviderType]AuthProvider)
	if config.FirebaseApp != nil {
		providers[AuthFirebase] = NewFirebaseAuth(config.FirebaseApp)
	}

	if config.JWT != nil {
		providers[AuthJWT] = NewJWTAuth(config.GQLClient, *config.JWT)
	}

	if config.DefaultProvider == "" {
		return nil, errors.New("DefaultProvider is required")
	}

	return &AccountManager{
		providers:    providers,
		gqlClient:    config.GQLClient,
		providerType: config.DefaultProvider,
	}, nil
}

// As get provider name
func (am AccountManager) As(providerType AuthProviderType) *AccountManager {
	return &AccountManager{
		providers:    am.providers,
		gqlClient:    am.gqlClient,
		providerType: providerType,
	}
}

// GetProviderName get provider name
func (am AccountManager) GetProviderName() AuthProviderType {
	return am.providerType
}

// GetProviderName get provider name
func (am AccountManager) getCurrentProvider() AuthProvider {
	return am.providers[am.providerType]
}

// CreateProviderAccount create account with provider
func (am *AccountManager) CreateProviderAccount(input CreateAccountInput) (*Account, error) {
	return am.getCurrentProvider().CreateUser(input)
}

// ChangeProviderPassword change account password with provider
func (am *AccountManager) ChangeProviderPassword(uid string, newPassword string) error {
	return am.getCurrentProvider().ChangePassword(uid, newPassword)
}

// GetAccountByEmail find account by email
func (am *AccountManager) GetAccountByEmail(email string) (*Account, error) {

	u, err := am.getCurrentProvider().GetUserByEmail(email)
	if err != nil {
		if !auth.IsUserNotFound(err) {
			return nil, err
		}
	}

	return u, nil
}

// CreateAccountWithProvider get or create account with provider
func (am *AccountManager) CreateAccountWithProvider(input CreateAccountInput) (*Account, error) {

	ctx := context.Background()

	if (input.EmailEnabled || (!input.EmailEnabled && !input.PhoneEnabled)) && input.Email == "" {
		return nil, errors.New(ErrorCodeEmailRequired)
	}

	if input.PhoneEnabled && (input.PhoneCode == 0 || input.PhoneNumber == "") {
		return nil, errors.New(ErrorCodePhoneRequired)
	}

	// set default login as email
	if !input.EmailEnabled && !input.PhoneEnabled {
		input.EmailEnabled = true
	}

	// check if the account exists
	var existAccount struct {
		Account []struct {
			ID               string `graphql:"id"`
			AccountProviders []struct {
				ProviderUserID string `graphql:"provider_user_id"`
			} `graphql:"account_providers(where: $whereProviders, limit: 1)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	condition := make([]map[string]interface{}, 0)

	if input.Email != "" {
		condition = append(condition, map[string]interface{}{
			"email": map[string]string{
				"_eq": input.Email,
			},
			"email_enabled": map[string]bool{
				"_eq": true,
			},
		})
	}

	if input.PhoneNumber != "" {
		condition = append(condition, map[string]interface{}{
			"phone_code": map[string]int{
				"_eq": input.PhoneCode,
			},
			"phone_number": map[string]string{
				"_eq": input.PhoneNumber,
			},
			"phone_enabled": map[string]bool{
				"_eq": true,
			},
		})
	}

	existAccountVariables := map[string]interface{}{
		"where": account_bool_exp{
			"_or": condition,
		},
		"whereProviders": account_provider_bool_exp{
			"provider_name": map[string]string{
				"_eq": string(am.providerType),
			},
		},
	}

	err := am.gqlClient.Query(ctx, &existAccount, existAccountVariables, gql.OperationName("FindExistingAccount"))

	if err != nil {
		return nil, err
	}

	if len(existAccount.Account) > 0 {
		return nil, errors.New(ErrorCodeAccountExisted)
	}

	input.ID = genID()
	acc, err := am.CreateProviderAccount(input)

	if err != nil {
		return nil, err
	}

	accInsertInput := map[string]interface{}{
		"id":            acc.ID,
		"display_name":  input.DisplayName,
		"role":          input.Role,
		"verified":      input.Verified,
		"email_enabled": input.EmailEnabled,
		"phone_enabled": input.PhoneEnabled,
		"account_providers": map[string]interface{}{
			"data": acc.AccountProviders,
		},
	}

	if acc.Password != "" {
		accInsertInput["password"] = acc.Password
	}

	if input.Email != "" {
		accInsertInput["email"] = input.Email
	}

	if input.PhoneCode != 0 {
		accInsertInput["phone_code"] = input.PhoneCode
	}

	if input.PhoneNumber != "" {
		accInsertInput["phone_number"] = input.PhoneNumber
	}

	_, err = am.InsertAccount(accInsertInput)
	if err != nil {
		return nil, err
	}

	return acc, nil

}

// SetCustomClaims set custom claims for JWT token
func (am *AccountManager) SetCustomClaims(uid string, values map[string]interface{}) error {

	customClaims := map[string]interface{}{
		HasuraClaims: values,
	}

	return am.getCurrentProvider().SetCustomClaims(uid, customClaims)
}

func (am *AccountManager) InsertAccount(input map[string]interface{}) (string, error) {

	var insertAccountMutation struct {
		InsertAccount struct {
			Returning []struct {
				ID string `graphql:"id"`
			} `graphql:"returning"`
		} `graphql:"insert_account(objects: $objects)"`
	}

	insertAccountVariables := map[string]interface{}{
		"objects": []account_insert_input{
			account_insert_input(input),
		},
	}

	err := am.gqlClient.Mutate(
		context.Background(),
		&insertAccountMutation,
		insertAccountVariables,
		gql.OperationName("InsertAccount"),
	)

	if err != nil {
		return "", err
	}

	if len(insertAccountMutation.InsertAccount.Returning) == 0 {
		return "", fmt.Errorf("can't insert account")
	}

	return insertAccountMutation.InsertAccount.Returning[0].ID, nil
}

// InsertProvider insert account provider to the database
func (am *AccountManager) InsertProvider(input AccountProvider) error {
	var insertProviders struct {
		InsertProviders struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"insert_account_provider(objects: $objects)"`
	}

	insertProvidersVariables := map[string]interface{}{
		"objects": []account_provider_insert_input{
			account_provider_insert_input(input),
		},
	}

	err := am.gqlClient.Mutate(
		context.Background(),
		&insertProviders,
		insertProvidersVariables,
		gql.OperationName("InsertAccountProviders"),
	)

	if err != nil {
		return err
	}

	if insertProviders.InsertProviders.AffectedRows == 0 {
		return fmt.Errorf("insert zero account provider")
	}

	return nil

}

// VerifyToken validate and return provider user id
func (am *AccountManager) VerifyToken(token string) (*Account, error) {
	provider, err := am.getCurrentProvider().VerifyToken(token)
	if err != nil {
		return nil, err
	}

	// Get user by provider
	var query struct {
		AccountProviders []struct {
			Account struct {
				ID          string `graphql:"id"`
				Role        string `graphql:"role"`
				Email       string `graphql:"email"`
				DisplayName string `graphql:"display_name"`
				PhoneCode   int    `graphql:"phone_code"`
				PhoneNumber string `graphql:"phone_number"`
			}
		} `graphql:"account_provider(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_provider_bool_exp{
			"provider_user_id": map[string]string{
				"_eq": provider.ProviderUserID,
			},
			"provider_name": map[string]string{
				"_eq": string(am.providerType),
			},
		},
	}

	err = am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountProvider"))
	if err != nil {
		return nil, err
	}

	if len(query.AccountProviders) == 0 {
		return nil, fmt.Errorf("account provider not found; provider: %s, user_id: %s", am.GetProviderName(), provider.ProviderUserID)
	}

	return &Account{
		ID:               query.AccountProviders[0].Account.ID,
		Role:             query.AccountProviders[0].Account.Role,
		Email:            query.AccountProviders[0].Account.Email,
		DisplayName:      query.AccountProviders[0].Account.DisplayName,
		PhoneCode:        query.AccountProviders[0].Account.PhoneCode,
		PhoneNumber:      query.AccountProviders[0].Account.PhoneNumber,
		AccountProviders: []AccountProvider{*provider},
	}, nil
}

func (am *AccountManager) SignInWithEmailAndPassword(email string, password string) (*Account, error) {
	return am.getCurrentProvider().SignInWithEmailAndPassword(email, password)
}

func (am *AccountManager) VerifyPassword(providerUserId string, password string) error {
	return am.getCurrentProvider().VerifyPassword(providerUserId, password)
}

func (am *AccountManager) SignInWithPhoneAndPassword(phoneCode int, phoneNumber string, password string) (*Account, error) {
	return am.getCurrentProvider().SignInWithPhoneAndPassword(phoneCode, phoneNumber, password)
}

func (am *AccountManager) EncodeToken(uid string) (*AccessToken, error) {
	return am.getCurrentProvider().EncodeToken(uid)
}

// ChangePassword change all providers's password of current user
func (am *AccountManager) ChangePassword(id string, currentPassword string, newPassword string, isAdmin bool) error {

	if newPassword == "" {
		return errors.New(ErrorCodeNewPasswordRequired)
	}

	if !isAdmin {
		if currentPassword == "" {
			return errors.New(ErrorCodeCurrentPasswordRequired)
		}

		if currentPassword == newPassword {
			return errors.New(ErrorCodeNewPasswordEqualCurrentPassword)
		}
	}

	var query struct {
		AccountProviders []AccountProvider `graphql:"account_provider(where: $where)"`
	}

	queryVariables := map[string]interface{}{
		"where": account_provider_bool_exp{
			"account_id": map[string]string{
				"_eq": id,
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, queryVariables, gql.OperationName("GetAccountWithProvider"))

	if err != nil {
		return err
	}

	if len(query.AccountProviders) == 0 {
		return errors.New(ErrorCodeAccountNoProvider)
	}

	var supportedProviders []AccountProvider
	// if isAdmin = true, skip password check
	if isAdmin {
		supportedProviders = query.AccountProviders
	} else {
		for _, ap := range query.AccountProviders {
			provider, ok := am.providers[AuthProviderType(ap.Name)]
			if !ok {
				continue
			}
			err := provider.VerifyPassword(ap.ProviderUserID, currentPassword)

			if err != nil {
				if err.Error() == ErrorCodeUnsupported {
					continue
				}
				return err
			}

			supportedProviders = append(supportedProviders, ap)
		}
	}

	return am.ChangeAllProvidersPassword(supportedProviders, newPassword)
}

// ChangeAllProvidersPassword change all providers's password of current user
func (am *AccountManager) ChangeAllProvidersPassword(providers []AccountProvider, password string) error {

	for _, ap := range providers {
		provider, ok := am.providers[AuthProviderType(ap.Name)]
		if !ok {
			continue
		}
		err := provider.ChangePassword(ap.ProviderUserID, password)
		if err != nil {
			if err.Error() == ErrorCodeUnsupported {
				continue
			}
			return err
		}
	}
	return nil
}
