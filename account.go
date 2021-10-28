// Package auth includes the collection of authentication solutions
package auth

import (
	"context"
	"errors"
	"fmt"

	firebase "firebase.google.com/go/v4"
	gql "github.com/hasura/go-graphql-client"
)

// AccountManagerConfig config options for AccountManager
type AccountManagerConfig struct {
	FirebaseApp     *firebase.App
	GQLClient       *gql.Client
	JWT             *JWTAuthConfig
	DefaultProvider AuthProviderType
	DefaultRole     string
	CreateFromToken bool
}

// AccountManager account business method
type AccountManager struct {
	providers       map[AuthProviderType]AuthProvider
	gqlClient       *gql.Client
	providerType    AuthProviderType
	defaultRole     string
	createFromToken bool
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
		if config.JWT == nil {
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
		defaultRole:  config.DefaultRole,
	}, nil
}

// As create new account manager with target provider
func (am AccountManager) As(providerType AuthProviderType) *AccountManager {
	return &AccountManager{
		providers:       am.providers,
		gqlClient:       am.gqlClient,
		providerType:    providerType,
		defaultRole:     am.defaultRole,
		createFromToken: am.createFromToken,
	}
}

// SetDefaultRole set default role
func (am *AccountManager) SetDefaultRole(role string) {
	am.defaultRole = role
}

// GetDefaultRole get default role
func (am *AccountManager) GetDefaultRole() string {
	return am.defaultRole
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
		return nil, err
	}

	// get account info from the database
	// if ID is not null, we assume that account has enough info
	if u.ID != "" {
		return u, nil
	}

	acc, err := am.findAccountByProviderUser(u.AccountProviders[0].ProviderUserID)
	if err != nil || acc != nil {
		return acc, err
	}

	return u, nil
}

// CreateAccountWithProvider get or create account with provider
func (am *AccountManager) CreateAccountWithProvider(input CreateAccountInput) (*Account, error) {

	ctx := context.Background()

	if (input.EmailEnabled || (!input.EmailEnabled && !input.PhoneEnabled)) && input.Email == "" {
		return nil, errors.New(ErrCodeEmailRequired)
	}

	if input.PhoneEnabled && (input.PhoneCode == 0 || input.PhoneNumber == "") {
		return nil, errors.New(ErrCodePhoneRequired)
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
		return nil, errors.New(ErrCodeAccountExisted)
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

	acc, err := am.findAccountByProviderUser(provider.ProviderUserID)
	if err != nil || acc != nil {
		return acc, err
	}

	if !am.createFromToken {
		return nil, errors.New(ErrCodeAccountNoProvider)
	}

	// allow create account with provider info
	acc, err = am.getCurrentProvider().GetUserByID(provider.ProviderUserID)
	if err != nil || acc.ID != "" {
		return acc, err
	}

	acc.ID = genID()
	accInsertInput := map[string]interface{}{
		"id":            acc.ID,
		"display_name":  acc.DisplayName,
		"role":          am.defaultRole,
		"verified":      acc.Verified,
		"email_enabled": acc.Email != "",
		"phone_enabled": acc.PhoneNumber != "",
		"account_providers": map[string]interface{}{
			"data": acc.AccountProviders,
		},
	}

	_, err = am.InsertAccount(accInsertInput)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (am *AccountManager) findAccountByProviderUser(userId string) (*Account, error) {
	// Get user by provider
	var query struct {
		AccountProviders []struct {
			Account BaseAccount `graphql:"account"`
		} `graphql:"account_provider(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_provider_bool_exp{
			"provider_user_id": map[string]string{
				"_eq": userId,
			},
			"provider_name": map[string]string{
				"_eq": string(am.providerType),
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountProvider"))
	if err != nil {
		return nil, err
	}

	if len(query.AccountProviders) > 0 {
		accProvider := query.AccountProviders[0]
		return &Account{
			BaseAccount: accProvider.Account,
			AccountProviders: []AccountProvider{
				{
					ProviderUserID: userId,
					AccountID:      &accProvider.Account.ID,
					Name:           string(am.providerType),
				},
			},
		}, nil
	}

	return nil, nil
}

func (am *AccountManager) SignInWithEmailAndPassword(email string, password string) (*Account, error) {
	return am.getCurrentProvider().SignInWithEmailAndPassword(email, password)
}

func (am *AccountManager) VerifyPassword(providerUserID string, password string) error {
	return am.getCurrentProvider().VerifyPassword(providerUserID, password)
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
		return errors.New(ErrCodeNewPasswordRequired)
	}

	if !isAdmin {
		if currentPassword == "" {
			return errors.New(ErrCodeCurrentPasswordRequired)
		}

		if currentPassword == newPassword {
			return errors.New(ErrCodeNewPasswordEqualCurrentPassword)
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
		return errors.New(ErrCodeAccountNoProvider)
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
				if err.Error() == ErrCodeUnsupported {
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
			if err.Error() == ErrCodeUnsupported {
				continue
			}
			return err
		}
	}
	return nil
}
