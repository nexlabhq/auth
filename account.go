// Package auth includes the collection of authentication solutions
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"github.com/google/uuid"
	"github.com/hasura/go-graphql-client"
	"github.com/hgiasac/graphql-utils/client"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// AuthOTPConfig contains authentication configurations from sms otp
type AuthOTPConfig struct {
	Enabled           bool          `envconfig:"AUTH_OTP_ENABLED" env:"AUTH_OTP_ENABLED" default:"false"`
	OTPLength         uint          `envconfig:"AUTH_OTP_LENGTH" env:"AUTH_OTP_LENGTH" default:"6"`
	LoginLimit        uint          `envconfig:"AUTH_OTP_LOGIN_LIMIT" env:"AUTH_OTP_LOGIN_LIMIT" default:"3"`
	LoginDisableLimit uint          `envconfig:"AUTH_OTP_DISABLE_LIMIT" env:"AUTH_OTP_DISABLE_LIMIT" default:"9"`
	LoginLockDuration time.Duration `envconfig:"AUTH_OTP_LOCK_DURATION" env:"AUTH_OTP_LOCK_DURATION" default:"10m"`
	TTL               time.Duration `envconfig:"AUTH_OTP_TTL" env:"AUTH_OTP_TTL" default:"60s"`
	DevMode           bool          `envconfig:"AUTH_OTP_DEV" env:"AUTH_OTP_DEV" default:"false"`
	DevOTPCode        string        `envconfig:"AUTH_OTP_DEV_CODE" env:"AUTH_OTP_DEV_CODE" default:"123456"`
}

// AccountManagerConfig config options for AccountManager
type AccountManagerConfig struct {
	FirebaseApp *firebase.App  `ignored:"true" kong:"-"`
	GQLClient   client.Client  `ignored:"true" kong:"-"`
	JWT         *JWTAuthConfig `embed:""`
	OTP         AuthOTPConfig  `embed:""`

	CreateFromToken      bool             `envconfig:"AUTH_CREATE_FROM_TOKEN" env:"AUTH_CREATE_FROM_TOKEN" default:"false"`
	Enabled2FA           bool             `envconfig:"AUTH_2FA_ENABLED" env:"AUTH_2FA_ENABLED" default:"false"`
	DefaultProvider      AuthProviderType `envconfig:"DEFAULT_AUTH_PROVIDER" env:"DEFAULT_AUTH_PROVIDER" required:"true"`
	DefaultRole          string           `envconfig:"DEFAULT_ROLE" env:"DEFAULT_ROLE" required:"true"`
	DefaultRoleAnonymous string           `envconfig:"DEFAULT_ROLE_ANONYMOUS" env:"DEFAULT_ROLE_ANONYMOUS" default:"anonymous"`
	AutoLinkProvider     bool             `envconfig:"AUTH_AUTO_LINK_PROVIDER" env:"AUTH_AUTO_LINK_PROVIDER" default:"false"`
	Logger               *zerolog.Logger  `ignored:"true" kong:"-"`
}

// AccountManager account business method
type AccountManager struct {
	providers            map[AuthProviderType]AuthProvider
	gqlClient            client.Client
	providerType         AuthProviderType
	defaultRole          string
	createFromToken      bool
	otp                  AuthOTPConfig
	defaultRoleAnonymous string
	autoLinkProvider     bool
	logger               zerolog.Logger
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
		firebaseAuth := NewFirebaseAuth(config.FirebaseApp)
		firebaseAuth.roleAnonymous = config.DefaultRoleAnonymous
		providers[AuthFirebase] = firebaseAuth
	}

	if config.JWT != nil {
		providers[AuthJWT] = NewJWTAuth(config.GQLClient, *config.JWT)
	}

	if config.DefaultProvider == "" {
		return nil, errors.New("DefaultProvider is required")
	}

	logger := log.Level(zerolog.GlobalLevel()).With().Str("component", "auth").Logger()
	if config.Logger != nil {
		logger = *config.Logger
	}

	return &AccountManager{
		providers:            providers,
		gqlClient:            config.GQLClient,
		providerType:         config.DefaultProvider,
		defaultRole:          config.DefaultRole,
		createFromToken:      config.CreateFromToken,
		otp:                  config.OTP,
		defaultRoleAnonymous: config.DefaultRoleAnonymous,
		autoLinkProvider:     config.AutoLinkProvider,
		logger:               logger,
	}, nil
}

// As create new account manager with target provider
func (am AccountManager) As(providerType AuthProviderType) *AccountManager {
	return &AccountManager{
		providers:            am.providers,
		gqlClient:            am.gqlClient,
		providerType:         providerType,
		defaultRole:          am.defaultRole,
		createFromToken:      am.createFromToken,
		otp:                  am.otp,
		defaultRoleAnonymous: am.defaultRoleAnonymous,
		autoLinkProvider:     am.autoLinkProvider,
		logger:               am.logger,
	}
}

// SetDefaultRole set default role
func (am *AccountManager) SetDefaultRole(role string) {
	am.defaultRole = role
}

// GetDefaultRole get default role name
func (am *AccountManager) GetDefaultRole() string {
	return am.defaultRole
}

// GetAnonymousRole get the unauthorized role name
func (am *AccountManager) GetAnonymousRole() string {
	return am.defaultRoleAnonymous
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
func (am *AccountManager) CreateProviderAccount(input *CreateAccountInput) (*Account, error) {
	return am.getCurrentProvider().CreateUser(input)
}

// ChangeProviderPassword change account password with provider
func (am *AccountManager) ChangeProviderPassword(uid string, newPassword string) error {
	return am.getCurrentProvider().ChangePassword(uid, newPassword)
}

// FindAccountByProviderEmail find account by email
func (am *AccountManager) FindAccountByProviderEmail(email string, accountBoolExp map[string]any) (*Account, error) {

	u, err := am.getCurrentProvider().GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	// get account info from the database
	// if ID is not null, we assume that account has enough info
	if u.ID != "" {
		return u, nil
	}

	acc, err := am.findAccountByProviderUser(u.AccountProviders[0].ProviderUserID, accountBoolExp)
	if err != nil || acc != nil {
		return acc, err
	}

	return u, nil
}

// FindAccountByID find account by id
func (am *AccountManager) FindAccountByID(id string) (*Account, error) {
	return am.FindOne(account_bool_exp{
		"id": map[string]string{
			"_eq": id,
		},
	})
}

// FindAccountByEmail find account by id
func (am *AccountManager) FindAccountByEmail(id string) (*Account, error) {
	return am.FindOne(account_bool_exp{
		"email": map[string]string{
			"_eq": id,
		},
	})
}

func (am *AccountManager) FindAll(where map[string]interface{}) ([]Account, error) {
	var query struct {
		Account []Account `graphql:"account(where: $where)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp(where),
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, graphql.OperationName("FindAccounts"))
	if err != nil {
		return nil, err
	}

	return query.Account, nil
}

func (am *AccountManager) FindOne(where map[string]interface{}) (*Account, error) {
	var query struct {
		Account []Account `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp(where),
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, graphql.OperationName("FindAccounts"))
	if err != nil {
		return nil, err
	}

	if len(query.Account) == 0 {
		return nil, nil
	}

	return &query.Account[0], nil
}

// CreateAccountWithProvider get or create account with provider
func (am *AccountManager) CreateAccountWithProvider(input *CreateAccountInput, extraFields map[string]any, extraFilters map[string]any) (*Account, error) {

	ctx := context.Background()

	if (isTrue(input.EmailEnabled) || (!isTrue(input.EmailEnabled) && !isTrue(input.PhoneEnabled))) &&
		isStringPtrEmpty(input.Email) {
		return nil, errors.New(ErrCodeEmailRequired)
	}

	if isTrue(input.PhoneEnabled) && (input.PhoneCode == nil || isStringPtrEmpty(input.PhoneNumber)) {
		return nil, errors.New(ErrCodePhoneRequired)
	}

	// set default login as email
	if !isTrue(input.EmailEnabled) && !isTrue(input.PhoneEnabled) {
		input.EmailEnabled = getPtr(true)
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

	condition := make([]map[string]any, 0)

	if !isStringPtrEmpty(input.Email) {
		emailFilter := map[string]any{
			"email": map[string]string{
				"_eq": *input.Email,
			},
			"email_enabled": map[string]bool{
				"_eq": true,
			},
		}

		if len(extraFilters) > 0 {
			for k, v := range extraFilters {
				emailFilter[k] = v
			}
		}
		condition = append(condition, emailFilter)
	}

	if !isStringPtrEmpty(input.PhoneNumber) {
		phoneFilter := map[string]any{
			"phone_code": map[string]any{
				"_eq": input.PhoneCode,
			},
			"phone_number": map[string]any{
				"_eq": input.PhoneNumber,
			},
			"phone_enabled": map[string]bool{
				"_eq": true,
			},
		}

		if len(extraFilters) > 0 {
			for k, v := range extraFilters {
				phoneFilter[k] = v
			}
		}

		condition = append(condition, phoneFilter)
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

	err := am.gqlClient.Query(ctx, &existAccount, existAccountVariables, graphql.OperationName("FindExistingAccount"))

	if err != nil {
		return nil, err
	}

	if len(existAccount.Account) > 0 {
		return nil, errors.New(ErrCodeAccountExisted)
	}

	input.ID = getPtr(genID())
	acc, err := am.CreateProviderAccount(input)

	if err != nil {
		return nil, err
	}

	accInsertInput := map[string]interface{}{
		"id":            acc.ID,
		"display_name":  input.DisplayName,
		"role":          input.Role,
		"verified":      isTrue(input.Verified),
		"email_enabled": isTrue(input.EmailEnabled),
		"phone_enabled": isTrue(input.PhoneEnabled),
		"account_providers": map[string]interface{}{
			"data": acc.AccountProviders,
		},
	}

	if acc.Password != "" {
		accInsertInput["password"] = acc.Password
	}

	if !isStringPtrEmpty(input.Email) {
		accInsertInput["email"] = input.Email
	}

	if input.PhoneCode != nil && *input.PhoneCode != 0 {
		accInsertInput["phone_code"] = input.PhoneCode
	}

	if !isStringPtrEmpty(input.PhoneNumber) {
		accInsertInput["phone_number"] = input.PhoneNumber
	}

	if len(extraFields) > 0 {
		for k, v := range extraFields {
			accInsertInput[k] = v
		}
	}

	uid, err := am.InsertAccount(accInsertInput)
	if err != nil {
		return nil, err
	}

	acc.ID = uid
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
		graphql.OperationName("InsertAccount"),
	)

	if err != nil {
		return "", err
	}

	if len(insertAccountMutation.InsertAccount.Returning) == 0 {
		return "", errors.New(ErrCodeAccountInsertZero)
	}

	return insertAccountMutation.InsertAccount.Returning[0].ID, nil
}

// CreateProvider insert account provider to the database
func (am *AccountManager) CreateProvider(input AccountProvider) error {
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
		graphql.OperationName("InsertAccountProviders"),
	)

	if err != nil {
		return err
	}

	if insertProviders.InsertProviders.AffectedRows == 0 {
		return errors.New(ErrCodeAccountProviderInsertZero)
	}

	return nil
}

// VerifyToken validate and return provider user id
func (am *AccountManager) VerifyToken(token string, accountBoolExp map[string]any, extraFields map[string]any) (*Account, map[string]interface{}, error) {
	logger := am.logger.With().
		Str("span_id", uuid.NewString()).
		Str("name", "VerifyToken").
		Str("provider", string(am.GetProviderName())).Logger()

	logger.Trace().Str("access_token", token).
		Interface("extra_condition", accountBoolExp).
		Interface("extra_fields", extraFields).
		Msg("VerifyToken")

	provider, claims, err := am.getCurrentProvider().VerifyToken(token)
	if err != nil {
		return nil, nil, err
	}

	logger.Trace().Interface("account_provider", provider).Interface("claims", claims).
		Msg("findAccountByProviderUser")

	acc, err := am.findAccountByProviderUser(provider.ProviderUserID, accountBoolExp)
	if err != nil {
		return nil, nil, err
	}

	if acc != nil {
		if acc.Disabled {
			return nil, nil, errors.New(ErrCodeAccountDisabled)
		}
		return acc, claims, nil
	}

	if !am.createFromToken {
		return nil, nil, errors.New(ErrCodeAccountNoProvider)
	}

	// allow create account with provider info
	logger.Trace().Interface("account_provider", provider).Msg("GetUserByID")

	acc, err = am.getCurrentProvider().GetUserByID(provider.ProviderUserID)
	if err != nil || (acc != nil && acc.ID != "") {
		return acc, nil, err
	} else if acc == nil {
		return nil, nil, errors.New(ErrCodeAccountNotFound)
	}

	acc, err = am.createAccountFromToken(acc, accountBoolExp, extraFields, logger)
	if err != nil {
		return nil, nil, err
	}

	return acc, claims, err
}

func (am *AccountManager) createAccountFromToken(acc *Account, accountBoolExp map[string]any, extraFields map[string]any, logger zerolog.Logger) (*Account, error) {

	logger.Trace().Interface("account", acc).
		Interface("extra_condition", accountBoolExp).
		Interface("extra_fields", extraFields).
		Msg("createAccountFromToken")

	acc.ID = genID()
	accInsertInput := map[string]interface{}{
		"id":            acc.ID,
		"verified":      acc.Verified,
		"email_enabled": acc.Email != "",
		"phone_enabled": acc.PhoneNumber != "",
		"account_providers": map[string]interface{}{
			"data": acc.AccountProviders,
		},
	}
	if acc.DisplayName != "" {
		accInsertInput["display_name"] = acc.DisplayName
	}
	role := am.defaultRole
	if acc.Role != "" {
		role = acc.Role
	}
	accInsertInput["role"] = role

	if acc.Email != "" {
		accInsertInput["email"] = acc.Email
	}

	if acc.PhoneNumber != "" {
		accInsertInput["phone_code"] = acc.PhoneCode
		accInsertInput["phone_number"] = acc.PhoneNumber
	}

	if len(extraFields) > 0 {
		for k, v := range extraFields {
			accInsertInput[k] = v
		}
	}

	logger.Trace().Interface("account_insert_input", accInsertInput).Msg("InsertAccount")
	_, err := am.InsertAccount(accInsertInput)

	if err != nil {
		isEmailUniqueError := strings.Contains(err.Error(), "account_email_unique")
		isPhoneUniqueError := strings.Contains(err.Error(), "account_phone_unique")

		logger.Trace().Interface("account_email_unique", isEmailUniqueError).
			Interface("account_phone_unique", isPhoneUniqueError).
			Interface("auto_link", am.autoLinkProvider).
			Interface("account", acc).
			Msg("Validate unique constraint and link account")

		if !am.autoLinkProvider || am.getCurrentProvider().GetName() != AuthFirebase ||
			len(acc.AccountProviders) == 0 ||
			(acc.PhoneNumber == "" && acc.Email == "") ||
			(!isEmailUniqueError && !isPhoneUniqueError) ||
			(isEmailUniqueError && acc.Email == "") ||
			(isPhoneUniqueError && acc.PhoneNumber == "") {
			return nil, err
		}

		// allow linking account with firebase auth provider
		var existedAccount struct {
			Account          []BaseAccount     `graphql:"account(where: $where, limit: 1)"`
			AccountProviders []AccountProvider `graphql:"account_provider(where: $providerWhere, limit: 1)"`
		}

		where := account_bool_exp{}
		if strings.Contains(err.Error(), "account_phone_unique") {
			where["phone_code"] = map[string]any{
				"_eq": acc.PhoneCode,
			}
			where["phone_number"] = map[string]any{
				"_eq": acc.PhoneNumber,
			}
			where["phone_enabled"] = map[string]any{
				"_eq": true,
			}
		} else if strings.Contains(err.Error(), "account_email_unique") {
			where["email"] = map[string]any{
				"_eq": acc.Email,
			}
			where["email_enabled"] = map[string]any{
				"_eq": true,
			}
		}

		for k, exp := range accountBoolExp {
			where[k] = exp
		}

		accountVariables := map[string]any{
			"where": where,
			"providerWhere": account_provider_bool_exp{
				"provider_name": map[string]any{
					"_eq": acc.AccountProviders[0].Name,
				},
				"provider_user_id": map[string]any{
					"_eq": acc.AccountProviders[0].ProviderUserID,
				},
			},
		}

		logger.Trace().Interface("variables", accountVariables).Msg("FindAccount")
		accountErr := am.gqlClient.Query(context.Background(), &existedAccount, accountVariables, graphql.OperationName("FindAccount"))
		if accountErr != nil || len(existedAccount.Account) == 0 {
			logger.Trace().
				Interface("existing_accounts", existedAccount.Account).
				Interface("error", accountErr).
				Msg("FindAccountFailure")
			return nil, err
		}

		if len(existedAccount.AccountProviders) > 0 {
			if *existedAccount.AccountProviders[0].AccountID == existedAccount.Account[0].ID {
				acc.BaseAccount = existedAccount.Account[0]
				return acc, nil
			}

			return nil, fmt.Errorf("provider belongs to another account")
		}

		logger.Trace().
			Interface("existing_account", existedAccount.Account[0]).
			Interface("providers", acc.AccountProviders).
			Msg("CreateProvider")

		var insertProviders struct {
			InsertProviders struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_provider(objects: $objects, on_conflict: {constraint: account_provider_pkey, update_columns: []})"`
		}

		insertProvidersVariables := map[string]interface{}{
			"objects": []account_provider_insert_input{
				account_provider_insert_input(AccountProvider{
					ProviderUserID: acc.AccountProviders[0].ProviderUserID,
					Name:           acc.AccountProviders[0].Name,
					AccountID:      &existedAccount.Account[0].ID,
				}),
			},
		}

		accountErr = am.gqlClient.Mutate(
			context.Background(),
			&insertProviders,
			insertProvidersVariables,
			graphql.OperationName("InsertAccountProvider"),
		)

		if accountErr != nil {
			return nil, accountErr
		}

		acc.BaseAccount = existedAccount.Account[0]
	} else {
		acc.Role = am.defaultRole
	}

	return acc, nil
}

func (am *AccountManager) findAccountByProviderUser(userId string, accountBoolExp map[string]any) (*Account, error) {
	// Get user by provider
	var query struct {
		Account []struct {
			BaseAccount
			AccountProviders []AccountProvider `graphql:"account_providers(where: $providerWhere)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	providerOrConditions := []map[string]any{
		{
			"provider_user_id": map[string]string{
				"_eq": userId,
			},
			"provider_name": map[string]string{
				"_eq": string(am.providerType),
			},
		},
	}

	// we may use custom firebase token with uid = account_id
	if am.providerType == AuthFirebase {
		providerOrConditions = append(providerOrConditions, map[string]any{
			"account_id": map[string]string{
				"_eq": userId,
			},
		})
	}

	where := account_bool_exp{
		"account_providers": map[string]any{
			"_or": providerOrConditions,
		},
	}

	for k, exp := range accountBoolExp {
		where[k] = exp
	}

	variables := map[string]interface{}{
		"where": where,
		"providerWhere": account_provider_bool_exp{
			"_or": providerOrConditions,
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, graphql.OperationName("FindAccountByProvider"))
	if err != nil {
		return nil, err
	}

	if len(query.Account) == 0 {
		return nil, nil
	}

	return &Account{
		BaseAccount:      query.Account[0].BaseAccount,
		AccountProviders: filterProvidersByType(query.Account[0].AccountProviders, am.providerType),
	}, nil
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

func (am *AccountManager) EncodeToken(cred *AccountProvider, scopes []AuthScope, options ...AccessTokenOption) (*AccessToken, error) {
	return am.getCurrentProvider().EncodeToken(cred, scopes, options...)
}

func (am *AccountManager) VerifyRefreshToken(refreshToken string) (*AccountProvider, error) {
	return am.getCurrentProvider().VerifyRefreshToken(refreshToken)
}

func (am *AccountManager) RefreshToken(refreshToken string, options ...AccessTokenOption) (*AccessToken, error) {
	return am.getCurrentProvider().RefreshToken(refreshToken, options...)
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

	err := am.gqlClient.Query(context.Background(), &query, queryVariables, graphql.OperationName("GetAccountWithProvider"))

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

// PromoteAnonymousUser promotes the current anonymous user to the default user role
func (am *AccountManager) PromoteAnonymousUser(accountID string, input *CreateAccountInput) (*Account, error) {

	if accountID == "" {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	var query struct {
		Accounts []struct {
			BaseAccount
			AccountProviders []AccountProvider `graphql:"account_providers(where: $providerWhere)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]any{
				"_eq": accountID,
			},
		},
		"providerWhere": account_provider_bool_exp{
			"provider_name": map[string]any{
				"_eq": am.providerType,
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, graphql.OperationName("FindAccountByProvider"))

	if err != nil {
		return nil, err
	}

	if len(query.Accounts) == 0 {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	u := query.Accounts[0]

	if u.Role != am.defaultRoleAnonymous {
		return nil, errors.New(ErrCodeAccountNotAnonymous)
	}

	providerUserID := ""
	if len(u.AccountProviders) > 0 {
		providerUserID = u.AccountProviders[0].ProviderUserID
	}
	input.ID = &u.ID
	account, err := am.getCurrentProvider().PromoteAnonymousUser(providerUserID, input)
	if err != nil {
		return nil, err
	}

	var updateMutation struct {
		UpdateAccount struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"update_account(where: $where, _set: $_set)"`
		UpsertProviders struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"insert_account_provider(objects: $providers, on_conflict: {constraint: account_provider_pkey, update_columns: [provider_user_id, metadata]})"`
	}

	updateValues := UpdateAccountInput{
		Email:        input.Email,
		PhoneCode:    input.PhoneCode,
		PhoneNumber:  input.PhoneNumber,
		DisplayName:  input.DisplayName,
		Verified:     input.Verified,
		EmailEnabled: input.EmailEnabled,
		PhoneEnabled: input.PhoneEnabled,
		Role:         input.Role,
	}
	if account.Password != "" {
		updateValues.Password = &account.Password
	}

	provider := account.AccountProviders[0]
	provider.AccountID = &u.ID
	mutationVariables := map[string]any{
		"where": account_bool_exp{
			"id": map[string]any{
				"_eq": u.ID,
			},
		},
		"_set":      updateValues,
		"providers": []account_provider_insert_input{account_provider_insert_input(provider)},
	}

	err = am.gqlClient.Mutate(context.TODO(), &updateMutation, mutationVariables, graphql.OperationName("PromoteAnonymousAccount"))
	if err != nil {
		return nil, err
	}

	baseAccount := updateValues.ToBaseAccount()
	baseAccount.ID = u.ID
	return &Account{
		BaseAccount:      baseAccount,
		AccountProviders: []AccountProvider{provider},
	}, nil
}

// DeleteUser delete user by id
func (am *AccountManager) DeleteUser(id string, softDelete bool) error {
	where := map[string]any{
		"id": map[string]any{
			"_eq": id,
		},
	}

	if !softDelete {
		_, err := am.deleteAccount(context.TODO(), where)

		return err
	}

	_, err := am.softDeleteAccounts(context.TODO(), where, map[string]any{
		"account_id": map[string]any{
			"_eq": id,
		},
	})

	return err
}

// DeleteUsers delete accounts from database
// if softDelete mode is enabled, disable the account and remove auth providers
func (am *AccountManager) DeleteUsers(where map[string]any, softDelete bool) (int, error) {

	if !softDelete {
		return am.deleteAccount(context.TODO(), where)
	}

	providerWhere := map[string]any{
		"account": where,
	}
	return am.softDeleteAccounts(context.TODO(), where, providerWhere)
}

func (am *AccountManager) deleteAccount(_ context.Context, where map[string]any) (int, error) {
	var deleteMutation struct {
		DeleteAccounts struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"delete_account(where: $where)"`
	}

	deleteVariables := map[string]any{
		"where": account_bool_exp(where),
	}

	err := am.gqlClient.Mutate(context.TODO(), &deleteMutation, deleteVariables, graphql.OperationName("DeleteAccounts"))
	return deleteMutation.DeleteAccounts.AffectedRows, err
}

func (am *AccountManager) softDeleteAccounts(ctx context.Context, where map[string]any, providerWhere map[string]any) (int, error) {

	var deleteMutation struct {
		UpdateAccounts struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"update_account(where: $where, _set: $_set)"`
		DeleteAccountProviders struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"delete_account_provider(where: $providerWhere)"`
	}

	variables := map[string]any{
		"where":         account_bool_exp(where),
		"providerWhere": account_provider_bool_exp(providerWhere),
		"_set": map[string]any{
			"verified":      false,
			"email_enabled": false,
			"phone_enabled": false,
			"disabled":      true,
		},
	}

	err := am.gqlClient.Mutate(ctx, &deleteMutation, variables, graphql.OperationName("SoftDeleteAccounts"))

	return deleteMutation.UpdateAccounts.AffectedRows, err
}

func filterProvidersByType(providers []AccountProvider, providerType AuthProviderType) []AccountProvider {
	for _, provider := range providers {
		if provider.Name == string(providerType) {
			return []AccountProvider{provider}
		}
	}

	if providerType == AuthFirebase {
		return filterProvidersByType(providers, AuthJWT)
	}
	return []AccountProvider{}
}
