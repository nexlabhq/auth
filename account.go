// Package auth includes the collection of authentication solutions
package auth

import (
	"context"
	"errors"
	"time"

	firebase "firebase.google.com/go/v4"
	"github.com/hasura/go-graphql-client"
	gql "github.com/hasura/go-graphql-client"
)

// AuthOTPConfig contains authentication configurations from sms otp
type AuthOTPConfig struct {
	Enabled           bool          `envconfig:"AUTH_OTP_ENABLED"`
	OTPLength         uint          `envconfig:"AUTH_OTP_LENGTH" default:"6"`
	LoginLimit        uint          `envconfig:"AUTH_OTP_LOGIN_LIMIT" default:"3"`
	LoginDisableLimit uint          `envconfig:"AUTH_OTP_DISABLE_LIMIT" default:"9"`
	LoginLockDuration time.Duration `envconfig:"AUTH_OTP_LOCK_DURATION" default:"10m"`
	TTL               time.Duration `envconfig:"AUTH_OTP_TTL" default:"60s"`
	DevMode           bool          `envconfig:"AUTH_OTP_DEV" default:"false"`
	DevOTPCode        string        `envconfig:"AUTH_OTP_DEV_CODE" default:"123456"`
}

// AccountManagerConfig config options for AccountManager
type AccountManagerConfig struct {
	FirebaseApp *firebase.App `ignored:"true"`
	GQLClient   *gql.Client   `ignored:"true"`
	JWT         *JWTAuthConfig
	OTP         AuthOTPConfig

	CreateFromToken      bool             `envconfig:"AUTH_CREATE_FROM_TOKEN" default:"false"`
	Enabled2FA           bool             `envconfig:"AUTH_2FA_ENABLED"`
	DefaultProvider      AuthProviderType `envconfig:"DEFAULT_AUTH_PROVIDER" required:"true"`
	DefaultRole          string           `envconfig:"DEFAULT_ROLE" required:"true"`
	DefaultRoleAnonymous string           `envconfig:"DEFAULT_ROLE_ANONYMOUS" default:"anonymous"`
}

// AccountManager account business method
type AccountManager struct {
	providers       map[AuthProviderType]AuthProvider
	gqlClient       *gql.Client
	providerType    AuthProviderType
	defaultRole     string
	createFromToken bool
	otp             AuthOTPConfig
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

	return &AccountManager{
		providers:       providers,
		gqlClient:       config.GQLClient,
		providerType:    config.DefaultProvider,
		defaultRole:     config.DefaultRole,
		createFromToken: config.CreateFromToken,
		otp:             config.OTP,
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
func (am *AccountManager) CreateProviderAccount(input *CreateAccountInput) (*Account, error) {
	return am.getCurrentProvider().CreateUser(input)
}

// ChangeProviderPassword change account password with provider
func (am *AccountManager) ChangeProviderPassword(uid string, newPassword string) error {
	return am.getCurrentProvider().ChangePassword(uid, newPassword)
}

// FindAccountByProviderEmail find account by email
func (am *AccountManager) FindAccountByProviderEmail(email string) (*Account, error) {

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

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccounts"))
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

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccounts"))
	if err != nil {
		return nil, err
	}

	if len(query.Account) == 0 {
		return nil, nil
	}

	return &query.Account[0], nil
}

// CreateAccountWithProvider get or create account with provider
func (am *AccountManager) CreateAccountWithProvider(input *CreateAccountInput, extraFields map[string]interface{}) (*Account, error) {

	ctx := context.Background()

	if (isTrue(input.EmailEnabled) || (isTrue(input.EmailEnabled) && !isTrue(input.PhoneEnabled))) &&
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

	condition := make([]map[string]interface{}, 0)

	if !isStringPtrEmpty(input.Email) {
		condition = append(condition, map[string]interface{}{
			"email": map[string]string{
				"_eq": *input.Email,
			},
			"email_enabled": map[string]bool{
				"_eq": true,
			},
		})
	}

	if !isStringPtrEmpty(input.PhoneNumber) {
		condition = append(condition, map[string]interface{}{
			"phone_code": map[string]any{
				"_eq": input.PhoneCode,
			},
			"phone_number": map[string]any{
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

	input.ID = getPtr(genID())
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
		gql.OperationName("InsertAccount"),
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
		gql.OperationName("InsertAccountProviders"),
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
func (am *AccountManager) VerifyToken(token string) (*Account, map[string]interface{}, error) {
	provider, claims, err := am.getCurrentProvider().VerifyToken(token)
	if err != nil {
		return nil, nil, err
	}

	acc, err := am.findAccountByProviderUser(provider.ProviderUserID)
	if err != nil || acc != nil {
		return acc, claims, err
	}

	if !am.createFromToken {
		return nil, nil, errors.New(ErrCodeAccountNoProvider)
	}

	// allow create account with provider info
	acc, err = am.getCurrentProvider().GetUserByID(provider.ProviderUserID)
	if err != nil || (acc != nil && acc.ID != "") {
		return acc, nil, err
	} else if acc == nil {
		return nil, nil, errors.New(ErrCodeAccountNotFound)
	}

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

	_, err = am.InsertAccount(accInsertInput)
	if err != nil {
		return nil, nil, err
	}

	acc.Role = am.defaultRole

	return acc, claims, nil
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

// DeleteUser delete user by identity
func (am *AccountManager) DeleteUser(id string) error {
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

	// delete user from authentication providers
	for _, ap := range query.AccountProviders {
		err = am.As(AuthProviderType(ap.Name)).getCurrentProvider().DeleteUser(ap.ProviderUserID)
		if err != nil {
			return err
		}
	}

	var deleteMutation struct {
		DeleteAccount struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"delete_account(where: $where)"`
	}

	deleteVariables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]string{
				"_eq": id,
			},
		},
	}

	return am.gqlClient.Mutate(context.Background(), &deleteMutation, deleteVariables, gql.OperationName("DeleteAccountById"))

}

// DeleteUsers delete many users by condition
func (am *AccountManager) DeleteUsers(where map[string]interface{}) error {
	var query struct {
		Accounts []Account `graphql:"account(where: $where)"`
	}

	queryVariables := map[string]interface{}{
		"where": account_bool_exp(where),
	}

	err := am.gqlClient.Query(context.Background(), &query, queryVariables, gql.OperationName("GetAccountsWithProvider"))

	if err != nil {
		return err
	}

	// delete user from authentication providers
	for _, acc := range query.Accounts {
		for _, ap := range acc.AccountProviders {
			err = am.As(AuthProviderType(ap.Name)).getCurrentProvider().DeleteUser(ap.ProviderUserID)
			if err != nil {
				return err
			}
		}
	}

	var deleteMutation struct {
		DeleteAccount struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"delete_account(where: $where)"`
	}

	return am.gqlClient.Mutate(context.Background(), &deleteMutation, queryVariables, gql.OperationName("DeleteAccountById"))
}

// GenerateOTP check if the account exists and generate the authentication otp
func (am *AccountManager) GenerateOTP(sessionVariables map[string]string, phoneCode int, phoneNumber string) OTPOutput {

	if !am.otp.Enabled {
		return OTPOutput{
			Error: ErrCodeUnsupported,
		}
	}

	if phoneNumber == "" {
		return OTPOutput{
			Error: ErrCodePhoneRequired,
		}
	}
	var err error
	phoneCode, phoneNumber, err = parseI18nPhoneNumber(phoneNumber, phoneCode)
	if err != nil {
		return OTPOutput{
			Error: ErrCodeInvalidPhone,
		}
	}

	var query struct {
		Account []struct {
			ID         string `graphql:"id"`
			Disabled   bool   `graphql:"disabled"`
			Activities []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc }, limit: $activityLimit)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"phone_code": map[string]interface{}{
				"_eq": phoneCode,
			},
			"phone_number": map[string]interface{}{
				"_eq": phoneNumber,
			},
			"phone_enabled": map[string]interface{}{
				"_eq": true,
			},
		},
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-1 * time.Hour),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityLogin, ActivityOTP, ActivityOTPFailure, ActivityLogout},
			},
		},
		"activityLimit": graphql.Int(am.otp.LoginDisableLimit),
	}

	err = am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountWithActivities"))
	if err != nil {
		return OTPOutput{
			Error: err.Error(),
		}
	}

	activity, otp, otpExpiry := am.newOTPActivity(sessionVariables, "", ActivityOTP)
	var accountID string
	if len(query.Account) == 0 {
		// create the account if it doesn't exist
		accountID, err = am.InsertAccount(map[string]interface{}{
			"id":            genID(),
			"phone_code":    phoneCode,
			"phone_number":  phoneNumber,
			"phone_enabled": true,
			"role":          am.defaultRole,
			"activities": map[string]interface{}{
				"data": []map[string]interface{}{activity},
			},
		})

		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	} else {
		account := query.Account[0]
		accountID = account.ID
		if account.Disabled {
			return OTPOutput{
				Error: ErrCodeAccountDisabled,
			}
		}

		var otpTime time.Time
		var failureLatestTime time.Time
		failureCount := 0

		for _, act := range account.Activities {
			if act.Type == ActivityOTP {
				otpTime = act.CreatedAt
			} else if act.Type == ActivityLogin || act.Type == ActivityLogout {
				break
			} else {
				if failureLatestTime.IsZero() {
					failureLatestTime = act.CreatedAt
				}
				failureCount++
			}
		}

		if failureCount > int(am.otp.LoginDisableLimit) {
			return OTPOutput{
				Error: ErrCodeAccountDisabled,
			}
		}

		now := time.Now()
		lockedRemain := failureLatestTime.Add(am.otp.LoginLockDuration).Sub(now)
		if failureCount >= int(am.otp.LoginLimit) && lockedRemain > 0 {
			return OTPOutput{
				Error:          ErrCodeAccountTemporarilyLocked,
				LockedDuration: uint(lockedRemain.Seconds()),
			}
		}

		if otpTime.Add(am.otp.TTL).After(now) {
			return OTPOutput{
				Error: ErrCodeOTPAlreadySent,
			}
		}

		// otherwise validate the account and insert the activity
		var createActivityMutation struct {
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $objects)"`
		}

		activity["account_id"] = account.ID
		variables := map[string]interface{}{
			"objects": []account_activity_insert_input{activity},
		}
		err = am.gqlClient.Mutate(context.TODO(), &createActivityMutation, variables, graphql.OperationName("CreateAccountActivities"))
		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	}

	return OTPOutput{
		Code:      otp,
		Expiry:    otpExpiry,
		AccountID: accountID,
	}
}

func (am *AccountManager) newOTPActivity(sessionVariables map[string]string, accountID string, activityType ActivityType) (account_activity_insert_input, string, time.Time) {

	otp := genRandomString(int(am.otp.OTPLength), digits)
	otpExpiry := time.Now().Add(am.otp.TTL)

	return am.newActivity(sessionVariables, accountID, activityType, map[string]interface{}{
		"otp": otp,
	}), otp, otpExpiry
}

// VerifyOTP verify if the otp code matches the current account
func (am *AccountManager) VerifyOTP(sessionVariables map[string]string, input VerifyOTPInput, options ...AccessTokenOption) (*AccessToken, error) {

	if !am.otp.Enabled {
		return nil, errors.New(ErrCodeUnsupported)
	}

	if input.PhoneNumber == "" {
		return nil, errors.New(ErrCodePhoneRequired)
	}

	var err error
	phoneCode, phoneNumber, err := parseI18nPhoneNumber(input.PhoneNumber, input.PhoneCode)
	if err != nil {
		return nil, errors.New(ErrCodeInvalidPhone)
	}

	var accountQuery struct {
		Accounts []struct {
			ID         string `graphql:"id"`
			Disabled   bool   `graphql:"disabled"`
			Activities []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
				Metadata  *struct {
					OTP string `json:"otp"`
				} `graphql:"metadata" scalar:"true" json:"metadata"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc }, limit: $activityLimit)"`
			AccountProviders []AccountProvider `json:"account_providers" graphql:"account_providers(where: $providerWhere, limit: 1)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"phone_code": map[string]interface{}{
				"_eq": phoneCode,
			},
			"phone_number": map[string]interface{}{
				"_eq": phoneNumber,
			},
			"phone_enabled": map[string]interface{}{
				"_eq": true,
			},
		},
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-time.Hour),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityOTP, ActivityLogin, ActivityLogout, ActivityOTPFailure},
			},
		},
		"activityLimit": graphql.Int(am.otp.LoginDisableLimit + 1),
		"providerWhere": account_provider_bool_exp{
			"provider_name": map[string]interface{}{
				"_eq": am.GetProviderName(),
			},
		},
	}

	err = am.gqlClient.Query(context.TODO(), &accountQuery, variables, graphql.OperationName("FindAccountWithActivities"))

	if err != nil {
		return nil, err
	}

	if len(accountQuery.Accounts) == 0 {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	if accountQuery.Accounts[0].Disabled {
		return nil, errors.New(ErrCodeAccountDisabled)
	}

	if len(accountQuery.Accounts[0].Activities) == 0 {
		return nil, errors.New(ErrCodeInvalidOTP)
	}

	account := accountQuery.Accounts[0]
	// static otp code check in dev mode
	if !am.otp.DevMode || input.OTP != am.otp.DevOTPCode {
		otpActivityIndex := -1
		for i, activity := range account.Activities {
			if activity.Type == ActivityLogin || activity.Type == ActivityLogout {
				break
			} else if activity.Type == ActivityOTP {
				otpActivityIndex = i
				break
			}
		}
		if otpActivityIndex < 0 || (account.Activities[otpActivityIndex].CreatedAt.Add(am.otp.TTL).Before(time.Now())) ||
			(account.Activities[otpActivityIndex].Metadata != nil && account.Activities[otpActivityIndex].Metadata.OTP != input.OTP) {

			_ = am.CreateActivity(sessionVariables, account.ID, ActivityOTPFailure, nil)
			if otpActivityIndex+1 > int(am.otp.LoginDisableLimit) {
				// disable the user if the failure count exceed limit
				var updateAccountMutation struct {
					UpdateAccount struct {
						AffectedRows int `graphql:"affected_rows"`
					} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
				}

				updateVariables := map[string]interface{}{
					"id": graphql.String(account.ID),
					"_set": UpdateAccountInput{
						Disabled: getPtr(true),
					},
				}

				_ = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
			}
			return nil, errors.New(ErrCodeInvalidOTP)
		}
	}

	// insert account provider if not exist
	if len(account.AccountProviders) == 0 {
		acc, err := am.getCurrentProvider().GetOrCreateUserByPhone(&CreateAccountInput{
			ID:          &account.ID,
			PhoneCode:   &input.PhoneCode,
			PhoneNumber: &input.PhoneNumber,
		})
		if err != nil {
			return nil, err
		}

		accProvider := AccountProvider{
			Name:           acc.AccountProviders[0].Name,
			ProviderUserID: acc.AccountProviders[0].ProviderUserID,
			AccountID:      &account.ID,
			Metadata:       acc.AccountProviders[0].Metadata,
		}
		err = am.CreateProvider(accProvider)
		if err != nil {
			return nil, err
		}

		account.AccountProviders = []AccountProvider{accProvider}
	}

	var updateAccountMutation struct {
		UpdateAccount struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
		CreateActivity struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"insert_account_activity(objects: $activities)"`
	}

	activity := map[string]interface{}{
		"account_id": account.ID,
		"type":       ActivityLogin,
	}

	if sessionVariables != nil {
		if ip := getRequestIPFromSession(sessionVariables); ip != nil {
			activity["ip"] = *ip
		}
		if p, err := getPositionFromSession(sessionVariables); err == nil && p != nil {
			activity["position"] = p
		}
	}

	updateVariables := map[string]interface{}{
		"id": graphql.String(account.ID),
		"_set": UpdateAccountInput{
			Verified: getPtr(true),
		},
		"activities": []account_activity_insert_input{activity},
	}

	err = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
	if err != nil {
		return nil, err
	}

	return am.EncodeToken(&account.AccountProviders[0], input.Scopes, options...)
}

// newActivity create an user activity model
func (am *AccountManager) newActivity(sessionVariables map[string]string, accountID string, activityType ActivityType, metadata map[string]interface{}) account_activity_insert_input {

	activity := map[string]interface{}{
		"type": activityType,
	}

	if accountID != "" {
		activity["account_id"] = accountID
	}
	if metadata != nil {
		activity["metadata"] = metadata
	}
	if sessionVariables != nil {
		if ip := getRequestIPFromSession(sessionVariables); ip != nil {
			activity["ip"] = *ip
		}
		if p, err := getPositionFromSession(sessionVariables); err == nil && p != nil {
			activity["position"] = p
		}
	}

	return activity
}

// CreateActivity insert an user activity record into the database
func (am *AccountManager) CreateActivity(sessionVariables map[string]string, accountID string, activityType ActivityType, metadata map[string]interface{}) error {

	var createActivityMutation struct {
		CreateActivity struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"insert_account_activity(objects: $objects)"`
	}

	activity := am.newActivity(sessionVariables, accountID, activityType, metadata)

	variables := map[string]interface{}{
		"objects": []account_activity_insert_input{activity},
	}

	return am.gqlClient.Mutate(context.TODO(), &createActivityMutation, variables, graphql.OperationName("CreateAccountActivities"))
}

// Generate2FaOTP generate 2FA OTP to the logon user
func (am *AccountManager) Generate2FaOTP(sessionVariables map[string]string, accountID string, phoneCode int, phoneNumber string) OTPOutput {

	if !am.otp.Enabled {
		return OTPOutput{
			Error: ErrCodeUnsupported,
		}
	}

	if accountID == "" {
		return OTPOutput{
			Error: ErrCodeAccountNotFound,
		}
	}
	var query struct {
		Account []struct {
			ID           string `graphql:"id"`
			PhoneCode    int    `graphql:"phone_code"`
			PhoneNumber  string `graphql:"phone_number"`
			PhoneEnabled bool   `graphql:"phone_enabled"`
			Disabled     bool   `graphql:"disabled"`
			Activities   []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc })"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]interface{}{
				"_eq": accountID,
			},
		},
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-1*am.otp.TTL - time.Second),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityOTP2FA, ActivityOTP2FASuccess},
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountWithActivities"))
	if err != nil {
		return OTPOutput{
			Error: err.Error(),
		}
	}

	if len(query.Account) == 0 {
		return OTPOutput{
			Error: ErrCodeAccountNotFound,
		}
	}

	if query.Account[0].Disabled {
		return OTPOutput{
			Error: ErrCodeAccountDisabled,
		}
	}

	if query.Account[0].PhoneNumber == "" && phoneNumber == "" {
		return OTPOutput{
			Error: ErrCodePhoneRequired,
		}
	}

	// if the otp exists in the TTL range, skip sending new one
	for _, ac := range query.Account[0].Activities {
		if ac.Type == ActivityOTP2FASuccess {
			break
		} else if ac.Type == ActivityOTP2FA {
			return OTPOutput{
				Error: ErrCodeOTPAlreadySent,
			}
		}
	}

	shouldUpdatePhone := false
	pNumber := query.Account[0].PhoneNumber
	pCode := query.Account[0].PhoneCode
	if query.Account[0].PhoneNumber == "" || !query.Account[0].PhoneEnabled {
		shouldUpdatePhone = true
	}
	if phoneNumber != "" && phoneNumber != query.Account[0].PhoneNumber {
		shouldUpdatePhone = true
		pCode, pNumber, err = parseI18nPhoneNumber(phoneNumber, phoneCode)
		if err != nil {
			return OTPOutput{
				Error: ErrCodeInvalidPhone,
			}
		}
	}
	activity, otp, otpExpiry := am.newOTPActivity(sessionVariables, accountID, ActivityOTP2FA)

	if shouldUpdatePhone {
		var updateAccountMutation struct {
			UpdateAccount struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"id": graphql.String(accountID),
			"_set": UpdateAccountInput{
				PhoneCode:   &pCode,
				PhoneNumber: &pNumber,
			},
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	} else {
		var createActivityMutation struct {
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &createActivityMutation, updateVariables, graphql.OperationName("CreateActivity"))
		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	}

	return OTPOutput{
		Code:   otp,
		Expiry: otpExpiry,
	}
}

// Verify2FaOTP verify 2FA OTP to the current user
func (am *AccountManager) Verify2FaOTP(sessionVariables map[string]string, accountID string, otp string, type2FA Auth2FAType) error {

	if !am.otp.Enabled {
		return errors.New(ErrCodeUnsupported)
	}

	if accountID == "" {
		return errors.New(ErrCodeAccountNotFound)
	}

	var query struct {
		Account []struct {
			ID           string `graphql:"id"`
			PhoneCode    int    `graphql:"phone_code"`
			PhoneNumber  string `graphql:"phone_number"`
			PhoneEnabled bool   `graphql:"phone_enabled"`
			Disabled     bool   `graphql:"disabled"`
			Activities   []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
				Metadata  *struct {
					OTP string `json:"otp"`
				} `graphql:"metadata" scalar:"true" json:"metadata"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc }, limit: 1)"`
			AccountProviders []AccountProvider `json:"account_providers" graphql:"account_providers(where: $providerWhere, limit: 1)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]interface{}{
				"_eq": accountID,
			},
		},
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-1*am.otp.TTL - time.Second),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityOTP2FA, ActivityOTP2FASuccess},
			},
		},
		"providerWhere": account_provider_bool_exp{
			"provider_name": map[string]interface{}{
				"_eq": am.GetProviderName(),
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountProviderWithActivities"))
	if err != nil {
		return err
	}

	if len(query.Account) == 0 {
		return errors.New(ErrCodeAccountNotFound)
	}

	if query.Account[0].Disabled {
		return errors.New(ErrCodeAccountDisabled)
	}

	if len(query.Account[0].AccountProviders) == 0 {
		return errors.New(ErrCodeAccountNoProvider)
	}

	if query.Account[0].PhoneNumber == "" && type2FA == Auth2FASms {
		return errors.New(ErrCodePhoneNotRegistered)
	}

	account := query.Account[0]
	if len(account.Activities) == 0 ||
		account.Activities[0].Type != ActivityOTP2FA ||
		account.Activities[0].Metadata == nil ||
		!(account.Activities[0].Metadata.OTP == otp || (am.otp.DevMode && am.otp.DevOTPCode == otp)) {
		return errors.New(ErrCodeInvalidOTP)
	}

	activity := am.newActivity(sessionVariables, accountID, ActivityOTP2FASuccess, nil)
	if type2FA == Auth2FASms && !account.PhoneEnabled {

		_, err = am.getCurrentProvider().UpdateUser(account.AccountProviders[0].ProviderUserID, UpdateAccountInput{
			PhoneCode:    &account.PhoneCode,
			PhoneNumber:  &account.PhoneNumber,
			PhoneEnabled: getPtr(true),
			Verified:     getPtr(true),
		})

		if err != nil {
			return err
		}

		var updateAccountMutation struct {
			UpdateAccount struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"id": graphql.String(accountID),
			"_set": UpdateAccountInput{
				PhoneEnabled: getPtr(true),
			},
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
		if err != nil {
			return err
		}
	} else {
		var createActivityMutation struct {
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &createActivityMutation, updateVariables, graphql.OperationName("CreateActivity"))
		if err != nil {
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
			AccountProviders []AccountProvider `graphql:"account_providers(where: providerWhere)"`
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

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountByProvider"))

	if err != nil {
		return nil, err
	}

	if len(query.Accounts) == 0 {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	u := query.Accounts[0]

	if u.Role != am.defaultRole {
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
