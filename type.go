package auth

import (
	"time"
)

type AuthProviderType string
type ActivityType string
type Auth2FAType string

type Role string

const (
	RoleBackend   Role = "backend"
	RoleModerator Role = "moderator"
	RoleUser      Role = "user"
	RoleCustomer  Role = "customer"
)

// AuthScope represents the OAuth Scopes specification
// https://oauth.net/2/scope/
type AuthScope string

const (
	// openid scope is used to get an ID Token
	ScopeOpenID AuthScope = "openid"
	// offline_access is used to get a Refresh Token.
	ScopeOfflineAccess AuthScope = "offline_access"
	// email scope is used to add the email info into the ID token
	ScopeEmail AuthScope = "email"
	// profile scope is used to add the profile info into the ID token
	ScopeProfile AuthScope = "profile"
	// profile scope is used to add the role info into the ID token
	ScopeRole AuthScope = "role"
)

const (
	AuthorizationHeader                  = "authorization"
	AuthBearer          AuthProviderType = "Bearer"
	AuthJWT             AuthProviderType = "jwt"
	AuthFirebase        AuthProviderType = "firebase"

	ActivityLogin         ActivityType = "L"
	ActivityLoginFailure  ActivityType = "LF"
	ActivityLogout        ActivityType = "LO"
	ActivityOTP           ActivityType = "O"
	ActivityOTPFailure    ActivityType = "OF"
	ActivityOTP2FA        ActivityType = "O2"
	ActivityOTP2FASuccess ActivityType = "O2S"

	Auth2FASms Auth2FAType = "sms"

	HasuraClaims          = "https://hasura.io/jwt/claims"
	XHasuraDefaultRole    = "x-hasura-default-role"
	XHasuraAllowedRoles   = "x-hasura-allowed-roles"
	XHasuraUserID         = "x-hasura-user-id"
	XHasuraUserEmail      = "x-hasura-user-email"
	XHasuraDisplayName    = "x-hasura-display-name"
	XHasuraRequestIP      = "x-hasura-request-ip"
	XHasuraLatitude       = "x-hasura-latitude"
	XHasuraLongitude      = "x-hasura-longitude"
	XHasuraGroupIDs       = "x-hasura-group-ids"
	XCoreAPIKey           = "x-core-api-key"
	XHasuraAcceptLanguage = "x-hasura-accept-language"
	XHasuraPhoneCode      = "x-hasura-phone-code"
	XHasuraPhoneNumber    = "x-hasura-phone-number"
	XHasuraFirstName      = "x-hasura-first-name"
	XHasuraLastName       = "x-hasura-last-name"
	XHasuraAvatarURL      = "x-hasura-avatar-url"
	XHasuraPermissions    = "x-hasura-permissions"

	OTPTestCodeName = "test_code"
)

const (
	ErrCodeUnsupported                      = "unsupported"
	ErrCodeTokenExpired                     = "token_expired"
	ErrCodeJWTInvalidIssuer                 = "jwt_invalid_issuer"
	ErrCodeTokenMismatched                  = "token_mismatched"
	ErrCodeTokenAudienceMismatched          = "token_audience_mismatched"
	ErrCodeRefreshTokenAudienceMismatched   = "refresh_token_audience_mismatched"
	ErrCodePasswordRequired                 = "required_password"
	ErrCodeCurrentPasswordRequired          = "required_current_password"
	ErrCodeNewPasswordRequired              = "required_new_password"
	ErrCodeNewPasswordEqualCurrentPassword  = "new_pw_equal_current_pw"
	ErrCodeEmailRequired                    = "required_email"
	ErrCodePhoneRequired                    = "required_phone"
	ErrCodePhoneNotRegistered               = "phone_not_registered"
	ErrCodeInvalidPhone                     = "invalid_phone"
	ErrCodePasswordNotMatch                 = "password_not_match"
	ErrCodeCurrentPasswordNotMatch          = "current_password_not_match"
	ErrCodeAccountNotFound                  = "account_not_found"
	ErrCodeAccountNotAnonymous              = "account_not_anonymous"
	ErrCodeAccountTemporarilyLocked         = "account_temporarily_locked"
	ErrCodeAccountDisabled                  = "account_disabled"
	ErrCodeAccountExisted                   = "account_existed"
	ErrCodeAccountNoProvider                = "account_no_provider"
	ErrCodeAccountInsertZero                = "account_insert_zero"
	ErrCodeAccountProviderInsertZero        = "account_provider_insert_zero"
	ErrCodeAPIKeyInvalidIP                  = "api_key_invalid_ip"
	ErrCodeAPIKeyInvalidFQDN                = "api_key_invalid_fqdn"
	ErrCodeAPIKeyExpired                    = "api_key_expired"
	ErrCodeAPIKeyRequired                   = "api_key_required"
	ErrCodeAPIKeyNotFound                   = "api_key_not_found"
	ErrCodeUpdateProviderNonExistentAccount = "update_provider_nonexistent_account"
	ErrCodeUpdatePasswordNonExistentAccount = "update_password_nonexistent_account"
	ErrCodeOTPAlreadySent                   = "otp_already_sent"
	ErrCodeInvalidOTP                       = "invalid_otp"
	ErrCodeInvalidAuthProvider              = "invalid_auth_provider"
)

func GetAuthProviderTypes() []AuthProviderType {
	return []AuthProviderType{
		AuthFirebase,
		AuthJWT,
	}
}

func (apt AuthProviderType) IsValid() bool {
	for _, v := range GetAuthProviderTypes() {
		if v == apt {
			return true
		}
	}
	return false
}

type CreateUserOutput struct {
	ID string `json:"id"`
}

// CreateAccountInput represents the account insert input
type CreateAccountInput struct {
	ID               *string           `json:"id,omitempty"`
	DisplayName      *string           `json:"display_name,omitempty"`
	Email            *string           `json:"email,omitempty"`
	PhoneCode        *int              `json:"phone_code,omitempty"`
	PhoneNumber      *string           `json:"phone_number,omitempty"`
	Role             *string           `json:"role,omitempty"`
	Password         *string           `json:"password,omitempty"`
	Verified         *bool             `json:"verified,omitempty"`
	AuthProviderType *AuthProviderType `json:"auth_provider_type,omitempty"`
	EmailEnabled     *bool             `json:"email_enabled,omitempty"`
	PhoneEnabled     *bool             `json:"phone_enabled,omitempty"`
}

// ToBaseAccount converts to BaseAccount struct
func (cai CreateAccountInput) ToBaseAccount() BaseAccount {
	result := BaseAccount{}
	if cai.ID != nil {
		result.ID = *cai.ID
	}
	if cai.DisplayName != nil {
		result.DisplayName = *cai.DisplayName
	}
	if cai.Email != nil {
		result.Email = *cai.Email
	}
	if cai.PhoneCode != nil {
		result.PhoneCode = *cai.PhoneCode
	}
	if cai.PhoneNumber != nil {
		result.PhoneNumber = *cai.PhoneNumber
	}
	if cai.Verified != nil {
		result.Verified = *cai.Verified
	}
	if cai.EmailEnabled != nil {
		result.EmailEnabled = *cai.EmailEnabled
	}
	if cai.PhoneEnabled != nil {
		result.PhoneEnabled = *cai.PhoneEnabled
	}
	if cai.Role != nil {
		result.Role = *cai.Role
	}

	return result
}

// UpdateAccountInput represents the update account input
type UpdateAccountInput struct {
	DisplayName  *string `json:"display_name,omitempty"`
	Email        *string `json:"email,omitempty"`
	PhoneCode    *int    `json:"phone_code,omitempty"`
	PhoneNumber  *string `json:"phone_number,omitempty"`
	Password     *string `json:"password,omitempty"`
	Verified     *bool   `json:"verified,omitempty"`
	EmailEnabled *bool   `json:"email_enabled,omitempty"`
	PhoneEnabled *bool   `json:"phone_enabled,omitempty"`
	Role         *string `json:"role,omitempty"`
	Disabled     *bool   `json:"disabled,omitempty"`
}

// GetGraphQLType returns the graphql schema type
func (uai UpdateAccountInput) GetGraphQLType() string {
	return "account_set_input"
}

// ToBaseAccount converts to BaseAccount struct
func (uai UpdateAccountInput) ToBaseAccount() BaseAccount {
	result := BaseAccount{}
	if uai.DisplayName != nil {
		result.DisplayName = *uai.DisplayName
	}
	if uai.Email != nil {
		result.Email = *uai.Email
	}
	if uai.PhoneCode != nil {
		result.PhoneCode = *uai.PhoneCode
	}
	if uai.PhoneNumber != nil {
		result.PhoneNumber = *uai.PhoneNumber
	}
	if uai.Verified != nil {
		result.Verified = *uai.Verified
	}
	if uai.EmailEnabled != nil {
		result.EmailEnabled = *uai.EmailEnabled
	}
	if uai.PhoneEnabled != nil {
		result.PhoneEnabled = *uai.PhoneEnabled
	}
	if uai.Role != nil {
		result.Role = *uai.Role
	}

	return result
}

type account_insert_input map[string]interface{}
type account_bool_exp map[string]interface{}
type account_provider_bool_exp map[string]interface{}
type account_activity_bool_exp map[string]interface{}
type account_activity_insert_input map[string]interface{}

type AccountProvider struct {
	AccountID      *string        `json:"account_id,omitempty" graphql:"account_id"`
	Name           string         `json:"provider_name" graphql:"provider_name"`
	ProviderUserID string         `json:"provider_user_id" graphql:"provider_user_id"`
	Metadata       map[string]any `json:"metadata" graphql:"metadata" scalar:"true"`
}

type account_provider_insert_input AccountProvider
type account_provider_set_input map[string]interface{}

type BaseAccount struct {
	ID           string `json:"id" graphql:"id"`
	Email        string `json:"email" graphql:"email"`
	PhoneCode    int    `json:"phone_code" graphql:"phone_code"`
	PhoneNumber  string `json:"phone_number" graphql:"phone_number"`
	DisplayName  string `json:"display_name" graphql:"display_name"`
	Role         string `json:"role" graphql:"role"`
	Verified     bool   `json:"verified" graphql:"verified"`
	EmailEnabled bool   `json:"email_enabled" graphql:"email_enabled"`
	PhoneEnabled bool   `json:"phone_enabled" graphql:"phone_enabled"`
	Disabled     bool   `json:"disabled" graphql:"disabled"`
}

type Account struct {
	BaseAccount
	Password         string            `json:"password,omitempty" graphql:"password"`
	AccountProviders []AccountProvider `json:"account_providers" graphql:"account_providers"`
}

type AccessToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type AuthProvider interface {
	GetName() AuthProviderType
	CreateUser(*CreateAccountInput) (*Account, error)
	PromoteAnonymousUser(string, *CreateAccountInput) (*Account, error)
	GetOrCreateUserByPhone(*CreateAccountInput) (*Account, error)
	UpdateUser(string, UpdateAccountInput) (*Account, error)
	DeleteUser(id string) error
	GetUserByID(id string) (*Account, error)
	GetUserByEmail(email string) (*Account, error)
	SetCustomClaims(uid string, input map[string]interface{}) error
	EncodeToken(cred *AccountProvider, scopes []AuthScope, options ...AccessTokenOption) (*AccessToken, error)
	RefreshToken(refreshToken string, options ...AccessTokenOption) (*AccessToken, error)
	VerifyToken(token string) (*AccountProvider, map[string]interface{}, error)
	VerifyRefreshToken(refreshToken string) (*AccountProvider, error)
	VerifyPassword(uid string, password string) error
	ChangePassword(uid string, newPassword string) error
	SignInWithEmailAndPassword(email string, password string) (*Account, error)
	SignInWithPhoneAndPassword(phoneCode int, phoneNumber string, password string) (*Account, error)
}

// AccessTokenOption the extensible interface for token encoding
type AccessTokenOption interface {
	Type() string
	Value() interface{}
}

type tokenClaimsOption struct {
	value map[string]interface{}
}

// NewTokenClaims create the access token option for custom claims
func NewTokenClaims(claims map[string]interface{}) AccessTokenOption {
	return &tokenClaimsOption{value: claims}
}

// Type create the access token option for custom claims
func (tco tokenClaimsOption) Type() string {
	return "claims"
}

// Value returns value of the custom claims
func (tco tokenClaimsOption) Value() interface{} {
	return tco.value
}

// OTPOutput represents the otp response
type OTPOutput struct {
	Error          string
	LockedDuration uint
	Code           string
	Expiry         time.Time
	AccountID      string
}

// GenerateOTPInput represents the otp generation input
type GenerateOTPInput struct {
	PhoneCode       int
	PhoneNumber     string
	ExtraConditions map[string]any
	ExtraInputs     map[string]any
}

// VerifyOTPInput represents the otp verification input
type VerifyOTPInput struct {
	PhoneCode       int            `json:"phone_code"`
	PhoneNumber     string         `json:"phone_number"`
	OTP             string         `json:"otp"`
	ExtraConditions map[string]any `json:"-"`
}
