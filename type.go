package auth

type AuthProviderType string

const (
	AuthorizationHeader                  = "authorization"
	AuthBearer          AuthProviderType = "Bearer"
	AuthJWT             AuthProviderType = "jwt"
	AuthFirebase        AuthProviderType = "firebase"
	HasuraClaims                         = "https://hasura.io/jwt/claims"
	XHasuraDefaultRole                   = "x-hasura-default-role"
	XHasuraAllowedRoles                  = "x-hasura-allowed-roles"
	XHasuraUserID                        = "x-hasura-user-id"
)

const (
	ErrCodeUnsupported                     = "unsupported"
	ErrCodeTokenExpired                    = "token_expired"
	ErrCodeJWTInvalidIssuer                = "jwt:invalid_issuer"
	ErrCodePasswordRequired                = "required:password"
	ErrCodeCurrentPasswordRequired         = "required:current_password"
	ErrCodeNewPasswordRequired             = "required:new_password"
	ErrCodeNewPasswordEqualCurrentPassword = "new_pw_equal_current_pw"
	ErrCodeEmailRequired                   = "required:email"
	ErrCodePhoneRequired                   = "required:phone"
	ErrCodePasswordNotMatch                = "password_not_match"
	ErrCodeCurrentPasswordNotMatch         = "current_password_not_match"
	ErrCodeAccountNotFound                 = "account:not_found"
	ErrCodeAccountExisted                  = "account:existed"
	ErrCodeAccountNoProvider               = "account:no_provider"
	ErrCodeAPIKeyInvalidIP                 = "api_key:invalid_ip"
	ErrCodeAPIKeyInvalidFQDN               = "api_key:invalid_fqdn"
	ErrCodeAPIKeyExpired                   = "api_key:expired"
	ErrCodeAPIKeyRequired                  = "api_key:required"
	ErrCodeAPIKeyNotFound                  = "api_key:not_found"
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

type CreateAccountInput struct {
	ID               string           `json:"id"`
	DisplayName      string           `json:"display_name"`
	Email            string           `json:"email"`
	PhoneCode        int              `json:"phone_code"`
	PhoneNumber      string           `json:"phone_number"`
	Role             string           `json:"role"`
	Password         string           `json:"password,omitempty"`
	Verified         bool             `json:"verified"`
	AuthProviderType AuthProviderType `json:"auth_provider_type"`
	EmailEnabled     bool             `json:"email_enabled"`
	PhoneEnabled     bool             `json:"phone_enabled"`
}

type account_insert_input map[string]interface{}
type account_set_input map[string]interface{}
type account_bool_exp map[string]interface{}
type account_provider_bool_exp map[string]interface{}

type AccountProvider struct {
	AccountID      *string `json:"account_id,omitempty" graphql:"account_id"`
	Name           string  `json:"provider_name" graphql:"provider_name"`
	ProviderUserID string  `json:"provider_user_id" graphql:"provider_user_id"`
}

type account_provider_insert_input AccountProvider

type BaseAccount struct {
	ID          string `json:"id" graphql:"id"`
	Email       string `json:"email" graphql:"email"`
	PhoneCode   int    `json:"phone_code" graphql:"phone_code"`
	PhoneNumber string `json:"phone_number" graphql:"phone_number"`
	DisplayName string `json:"display_name" graphql:"display_name"`
	Password    string `json:"password,omitempty" graphql:"password"`
	Role        string `json:"role" graphql:"role"`
	Verified    bool   `json:"verified" graphql:"verified"`
}

type Account struct {
	BaseAccount
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
	CreateUser(CreateAccountInput) (*Account, error)
	GetUserByID(id string) (*Account, error)
	GetUserByEmail(email string) (*Account, error)
	SetCustomClaims(uid string, input map[string]interface{}) error
	EncodeToken(uid string) (*AccessToken, error)
	VerifyToken(token string) (*AccountProvider, error)
	VerifyPassword(uid string, password string) error
	ChangePassword(uid string, newPassword string) error
	SignInWithEmailAndPassword(email string, password string) (*Account, error)
	SignInWithPhoneAndPassword(phoneCode int, phoneNumber string, password string) (*Account, error)
}
