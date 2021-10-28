package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/google/uuid"
	gql "github.com/hasura/go-graphql-client"
	"golang.org/x/crypto/bcrypt"
)

type jwtPayload struct {
	Issuer         string `json:"iss"`
	Subject        string `json:"sub"`
	Audience       string `json:"aud"`
	ExpirationTime int64  `json:"exp"`
	NotBeforeTime  int64  `json:"nbt"`
	IssuedAt       int64  `json:"iat"`
	JwtID          string `json:"jti"`
}

type JWTAuthConfig struct {
	Cost       int           `envconfig:"JWT_HASH_COST" default:"10"`
	SessionKey string        `envconfig:"SESSION_KEY"`
	TTL        time.Duration `envconfig:"SESSION_TTL" default:"1h"`
	Issuer     string        `envconfig:"JWT_ISSUER"`
	Algorithm  string        `envconfig:"JWT_ALGORITHM" default:"HS256"`
}

func (jac JWTAuthConfig) Validate() error {
	if jac.SessionKey == "" {
		return errors.New("SESSION_KEY is required")
	}
	if jac.Issuer == "" {
		return errors.New("JWT_ISSUER is required")
	}

	return nil
}

type JWTAuth struct {
	client *gql.Client
	config JWTAuthConfig
}

func NewJWTAuth(client *gql.Client, config JWTAuthConfig) *JWTAuth {
	if config.Cost == 0 {
		config.Cost = bcrypt.DefaultCost
	}
	if config.Algorithm == "" {
		config.Algorithm = jose.HS256
	}

	return &JWTAuth{
		client: client,
		config: config,
	}
}

func (ja JWTAuth) GetName() AuthProviderType {
	return AuthJWT
}

func (ja *JWTAuth) CreateUser(input *CreateAccountInput) (*Account, error) {
	if input.Password == "" {
		return nil, errors.New(ErrCodePasswordRequired)
	}

	if input.ID == "" {
		input.ID = genID()
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), ja.config.Cost)
	if err != nil {
		return nil, err
	}
	return &Account{
		BaseAccount: BaseAccount{
			ID:          input.ID,
			Email:       input.Email,
			Password:    string(hashedPassword),
			DisplayName: input.DisplayName,
			PhoneCode:   input.PhoneCode,
			PhoneNumber: input.PhoneNumber,
			Role:        input.Role,
			Verified:    input.Verified,
		},
		AccountProviders: []AccountProvider{
			{
				Name:           string(AuthJWT),
				ProviderUserID: input.ID,
			},
		},
	}, nil
}

func (ja *JWTAuth) GetUserByID(id string) (*Account, error) {
	return ja.getUser(map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]string{
				"_eq": id,
			},
		},
	})
}

func (ja *JWTAuth) GetUserByEmail(email string) (*Account, error) {
	return ja.getUser(map[string]interface{}{
		"where": account_bool_exp{
			"email": map[string]string{
				"_eq": email,
			},
		},
	})
}

func (ja *JWTAuth) getUser(variables map[string]interface{}) (*Account, error) {
	ctx := context.Background()

	var query struct {
		Accounts []Account `graphql:"account(where: $where, limit: 1)"`
	}

	err := ja.client.Query(ctx, &query, variables, gql.OperationName("GetAccountByEmail"))
	if err != nil {
		return nil, err
	}

	if len(query.Accounts) == 0 {
		return nil, nil
	}

	return &query.Accounts[0], nil
}

func (ja *JWTAuth) SetCustomClaims(uid string, input map[string]interface{}) error {
	return errors.New(ErrCodeUnsupported)
}

func (ja *JWTAuth) EncodeToken(uid string) (*AccessToken, error) {

	now := time.Now()
	exp := now.Add(ja.config.TTL)

	payload := jwtPayload{
		JwtID:          uuid.New().String(),
		Issuer:         ja.config.Issuer,
		Subject:        uid,
		Audience:       "identity",
		IssuedAt:       now.Unix(),
		NotBeforeTime:  now.Unix(),
		ExpirationTime: exp.Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	token, err := jose.SignBytes(payloadBytes, ja.config.Algorithm, []byte(ja.config.SessionKey),
		jose.Header("typ", "JWT"),
		jose.Header("alg", ja.config.Algorithm),
	)

	if err != nil {
		return nil, err
	}

	return &AccessToken{
		AccessToken: token,
		TokenType:   string(ja.GetName()),
		ExpiresIn:   int(ja.config.TTL / time.Second),
	}, nil
}

func (ja *JWTAuth) VerifyToken(token string) (*AccountProvider, error) {

	bytes, _, err := jose.DecodeBytes(token, []byte(ja.config.SessionKey))
	if err != nil {
		return nil, err
	}

	var result jwtPayload

	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return nil, err
	}

	if result.ExpirationTime <= time.Now().Unix() {
		return nil, errors.New(ErrCodeTokenExpired)
	}

	if ja.config.Issuer != "" && ja.config.Issuer != result.Issuer {
		return nil, errors.New(ErrCodeJWTInvalidIssuer)
	}

	return &AccountProvider{
		AccountID:      &result.Subject,
		Name:           string(AuthJWT),
		ProviderUserID: result.Subject,
	}, nil
}

func (ja *JWTAuth) ChangePassword(uid string, newPassword string) error {
	ctx := context.Background()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), ja.config.Cost)
	if err != nil {
		return err
	}

	var mutation struct {
		UpdateAccounts struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"update_account(where: $where, _set: $setValues)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]string{
				"_eq": uid,
			},
		},
		"setValues": account_set_input{
			"password": string(hashedPassword),
		},
	}

	err = ja.client.Mutate(ctx, &mutation, variables, gql.OperationName("UpdateAccountPassword"))

	return err
}

func (ja *JWTAuth) SignInWithEmailAndPassword(email string, password string) (*Account, error) {
	return ja.signInWithPassword(account_bool_exp{
		"email": map[string]string{
			"_eq": email,
		},
	}, password)
}

func (ja *JWTAuth) SignInWithPhoneAndPassword(phoneCode int, phoneNumber string, password string) (*Account, error) {
	return ja.signInWithPassword(account_bool_exp{
		"phone_code": map[string]int{
			"_eq": phoneCode,
		},
		"phone_number": map[string]string{
			"_eq": phoneNumber,
		},
	}, password)
}

func (ja *JWTAuth) comparePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (ja *JWTAuth) signInWithPassword(where account_bool_exp, password string) (*Account, error) {

	var query struct {
		Accounts []Account `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": where,
	}

	err := ja.client.Query(context.Background(), &query, variables, gql.OperationName("GetAccount"))

	if err != nil {
		return nil, err
	}

	if err == nil && len(query.Accounts) == 0 {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	u := query.Accounts[0]

	if u.Password == "" {
		return nil, errors.New(ErrCodePasswordNotMatch)
	}

	err = ja.comparePassword(u.Password, password)

	if err != nil {
		return nil, errors.New(ErrCodePasswordNotMatch)
	}

	return &u, nil
}

func (ja *JWTAuth) VerifyPassword(providerUserId string, password string) error {
	_, err := ja.signInWithPassword(account_bool_exp{
		"id": map[string]string{
			"_eq": providerUserId,
		},
	}, password)

	return err
}

func (ja *JWTAuth) DeleteUser(uid string) error {
	return nil
}
