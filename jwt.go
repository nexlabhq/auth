package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/google/uuid"
	gql "github.com/hasura/go-graphql-client"
	"golang.org/x/crypto/bcrypt"
)

type jwtPayload struct {
	Issuer         string                 `json:"iss"`
	Subject        string                 `json:"sub"`
	Audience       string                 `json:"aud"`
	ExpirationTime int64                  `json:"exp"`
	NotBeforeTime  int64                  `json:"nbt"`
	IssuedAt       int64                  `json:"iat"`
	JwtID          string                 `json:"jti"`
	Checksum       string                 `json:"checksum"`
	CustomClaims   map[string]interface{} `json:"https://hasura.io/jwt/claims"`
}

type JWTAuthConfig struct {
	Cost              int           `envconfig:"JWT_HASH_COST" default:"10"`
	SessionKey        string        `envconfig:"SESSION_KEY"`
	TTL               time.Duration `envconfig:"SESSION_TTL" default:"1h"`
	RefreshTTL        time.Duration `envconfig:"SESSION_REFRESH_TTL" default:"0ms"`
	Issuer            string        `envconfig:"JWT_ISSUER"`
	Algorithm         string        `envconfig:"JWT_ALGORITHM" default:"HS256"`
	HasChecksum       bool          `envconfig:"JWT_CHECKSUM" default:"false"`
	ChecksumLength    int           `envconfig:"JWT_CHECKSUM_LENGTH" default:"8"`
	LoginLimit        uint          `envconfig:"JWT_LOGIN_LIMIT" default:"5"`
	LoginLockLimit    uint          `envconfig:"JWT_DISABLE_LIMIT" default:"15"`
	LoginLockDuration time.Duration `envconfig:"JWT_LOCK_DURATION" default:"10m"`
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

// JWTAuth implements the AuthProvider interface for JWT authentication
type JWTAuth struct {
	client *gql.Client
	config JWTAuthConfig
}

// NewJWTAuth creates a new JWTAuth instance
func NewJWTAuth(client *gql.Client, config JWTAuthConfig) *JWTAuth {
	if config.Cost == 0 {
		config.Cost = bcrypt.DefaultCost
	}
	if config.Algorithm == "" {
		config.Algorithm = jose.HS256
	}

	if config.HasChecksum && config.ChecksumLength == 0 {
		config.ChecksumLength = 8
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

	metadata := map[string]interface{}{
		"checksum": genRandomString(ja.config.ChecksumLength),
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
				Metadata:       metadata,
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

func (ja *JWTAuth) EncodeToken(cred *AccountProvider, scopes []AuthScope, options ...AccessTokenOption) (*AccessToken, error) {

	now := time.Now()
	exp := now.Add(ja.config.TTL)
	jwtID := uuid.New().String()
	checksum := ""
	if cred.Metadata != nil {
		if chk, ok := cred.Metadata["checksum"]; ok {
			if sc, ok := chk.(string); ok {
				checksum = sc
			}
		}
	}

	payload := jwtPayload{
		JwtID:          jwtID,
		Issuer:         ja.config.Issuer,
		Subject:        cred.ProviderUserID,
		Audience:       "access",
		IssuedAt:       now.Unix(),
		NotBeforeTime:  now.Unix(),
		ExpirationTime: exp.Unix(),
		Checksum:       checksum,
	}

	for _, option := range options {
		if option == nil {
			continue
		}
		switch option.Type() {
		case "claims":
			value := option.Value()
			if claims, ok := value.(map[string]interface{}); ok {
				payload.CustomClaims = claims
			} else {
				return nil, errors.New("claims input must be an map[string]interface{}")
			}
		}
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

	// encode refresh token if the expiry is set
	var refreshToken string
	if sliceContains(scopes, ScopeOfflineAccess) && ja.config.RefreshTTL >= ja.config.TTL {
		refreshPayload := jwtPayload{
			JwtID:          ja.genRefreshTokenID(jwtID),
			Issuer:         ja.config.Issuer,
			Subject:        cred.ProviderUserID,
			Audience:       "refresh",
			IssuedAt:       now.Unix(),
			NotBeforeTime:  now.Unix(),
			ExpirationTime: now.Add(ja.config.RefreshTTL).Unix(),
			Checksum:       checksum,
		}

		refreshPayloadBytes, err := json.Marshal(refreshPayload)
		if err != nil {
			return nil, err
		}

		refreshToken, err = jose.SignBytes(refreshPayloadBytes, ja.config.Algorithm, []byte(ja.config.SessionKey),
			jose.Header("typ", "JWT"),
			jose.Header("alg", ja.config.Algorithm),
		)

		if err != nil {
			return nil, err
		}
	}

	return &AccessToken{
		AccessToken:  token,
		TokenType:    string(ja.GetName()),
		ExpiresIn:    int(ja.config.TTL / time.Second),
		RefreshToken: refreshToken,
	}, nil
}

func (ja *JWTAuth) validateTokenChecksum(userId string, checksum string) (*AccountProvider, error) {

	if !ja.config.HasChecksum {
		return &AccountProvider{
			AccountID:      &userId,
			Name:           string(AuthJWT),
			ProviderUserID: userId,
		}, nil
	}

	// fetch account provider and validate checksum
	var query struct {
		AccountProviders []AccountProvider `graphql:"account_provider(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_provider_bool_exp{
			"provider_user_id": map[string]string{
				"_eq": userId,
			},
			"provider_name": map[string]string{
				"_eq": string(string(AuthJWT)),
			},
		},
	}

	err := ja.client.Query(context.Background(), &query, variables, gql.OperationName("GetProviders"))

	if err != nil {
		return nil, err
	}

	if len(query.AccountProviders) == 0 {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	userChecksum := ""
	provider := query.AccountProviders[0]
	if provider.Metadata != nil {
		iChecksum, ok := provider.Metadata["checksum"]
		if ok {
			userChecksum, _ = iChecksum.(string)
		}
	}

	if userChecksum != checksum {
		return nil, errors.New(ErrCodeTokenExpired)
	}

	return &provider, nil
}

// VerifyToken decodes and verifies the JWT token
func (ja *JWTAuth) VerifyToken(token string) (*AccountProvider, map[string]interface{}, error) {

	result, err := ja.decodeToken(token)
	if err != nil {
		return nil, nil, err
	}

	if result.Audience != "access" {
		return nil, nil, errors.New(ErrCodeTokenAudienceMismatched)
	}

	provider, err := ja.validateTokenChecksum(result.Subject, result.Checksum)
	if err != nil {
		return nil, nil, err
	}

	return provider, result.CustomClaims, nil
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

	if err != nil {
		return err
	}

	if mutation.UpdateAccounts.AffectedRows == 0 {
		return errors.New(ErrCodeUpdatePasswordNonExistentAccount)
	}

	if ja.config.HasChecksum {
		err = ja.updateProviderChecksum(uid)
	}

	return err
}

func (ja *JWTAuth) updateProviderChecksum(uid string) error {
	ctx := context.Background()

	checksum := genRandomString(ja.config.ChecksumLength)
	metadata := map[string]string{
		"checksum": checksum,
	}
	var mutation struct {
		UpdateAccountProviders struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"update_account_provider(where: $where, _set: $setValues)"`
	}

	variables := map[string]interface{}{
		"where": account_provider_bool_exp{
			"account_id": map[string]string{
				"_eq": uid,
			},
			"provider_name": map[string]string{
				"_eq": string(AuthJWT),
			},
		},
		"setValues": account_provider_set_input{
			"metadata": metadata,
		},
	}

	err := ja.client.Mutate(ctx, &mutation, variables, gql.OperationName("UpdateAccountProviders"))

	if err != nil {
		return err
	}

	if mutation.UpdateAccountProviders.AffectedRows == 0 {
		return errors.New(ErrCodeUpdateProviderNonExistentAccount)
	}
	return nil
}

func (ja *JWTAuth) SignInWithEmailAndPassword(email string, password string) (*Account, error) {
	return ja.signInWithPassword(account_bool_exp{
		"email": map[string]string{
			"_eq": email,
		},
		"email_enabled": map[string]bool{
			"_eq": true,
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
		"phone_enabled": map[string]bool{
			"_eq": true,
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

func (ja *JWTAuth) RefreshToken(refreshToken string, options ...AccessTokenOption) (*AccessToken, error) {
	decodedRefreshToken, err := ja.decodeToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if decodedRefreshToken.Audience != "refresh" {
		return nil, errors.New(ErrCodeRefreshTokenAudienceMismatched)
	}

	provider, err := ja.validateTokenChecksum(decodedRefreshToken.Subject, decodedRefreshToken.Checksum)
	if err != nil {
		return nil, err
	}

	return ja.EncodeToken(provider, []AuthScope{ScopeOpenID, ScopeOfflineAccess}, options...)
}

func (ja *JWTAuth) decodeToken(token string) (*jwtPayload, error) {

	bytes, _, err := jose.DecodeBytes(token, []byte(ja.config.SessionKey))
	if err != nil {
		return nil, err
	}

	var result jwtPayload

	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return nil, err
	}

	if ja.config.Issuer != "" && ja.config.Issuer != result.Issuer {
		return &result, errors.New(ErrCodeJWTInvalidIssuer)
	}

	if result.ExpirationTime <= time.Now().Unix() {
		return &result, errors.New(ErrCodeTokenExpired)
	}

	return &result, nil
}

func (ja *JWTAuth) genRefreshTokenID(id string) string {
	return fmt.Sprintf("%s-refresh", id)
}

func (ja *JWTAuth) GetOrCreateUserByPhone(input *CreateAccountInput) (*Account, error) {
	metadata := map[string]interface{}{
		"checksum": genRandomString(ja.config.ChecksumLength),
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
				Name:           string(AuthJWT),
				ProviderUserID: input.ID,
				Metadata:       metadata,
			},
		},
	}, nil
}

func (ja *JWTAuth) UpdateUser(uid string, input UpdateAccountInput) (*Account, error) {
	return &Account{
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
				Name:           string(AuthJWT),
				ProviderUserID: uid,
			},
		},
	}, nil
}
