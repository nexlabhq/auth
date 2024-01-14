package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/hasura/go-graphql-client"
	"github.com/hgiasac/graphql-utils/client"
)

// APIKeyGetter abstracts an API key model with getter
type APIKeysGetter interface {
	Get() []APIKey
}

// APIKey represents an API key model
type APIKey struct {
	ID           string    `graphql:"id" json:"id"`
	Type         string    `graphql:"type" json:"type"`
	AllowedFQDN  []string  `graphql:"allowed_fqdn" json:"allowed_fqdn"`
	AllowedIPs   []string  `graphql:"allowed_ips" json:"allowed_ips"`
	ExpiredAt    time.Time `graphql:"expired_at" json:"expired_at"`
	HasuraRoles  []string  `graphql:"hasura_roles" json:"hasura_roles"`
	PermissionID string    `graphql:"permission_id" json:"permission_id"`
}

type APIKeys []APIKey

func (ak APIKeys) Get() []APIKey {
	return ak
}

type api_key_bool_exp map[string]interface{}

// ApiKeyAuth represents the api key authentication service
type ApiKeyAuth struct {
	client client.Client
}

// NewAPIKeyAuth create new APIKeyAuth instance
func NewAPIKeyAuth(client client.Client) *ApiKeyAuth {
	return &ApiKeyAuth{client}
}

// Verify and validate the api key
func (ak *ApiKeyAuth) Verify(apiKey string, headers http.Header) (*APIKey, error) {
	keys := APIKeys{}
	return ak.VerifyCustomKey(&keys, apiKey, headers)
}

// VerifyCustomKey verifies a custom API key model
func (ak *ApiKeyAuth) VerifyCustomKey(input APIKeysGetter, apiKey string, headers http.Header) (*APIKey, error) {

	// get either api key header or web domain to authorize the application
	var andWhere []map[string]any
	origin := getRequestOrigin(headers)
	if isWebBrowserAgent(headers.Get("User-Agent")) {
		if origin == "" {
			return nil, errors.New("request origin required")
		}

		andWhere = append(andWhere, map[string]any{
			"allowed_fqdn": map[string]any{
				"_contains": []string{origin},
			},
		})
	}

	if apiKey != "" {
		andWhere = append(andWhere, map[string]any{
			"api_key": map[string]any{
				"_eq": apiKey,
			},
		})
	}

	if len(andWhere) == 0 {
		return nil, errors.New(ErrCodeAPIKeyRequired)
	}

	builder := graphql.NewBuilder().Bind("api_key(where: $where, limit: 1)", input).
		Variable("where", api_key_bool_exp{
			"_and": andWhere,
		})

	q, v, err := builder.Build()
	if err != nil {
		return nil, err
	}

	err = ak.client.Query(context.TODO(), &q, v, graphql.OperationName("GetAPIKey"))
	if err != nil {
		return nil, err
	}

	keys := input.Get()
	if len(keys) == 0 {
		return nil, errors.New(ErrCodeAPIKeyNotFound)
	}

	if err = ak.validate(&keys[0], headers, origin); err != nil {
		return nil, err
	}
	return &keys[0], nil
}

func (ak *ApiKeyAuth) validate(apiK *APIKey, headers http.Header, origin string) error {

	if !apiK.ExpiredAt.IsZero() && apiK.ExpiredAt.Before(time.Now()) {
		return errors.New(ErrCodeAPIKeyExpired)
	}

	if origin == "" && len(apiK.AllowedFQDN) > 0 {
		return errors.New(ErrCodeAPIKeyInvalidFQDN)
	}

	ipValid := false
	if len(apiK.AllowedIPs) > 0 {
		if headers != nil {
			ip := net.ParseIP(GetRequestIpFromHeader(headers))

			if ip != nil {
				for _, cidr := range apiK.AllowedIPs {
					_, ipNet, err := net.ParseCIDR(cidr)
					if err != nil {
						return err
					}

					if ipNet.Contains(ip) {
						ipValid = true
						break
					}
				}
			}
		}

	} else {
		ipValid = true
	}

	if !ipValid {
		return errors.New(ErrCodeAPIKeyInvalidIP)
	}

	return nil
}
