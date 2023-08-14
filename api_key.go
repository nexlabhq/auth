package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	gql "github.com/hasura/go-graphql-client"
)

type APIKey struct {
	ID          int       `graphql:"id"`
	Type        string    `graphql:"type"`
	AllowedFQDN []string  `graphql:"allowed_fqdn"`
	AllowedIPs  []string  `graphql:"allowed_ips"`
	ExpiredAt   time.Time `graphql:"expired_at"`
	HasuraRoles []string  `graphql:"hasura_roles"`
	Permissions []struct {
		PermissionID string `graphql:"permission_id"`
	} `graphql:"permissions"`
}

type api_key_bool_exp map[string]interface{}

// apiKeyAuth represents api key authentication
type apiKeyAuth struct {
	client *gql.Client
}

// NewAPIKeyAuth create new APIKeyAuth instance
func NewAPIKeyAuth(client *gql.Client) *apiKeyAuth {
	return &apiKeyAuth{client}
}

// Verify and validate the api key
func (ak *apiKeyAuth) Verify(apiKey string, headers http.Header) (*APIKey, error) {

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

	var query struct {
		APIKeys []APIKey `graphql:"api_key(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": api_key_bool_exp{
			"_and": andWhere,
		},
	}

	err := ak.client.Query(context.Background(), &query, variables, gql.OperationName("GetAPIKey"))

	if err != nil {
		return nil, err
	}

	if len(query.APIKeys) == 0 {
		return nil, errors.New(ErrCodeAPIKeyNotFound)
	}

	apiK := query.APIKeys[0]
	if err = ak.validate(&apiK, headers, origin); err != nil {
		return nil, err
	}
	return &apiK, nil
}

func (ak *apiKeyAuth) validate(apiK *APIKey, headers http.Header, origin string) error {

	if !apiK.ExpiredAt.IsZero() && apiK.ExpiredAt.Before(time.Now()) {
		return errors.New(ErrCodeAPIKeyExpired)
	}

	if origin == "" && len(apiK.AllowedFQDN) > 0 {
		return errors.New(ErrCodeAPIKeyInvalidFQDN)
	}

	ipValid := false
	if len(apiK.AllowedIPs) > 0 {
		if headers != nil {
			ip := net.ParseIP(getRequestIP(headers))

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
