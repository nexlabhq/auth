package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	gql "github.com/hasura/go-graphql-client"
)

type APIKey struct {
	ID          int       `graphql:"id"`
	Type        string    `graphql:"type"`
	AllowedFQDN string    `graphql:"allowed_fqdn"`
	AllowedIPs  []string  `graphql:"allowed_ips"`
	ExpiredAt   time.Time `graphql:"expired_at"`
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

// Verify verify and validate the api key
func (ak *apiKeyAuth) Verify(apiKey string, headers http.Header) (*APIKey, error) {

	if apiKey == "" {
		return nil, errors.New(ErrCodeAPIKeyRequired)
	}

	var query struct {
		APIKeys []APIKey `graphql:"api_key(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": api_key_bool_exp{
			"api_key": map[string]string{
				"_eq": apiKey,
			},
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
	if err = ak.validate(&apiK, headers); err != nil {
		return nil, err
	}
	return &apiK, nil
}

func (ak *apiKeyAuth) validate(apiK *APIKey, headers http.Header) error {

	if !apiK.ExpiredAt.IsZero() && apiK.ExpiredAt.Before(time.Now()) {
		return errors.New(ErrCodeAPIKeyExpired)
	}

	if apiK.AllowedFQDN != "" {
		if headers == nil {
			return errors.New(ErrCodeAPIKeyInvalidFQDN)
		}
		fqdn := strings.Split(apiK.AllowedFQDN, ":")
		reqHost, reqPort := getRequestHost(headers)
		if fqdn[0] != reqHost || (len(fqdn) == 1 && reqPort != "80" && reqPort != "443") ||
			(len(fqdn) == 2 && reqPort != fqdn[1]) ||
			len(fqdn) > 2 {
			return errors.New(ErrCodeAPIKeyInvalidFQDN)
		}
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
