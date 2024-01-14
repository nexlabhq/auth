package auth

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/hgiasac/graphql-utils/client"
	"github.com/hgiasac/graphql-utils/test"
	"github.com/stretchr/testify/assert"
)

func TestAPIKeyValidate(t *testing.T) {

	keyAuth := NewAPIKeyAuth(nil)

	for i, ft := range []struct {
		APIKey  *APIKey
		Headers http.Header
		Error   error
	}{
		{
			&APIKey{
				AllowedFQDN: []string{},
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"Origin": []string{"example.com"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"Origin": []string{"example.com"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"8080"},
			},
			errors.New(ErrCodeAPIKeyInvalidFQDN),
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  []string{"0.0.0.0/0"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"Origin":    []string{"example.com"},
				"X-Real-Ip": []string{"1.1.1.1"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  []string{"192.168.0.1/32"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"Origin":    []string{"example.com"},
				"X-Real-Ip": []string{"1.1.1.1"},
			},
			errors.New(ErrCodeAPIKeyInvalidIP),
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  []string{"192.168.0.1/32"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"Origin":    []string{"example.com"},
				"X-Real-Ip": []string{"192.168.0.1"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  []string{"192.168.0.0/24"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"Origin":    []string{"example.com"},
				"X-Real-Ip": []string{"192.168.0.100"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: []string{"example.com"},
				AllowedIPs:  []string{"192.168.0.0/24"},
				ExpiredAt:   time.Now().Add(-1 * time.Second),
			},
			http.Header{
				"Origin":    []string{"example.com"},
				"X-Real-Ip": []string{"192.168.0.100"},
			},
			errors.New(ErrCodeAPIKeyExpired),
		},
	} {
		assert.Equal(t, ft.Error, keyAuth.validate(ft.APIKey, ft.Headers, getRequestOrigin(ft.Headers)), "%d", i)
	}
}

func TestApiKey_Verify(t *testing.T) {
	fixtures := []struct {
		client   client.Client
		inputKey string
		header   http.Header
		expected *APIKey
		errorMsg string
	}{
		{
			client: test.NewMockGraphQLClientSingle(map[string]any{
				"api_key": []APIKey{
					{
						ID:           "1",
						Type:         "app",
						AllowedFQDN:  []string{"example.com"},
						HasuraRoles:  []string{"admin"},
						PermissionID: "*",
					},
				},
			}, nil),
			inputKey: "key",
			header: http.Header{
				"Origin": []string{"example.com"},
			},
			expected: &APIKey{
				ID:           "1",
				Type:         "app",
				AllowedFQDN:  []string{"example.com"},
				HasuraRoles:  []string{"admin"},
				PermissionID: "*",
			},
		},
	}

	for i, fixture := range fixtures {
		client := NewAPIKeyAuth(fixture.client)
		result, err := client.Verify(fixture.inputKey, fixture.header)
		if fixture.errorMsg != "" {
			assert.EqualError(t, err, fixture.errorMsg, "%d", i)
		} else {
			assert.NoError(t, err, "%d", i)
			assert.Equal(t, *fixture.expected, *result, "%d", i)
		}
	}
}
