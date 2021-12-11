package auth

import (
	"errors"
	"net/http"
	"testing"
	"time"

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
				AllowedFQDN: "",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"80"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"443"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
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
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"0.0.0.0/0"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"80"},
				"X-Real-Ip":        []string{"1.1.1.1"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.1/32"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"80"},
				"X-Real-Ip":        []string{"1.1.1.1"},
			},
			errors.New(ErrCodeAPIKeyInvalidIP),
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.1/32"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"443"},
				"X-Real-Ip":        []string{"192.168.0.1"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.0/24"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"443"},
				"X-Real-Ip":        []string{"192.168.0.100"},
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.0/24"},
				ExpiredAt:   time.Now().Add(-1 * time.Second),
			},
			http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Port": []string{"443"},
				"X-Real-Ip":        []string{"192.168.0.100"},
			},
			errors.New(ErrCodeAPIKeyExpired),
		},
	} {
		assert.Equal(t, ft.Error, keyAuth.validate(ft.APIKey, ft.Headers), "%d", i)
	}
}
