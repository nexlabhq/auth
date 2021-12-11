package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAPIKeyValidate(t *testing.T) {

	keyAuth := NewAPIKeyAuth(nil)

	for i, ft := range []struct {
		APIKey  *APIKey
		Headers map[string]string
		Error   error
	}{
		{
			&APIKey{
				AllowedFQDN: "",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "80",
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "443",
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  nil,
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "8080",
			},
			errors.New(ErrCodeAPIKeyInvalidFQDN),
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"0.0.0.0/0"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "80",
				"X-Real-Ip":        "1.1.1.1",
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.1/32"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "80",
				"X-Real-Ip":        "1.1.1.1",
			},
			errors.New(ErrCodeAPIKeyInvalidIP),
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.1/32"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "443",
				"X-Real-Ip":        "192.168.0.1",
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.0/24"},
				ExpiredAt:   time.Now().Add(1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "443",
				"X-Real-Ip":        "192.168.0.100",
			},
			nil,
		},
		{
			&APIKey{
				AllowedFQDN: "example.com",
				AllowedIPs:  []string{"192.168.0.0/24"},
				ExpiredAt:   time.Now().Add(-1 * time.Second),
			},
			map[string]string{
				"X-Forwarded-Host": "example.com",
				"X-Forwarded-Port": "443",
				"X-Real-Ip":        "192.168.0.100",
			},
			errors.New(ErrCodeAPIKeyExpired),
		},
	} {
		assert.Equal(t, ft.Error, keyAuth.validate(ft.APIKey, ft.Headers), "%d", i)
	}
}
