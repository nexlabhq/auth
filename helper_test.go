package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePhoneNumber(t *testing.T) {
	rawPhoneNumber := "+84900000000"
	code, num, err := parseI18nPhoneNumber(rawPhoneNumber, "")
	assert.NoError(t, err)

	assert.Equal(t, 84, code)
	assert.Equal(t, "0900000000", num)

	assert.Equal(t, rawPhoneNumber, formatI18nPhoneNumber(code, num))
}
