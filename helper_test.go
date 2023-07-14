package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePhoneNumber(t *testing.T) {
	var fixtures = []struct {
		PhoneCode   int
		PhoneNumber string
		PhoneRaw    string
	}{
		{
			84,
			"0900000000",
			"+84900000000",
		},
		{
			84,
			"0357839884",
			"0357839884",
		},
	}

	for _, f := range fixtures {
		code, num, err := parseI18nPhoneNumber(f.PhoneRaw, f.PhoneCode)
		assert.NoError(t, err)

		assert.Equal(t, f.PhoneCode, code)
		assert.Equal(t, f.PhoneNumber, num)
	}
}

func TestGetPtr(t *testing.T) {
	value := "hello"
	assert.Equal(t, value, getPtr(value))
}

func TestPtrEmpty(t *testing.T) {
	assert.Equal(t, true, isStringPtrEmpty(nil))
	assert.Equal(t, true, isStringPtrEmpty(getPtr("")))
	assert.Equal(t, false, isStringPtrEmpty(getPtr("hello")))

	assert.Equal(t, false, isTrue(nil))
	assert.Equal(t, false, isTrue(getPtr(false)))
	assert.Equal(t, true, isTrue(getPtr(true)))
}
