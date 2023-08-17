package auth

import (
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ttacon/libphonenumber"
)

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	digits        = "0123456789"
	alphabets     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphaDigits   = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	webBrowserRegex = regexp.MustCompile(`(?i)(opera|chrome|safari|firefox|msie|trident)[/\s]([\d.]+)`)
)

var src = rand.NewSource(time.Now().UnixNano())

// genRandomString generate random string with fixed length
func genRandomString(n int, allowedCharacters ...string) string {
	allowedChars := alphaDigits
	if len(allowedCharacters) > 0 {
		allowedChars = allowedCharacters[0]
	}
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(allowedChars) {
			sb.WriteByte(allowedChars[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

// genID generate random unique id
func genID() string {
	now := time.Now()
	return strconv.FormatInt(int64(now.Year()), 32) +
		string(alphaDigits[int(now.Month())]) +
		string(alphaDigits[now.Day()]) +
		string(alphaDigits[now.Hour()]) +
		string(alphaDigits[now.Minute()]) +
		string(alphaDigits[now.Second()]) +
		genRandomString(8)
}

// isWebBrowserAgent checks if the user agent is from web browser
func isWebBrowserAgent(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	return webBrowserRegex.MatchString(userAgent)
}

// getRequestOrigin get request origin from origin or x-forwarded-origin header
func getRequestOrigin(header http.Header) string {
	origin := header.Get("Origin")
	if origin != "" {
		return origin
	}

	return header.Get("X-Forwarded-Origin")
}

// getRequestIP gets a requests IP address by reading off the forwarded-for
// header (for proxies) and falls back to use the remote address.
func getRequestIP(r http.Header) string {
	ip := r.Get("X-Real-Ip")
	if ip == "" {
		ip = r.Get("X-Forwarded-For")
	}
	return ip
}

func formatI18nPhoneNumber(code int, phone string) string {
	if len(phone) == 0 {
		return ""
	}

	phone = strings.TrimLeft(phone, "0")
	return fmt.Sprintf("+%d%s", code, phone)
}

func parseI18nPhoneNumber(rawNumber string, countryCode int) (int, string, error) {
	pn, err := libphonenumber.Parse(rawNumber, libphonenumber.GetRegionCodeForCountryCode(countryCode))
	if err != nil {
		return 0, "", err
	}

	sNumber := strconv.Itoa(int(pn.GetNationalNumber()))
	return int(pn.GetCountryCode()),
		fmt.Sprintf("%0*d", int(pn.GetNumberOfLeadingZeros())+len(sNumber), pn.GetNationalNumber()),
		nil
}

func getRequestIPFromSession(sessionVariables map[string]string) *string {
	if ip, ok := sessionVariables[XHasuraRequestIP]; ok {
		return &ip
	}
	return nil
}

type GeoPoint struct {
	Type        string    `json:"type"`
	Coordinates []float64 `json:"coordinates"`
}

func getPositionFromSession(sessionVariables map[string]string) (*GeoPoint, error) {
	result := &GeoPoint{
		Type:        "Point",
		Coordinates: []float64{0, 0},
	}
	if l, ok := sessionVariables[XHasuraLongitude]; ok && l != "" && l != "0" {
		fl, err := strconv.ParseFloat(l, 64)
		if err == nil {
			return nil, err
		}
		result.Coordinates[0] = fl
	} else {
		return nil, nil
	}
	if l, ok := sessionVariables[XHasuraLatitude]; ok && l != "" && l != "0" {
		fl, err := strconv.ParseFloat(l, 64)
		if err == nil {
			return nil, err
		}
		result.Coordinates[1] = fl
	} else {
		return nil, nil
	}
	return result, nil
}

func getPtr[V any](value V) *V {
	return &value
}

func isTrue(ptr *bool) bool {
	if ptr != nil && *ptr {
		return true
	}

	return false
}

func isStringPtrEmpty(ptr *string) bool {
	if ptr != nil && *ptr != "" {
		return false
	}

	return true
}

// sliceIndex returns the index of the first occurrence of v in s,
// or -1 if not present.
func sliceIndex[E comparable](s []E, v E) int {
	for i, vs := range s {
		if v == vs {
			return i
		}
	}
	return -1
}

// sliceContains reports whether v is present in s.
func sliceContains[E comparable](s []E, v E) bool {
	return sliceIndex(s, v) >= 0
}

// mergeMap merge values of maps
func mergeMap[K comparable, V any](src map[K]V, dest map[K]V, extras ...map[K]V) map[K]V {
	if src == nil {
		src = make(map[K]V)
	}
	for k, v := range dest {
		src[k] = v
	}
	if len(extras) > 0 {
		for _, extra := range extras {
			for k, v := range extra {
				src[k] = v
			}
		}
	}
	return src
}
