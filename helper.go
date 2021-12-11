package auth

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/ttacon/libphonenumber"
)

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	alphaDigits   = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var src = rand.NewSource(time.Now().UnixNano())

// genRandomString generate random string with fixed length
func genRandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(alphaDigits) {
			sb.WriteByte(alphaDigits[idx])
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

// getRequestHost gets a requests host by reading off the forwarded-host
// header (for proxies) and falls back to use the remote address.
func getRequestHost(r map[string]string) (string, string) {
	host, hostOk := r["X-Forwarded-Host"]
	port, portOk := r["X-Forwarded-Port"]

	if !hostOk && !portOk {
		return "", ""
	}

	return host, port
}

// getRequestIP gets a requests IP address by reading off the forwarded-for
// header (for proxies) and falls back to use the remote address.
func getRequestIP(r map[string]string) string {
	ip, ok := r["X-Real-Ip"]
	if ip == "" {
		ip, ok = r["X-Forwarded-For"]
	}
	if !ok {
		return ""
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

func parseI18nPhoneNumber(rawNumber string, defaultRegion string) (int, string, error) {
	pn, err := libphonenumber.Parse(rawNumber, defaultRegion)
	if err != nil {
		return 0, "", err
	}

	sNumber := strconv.Itoa(int(pn.GetNationalNumber()))
	return int(pn.GetCountryCode()),
		fmt.Sprintf("%0*d", int(pn.GetNumberOfLeadingZeros())+len(sNumber), pn.GetNationalNumber()),
		nil
}
