//go:build integration
// +build integration

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
)

func setupFirebaseApp() *firebase.App {
	app, err := firebase.NewApp(context.Background(), nil, option.WithCredentialsJSON([]byte(os.Getenv("GOOGLE_CREDENTIALS"))))

	if err != nil {
		panic(err)
	}

	return app
}

func getFirebaseIdToken(token string) (string, error) {
	client := http.DefaultClient
	url := fmt.Sprintf("https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=%s", os.Getenv("FIREBASE_API_KEY"))
	resp, err := client.Post(url, "application/json", bytes.NewBuffer([]byte(fmt.Sprintf(`{
		"token": "%s",
		"returnSecureToken": true
	}`, token))))

	if err != nil {
		return "", err
	}

	var result struct {
		IDToken string `json:"idToken"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return "", err
	}

	return result.IDToken, nil
}

func test_sprintJson(input interface{}) string {
	b, _ := json.Marshal(input)
	return string(b)
}

func TestFirebase_anonymousAccount(t *testing.T) {

	app := setupFirebaseApp()
	ctx := context.Background()
	authClient, err := app.Auth(ctx)
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	var eu, pu *auth.UserRecord
	au, err := authClient.CreateUser(ctx, &auth.UserToCreate{})
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	log.Println("anonymous user: ", test_sprintJson(au))
	defer func() {
		for _, u := range []*auth.UserRecord{au, eu, pu} {
			if u == nil {
				continue
			}
			if err := authClient.DeleteUser(ctx, u.UID); err != nil {
				log.Println(err)
			}
		}
	}()

	authApp := NewFirebaseAuth(app)
	anonymousUser, err := authApp.GetUserByID(au.UID)
	assert.NoError(t, err)
	assert.Equal(t, "anonymous", anonymousUser.Role)

	email := fmt.Sprintf("%s@example.com", strings.ToLower(genRandomString(16, alphabets)))
	eu, err = authClient.CreateUser(ctx, (&auth.UserToCreate{}).Email(email).Password("test_password"))
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	log.Println("email user: ", test_sprintJson(eu))
	emailUser, err := authApp.GetUserByID(eu.UID)
	assert.NoError(t, err)
	assert.Equal(t, "", emailUser.Role)
	assert.Equal(t, email, emailUser.Email)

	phoneCode := 84
	phoneNumber := fmt.Sprintf("9%s", genRandomString(8, digits))
	phone := fmt.Sprintf("+%d%s", phoneCode, phoneNumber)
	pu, err = authClient.CreateUser(ctx, (&auth.UserToCreate{}).PhoneNumber(phone))
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	log.Println("phone user: ", test_sprintJson(pu))
	phoneUser, err := authApp.GetUserByID(pu.UID)
	assert.NoError(t, err)
	assert.Equal(t, "", phoneUser.Role)
	assert.Equal(t, "0"+phoneNumber, phoneUser.PhoneNumber)
	assert.Equal(t, phoneCode, phoneUser.PhoneCode)
	assert.Equal(t, phone, formatI18nPhoneNumber(phoneUser.PhoneCode, phoneUser.PhoneNumber))
}
