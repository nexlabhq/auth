package auth

import (
	"testing"

	firebase "firebase.google.com/go/v4"
	testUtils "github.com/hgiasac/graphql-utils/test"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestAutoLinkProvider_failure(t *testing.T) {
	logger := log.Logger
	am, err := NewAccountManager(AccountManagerConfig{
		DefaultProvider: AuthFirebase,
		FirebaseApp:     &firebase.App{},
		JWT:             &JWTAuthConfig{},
		GQLClient: testUtils.NewMockGraphQLClientQueries(map[string]string{
			`mutation InsertAccount($objects:[account_insert_input!]!){insert_account(objects: $objects){returning{id}}}`: `{
				"errors": [
					{
						"message": "Uniqueness violation. duplicate key value violates unique constraint \"account_email_unique\"",
						"extensions": {
							"path": "$.selectionSet.insert_account.args.objects",
							"code": "constraint-violation"
						}
					}
				]
			}`,
		}),
		AutoLinkProvider: true,
	})
	assert.NoError(t, err)

	_, err = am.createAccountFromToken(&Account{
		BaseAccount: BaseAccount{
			Email:       "test@example.local",
			PhoneCode:   1,
			PhoneNumber: "5555555555",
			DisplayName: "Test User",
			Role:        "user",
		},
	}, map[string]any{
		"disabled": map[string]any{
			"_eq": false,
		},
	}, map[string]any{
		"disabled": false,
	}, logger)
	assert.ErrorContains(t, err, "account_email_unique")

	_, err = am.createAccountFromToken(&Account{
		BaseAccount: BaseAccount{
			Email:       "test@example.local",
			PhoneCode:   1,
			PhoneNumber: "5555555555",
			DisplayName: "Test User",
			Role:        "user",
		},
		AccountProviders: []AccountProvider{
			{
				ProviderUserID: "1",
				Name:           "firebase",
			},
		},
	}, map[string]any{
		"disabled": map[string]any{
			"_eq": false,
		},
	}, map[string]any{
		"disabled": false,
	}, logger)
	assert.ErrorContains(t, err, "account_email_unique")

	am, err = NewAccountManager(AccountManagerConfig{
		DefaultProvider: AuthFirebase,
		FirebaseApp:     &firebase.App{},
		JWT:             &JWTAuthConfig{},
		GQLClient: testUtils.NewMockGraphQLClientQueries(map[string]string{
			`mutation InsertAccount($objects:[account_insert_input!]!){insert_account(objects: $objects){returning{id}}}`: `{
				"errors": [
					{
						"message": "Uniqueness violation. duplicate key value violates unique constraint \"account_phone_unique\"",
						"extensions": {
							"path": "$.selectionSet.insert_account.args.objects",
							"code": "constraint-violation"
						}
					}
				]
			}`,
			`query FindAccount($providerWhere:account_provider_bool_exp!$where:account_bool_exp!){account(where: $where, limit: 1){id,email,phone_code,phone_number,display_name,role,verified,email_enabled,phone_enabled,disabled},account_provider(where: $providerWhere, limit: 1){account_id,provider_name,provider_user_id,metadata}}`: `{
				"data": {
					"account": [{
						"id": "1"
					}],
					"account_provider": [{
						"account_id": "2",
						"provider_user_id": "test",
						"provider_name": "firebase"
					}]
				}
			}`,
			`mutation InsertAccountProvider($objects:[account_provider_insert_input!]!){insert_account_provider(objects: $objects, on_conflict: {constraint: account_provider_pkey, update_columns: []}){affected_rows}}`: `{
				"data": {
					"insert_account_provider": {
						"affected_rows": 0
					}
				}
			}`,
		}),
		AutoLinkProvider: true,
	})
	assert.NoError(t, err)

	_, err = am.createAccountFromToken(&Account{
		BaseAccount: BaseAccount{
			Email:       "test@example.local",
			PhoneCode:   1,
			PhoneNumber: "5555555555",
			DisplayName: "Test User",
			Role:        "user",
		},
		AccountProviders: []AccountProvider{
			{
				ProviderUserID: "1",
				Name:           "firebase",
			},
		},
	}, map[string]any{
		"disabled": map[string]any{
			"_eq": false,
		},
	}, map[string]any{
		"disabled": false,
	}, logger)
	assert.ErrorContains(t, err, "provider belongs to another account")
}

func TestAutoLinkProvider_success(t *testing.T) {
	logger := zerolog.Nop()
	am, err := NewAccountManager(AccountManagerConfig{
		DefaultProvider: AuthFirebase,
		FirebaseApp:     &firebase.App{},
		JWT:             &JWTAuthConfig{},
		GQLClient: testUtils.NewMockGraphQLClientQueries(map[string]string{
			`mutation InsertAccount($objects:[account_insert_input!]!){insert_account(objects: $objects){returning{id}}}`: `{
				"errors": [
					{
						"message": "Uniqueness violation. duplicate key value violates unique constraint \"account_phone_unique\"",
						"extensions": {
							"path": "$.selectionSet.insert_account.args.objects",
							"code": "constraint-violation"
						}
					}
				]
			}`,
			`query FindAccount($providerWhere:account_provider_bool_exp!$where:account_bool_exp!){account(where: $where, limit: 1){id,email,phone_code,phone_number,display_name,role,verified,email_enabled,phone_enabled,disabled},account_provider(where: $providerWhere, limit: 1){account_id,provider_name,provider_user_id,metadata}}`: `{
				"data": {
					"account": [{
						"id": "1"
					}],
					"account_provider": []
				}
			}`,
			`mutation InsertAccountProvider($objects:[account_provider_insert_input!]!){insert_account_provider(objects: $objects, on_conflict: {constraint: account_provider_pkey, update_columns: []}){affected_rows}}`: `{
				"data": {
					"insert_account_provider": {
						"affected_rows": 1
					}
				}
			}`,
		}),
		AutoLinkProvider: true,
	})
	assert.NoError(t, err)

	account := &Account{
		BaseAccount: BaseAccount{
			Email:       "test@example.local",
			PhoneCode:   1,
			PhoneNumber: "5555555555",
			DisplayName: "Test User",
			Role:        "user",
		},
		AccountProviders: []AccountProvider{
			{
				ProviderUserID: "1",
				Name:           "firebase",
			},
		},
	}
	result, err := am.createAccountFromToken(account, map[string]any{
		"disabled": map[string]any{
			"_eq": false,
		},
	}, map[string]any{
		"disabled": false,
	}, logger)
	assert.NoError(t, err)
	assert.Equal(t, account, result)

	am, err = NewAccountManager(AccountManagerConfig{
		DefaultProvider: AuthFirebase,
		FirebaseApp:     &firebase.App{},
		JWT:             &JWTAuthConfig{},
		GQLClient: testUtils.NewMockGraphQLClientQueries(map[string]string{
			`mutation InsertAccount($objects:[account_insert_input!]!){insert_account(objects: $objects){returning{id}}}`: `{
				"errors": [
					{
						"message": "Uniqueness violation. duplicate key value violates unique constraint \"account_phone_unique\"",
						"extensions": {
							"path": "$.selectionSet.insert_account.args.objects",
							"code": "constraint-violation"
						}
					}
				]
			}`,
			`query FindAccount($providerWhere:account_provider_bool_exp!$where:account_bool_exp!){account(where: $where, limit: 1){id,email,phone_code,phone_number,display_name,role,verified,email_enabled,phone_enabled,disabled},account_provider(where: $providerWhere, limit: 1){account_id,provider_name,provider_user_id,metadata}}`: `{
				"data": {
					"account": [{
						"id": "1"
					}],
					"account_provider": [{
						"account_id": "1",
						"provider_user_id": "test",
						"provider_name": "firebase"
					}]
				}
			}`,
			`mutation InsertAccountProvider($objects:[account_provider_insert_input!]!){insert_account_provider(objects: $objects, on_conflict: {constraint: account_provider_pkey, update_columns: []}){affected_rows}}`: `{
				"data": {
					"insert_account_provider": {
						"affected_rows": 0
					}
				}
			}`,
		}),
		AutoLinkProvider: true,
	})
	assert.NoError(t, err)

	_, err = am.createAccountFromToken(&Account{
		BaseAccount: BaseAccount{
			Email:       "test@example.local",
			PhoneCode:   1,
			PhoneNumber: "5555555555",
			DisplayName: "Test User",
			Role:        "user",
		},
		AccountProviders: []AccountProvider{
			{
				ProviderUserID: "1",
				Name:           "firebase",
			},
		},
	}, map[string]any{
		"disabled": map[string]any{
			"_eq": false,
		},
	}, map[string]any{
		"disabled": false,
	}, logger)
	assert.NoError(t, err)
}
