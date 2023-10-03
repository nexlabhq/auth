package auth

import (
	"context"
	"errors"
	"time"

	"github.com/hasura/go-graphql-client"
	gql "github.com/hasura/go-graphql-client"
)

// GenerateOTP check if the account exists and generate the authentication otp
func (am *AccountManager) GenerateOTP(sessionVariables map[string]string, input GenerateOTPInput) OTPOutput {

	if !am.otp.Enabled {
		return OTPOutput{
			Error: ErrCodeUnsupported,
		}
	}

	if input.PhoneNumber == "" {
		return OTPOutput{
			Error: ErrCodePhoneRequired,
		}
	}

	phoneCode, phoneNumber, err := parseI18nPhoneNumber(input.PhoneNumber, input.PhoneCode)
	if err != nil {
		return OTPOutput{
			Error: ErrCodeInvalidPhone,
		}
	}

	var query struct {
		Account []struct {
			ID         string `graphql:"id"`
			Disabled   bool   `graphql:"disabled"`
			Activities []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc }, limit: $activityLimit)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp(
			mergeMap(map[string]any{
				"phone_code": map[string]interface{}{
					"_eq": phoneCode,
				},
				"phone_number": map[string]interface{}{
					"_eq": phoneNumber,
				},
				"phone_enabled": map[string]interface{}{
					"_eq": true,
				},
			}, input.ExtraConditions),
		),
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-1 * time.Hour),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityLogin, ActivityOTP, ActivityOTPFailure, ActivityLogout},
			},
		},
		"activityLimit": graphql.Int(am.otp.LoginDisableLimit),
	}

	err = am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountWithActivities"))
	if err != nil {
		return OTPOutput{
			Error: err.Error(),
		}
	}

	activity, otp, otpExpiry := am.newOTPActivity(sessionVariables, "", ActivityOTP)

	var accountID string
	if len(query.Account) == 0 {
		// create the account if it doesn't exist
		accountID, err = am.InsertAccount(mergeMap(map[string]any{
			"id":            genID(),
			"phone_code":    phoneCode,
			"phone_number":  phoneNumber,
			"phone_enabled": true,
			"role":          am.defaultRole,
			"activities": map[string]interface{}{
				"data": []map[string]interface{}{activity},
			},
		}, input.ExtraInputs))

		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	} else {
		account := query.Account[0]
		accountID = account.ID
		if account.Disabled {
			return OTPOutput{
				Error: ErrCodeAccountDisabled,
			}
		}

		var otpTime time.Time
		var failureLatestTime time.Time
		failureCount := 0

		for _, act := range account.Activities {
			if act.Type == ActivityOTP {
				otpTime = act.CreatedAt
			} else if act.Type == ActivityLogin || act.Type == ActivityLogout {
				break
			} else {
				if failureLatestTime.IsZero() {
					failureLatestTime = act.CreatedAt
				}
				failureCount++
			}
		}

		if failureCount > int(am.otp.LoginDisableLimit) {
			return OTPOutput{
				Error: ErrCodeAccountDisabled,
			}
		}

		now := time.Now()
		lockedRemain := failureLatestTime.Add(am.otp.LoginLockDuration).Sub(now)
		if failureCount >= int(am.otp.LoginLimit) && lockedRemain > 0 {
			return OTPOutput{
				Error:          ErrCodeAccountTemporarilyLocked,
				LockedDuration: uint(lockedRemain.Seconds()),
			}
		}

		if otpTime.Add(am.otp.TTL).After(now) {
			return OTPOutput{
				Error: ErrCodeOTPAlreadySent,
			}
		}

		// otherwise validate the account and insert the activity
		var createActivityMutation struct {
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $objects)"`
		}

		activity["account_id"] = account.ID
		variables := map[string]interface{}{
			"objects": []account_activity_insert_input{activity},
		}
		err = am.gqlClient.Mutate(context.TODO(), &createActivityMutation, variables, graphql.OperationName("CreateAccountActivities"))
		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	}

	return OTPOutput{
		Code:      otp,
		Expiry:    otpExpiry,
		AccountID: accountID,
	}
}

// VerifyOTP verify if the otp code matches the current account
func (am *AccountManager) VerifyOTP(sessionVariables map[string]string, input VerifyOTPInput) (*Account, error) {

	if !am.otp.Enabled {
		return nil, errors.New(ErrCodeUnsupported)
	}

	if input.PhoneNumber == "" {
		return nil, errors.New(ErrCodePhoneRequired)
	}

	var err error
	phoneCode, phoneNumber, err := parseI18nPhoneNumber(input.PhoneNumber, input.PhoneCode)
	if err != nil {
		return nil, errors.New(ErrCodeInvalidPhone)
	}

	var accountQuery struct {
		Accounts []struct {
			BaseAccount
			Activities []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
				Metadata  *struct {
					OTP string `json:"otp"`
				} `graphql:"metadata" scalar:"true" json:"metadata"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc }, limit: $activityLimit)"`
			AccountProviders []AccountProvider `json:"account_providers" graphql:"account_providers(where: $providerWhere, limit: 1)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	providerNames := []AuthProviderType{am.GetProviderName()}
	if am.GetProviderName() == AuthFirebase {
		providerNames = append(providerNames, AuthJWT)
	}
	variables := map[string]any{
		"where": account_bool_exp(mergeMap(map[string]any{
			"phone_code": map[string]interface{}{
				"_eq": phoneCode,
			},
			"phone_number": map[string]interface{}{
				"_eq": phoneNumber,
			},
			"phone_enabled": map[string]interface{}{
				"_eq": true,
			},
		}, input.ExtraConditions)),
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-time.Hour),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityOTP, ActivityLogin, ActivityLogout, ActivityOTPFailure},
			},
		},
		"activityLimit": graphql.Int(am.otp.LoginDisableLimit + 1),
		"providerWhere": account_provider_bool_exp{
			"provider_name": map[string]interface{}{
				"_in": providerNames,
			},
		},
	}

	err = am.gqlClient.Query(context.TODO(), &accountQuery, variables, graphql.OperationName("FindAccountWithActivities"))

	if err != nil {
		return nil, err
	}

	if len(accountQuery.Accounts) == 0 {
		return nil, errors.New(ErrCodeAccountNotFound)
	}

	if accountQuery.Accounts[0].Disabled {
		return nil, errors.New(ErrCodeAccountDisabled)
	}

	if len(accountQuery.Accounts[0].Activities) == 0 {
		return nil, errors.New(ErrCodeInvalidOTP)
	}

	account := accountQuery.Accounts[0]
	var testAccountCode string
	for _, provider := range account.AccountProviders {
		if provider.Metadata != nil {
			if anyCode, ok := provider.Metadata[OTPTestCodeName]; ok {
				if code, ok := anyCode.(string); ok && code != "" {
					testAccountCode = code
				}
			}
		}
	}

	// static otp code check in dev mode
	if !(am.otp.DevMode && input.OTP == am.otp.DevOTPCode) && !(testAccountCode != "" && input.OTP == testAccountCode) {
		otpActivityIndex := -1
		for i, activity := range account.Activities {
			if activity.Type == ActivityLogin || activity.Type == ActivityLogout {
				break
			} else if activity.Type == ActivityOTP {
				otpActivityIndex = i
				break
			}
		}
		if otpActivityIndex < 0 || (account.Activities[otpActivityIndex].CreatedAt.Add(am.otp.TTL).Before(time.Now())) ||
			(account.Activities[otpActivityIndex].Metadata != nil && account.Activities[otpActivityIndex].Metadata.OTP != input.OTP) {

			_ = am.CreateActivity(sessionVariables, account.ID, ActivityOTPFailure, nil)
			if otpActivityIndex+1 > int(am.otp.LoginDisableLimit) {
				// disable the user if the failure count exceed limit
				var updateAccountMutation struct {
					UpdateAccount struct {
						AffectedRows int `graphql:"affected_rows"`
					} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
				}

				updateVariables := map[string]interface{}{
					"id": graphql.String(account.ID),
					"_set": UpdateAccountInput{
						Disabled: getPtr(true),
					},
				}

				_ = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
			}
			return nil, errors.New(ErrCodeInvalidOTP)
		}
	}

	// insert account provider if not exist
	if len(account.AccountProviders) == 0 {
		acc, err := am.getCurrentProvider().GetOrCreateUserByPhone(&CreateAccountInput{
			ID:          &account.ID,
			PhoneCode:   &input.PhoneCode,
			PhoneNumber: &input.PhoneNumber,
		})
		if err != nil {
			return nil, err
		}

		accProvider := AccountProvider{
			Name:           acc.AccountProviders[0].Name,
			ProviderUserID: acc.AccountProviders[0].ProviderUserID,
			AccountID:      &account.ID,
			Metadata:       acc.AccountProviders[0].Metadata,
		}
		err = am.CreateProvider(accProvider)
		if err != nil {
			return nil, err
		}

		account.AccountProviders = []AccountProvider{accProvider}
	}

	var updateAccountMutation struct {
		UpdateAccount struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
		CreateActivity struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"insert_account_activity(objects: $activities)"`
	}

	activity := map[string]interface{}{
		"account_id": account.ID,
		"type":       ActivityLogin,
	}

	if sessionVariables != nil {
		if ip := getRequestIPFromSession(sessionVariables); ip != nil {
			activity["ip"] = *ip
		}
		if p, err := getPositionFromSession(sessionVariables); err == nil && p != nil {
			activity["position"] = p
		}
	}

	updateVariables := map[string]interface{}{
		"id": graphql.String(account.ID),
		"_set": UpdateAccountInput{
			Verified: getPtr(true),
		},
		"activities": []account_activity_insert_input{activity},
	}

	err = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
	if err != nil {
		return nil, err
	}

	return &Account{
		BaseAccount:      account.BaseAccount,
		AccountProviders: filterProvidersByType(account.AccountProviders, am.providerType),
	}, nil
}

func (am *AccountManager) newOTPActivity(sessionVariables map[string]string, accountID string, activityType ActivityType) (account_activity_insert_input, string, time.Time) {
	otp := genRandomString(int(am.otp.OTPLength), digits)
	otpExpiry := time.Now().Add(am.otp.TTL)

	return am.newActivity(sessionVariables, accountID, activityType, map[string]interface{}{
		"otp": otp,
	}), otp, otpExpiry
}
