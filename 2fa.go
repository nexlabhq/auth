package auth

import (
	"context"
	"errors"
	"time"

	"github.com/hasura/go-graphql-client"
	gql "github.com/hasura/go-graphql-client"
)

// newActivity create an user activity model
func (am *AccountManager) newActivity(sessionVariables map[string]string, accountID string, activityType ActivityType, metadata map[string]interface{}) account_activity_insert_input {

	activity := map[string]interface{}{
		"type": activityType,
	}

	if accountID != "" {
		activity["account_id"] = accountID
	}
	if metadata != nil {
		activity["metadata"] = metadata
	}
	if sessionVariables != nil {
		if ip := getRequestIPFromSession(sessionVariables); ip != nil {
			activity["ip"] = *ip
		}
		if p, err := getPositionFromSession(sessionVariables); err == nil && p != nil {
			activity["position"] = p
		}
	}

	return activity
}

// CreateActivity insert an user activity record into the database
func (am *AccountManager) CreateActivity(sessionVariables map[string]string, accountID string, activityType ActivityType, metadata map[string]interface{}) error {

	var createActivityMutation struct {
		CreateActivity struct {
			AffectedRows int `graphql:"affected_rows"`
		} `graphql:"insert_account_activity(objects: $objects)"`
	}

	activity := am.newActivity(sessionVariables, accountID, activityType, metadata)

	variables := map[string]interface{}{
		"objects": []account_activity_insert_input{activity},
	}

	return am.gqlClient.Mutate(context.TODO(), &createActivityMutation, variables, graphql.OperationName("CreateAccountActivities"))
}

// Generate2FaOTP generate 2FA OTP to the logon user
func (am *AccountManager) Generate2FaOTP(sessionVariables map[string]string, accountID string, phoneCode int, phoneNumber string) OTPOutput {

	if !am.otp.Enabled {
		return OTPOutput{
			Error: ErrCodeUnsupported,
		}
	}

	if accountID == "" {
		return OTPOutput{
			Error: ErrCodeAccountNotFound,
		}
	}
	var query struct {
		Account []struct {
			ID           string `graphql:"id"`
			PhoneCode    int    `graphql:"phone_code"`
			PhoneNumber  string `graphql:"phone_number"`
			PhoneEnabled bool   `graphql:"phone_enabled"`
			Disabled     bool   `graphql:"disabled"`
			Activities   []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc })"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]interface{}{
				"_eq": accountID,
			},
		},
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-1*am.otp.TTL - time.Second),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityOTP2FA, ActivityOTP2FASuccess},
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountWithActivities"))
	if err != nil {
		return OTPOutput{
			Error: err.Error(),
		}
	}

	if len(query.Account) == 0 {
		return OTPOutput{
			Error: ErrCodeAccountNotFound,
		}
	}

	if query.Account[0].Disabled {
		return OTPOutput{
			Error: ErrCodeAccountDisabled,
		}
	}

	if query.Account[0].PhoneNumber == "" && phoneNumber == "" {
		return OTPOutput{
			Error: ErrCodePhoneRequired,
		}
	}

	// if the otp exists in the TTL range, skip sending new one
	for _, ac := range query.Account[0].Activities {
		if ac.Type == ActivityOTP2FASuccess {
			break
		} else if ac.Type == ActivityOTP2FA {
			return OTPOutput{
				Error: ErrCodeOTPAlreadySent,
			}
		}
	}

	shouldUpdatePhone := false
	pNumber := query.Account[0].PhoneNumber
	pCode := query.Account[0].PhoneCode
	if query.Account[0].PhoneNumber == "" || !query.Account[0].PhoneEnabled {
		shouldUpdatePhone = true
	}
	if phoneNumber != "" && phoneNumber != query.Account[0].PhoneNumber {
		shouldUpdatePhone = true
		pCode, pNumber, err = parseI18nPhoneNumber(phoneNumber, phoneCode)
		if err != nil {
			return OTPOutput{
				Error: ErrCodeInvalidPhone,
			}
		}
	}
	activity, otp, otpExpiry := am.newOTPActivity(sessionVariables, accountID, ActivityOTP2FA)

	if shouldUpdatePhone {
		var updateAccountMutation struct {
			UpdateAccount struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"id": graphql.String(accountID),
			"_set": UpdateAccountInput{
				PhoneCode:   &pCode,
				PhoneNumber: &pNumber,
			},
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	} else {
		var createActivityMutation struct {
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &createActivityMutation, updateVariables, graphql.OperationName("CreateActivity"))
		if err != nil {
			return OTPOutput{
				Error: err.Error(),
			}
		}
	}

	return OTPOutput{
		Code:   otp,
		Expiry: otpExpiry,
	}
}

// Verify2FaOTP verify 2FA OTP to the current user
func (am *AccountManager) Verify2FaOTP(sessionVariables map[string]string, accountID string, otp string, type2FA Auth2FAType) error {

	if !am.otp.Enabled {
		return errors.New(ErrCodeUnsupported)
	}

	if accountID == "" {
		return errors.New(ErrCodeAccountNotFound)
	}

	var query struct {
		Account []struct {
			ID           string `graphql:"id"`
			PhoneCode    int    `graphql:"phone_code"`
			PhoneNumber  string `graphql:"phone_number"`
			PhoneEnabled bool   `graphql:"phone_enabled"`
			Disabled     bool   `graphql:"disabled"`
			Activities   []struct {
				Type      ActivityType `graphql:"type"`
				CreatedAt time.Time    `graphql:"created_at"`
				Metadata  *struct {
					OTP string `json:"otp"`
				} `graphql:"metadata" scalar:"true" json:"metadata"`
			} `graphql:"activities(where: $activityWhere, order_by: { created_at: desc }, limit: 1)"`
			AccountProviders []AccountProvider `json:"account_providers" graphql:"account_providers(where: $providerWhere, limit: 1)"`
		} `graphql:"account(where: $where, limit: 1)"`
	}

	variables := map[string]interface{}{
		"where": account_bool_exp{
			"id": map[string]interface{}{
				"_eq": accountID,
			},
		},
		"activityWhere": account_activity_bool_exp{
			"created_at": map[string]interface{}{
				"_gte": time.Now().Add(-1*am.otp.TTL - time.Second),
			},
			"type": map[string]interface{}{
				"_in": []ActivityType{ActivityOTP2FA, ActivityOTP2FASuccess},
			},
		},
		"providerWhere": account_provider_bool_exp{
			"provider_name": map[string]interface{}{
				"_eq": am.GetProviderName(),
			},
		},
	}

	err := am.gqlClient.Query(context.Background(), &query, variables, gql.OperationName("FindAccountProviderWithActivities"))
	if err != nil {
		return err
	}

	if len(query.Account) == 0 {
		return errors.New(ErrCodeAccountNotFound)
	}

	if query.Account[0].Disabled {
		return errors.New(ErrCodeAccountDisabled)
	}

	if len(query.Account[0].AccountProviders) == 0 {
		return errors.New(ErrCodeAccountNoProvider)
	}

	if query.Account[0].PhoneNumber == "" && type2FA == Auth2FASms {
		return errors.New(ErrCodePhoneNotRegistered)
	}

	account := query.Account[0]
	if len(account.Activities) == 0 ||
		account.Activities[0].Type != ActivityOTP2FA ||
		account.Activities[0].Metadata == nil ||
		!(account.Activities[0].Metadata.OTP == otp || (am.otp.DevMode && am.otp.DevOTPCode == otp)) {
		return errors.New(ErrCodeInvalidOTP)
	}

	activity := am.newActivity(sessionVariables, accountID, ActivityOTP2FASuccess, nil)
	if type2FA == Auth2FASms && !account.PhoneEnabled {

		_, err = am.getCurrentProvider().UpdateUser(account.AccountProviders[0].ProviderUserID, UpdateAccountInput{
			PhoneCode:    &account.PhoneCode,
			PhoneNumber:  &account.PhoneNumber,
			PhoneEnabled: getPtr(true),
			Verified:     getPtr(true),
		})

		if err != nil {
			return err
		}

		var updateAccountMutation struct {
			UpdateAccount struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"update_account(where: { id: { _eq: $id } }, _set: $_set)"`
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"id": graphql.String(accountID),
			"_set": UpdateAccountInput{
				PhoneEnabled: getPtr(true),
			},
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &updateAccountMutation, updateVariables, graphql.OperationName("UpdateAccount"))
		if err != nil {
			return err
		}
	} else {
		var createActivityMutation struct {
			CreateActivity struct {
				AffectedRows int `graphql:"affected_rows"`
			} `graphql:"insert_account_activity(objects: $activities)"`
		}

		updateVariables := map[string]interface{}{
			"activities": []account_activity_insert_input{activity},
		}

		err = am.gqlClient.Mutate(context.TODO(), &createActivityMutation, updateVariables, graphql.OperationName("CreateActivity"))
		if err != nil {
			return err
		}
	}

	return nil
}
