package cloudyad

import (
	"context"
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initUserManager() (*AdUserManager, context.Context, error) {
	cfg := &AdUserManager{
		address:     "ldaps://10.1.128.254:636",
		user:        "CN=test-user,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US",
		pwd:         "Fr33b33r!",
		base:        "DC=INT,DC=ARKLOUDDEMO,DC=US",
		insecureTLS: true,
	}

	ad := NewAdUserManager(cfg)
	ctx := cloudy.StartContext()
	err := ad.connect(ctx)

	return ad, ctx, err
}

func TestGetUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	user, err := ad.GetUser(ctx, "CN=test-user,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.Nil(t, err)
	assert.NotNil(t, user)
}

func TestGetUserByEmail(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	user, err := ad.GetUserByEmail(ctx, "jane.doe@us.af.mil", &cloudy.UserOptions{IncludeLastSignIn: cloudy.BoolP(true)})
	assert.Nil(t, err)
	assert.NotNil(t, user)
}

func TestGetUserWithAttributes(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	attrs := []string{"sAMAccountName", "telephoneNumber", "primaryGroupId"}
	user, err := ad.GetUserWithAttributes(ctx, "jane.doe@us.af.mil", attrs)
	assert.Nil(t, err)
	assert.NotNil(t, user)
}

func TestCreateDisabledUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	usr := &models.User{
		DisplayName: "Jane Doe",
		FirstName:   "Jane",
		LastName:    "Doe",
		Email:       "jane.doe@abc.com",
	}
	newUsr, err := ad.NewUser(ctx, usr)
	assert.Nil(t, err)
	assert.NotNil(t, newUsr)
}

func TestEnableUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	err = ad.Enable(ctx, "CN=test-user,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.Nil(t, err)
}

func TestDisableUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	err = ad.Disable(ctx, "CN=test-user,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.Nil(t, err)
}

func TestUpdateUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	m := make(map[string]string)
	m["telephoneNumber"] = "800-555-1212"
	user := &models.User{
		UID:         "CN=test-user,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US",
		Username:    "test-user",
		FirstName:   "test",
		LastName:    "user1",
		DisplayName: "test user1",
		Attributes:  m,
	}
	err = ad.UpdateUser(ctx, user)
	assert.Nil(t, err)
}

func TestDeleteUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	err = ad.DeleteUser(ctx, "CN=test-user,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.Nil(t, err)
}
