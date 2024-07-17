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
		address:     "ldap://10.1.128.254:389",
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

func TestCreateDisabledUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	usr := &models.User{
		DisplayName: "Test User",
		FirstName:   "Test",
		LastName:    "User",
		Email:       "test.user@abc.com",
	}
	newUsr, err := ad.NewUser(ctx, usr)
	assert.Nil(t, err)
	assert.NotNil(t, newUsr)

}
