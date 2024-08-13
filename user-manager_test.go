package cloudyad

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initUserManager() (*AdUserManager, context.Context, error) {
	cfg := &AdUserManagerConfig{
		Address:     "ldaps://localhost:636",
		User:        "DEV-AD\\Administrator",
		Pwd:         "admin123!",
		Base:        "DC=ldap,DC=schneide,DC=dev",
		InsecureTLS: true,
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

	user, err := ad.GetUser(ctx, base64.URLEncoding.EncodeToString([]byte("CN=jane-doe,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.Nil(t, err)
	assert.NotNil(t, user)
}

func TestListUsers(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	users, err := ad.ListUsers(ctx, "", nil)
	assert.Nil(t, err)
	assert.NotNil(t, users)
}

func TestGetUserByUserName(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	user, err := ad.GetUserByUserName(ctx, "jane-doe")
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
		Email:       "jane.doe@us.af.mil",
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

	err = ad.Enable(ctx, base64.URLEncoding.EncodeToString([]byte("CN=jane-doe,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.Nil(t, err)
}

func TestDisableUser(t *testing.T) {
	ad, ctx, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	err = ad.Disable(ctx, base64.URLEncoding.EncodeToString([]byte("CN=jane-doe,CN=Users,DC=ldap,DC=schneide,DC=dev")))
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
		UID:         base64.URLEncoding.EncodeToString([]byte("CN=jane-doe,CN=Users,DC=ldap,DC=schneide,DC=dev")),
		Username:    "jane-doe",
		FirstName:   "jane2",
		LastName:    "doe2",
		DisplayName: "jane2 doe2",
		Email:       "jane.doe@us.af.mil",
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

	err = ad.DeleteUser(ctx, base64.URLEncoding.EncodeToString([]byte("CN=jane-doe,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.Nil(t, err)
}
