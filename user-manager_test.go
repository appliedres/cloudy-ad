package cloudyad

import (
	"context"
	"testing"
	"time"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initUserManager() (*AdUserManager, context.Context, error) {
	cfg := CreateUserADTestContainer()

	ad := NewAdUserManager(cfg)
	ctx := cloudy.StartContext()
	err := ad.connect(ctx)

	return ad, ctx, err
}

func TestCloudyADUserMgr(t *testing.T) {
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
	assert.Equal(t, newUsr.FirstName, "Jane")
	assert.Equal(t, newUsr.Enabled, false)

	time.Sleep(2 * time.Second)

	err = ad.Enable(ctx, "jane-doe")
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)

	user, err := ad.GetUser(ctx, "jane-doe")
	assert.Nil(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, user.FirstName, "Jane")
	assert.Equal(t, user.Enabled, true)

	user, err = ad.GetUserByEmail(ctx, "jane.doe@us.af.mil", &cloudy.UserOptions{IncludeLastSignIn: cloudy.BoolP(true)})
	assert.Nil(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, user.FirstName, "Jane")

	m := make(map[string]string)
	m["telephoneNumber"] = "800-555-1212"
	user = &models.User{
		UID:         "jane-doe",
		Username:    "jane-doe",
		FirstName:   "jane2",
		LastName:    "doe2",
		DisplayName: "jane2 doe2",
		Email:       "jane.doe@us.af.mil",
		Attributes:  m,
	}
	err = ad.UpdateUser(ctx, user)
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)

	err = ad.SetUserPassword(ctx, user.UID, "W!SjA-as44", true)
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)

	attrs := []string{SAM_ACCT_NAME_TYPE, "telephoneNumber", "primaryGroupId", PASSWORD_LAST_SET}
	user, err = ad.GetUserWithAttributes(ctx, "jane-doe", attrs)
	assert.Nil(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, user.FirstName, "jane2")
	assert.Equal(t, user.Attributes["telephoneNumber"], "800-555-1212")
	assert.Equal(t, user.Attributes[PASSWORD_LAST_SET], "0")

	err = ad.Disable(ctx, "jane-doe")
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)

	user, err = ad.GetUserByUserName(ctx, "jane-doe")
	assert.Nil(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, user.FirstName, "jane2")
	assert.Equal(t, user.Enabled, false)

	users, err := ad.ListUsers(ctx, "", nil)
	assert.Nil(t, err)
	assert.NotNil(t, users)

	err = ad.DeleteUser(ctx, "jane-doe")
	assert.Nil(t, err)

}
