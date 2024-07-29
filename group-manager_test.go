package cloudyad

import (
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initGroupManager() *AdGroupManager {
	cfg := &AdGroupManager{
		address:     "ldaps://localhost:636",
		user:        "DEV-AD\\Administrator",
		pwd:         "admin123!",
		base:        "DC=ldap,DC=schneide,DC=dev",
		insecureTLS: true,
	}
	return cfg

}

func TestCreateGroup(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	newGrp := &models.Group{
		Name: "TestGroup",
	}

	grp, err := ad.NewGroup(ctx, newGrp)
	assert.NotNil(t, grp)
	assert.Nil(t, err)
}

func TestGetGroup(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	grp, err := ad.GetGroup(ctx, "CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")
	assert.NotNil(t, grp)
	assert.Nil(t, err)
}

func TestGetGroupId(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	grp, err := ad.GetGroupId(ctx, "TestGroup")
	assert.NotNil(t, grp)
	assert.Nil(t, err)
}

func TestAddGroupMembers(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	users := []string{}
	users = append(users, "test-user")

	err = ad.AddMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)
}

func TestRemoveGroupMembers(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	users := []string{}
	users = append(users, "test-user")

	err = ad.RemoveMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)
}

func TestGetGroupMembers(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	users, err := ad.GetGroupMembers(ctx, "CN=TestGroup,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.NotNil(t, users)
	assert.Nil(t, err)
}

func TestDeleteGroup(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	err = ad.DeleteGroup(ctx, "CN=TestGroup,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.Nil(t, err)
}
