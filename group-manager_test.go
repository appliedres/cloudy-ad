package cloudyad

import (
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initGroupManager() *AdGroupManager {
	cfg := &AdGroupManager{
		address:     "ldap://10.1.128.254:389",
		user:        "CN=TESTUSER,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US",
		pwd:         "Fr33b33r!!",
		base:        "DC=INT,DC=ARKLOUDDEMO,DC=US",
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
	assert.NotNil(t, err)

	grp, err := ad.GetGroup(ctx, "CN=TestGroup,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
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
	assert.NotNil(t, err)

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
	assert.NotNil(t, err)

	users := []string{}
	users = append(users, "william-flentje")

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
	assert.NotNil(t, err)

	users := []string{}
	users = append(users, "william-flentje")

	err = ad.RemoveMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)
}

func TestDeleteGroup(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.NotNil(t, err)

	err = ad.DeleteGroup(ctx, "CN=TestGroup,CN=USERS,DC=INT,DC=ARKLOUDDEMO,DC=US")
	assert.Nil(t, err)
}
