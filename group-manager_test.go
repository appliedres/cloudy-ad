package cloudyad

import (
	"encoding/base64"
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

func TestGetGroupNoExplicitConnect(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	grp, err := ad.GetGroup(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.NotNil(t, grp)
	assert.Nil(t, err)
}

func TestGetGroupsByUser(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	grps, err := ad.GetUserGroups(ctx, base64.URLEncoding.EncodeToString([]byte("CN=jane-doe,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.NotNil(t, grps)
	assert.Nil(t, err)
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

	grp, err := ad.GetGroup(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.NotNil(t, grp)
	assert.Nil(t, err)
}

func TestListGroups(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()
	err := ad.connect(ctx)
	assert.Nil(t, err)

	grp, err := ad.ListGroups(ctx, "", nil)
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
	users = append(users, "jane-doe")

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
	users = append(users, "jane-doe")

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

	users, err := ad.GetGroupMembers(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
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

	err = ad.DeleteGroup(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.Nil(t, err)
}
