package cloudyad

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initGroupManager() (*AdGroupManager, context.Context, error) {
	cfg := CreateGroupADTestContainer()

	ad := NewAdGroupManager(cfg)
	ctx := cloudy.StartContext()
	err := ad.connect(ctx)

	return ad, ctx, err

}

func TestCloudyADGroupMgr(t *testing.T) {
	ad, ctx, err := initGroupManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	newGrp := &models.Group{
		Name: "TestGroup",
	}

	grp, err := ad.NewGroup(ctx, newGrp)
	assert.NotNil(t, grp)
	assert.Nil(t, err)

	grp, err = ad.GetGroup(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.NotNil(t, grp)
	assert.Nil(t, err)

	id, err := ad.GetGroupId(ctx, "TestGroup")
	assert.NotNil(t, id)
	assert.Nil(t, err)

	grps, err := ad.ListGroups(ctx, "", nil)
	assert.NotNil(t, grps)
	assert.Equal(t, containsGroup(grps, "TestGroup"), true)
	assert.Nil(t, err)

	users := []string{}
	users = append(users, base64.URLEncoding.EncodeToString([]byte("krbtgt")))

	err = ad.AddMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)

	usrs, err := ad.GetGroupMembers(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.NotNil(t, usrs)
	assert.Equal(t, containsUser(usrs, base64.URLEncoding.EncodeToString([]byte("CN=krbtgt,CN=Users,DC=ldap,DC=schneide,DC=dev"))), true)
	assert.Nil(t, err)

	grps1, err := ad.GetUserGroups(ctx, "Q049a3JidGd0LENOPVVzZXJzLERDPWxkYXAsREM9c2NobmVpZGUsREM9ZGV2")
	assert.NotNil(t, grps1)
	assert.Equal(t, containsGroup1(grps1, "TestGroup"), true)
	assert.Nil(t, err)

	err = ad.RemoveMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)

	grps1, err = ad.GetUserGroups(ctx, "Q049a3JidGd0LENOPVVzZXJzLERDPWxkYXAsREM9c2NobmVpZGUsREM9ZGV2")
	assert.NotNil(t, grps1)
	assert.Equal(t, containsGroup1(grps1, "TestGroup"), false)
	assert.Nil(t, err)

	err = ad.DeleteGroup(ctx, base64.URLEncoding.EncodeToString([]byte("CN=TestGroup,CN=Users,DC=ldap,DC=schneide,DC=dev")))
	assert.Nil(t, err)
}

func containsGroup(groups *[]models.Group, name string) bool {
	for _, grp := range *groups {
		if grp.Name == name {
			return true
		}
	}
	return false
}

func containsGroup1(groups []*models.Group, name string) bool {
	for _, grp := range groups {
		if grp.Name == name {
			return true
		}
	}
	return false
}

func containsUser(users []*models.User, uid string) bool {
	for _, user := range users {
		if user.UID == uid {
			return true
		}
	}
	return false
}
