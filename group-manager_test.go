package cloudyad

import (
	"context"
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

func TestGetUserGroups(t *testing.T) {
	ad, ctx, err := initGroupManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	groups, err := ad.GetUserGroups(ctx, "dcarlet")
	assert.Nil(t, err)
	assert.NotNil(t, groups)
}

func TestGetGroupMembers(t *testing.T) {
	ad, ctx, err := initGroupManager()
	assert.Nil(t, err)
	assert.NotNil(t, ad)
	assert.NotNil(t, ctx)

	users, err := ad.GetGroupMembers(ctx, "Team 1")
	assert.Nil(t, err)
	assert.NotNil(t, users)
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

	grp, err = ad.GetGroup(ctx, "TestGroup")
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
	users = append(users, "krbtgt")

	err = ad.AddMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)

	usrs, err := ad.GetGroupMembers(ctx, "TestGroup")
	assert.NotNil(t, usrs)
	assert.Nil(t, err)

	grps1, err := ad.GetUserGroups(ctx, "krbtgt")
	assert.NotNil(t, grps1)
	assert.Equal(t, containsGroup1(grps1, "TestGroup"), true)
	assert.Nil(t, err)

	err = ad.RemoveMembers(ctx, "TestGroup", users)
	assert.Nil(t, err)

	grps1, err = ad.GetUserGroups(ctx, "krbtgt")
	assert.NotNil(t, grps1)
	assert.Equal(t, containsGroup1(grps1, "TestGroup"), false)
	assert.Nil(t, err)

	err = ad.DeleteGroup(ctx, "TestGroup")
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
