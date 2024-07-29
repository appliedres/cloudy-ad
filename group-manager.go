package cloudyad

import (
	"context"
	"fmt"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/go-ldap/ldap/v3"

	"github.com/appliedres/adc"
)

func init() {
	cloudy.GroupProviders.Register(ActiveDirectory, &AdGroupManagerFactory{})
}

type AdGroupManagerFactory struct{}

func (gmf *AdGroupManagerFactory) Create(cfg interface{}) (cloudy.GroupManager, error) {
	return cfg.(*AdGroupManager), nil
}

func (gmf *AdGroupManagerFactory) FromEnv(env *cloudy.Environment) (interface{}, error) {
	cfg := NewAdGroupManagerFromEnv(context.Background(), env)
	return cfg, nil
}

/// ------------- GROUP MANAGER

type AdGroupManager struct {
	address     string
	user        string
	pwd         string
	base        string
	insecureTLS bool
	client      *adc.Client
}

func NewAdGroupManager(cfg *AdGroupManager) *AdGroupManager {
	cl := adc.New(&adc.Config{
		URL:         cfg.address,
		InsecureTLS: cfg.insecureTLS,
		SearchBase:  cfg.base,
		Users: &adc.UsersConfigs{
			SearchBase: fmt.Sprintf("CN=Users,%v", cfg.base),
		},
		Groups: &adc.GroupsConfigs{
			SearchBase: fmt.Sprintf("CN=Users,%v", cfg.base),
		},
		Bind: &adc.BindAccount{
			DN:       cfg.user,
			Password: cfg.pwd,
		},
	})

	cfg.client = cl
	return cfg
}

func NewAdGroupManagerFromEnv(ctx context.Context, env *cloudy.Environment) *AdGroupManager {
	cfg := &AdGroupManager{
		address:     env.Force("AD_HOST"),
		user:        env.Force("AD_USER"),
		pwd:         env.Force("AD_PWD"),
		base:        env.Force("AD_BASE"),
		insecureTLS: false,
	}

	return NewAdGroupManager(cfg)
}

func (gm *AdGroupManager) connect(ctx context.Context) error {
	_ = ctx
	return gm.client.Connect()
}

func (gm *AdGroupManager) ListGroups(ctx context.Context) ([]*models.Group, error) {
	return nil, nil
}

// Get a specific group by id
func (gm *AdGroupManager) GetGroup(ctx context.Context, id string) (*models.Group, error) {
	grp, err := gm.client.GetGroup(adc.GetGroupArgs{
		Dn: id,
	})
	if err != nil {
		return nil, err
	}
	if grp == nil {
		return nil, nil
	}

	return groupAttributesToCloudy(grp), err
}

// Get a group id from name
func (gm *AdGroupManager) GetGroupId(ctx context.Context, name string) (string, error) {
	args := adc.GetGroupArgs{
		Id: name,
	}
	grp, err := gm.client.GetGroup(args)
	return grp.DN, err
}

// Get all the groups for a single user
func (gm *AdGroupManager) GetUserGroups(ctx context.Context, uid string) ([]*models.Group, error) {
	return nil, nil
}

// Create a new Group
func (gm *AdGroupManager) NewGroup(ctx context.Context, grp *models.Group) (*models.Group, error) {
	grp.ID = "CN=" + grp.Name + "," + gm.client.Config.Groups.SearchBase
	err := gm.client.CreateGroup(grp.ID, cloudyToGroupAttributes(grp))
	return grp, err
}

// Update a group. This is generally just the name of the group.
func (gm *AdGroupManager) UpdateGroup(ctx context.Context, grp *models.Group) (bool, error) {
	return true, nil
}

// Get all the members of a group. This returns partial users only,
// typically just the user id, name and email fields
func (gm *AdGroupManager) GetGroupMembers(ctx context.Context, grpId string) ([]*models.User, error) {
	grp, err := gm.client.GetGroup(adc.GetGroupArgs{
		Dn: grpId,
	})
	if err != nil {
		return nil, err
	}
	if grp == nil {
		return nil, nil
	}
	users := []*models.User{}
	for _, user := range grp.Members {
		usr := &models.User{
			UID:      user.DN,
			Username: user.Id,
		}
		users = append(users, usr)
	}
	return users, nil
}

// Remove members from a group
func (gm *AdGroupManager) RemoveMembers(ctx context.Context, groupName string, userNames []string) error {
	_, err := gm.client.DeleteGroupMembers(groupName, userNames...)
	return err
}

// Add member(s) to a group
func (gm *AdGroupManager) AddMembers(ctx context.Context, groupName string, userNames []string) error {
	_, err := gm.client.AddGroupMembers(groupName, userNames...)
	return err
}

func (gm *AdGroupManager) DeleteGroup(ctx context.Context, groupId string) error {
	return gm.client.DeleteGroup(groupId)
}

func groupAttributesToCloudy(adc *adc.Group) *models.Group {
	grp := &models.Group{
		ID:   adc.DN,
		Name: adc.Id,
	}
	return grp
}

func cloudyToGroupAttributes(grp *models.Group) []ldap.Attribute {
	attrs := []ldap.Attribute{}

	attrs = append(attrs, ldap.Attribute{
		Type: OBJ_CLASS_TYPE,
		Vals: GROUP_OBJ_CLASS_VALS,
	})
	attrs = append(attrs, ldap.Attribute{
		Type: GROUP_NAME_TYPE,
		Vals: []string{grp.Name},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: SAM_ACCT_NAME_TYPE,
		Vals: []string{grp.Name},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: INSTANCE_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_INSTANCE_TYPE_WRITEABLE)},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: GROUP_TYPE,
		Vals: []string{fmt.Sprintf("%d", ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP|ADS_GROUP_TYPE_SECURITY_ENABLED)},
	})

	return attrs
}
