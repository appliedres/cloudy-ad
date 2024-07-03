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

	err := gm.client.Connect()

	return err
}

func (gm *AdGroupManager) ListGroups(ctx context.Context) ([]*models.Group, error) {
	return nil, nil
}

// Get a specific group by id
func (gm *AdGroupManager) GetGroup(ctx context.Context, id string) (*models.Group, error) {
	return nil, nil
}

// Get a group id from name
func (gm *AdGroupManager) GetGroupId(ctx context.Context, name string) (string, error) {
	return "", nil
}

// Get all the groups for a single user
func (gm *AdGroupManager) GetUserGroups(ctx context.Context, uid string) ([]*models.Group, error) {
	return nil, nil
}

// Create a new Group
func (gm *AdGroupManager) NewGroup(ctx context.Context, grp *models.Group) (*models.Group, error) {
	err := gm.client.CreateGroup(gm.client.Config.Groups.SearchBase, cloudyToGroupAttributes(grp))
	return grp, err
}

// Update a group. This is generally just the name of the group.
func (gm *AdGroupManager) UpdateGroup(ctx context.Context, grp *models.Group) (bool, error) {
	return true, nil
}

// Get all the members of a group. This returns partial users only,
// typically just the user id, name and email fields
func (gm *AdGroupManager) GetGroupMembers(ctx context.Context, grpId string) ([]*models.User, error) {
	return nil, nil
}

// Remove members from a group
func (gm *AdGroupManager) RemoveMembers(ctx context.Context, groupId string, userIds []string) error {
	return nil
}

// Add member(s) to a group
func (gm *AdGroupManager) AddMembers(ctx context.Context, groupId string, userIds []string) error {
	return nil
}

func (gm *AdGroupManager) DeleteGroup(ctx context.Context, groupId string) error {
	return nil
}

func cloudyToGroupAttributes(grp *models.Group) []ldap.Attribute {
	objectClass := &ldap.Attribute{
		Type: "objectClass",
		Vals: []string{"top", "group"},
	}
	name := &ldap.Attribute{
		Type: "name",
		Vals: []string{grp.Name},
	}
	instanceType := &ldap.Attribute{
		Type: "instanceType",
		Vals: []string{fmt.Sprintf("%d", AC_INSTANCE_TYPE_WRITEABLE)},
	}
	groupType := &ldap.Attribute{
		Type: "groupType",
		Vals: []string{fmt.Sprintf("%d", ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP|ADS_GROUP_TYPE_SECURITY_ENABLED)},
	}
	attrs := []ldap.Attribute{}

	attrs = append(attrs, *objectClass)
	attrs = append(attrs, *name)
	attrs = append(attrs, *instanceType)
	attrs = append(attrs, *groupType)

	return attrs
}
