package cloudyad

import (
	"context"
	"fmt"
	"strconv"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/go-ldap/ldap/v3"

	"github.com/appliedres/adc"
)

func init() {
	cloudy.GroupProviders.Register(ACTIVE_DIRECTORY, &AdGroupManagerFactory{})
}

type AdGroupManagerFactory struct{}

func (gmf *AdGroupManagerFactory) Create(cfg interface{}) (cloudy.GroupManager, error) {
	return cfg.(*AdGroupManager), nil
}

func (gmf *AdGroupManagerFactory) FromEnv(env *cloudy.Environment) (interface{}, error) {
	cfg := NewAdGroupManagerFromEnv(context.Background(), env)
	return cfg, nil
}

type AdGroupManagerConfig struct {
	Address         string
	User            string
	Pwd             string
	Base            string
	UserBase        string
	GroupBase       string
	Domain          string
	InsecureTLS     string
	UserIdAttribute string
	PageSize        int
}

type AdGroupManager struct {
	cfg    AdGroupManagerConfig
	client *adc.Client
}

func NewAdGroupManager(cfg *AdGroupManagerConfig) *AdGroupManager {
	insecureTLS, err := strconv.ParseBool(cfg.InsecureTLS)
	if err != nil {
		insecureTLS = false
	}

	if cfg.UserIdAttribute == "" {
		cfg.UserIdAttribute = USERNAME_TYPE
	}

	if cfg.PageSize <= 0 {
		cfg.PageSize = PAGE_SIZE
	}

	cl := adc.New(&adc.Config{
		URL:         cfg.Address,
		InsecureTLS: insecureTLS,
		SearchBase:  cfg.Base,
		Users: &adc.UsersConfigs{
			SearchBase:  cfg.Base,
			IdAttribute: cfg.UserIdAttribute,
			Attributes:  USER_STANDARD_ATTRS,
		},
		Groups: &adc.GroupsConfigs{
			SearchBase:  cfg.Base,
			IdAttribute: cfg.UserIdAttribute,
			Attributes:  GROUP_STANDARD_ATTRS,
		},
		Bind: &adc.BindAccount{
			DN:       cfg.User,
			Password: cfg.Pwd,
		},
	})

	ad := &AdGroupManager{
		client: cl,
		cfg:    *cfg,
	}

	ad.client = cl
	return ad
}

func NewAdGroupManagerFromEnv(ctx context.Context, env *cloudy.Environment) *AdGroupManager {
	pageSize, err := strconv.ParseInt(env.Force("AD_PAGE_SIZE"), 10, 32)
	if err != nil {
		pageSize = PAGE_SIZE
	}

	cfg := &AdGroupManagerConfig{
		Address:         env.Force("AD_HOST"),
		User:            env.Force("AD_USER"),
		Pwd:             env.Force("AD_PWD"),
		Base:            env.Force("AD_BASE"),
		GroupBase:       env.Force("AD_GROUP_BASE"),
		UserBase:        env.Force("AD_USER_BASE"),
		Domain:          env.Force("AD_DOMAIN"),
		InsecureTLS:     env.Force("AD_INSECURE_TLS"),
		UserIdAttribute: env.Force("AD_USER_ID_ATTRIBUTE"),
		PageSize:        int(pageSize),
	}

	return NewAdGroupManager(cfg)
}

func (gm *AdGroupManager) connect(ctx context.Context) error {
	_ = ctx
	return gm.client.Connect()
}

func (um *AdGroupManager) reconnect(ctx context.Context) error {
	err := um.client.Reconnect(ctx, TICKER_DURATION, MAX_ATTEMPTS)

	return err
}

func (um *AdGroupManager) connectAsNeeded(ctx context.Context) error {
	var err error
	if !um.client.ConnectedStatus() {
		err = um.connect(ctx)
	} else {
		err = um.reconnect(ctx)
	}
	return err
}

func (gm *AdGroupManager) ListGroups(ctx context.Context, filter string, attrs []string) (*[]models.Group, error) {
	var args adc.GetGroupArgs

	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	args.Attributes = append(attrs, GROUP_STANDARD_ATTRS...)
	grps, err := gm.client.ListGroups(args, gm.cfg.PageSize, filter)
	if err != nil {
		return nil, err
	}
	if grps == nil {
		return nil, nil
	}

	var results []models.Group
	for _, grp := range *grps {
		results = append(results, *groupAttributesToCloudy(&grp))
	}
	return &results, nil
}

// Get a specific group by id
func (gm *AdGroupManager) GetGroup(ctx context.Context, id string) (*models.Group, error) {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	grp, err := gm.client.GetGroup(adc.GetGroupArgs{
		Dn: gm.buildGroupDN(id),
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
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return "", err
	}

	args := adc.GetGroupArgs{
		Id: name,
	}
	grp, err := gm.client.GetGroup(args)
	return grp.DN, err
}

// Get all the groups for a single user
func (gm *AdGroupManager) GetUserGroups(ctx context.Context, uid string) ([]*models.Group, error) {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	user, err := gm.client.GetUser(adc.GetUserArgs{
		Id:               uid,
		SkipGroupsSearch: false,
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	var groups []*models.Group
	for _, group := range user.Groups {
		grp, err := gm.client.GetGroup(adc.GetGroupArgs{
			Id: group.Id,
		})
		if err != nil {
			continue
		}
		if grp == nil {
			continue
		}

		groups = append(groups, groupAttributesToCloudy(grp))
	}

	return groups, nil
}

// Create a new Group
func (gm *AdGroupManager) NewGroup(ctx context.Context, grp *models.Group) (*models.Group, error) {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	err = gm.client.CreateGroup(gm.buildGroupDN(grp.Name), *cloudyToGroupAttributes(grp))
	if err != nil {
		return nil, err
	}

	group, err := gm.client.GetGroup(adc.GetGroupArgs{
		Dn: gm.buildGroupDN(grp.Name),
	})
	if err != nil || group == nil {
		return nil, err
	}
	return groupAttributesToCloudy(group), err
}

// This is only a rename of the group.
func (gm *AdGroupManager) UpdateGroup(ctx context.Context, grp *models.Group) (bool, error) {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return false, err
	}

	err = gm.client.RenameGroup(grp.Source, "CN="+grp.Name)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Get all the members of a group. This returns partial users only,
// typically just the user id, name and email fields
func (gm *AdGroupManager) GetGroupMembers(ctx context.Context, name string) ([]*models.User, error) {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	grp, err := gm.client.GetGroup(adc.GetGroupArgs{
		Id: name,
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
			Username: user.Id,
			UID:      user.DN,
		}
		users = append(users, usr)
	}
	return users, nil
}

// Remove members from a group
func (gm *AdGroupManager) RemoveMembers(ctx context.Context, groupName string, userNames []string) error {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	_, err = gm.client.DeleteGroupMembers(groupName, userNames...)
	return err
}

// Add member(s) to a group
func (gm *AdGroupManager) AddMembers(ctx context.Context, groupName string, userNames []string) error {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	_, err = gm.client.AddGroupMembers(groupName, userNames...)
	return err
}

func (gm *AdGroupManager) DeleteGroup(ctx context.Context, groupName string) error {
	err := gm.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	return gm.client.DeleteGroup(gm.buildGroupDN(groupName))
}

func (gm *AdGroupManager) buildGroupDN(groupName string) string {
	return fmt.Sprintf("CN=%v,%v", groupName, gm.cfg.GroupBase)
}

func groupAttributesToCloudy(adc *adc.Group) *models.Group {
	grp := &models.Group{
		ID: adc.DN,
	}

	val, ok := adc.Attributes[GROUP_NAME_TYPE]
	if ok {
		grp.Name = fmt.Sprintf("%v", val)
	}

	val, ok = adc.Attributes[GROUP_COMMON_NAME]
	if ok {
		grp.ID = fmt.Sprintf("%v", val)
	}

	grp.Source = adc.DN
	return grp
}

func cloudyToGroupAttributes(grp *models.Group) *[]ldap.Attribute {
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

	return &attrs
}
