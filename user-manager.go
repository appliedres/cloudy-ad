package cloudyad

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/go-ldap/ldap/v3"

	"github.com/appliedres/adc"
)

type PageRequest struct {
	First int
	Max   int
}

// FACTORY
const ActiveDirectory = "active-directory"
const PageSize = 100

func init() {
	cloudy.UserProviders.Register(ActiveDirectory, &AdUserManagerFactory{})
}

type AdUserManagerFactory struct{}

func (umf *AdUserManagerFactory) Create(cfg interface{}) (cloudy.UserManager, error) {
	return cfg.(*AdUserManager), nil
}

func (umf *AdUserManagerFactory) FromEnv(env *cloudy.Environment) (interface{}, error) {
	cfg := NewAdUserManagerFromEnv(context.Background(), env)
	return cfg, nil
}

/// ------------- USER MANAGER

type AdUserManager struct {
	address     string
	user        string
	pwd         string
	base        string
	insecureTLS bool
	client      *adc.Client
	UserCN      string
}

func NewAdUserManager(cfg *AdUserManager) *AdUserManager {
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

func NewAdUserManagerFromEnv(ctx context.Context, env *cloudy.Environment) *AdUserManager {

	cfg := &AdUserManager{
		address:     env.Force("AD_HOST"),
		user:        env.Force("AD_USER"),
		pwd:         env.Force("AD_PWD"),
		base:        env.Force("AD_BASE"),
		insecureTLS: false,
	}
	return NewAdUserManager(cfg)
}

func (um *AdUserManager) connect(ctx context.Context) error {
	_ = ctx
	err := um.client.Connect()

	return err
}

// ForceUserName takes a proposed user name, validates it and transforms it.
// Then it checks to see if it is a real user
// Returns: string - updated user name, bool - if the user exists, error - if an error is encountered
func (um *AdUserManager) ForceUserName(ctx context.Context, name string) (string, bool, error) {

	return name, false, nil
}

func (um *AdUserManager) ListUsers(ctx context.Context, page interface{}, filter interface{}) ([]*models.User, interface{}, error) {
	return nil, nil, nil
}

func (um *AdUserManager) ListUserPage(ctx context.Context, page *PageRequest) ([]*models.User, *PageRequest, error) {
	var nextPage *PageRequest
	var err error
	var rtn []*models.User

	return rtn, nextPage, err
}

// Retrieves a specific user.
func (um *AdUserManager) GetUser(ctx context.Context, id string) (*models.User, error) {
	user, err := um.client.GetUser(adc.GetUserArgs{
		Dn: id,
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return UserToCloudy(user), nil
}

// Retrieves a specific user.
func (um *AdUserManager) GetUserByEmail(ctx context.Context, email string, opts *cloudy.UserOptions) (*models.User, error) {

	return nil, nil
}

// NewUser creates a new user with the given information and returns the new user with any additional
// fields populated
func (um *AdUserManager) NewUser(ctx context.Context, newUser *models.User) (*models.User, error) {
	newUser.UPN = createUserName(newUser)
	newUser.ID = "CN=" + newUser.UPN + "," + um.client.Config.Groups.SearchBase
	err := um.client.CreateUser(newUser.ID, cloudyToUserAttributes(newUser))
	return newUser, err
}

func (um *AdUserManager) UpdateUser(ctx context.Context, usr *models.User) error {
	return nil
}

func (um *AdUserManager) Enable(ctx context.Context, uid string) error {
	userAccountControl := ldap.Attribute{
		Type: "userAccountControl",
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT)},
	}
	return um.client.UpdateUser(uid, []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) Disable(ctx context.Context, uid string) error {
	userAccountControl := ldap.Attribute{
		Type: "userAccountControl",
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT|AC_ACCOUNTDISABLE)},
	}
	return um.client.UpdateUser(uid, []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) DeleteUser(ctx context.Context, uid string) error {
	return um.client.DeleteUser(uid)
}

func UserToCloudy(user *adc.User) *models.User {
	uacString := user.GetStringAttribute("userAccountControl")
	uac, _ := strconv.Atoi(uacString)

	enabled := (uac & AC_LOCKOUT) == 0

	u := &models.User{
		Enabled: enabled,

		ID:        user.Id,
		UPN:       user.GetStringAttribute("userPrincipalName"),
		FirstName: user.GetStringAttribute("givenName"),
		LastName:  user.GetStringAttribute("sn"),
		Email:     user.GetStringAttribute("mail"),
		// AccountType:    user.GetStringAttribute("AccountType"),
		// Citizenship:    user.GetStringAttribute("Citizenship"), (COUNTRY)
		Company: user.GetStringAttribute("o"),
		// ContractDate:   user.GetStringAttribute("ContractDate"),
		// ContractNumber: user.GetStringAttribute("ContractNumber"),
		// Department:     user.GetStringAttribute("Department"), department
		DisplayName: user.GetStringAttribute("displayName"),
		MobilePhone: user.GetStringAttribute("mobile"),
		OfficePhone: user.GetStringAttribute("telephoneNumber"),
		// Organization:   user.GetStringAttribute("Organization"),
		JobTitle: user.GetStringAttribute("title"),
		// ProgramRole:    user.GetStringAttribute("ProgramRole"),
		// Project:        user.GetStringAttribute("Project"),
	}

	return u
}

func UserToKeycloak(u *models.User) *adc.User {
	// attr := make(map[string][]string)

	// if u.AccountType != "" {
	// 	attr["AccountType"] = []string{u.AccountType}
	// }
	// if u.Citizenship != "" {
	// 	attr["Citizenship"] = []string{u.Citizenship}
	// }
	// if u.Company != "" {
	// 	attr["Company"] = []string{u.Company}
	// }
	// if u.ContractDate != "" {
	// 	attr["ContractDate"] = []string{u.ContractDate}
	// }
	// if u.ContractNumber != "" {
	// 	attr["ContractNumber"] = []string{u.ContractNumber}
	// }
	// if u.Department != "" {
	// 	attr["Department"] = []string{u.Department}
	// }
	// if u.DisplayName != "" {
	// 	attr["DisplayName"] = []string{u.DisplayName}
	// }
	// if u.MobilePhone != "" {
	// 	attr["MobilePhone"] = []string{u.MobilePhone}
	// }
	// if u.OfficePhone != "" {
	// 	attr["OfficePhone"] = []string{u.OfficePhone}
	// }
	// if u.Organization != "" {
	// 	attr["Organization"] = []string{u.Organization}
	// }
	// if u.JobTitle != "" {
	// 	attr["JobTitle"] = []string{u.JobTitle}
	// }
	// if u.ProgramRole != "" {
	// 	attr["ProgramRole"] = []string{u.ProgramRole}
	// }
	// if u.Project != "" {
	// 	attr["Project"] = []string{u.Project}
	// }

	// // user := &gocloak.User{
	// // 	ID:         &u.ID,
	// // 	Username:   &u.UPN,
	// // 	Enabled:    &u.Enabled,
	// // 	FirstName:  &u.FirstName,
	// // 	LastName:   &u.LastName,
	// // 	Email:      &u.Email,
	// // 	Attributes: &attr,
	// // }

	return nil
}

func createUserName(usr *models.User) string {
	userName := strings.ToLower(usr.FirstName + "-" + usr.LastName)
	return userName
}

func cloudyToUserAttributes(usr *models.User) []ldap.Attribute {
	objectClass := &ldap.Attribute{
		Type: "objectClass",
		Vals: []string{"top", "organizationalPerson", "user", "person"},
	}
	name := &ldap.Attribute{
		Type: "name",
		Vals: []string{usr.UPN},
	}
	sAMAccountName := &ldap.Attribute{
		Type: "sAMAccountName",
		Vals: []string{usr.UPN},
	}
	firstName := &ldap.Attribute{
		Type: "givenName",
		Vals: []string{usr.FirstName},
	}
	lastName := &ldap.Attribute{
		Type: "sn",
		Vals: []string{usr.LastName},
	}
	displayName := &ldap.Attribute{
		Type: "displayName",
		Vals: []string{usr.DisplayName},
	}
	email := &ldap.Attribute{
		Type: "mail",
		Vals: []string{usr.Email},
	}
	instanceType := &ldap.Attribute{
		Type: "instanceType",
		Vals: []string{fmt.Sprintf("%d", AC_INSTANCE_TYPE_WRITEABLE)},
	}
	userAccountControl := &ldap.Attribute{
		Type: "userAccountControl",
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT|AC_ACCOUNTDISABLE)},
	}
	accountExpires := &ldap.Attribute{
		Type: "accountExpires",
		Vals: []string{fmt.Sprintf("%d", AC_ACCOUNT_NEVER_EXPIRES)},
	}

	attrs := []ldap.Attribute{}

	attrs = append(attrs, *objectClass)
	attrs = append(attrs, *name)
	attrs = append(attrs, *sAMAccountName)
	attrs = append(attrs, *firstName)
	attrs = append(attrs, *lastName)
	attrs = append(attrs, *displayName)
	attrs = append(attrs, *email)
	attrs = append(attrs, *instanceType)
	attrs = append(attrs, *userAccountControl)
	attrs = append(attrs, *accountExpires)

	return attrs
}
