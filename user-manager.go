package cloudyad

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/appliedres/adc"
	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/exp/maps"
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
	cl.Config.AppendUsesAttributes(DISPLAY_NAME_TYPE)

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

	return UserToCloudy(user, nil), nil
}

func (um *AdUserManager) GetUserByUserName(ctx context.Context, un string) (*models.User, error) {
	user, err := um.client.GetUser(adc.GetUserArgs{
		Id: un,
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return UserToCloudy(user, nil), nil
}

func (um *AdUserManager) GetUserWithAttributes(ctx context.Context, id string, attrs []string) (*models.User, error) {
	user, err := um.client.GetUser(adc.GetUserArgs{
		Dn:         id,
		Attributes: attrs,
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return UserToCloudy(user, nil), nil
}

// Retrieves a specific user.
func (um *AdUserManager) GetUserByEmail(ctx context.Context, email string, opts *cloudy.UserOptions) (*models.User, error) {
	user, err := um.client.GetUser(adc.GetUserArgs{
		Filter:     "(&(objectclass=person)(mail=" + email + "))",
		Attributes: []string{FIRST_NAME_TYPE, LAST_NAME_TYPE, EMAIL_TYPE, DISPLAY_NAME_TYPE, LAST_LOGIN_TYPE},
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return UserToCloudy(user, opts), nil
}

// NewUser creates a new user with the given information and returns the new user with any additional
// fields populated
func (um *AdUserManager) NewUser(ctx context.Context, newUser *models.User) (*models.User, error) {
	newUser.Username = createUserName(newUser)
	newUser.UID = "CN=" + newUser.Username + "," + um.client.Config.Groups.SearchBase
	err := um.client.CreateUser(newUser.UID, cloudyToUserAttributes(newUser))
	return newUser, err
}

func (um *AdUserManager) UpdateUser(ctx context.Context, usr *models.User) error {
	currentUser, err := um.GetUserWithAttributes(ctx, usr.UID, maps.Keys(usr.Attributes))
	if err != nil || currentUser == nil {
		return err
	}
	return um.client.UpdateUser(usr.UID, cloudyToModifiedAttributes(usr, currentUser))
}

func (um *AdUserManager) Enable(ctx context.Context, uid string) error {
	userAccountControl := ldap.Attribute{
		Type: USER_ACCOUNT_CONTROL_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT)},
	}
	return um.client.UpdateUser(uid, []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) Disable(ctx context.Context, uid string) error {
	userAccountControl := ldap.Attribute{
		Type: USER_ACCOUNT_CONTROL_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT|AC_ACCOUNTDISABLE)},
	}
	return um.client.UpdateUser(uid, []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) DeleteUser(ctx context.Context, uid string) error {
	return um.client.DeleteUser(uid)
}

func UserToCloudy(user *adc.User, opts *cloudy.UserOptions) *models.User {
	u := &models.User{
		UID:         user.DN,
		Username:    user.Id,
		FirstName:   user.GetStringAttribute(FIRST_NAME_TYPE),
		LastName:    user.GetStringAttribute(LAST_NAME_TYPE),
		Email:       user.GetStringAttribute(EMAIL_TYPE),
		DisplayName: user.GetStringAttribute(DISPLAY_NAME_TYPE),
	}

	if opts != nil && *opts.IncludeLastSignIn {
		var lastLogon int64
		lastLogon, err := strconv.ParseInt(user.GetStringAttribute(LAST_LOGIN_TYPE), 10, 64)
		if err == nil {
			u.Attributes = make(map[string]string)
			// Windows NT time format to linux time
			u.Attributes[LAST_LOGIN_TYPE] = time.Unix((lastLogon/10000000)-11644473600, 0).String()
		}
	}
	// uacString := user.GetStringAttribute(USER_ACCOUNT_CONTROL_TYPE)
	// uac, _ := strconv.Atoi(uacString)
	// enabled := (uac & AC_LOCKOUT) == 0

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
	attrs := []ldap.Attribute{}

	attrs = append(attrs, ldap.Attribute{
		Type: OBJ_CLASS_TYPE,
		Vals: USER_OBJ_CLASS_VALS,
	})
	attrs = append(attrs, ldap.Attribute{
		Type: USERNAME_TYPE,
		Vals: []string{usr.Username},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: SAM_ACCT_NAME_TYPE,
		Vals: []string{usr.Username},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: FIRST_NAME_TYPE,
		Vals: []string{usr.FirstName},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: LAST_NAME_TYPE,
		Vals: []string{usr.LastName},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: DISPLAY_NAME_TYPE,
		Vals: []string{usr.DisplayName},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: EMAIL_TYPE,
		Vals: []string{usr.Email},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: INSTANCE_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_INSTANCE_TYPE_WRITEABLE)},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: USER_ACCOUNT_CONTROL_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT|AC_ACCOUNTDISABLE)},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: ACCT_EXPIRES_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_ACCOUNT_NEVER_EXPIRES)},
	})

	return attrs
}

func cloudyToModifiedAttributes(updateReqUser *models.User, currentUser *models.User) []ldap.Attribute {
	var attrs []ldap.Attribute

	if currentUser.DisplayName == "" || currentUser.DisplayName != updateReqUser.DisplayName {
		attrs = append(attrs, ldap.Attribute{
			Type: DISPLAY_NAME_TYPE,
			Vals: []string{updateReqUser.DisplayName},
		})
	}

	if currentUser.Email == "" || currentUser.Email != updateReqUser.Email {
		attrs = append(attrs, ldap.Attribute{
			Type: EMAIL_TYPE,
			Vals: []string{updateReqUser.Email},
		})
	}

	if currentUser.FirstName == "" || currentUser.FirstName != updateReqUser.FirstName {
		attrs = append(attrs, ldap.Attribute{
			Type: FIRST_NAME_TYPE,
			Vals: []string{updateReqUser.FirstName},
		})
	}

	if currentUser.LastName == "" || currentUser.LastName != updateReqUser.LastName {
		attrs = append(attrs, ldap.Attribute{
			Type: LAST_NAME_TYPE,
			Vals: []string{updateReqUser.LastName},
		})
	}

	for k, v := range updateReqUser.Attributes {
		if currentUser.Attributes[k] == "" || currentUser.Attributes[k] != v {
			attrs = append(attrs, ldap.Attribute{
				Type: k,
				Vals: []string{v},
			})
		}
	}
	return attrs
}
