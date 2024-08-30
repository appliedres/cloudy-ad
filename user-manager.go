package cloudyad

import (
	"context"
	"encoding/base64"
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

const ActiveDirectory = "active-directory"
const PageSize = 100

func init() {
	cloudy.UserProviders.Register(ActiveDirectory, &AdUserManagerFactory{})
}

type AdUserManagerFactory struct{}

// FACTORY
func (umf *AdUserManagerFactory) Create(cfg interface{}) (cloudy.UserManager, error) {
	return cfg.(*AdUserManager), nil
}

func (umf *AdUserManagerFactory) FromEnv(env *cloudy.Environment) (interface{}, error) {
	cfg := NewAdUserManagerFromEnv(context.Background(), env)
	return cfg, nil
}

type AdUserManagerConfig struct {
	Address     string
	User        string
	Pwd         string
	Base        string
	InsecureTLS string
}

// USER MANAGER
type AdUserManager struct {
	cfg    AdUserManagerConfig
	client *adc.Client
}

func NewAdUserManager(cfg *AdUserManagerConfig) *AdUserManager {
	insecureTLS, err := strconv.ParseBool(cfg.InsecureTLS)
	if err != nil {
		insecureTLS = false
	}

	cl := adc.New(&adc.Config{
		URL:         cfg.Address,
		InsecureTLS: insecureTLS,
		SearchBase:  cfg.Base,
		Users: &adc.UsersConfigs{
			SearchBase:  fmt.Sprintf("CN=Users,%v", cfg.Base),
			IdAttribute: USERNAME_TYPE,
			Attributes:  USER_STANDARD_ATTRS,
		},
		Groups: &adc.GroupsConfigs{
			SearchBase: fmt.Sprintf("CN=Users,%v", cfg.Base),
			Attributes: GROUP_STANDARD_ATTRS,
		},
		Bind: &adc.BindAccount{
			DN:       cfg.User,
			Password: cfg.Pwd,
		},
	})

	ad := &AdUserManager{
		client: cl,
		cfg:    *cfg,
	}

	ad.client = cl
	cl.Config.AppendUsesAttributes(DISPLAY_NAME_TYPE)

	return ad
}

func NewAdUserManagerFromEnv(ctx context.Context, env *cloudy.Environment) *AdUserManager {
	cfg := &AdUserManagerConfig{
		Address:     env.Force("AD_HOST"),
		User:        env.Force("AD_USER"),
		Pwd:         env.Force("AD_PWD"),
		Base:        env.Force("AD_BASE"),
		InsecureTLS: env.Force("AD_INSECURE_TLS"),
	}
	return NewAdUserManager(cfg)
}

func (um *AdUserManager) connect(ctx context.Context) error {
	_ = ctx
	err := um.client.Connect()

	return err
}

func (um *AdUserManager) reconnect(ctx context.Context) error {
	err := um.client.Reconnect(ctx, TICKER_DURATION, MAX_ATTEMPTS)

	return err
}

func (um *AdUserManager) connectAsNeeded(ctx context.Context) error {
	var err error
	if um.client.ConnectedStatus() == false {
		err = um.connect(ctx)
	} else {
		err = um.reconnect(ctx)
	}
	return err
}

// ForceUserName takes a proposed user name, validates it and transforms it.
// Then it checks to see if it is a real user
// Returns: string - updated user name, bool - if the user exists, error - if an error is encountered
func (um *AdUserManager) ForceUserName(ctx context.Context, name string) (string, bool, error) {
	usr, err := um.GetUserByUserName(ctx, name)
	if err != nil {
		return name, false, err
	}
	if usr != nil {
		return name, true, nil
	}
	return name, false, nil
}

func (um *AdUserManager) ListUsers(ctx context.Context, filter string, attrs []string) (*[]models.User, error) {
	var args adc.GetUserArgs

	err := um.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	args.Attributes = append(attrs, USER_STANDARD_ATTRS...)
	users, err := um.client.ListUsers(args, filter)
	if err != nil {
		return nil, err
	}
	if users == nil {
		return nil, nil
	}

	var results []models.User
	for _, user := range *users {
		results = append(results, *UserToCloudy(&user, nil))
	}
	return &results, nil
}

// Retrieves a specific user.
func (um *AdUserManager) GetUser(ctx context.Context, uid string) (*models.User, error) {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	user, err := um.client.GetUser(adc.GetUserArgs{
		Dn: decodeToStr(uid),
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return UserToCloudy(user, nil), nil
}

// not adding to Cloudy unless needed
func (um *AdUserManager) GetUserByUserName(ctx context.Context, un string) (*models.User, error) {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

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

func (um *AdUserManager) GetUserWithAttributes(ctx context.Context, uid string, attrs []string) (*models.User, error) {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	user, err := um.client.GetUser(adc.GetUserArgs{
		Dn:         decodeToStr(uid),
		Attributes: append(attrs, USER_STANDARD_ATTRS...),
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
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	user, err := um.client.GetUser(adc.GetUserArgs{
		Filter: "(&(objectclass=person)(mail=" + email + "))",
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
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return nil, err
	}

	userName, userExists, err := um.ForceUserName(ctx, createUserName(newUser))
	if err != nil {
		return nil, err
	}
	if userExists {
		return nil, fmt.Errorf("User already exists %v", userName)
	} else {
		newUser.Username = userName
	}

	newUser.UID = "CN=" + newUser.Username + "," + um.client.Config.Groups.SearchBase
	err = um.client.CreateUser(newUser.UID, *cloudyToUserAttributes(newUser))
	if err != nil {
		return nil, err
	}

	newUser.UID = base64.URLEncoding.EncodeToString([]byte(newUser.UID))
	return newUser, err
}

func (um *AdUserManager) UpdateUser(ctx context.Context, usr *models.User) error {
	currentUser, err := um.GetUserWithAttributes(ctx, usr.UID, maps.Keys(usr.Attributes))
	if err != nil || currentUser == nil {
		return err
	}
	return um.client.UpdateUser(decodeToStr(usr.UID), *cloudyToModifiedAttributes(usr, currentUser))
}

func (um *AdUserManager) Enable(ctx context.Context, uid string) error {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	userAccountControl := ldap.Attribute{
		Type: USER_ACCOUNT_CONTROL_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT)},
	}

	return um.client.UpdateUser(decodeToStr(uid), []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) Disable(ctx context.Context, uid string) error {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	userAccountControl := ldap.Attribute{
		Type: USER_ACCOUNT_CONTROL_TYPE,
		Vals: []string{fmt.Sprintf("%d", AC_NORMAL_ACCOUNT|AC_ACCOUNTDISABLE)},
	}
	return um.client.UpdateUser(decodeToStr(uid), []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) DeleteUser(ctx context.Context, uid string) error {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	return um.client.DeleteUser(decodeToStr(uid))
}

func UserToCloudy(user *adc.User, opts *cloudy.UserOptions) *models.User {
	uac, _ := strconv.Atoi(user.GetStringAttribute(USER_ACCOUNT_CONTROL_TYPE))
	enabled := (uac & AC_ACCOUNTDISABLE) == 0
	// locked := (uac & AC_LOCKOUT) == 0
	u := &models.User{
		UID:         base64.URLEncoding.EncodeToString([]byte(user.DN)),
		Username:    user.Id,
		FirstName:   user.GetStringAttribute(FIRST_NAME_TYPE),
		LastName:    user.GetStringAttribute(LAST_NAME_TYPE),
		Email:       user.GetStringAttribute(EMAIL_TYPE),
		DisplayName: user.GetStringAttribute(DISPLAY_NAME_TYPE),
		Enabled:     enabled,
	}

	for k, v := range user.Attributes {
		if !inStdAttrs(k) {
			if u.Attributes == nil {
				u.Attributes = make(map[string]string)
			}
			u.Attributes[k] = v.(string)
		}
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
	return u
}

func createUserName(usr *models.User) string {
	userName := strings.ToLower(usr.FirstName + "-" + usr.LastName)
	return userName
}

func cloudyToUserAttributes(usr *models.User) *[]ldap.Attribute {
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

	for k, v := range usr.Attributes {
		attrs = append(attrs, ldap.Attribute{
			Type: k,
			Vals: []string{v},
		})
	}

	return &attrs
}

func cloudyToModifiedAttributes(updateReqUser *models.User, currentUser *models.User) *[]ldap.Attribute {
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
	return &attrs
}

func decodeToStr(encodedStr string) string {
	bytes, err := base64.URLEncoding.DecodeString(encodedStr)
	if err != nil {
		return ("")
	}
	return (string(bytes))
}

func inStdAttrs(key string) bool {
	for _, v := range USER_STANDARD_ATTRS {
		if key == v {
			return true
		}
	}
	return false
}
