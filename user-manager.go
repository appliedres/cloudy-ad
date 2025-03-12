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

func init() {
	cloudy.UserProviders.Register(ACTIVE_DIRECTORY, &AdUserManagerFactory{})
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

	if cfg.GroupBase == "" {
		cfg.GroupBase = cfg.Base
	}

	if cfg.UserBase == "" {
		cfg.UserBase = cfg.Base
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

	ad := &AdUserManager{
		client: cl,
		cfg:    *cfg,
	}

	ad.client = cl
	cl.Config.AppendUsesAttributes(DISPLAY_NAME_TYPE)

	return ad
}

func NewAdUserManagerFromEnv(ctx context.Context, env *cloudy.Environment) *AdUserManager {
	pageSize, err := strconv.ParseInt(env.Force("AD_PAGE_SIZE"), 10, 32)
	if err != nil {
		pageSize = PAGE_SIZE
	}

	cfg := &AdUserManagerConfig{
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
	if !um.client.ConnectedStatus() {
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
	users, err := um.client.ListUsers(args, um.cfg.PageSize, filter)
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
		Id: uid,
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
		Id:         uid,
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

	if newUser.DisplayName == "" {
		newUser.DisplayName = fmt.Sprintf("%v %v", newUser.FirstName, newUser.LastName)
	}

	userName, userExists, err := um.ForceUserName(ctx, um.createUserName(newUser))
	if err != nil {
		return nil, err
	}
	if userExists {
		return nil, fmt.Errorf("User already exists %v", userName)
	} else {
		newUser.Username = userName
	}

	newUser.UID = newUser.Username
	err = um.client.CreateUser(um.buildUserDN(newUser.UID), *cloudyToUserAttributes(newUser, fmt.Sprintf("%v.%v@%v", newUser.FirstName, newUser.LastName, um.cfg.Domain)))
	if err != nil {
		return nil, err
	}

	return newUser, err
}

func (um *AdUserManager) SetUserPassword(ctx context.Context, usrId string, pwd string, mustChange bool) error {
	return um.client.SetPassword(um.buildUserDN(usrId), pwd, mustChange)
}

func (um *AdUserManager) UpdateUser(ctx context.Context, usr *models.User) error {
	currentUser, err := um.GetUserWithAttributes(ctx, usr.UID, maps.Keys(usr.Attributes))
	if err != nil || currentUser == nil {
		return err
	}

	attrs := *cloudyToModifiedAttributes(usr, currentUser)
	if len(attrs) == 0 {
		return nil
	}

	return um.client.UpdateUser(um.buildUserDN(usr.UID), attrs)
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

	return um.client.UpdateUser(um.buildUserDN(uid), []ldap.Attribute{userAccountControl})
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

	return um.client.UpdateUser(um.buildUserDN(uid), []ldap.Attribute{userAccountControl})
}

func (um *AdUserManager) DeleteUser(ctx context.Context, uid string) error {
	err := um.connectAsNeeded(ctx)
	if err != nil {
		return err
	}

	return um.client.DeleteUser(um.buildUserDN(uid))
}

func UserToCloudy(user *adc.User, opts *cloudy.UserOptions) *models.User {
	uac, _ := strconv.Atoi(user.GetStringAttribute(USER_ACCOUNT_CONTROL_TYPE))
	enabled := (uac & AC_ACCOUNTDISABLE) == 0
	// locked := (uac & AC_LOCKOUT) == 0
	u := &models.User{
		UID:         user.Id,
		Username:    user.Id,
		FirstName:   user.GetStringAttribute(FIRST_NAME_TYPE),
		LastName:    user.GetStringAttribute(LAST_NAME_TYPE),
		Email:       user.GetStringAttribute(EMAIL_TYPE),
		DisplayName: user.GetStringAttribute(DISPLAY_NAME_TYPE),
		Enabled:     enabled,
	}

	for k, v := range user.Attributes {
		if !inObjAttrs(k) {
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

func (um *AdUserManager) buildUserDN(username string) string {
	return fmt.Sprintf("CN=%v,%v", username, um.cfg.UserBase)
}

func (um *AdUserManager) createUserName(usr *models.User) string {
	var userName string
	if um.cfg.UserIdAttribute == DISPLAY_NAME_TYPE {
		userName = usr.DisplayName
	} else {
		userName = strings.ToLower(usr.FirstName + "-" + usr.LastName)
	}
	return userName
}

func cloudyToUserAttributes(usr *models.User, upn string) *[]ldap.Attribute {
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
		Type: USER_PRINCIPAL_NAME_TYPE,
		Vals: []string{upn},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: SAM_ACCT_NAME_TYPE,
		Vals: []string{usr.Username},
	})
	attrs = append(attrs, ldap.Attribute{
		Type: NAME_TYPE,
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
		if v == "" {
			continue
		}

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
		if v == "" {
			continue
		}
		if currentUser.Attributes[k] == "" || currentUser.Attributes[k] != v {
			attrs = append(attrs, ldap.Attribute{
				Type: k,
				Vals: []string{v},
			})
		}
	}
	return &attrs
}

func inObjAttrs(key string) bool {
	for _, v := range USER_OBJECT_ATTRS {
		if key == v {
			return true
		}
	}
	return false
}
