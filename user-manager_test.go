package cloudyad

import (
	"fmt"
	"testing"

	"github.com/appliedres/adc"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

func initUserManager() (*adc.Client, error) {
	client := adc.New(&adc.Config{
		URL:         "ldaps://localhost:636",
		InsecureTLS: true,
		SearchBase:  "DC=ldap,DC=schneide,DC=dev",
		Users: &adc.UsersConfigs{
			SearchBase: "CN=Users,DC=ldap,DC=schneide,DC=dev",
		},
		Groups: &adc.GroupsConfigs{
			SearchBase: "CN=Users,DC=ldap,DC=schneide,DC=dev",
		},
		Bind: &adc.BindAccount{
			DN:       "DEV-AD\\Administrator",
			Password: "admin123!",
		},
	})

	// Connect
	err := client.Connect()
	if err != nil {
		return nil, err
	}

	return client, err
}

func TestAddUser(t *testing.T) {

	client, err := initUserManager()
	assert.Nil(t, err)
	assert.NotNil(t, client)

	objectClass := &ldap.Attribute{
		Type: "objectClass",
		Vals: []string{"top", "group"},
	}
	name := &ldap.Attribute{
		Type: "name",
		Vals: []string{"testgroup"},
	}
	instanceType := &ldap.Attribute{
		Type: "instanceType",
		Vals: []string{fmt.Sprintf("%d", 0x00000004)},
	}
	groupType := &ldap.Attribute{
		Type: "groupType",
		Vals: []string{fmt.Sprintf("%d", 0x00000004|0x80000000)},
	}
	attrs := []ldap.Attribute{}

	attrs = append(attrs, *objectClass)
	attrs = append(attrs, *name)
	attrs = append(attrs, *instanceType)
	attrs = append(attrs, *groupType)

	err = client.CreateGroup("CN=testgroup,OU=groups,CN=Users,DC=ldap", attrs)
	assert.Nil(t, err)
}
