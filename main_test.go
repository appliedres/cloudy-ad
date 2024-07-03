package cloudyad

import (
	"fmt"
	"log"
	"testing"

	"github.com/appliedres/adc"
)

func TestMe(t *testing.T) {
	// Init client
	cl := adc.New(&adc.Config{
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
	if err := cl.Connect(); err != nil {
		log.Fatal(err)
		// Handle error
	}

	// Search for a user
	user, err := cl.GetUser(adc.GetUserArgs{
		// Dn: "CN=john.bauer,CN=Users,DC=ldap,DC=schneide,DC=dev",
		Id: "john.bauer",
	})
	if err != nil {
		log.Fatal(err)
		// Handle error
	}
	if user == nil {
		log.Fatal("NO USER")
		// Handle not found
	}
	fmt.Printf("%+v\n", user)

	// Search for a group
	group, err := cl.GetGroup(adc.GetGroupArgs{Id: "groupId"})
	if err != nil {
		// Handle error
	}
	if group == nil {
		// Handle not found
	}
	fmt.Println(group)

	// Add new users to group members
	added, err := cl.AddGroupMembers("groupId", "newUserId1", "newUserId2", "newUserId3")
	if err != nil {
		// Handle error
	}
	fmt.Printf("Added %d members", added)

	// Delete users from group members
	deleted, err := cl.DeleteGroupMembers("groupId", "userId1", "userId2")
	if err != nil {
		// Handle error
	}
	fmt.Printf("Deleted %d users from group members", deleted)
}

// func AddUser(cl *adc.Client) {
// 	var client ldap.Client
// 	client.Add(&ldap.AddRequest{
// 		DN: "CN=Users,DC=ldap,DC=schneide,DC=dev",
// 		Attributes: []ldap.Attribute{
// 			ldap.Attribute{
// 				Type: ,
// 			}
// 		},
// 	})

// }
