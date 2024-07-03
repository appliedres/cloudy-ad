package cloudyad

import (
	"testing"

	"github.com/appliedres/cloudy"
	"github.com/appliedres/cloudy/models"
	"github.com/stretchr/testify/assert"
)

func initGroupManager() *AdGroupManager {
	cfg := &AdGroupManager{
		address:     "ldaps://localhost:636",
		user:        "DEV-AD\\Administrator",
		pwd:         "admin123!",
		base:        "DC=ldap,DC=schneide,DC=dev",
		insecureTLS: false,
	}
	return cfg
}

func TestCreateGroup(t *testing.T) {
	cfg := initGroupManager()
	assert.NotNil(t, cfg)

	ad := NewAdGroupManager(cfg)
	assert.NotNil(t, ad)

	ctx := cloudy.StartContext()

	newGrp := &models.Group{
		Name: "TestGroup",
	}

	grp, err := ad.NewGroup(ctx, newGrp)
	assert.NotNil(t, grp)
	assert.Nil(t, err)
}
