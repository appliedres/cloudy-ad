package cloudyad

import (
	"testing"

	"github.com/appliedres/adc"
	"github.com/stretchr/testify/assert"
)

func TestSambaStart(t *testing.T) {

	assert.NotPanics(t, func() {
		cfg := CreateUserADTestContainer()
		cl := adc.New(&adc.Config{
			URL:         cfg.Address,
			InsecureTLS: true,
			SearchBase:  cfg.Base,
			Users: &adc.UsersConfigs{
				SearchBase: cfg.Base,
			},
			Groups: &adc.GroupsConfigs{
				SearchBase: cfg.Base,
			},
			Bind: &adc.BindAccount{
				DN:       cfg.User,
				Password: cfg.Pwd,
			},
		})

		if err := cl.Connect(); err != nil {
			t.Fatal(err)
		}

	})
}
