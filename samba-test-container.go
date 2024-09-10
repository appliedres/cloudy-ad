package cloudyad

import (
	"context"
	"fmt"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func CreateADTestContainer() *AdUserManagerConfig {
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "appliedres/dev-ad",
			ExposedPorts: []string{"636/tcp"},
			Env: map[string]string{
				"SMB_ADMIN_PASSWORD": "admin123!",
			},
			Hostname:   "ldap.schneide.dev",
			Privileged: true,
			// Cmd:          []string{"start-dev"},
			WaitingFor: wait.ForLog("TLS self-signed keys generated OK"),
		},
		Started: true,
	})
	if err != nil {
		panic(err)
	}
	time.Sleep(2 * time.Second)

	hostname, err := container.Host(ctx)
	if err != nil {
		panic(err)
	}

	port, err := container.MappedPort(ctx, "636")
	if err != nil {
		panic(err)
	}

	return &AdUserManagerConfig{
		Address:     fmt.Sprintf("ldaps://%v:%v", hostname, port.Port()),
		User:        "DEV-AD\\Administrator",
		Pwd:         "admin123!",
		Base:        "DC=ldap,DC=schneide,DC=dev",
		InsecureTLS: "true",
	}
}
