// main.go
package main

import (
	"context"
	"log"

	"terraform-provider-clearpass/internal/provider" // Import our new provider package

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// (Make sure to change this import path if your go.mod module name is different)
var (
	version = "dev" // This will be set by CI/CD
)

func main() {
	ctx := context.Background()

	// This is the standard "launcher" for a Terraform Framework provider.
	err := providerserver.Serve(ctx, provider.New(version), providerserver.ServeOpts{
		Address: "hashicorp.com/edu/clearpass", // This is the "source" address
	})

	if err != nil {
		log.Fatal(err.Error())
	}
}