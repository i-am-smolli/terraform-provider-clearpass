// internal/provider/provider_test.go
package provider_test

import (
	"os"
	"testing"

	"terraform-provider-clearpass/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories tells the test runner how to start our provider.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"clearpass": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// testAccProviderConfig builds the provider HCL block using Env Vars.
// You MUST export CLEARPASS_HOST, CLEARPASS_CLIENT_ID, and CLEARPASS_CLIENT_SECRET
// in your terminal before running tests.
func testAccProviderConfig() string {
	host := os.Getenv("CLEARPASS_HOST")
	clientID := os.Getenv("CLEARPASS_CLIENT_ID")
	secret := os.Getenv("CLEARPASS_CLIENT_SECRET")

	// We assume 'insecure = true' for tests usually
	return `
provider "clearpass" {
  host          = "` + host + `"
  client_id     = "` + clientID + `"
  client_secret = "` + secret + `"
  insecure      = true
}
`
}

func TestProvider(t *testing.T) {

}
