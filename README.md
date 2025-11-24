# Terraform Provider for Aruba ClearPass

A community-built Terraform provider for managing [Aruba ClearPass Policy Manager](https://www.hpe.com/de/de/aruba-clearpass-policy-manager.html). Born out of necessity to automate ClearPass when no existing solution was found.

[![License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](LICENSE)

## ⚠️ Important Disclaimers

- **Limited Scope**: This provider covers only a specific set of resources. It's not exhaustive.
- **No Official Support**: Community-maintained, use at your own risk.
- **Always Test First**: Test against dev/lab instances. Never go straight to production.
- **Not Aruba-Endorsed**: This is not an official Aruba product. A community effort to simplify ClearPass automation.

## What This Provider Does

It covers the basics needed for ClearPass automation:

- ✅ Roles, users, and authentication services
- ✅ Role mapping policies
- ✅ Enforcement profiles and policies
- ✅ Import existing configs

If you need more resources or features, you're welcome to contribute!

## Supported Resources

| Resource | Description |
|----------|-------------|
| `clearpass_role` | User roles defining access levels and permissions |
| `clearpass_local_user` | Local user accounts with authentication |
| `clearpass_role_mapping` | Policy-based role assignment rules |
| `clearpass_service` | Authentication services (802.1X, MAB, Guest, etc.) |
| `clearpass_enforcement_profile` | Network access enforcement profiles (RADIUS, TACACS, Agent) |
| `clearpass_enforcement_policy` | Policies linking roles to enforcement actions |

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.21 (for building from source)
- Aruba ClearPass Policy Manager 6.12+ with API access
- A service configured (Configuration -> Services) that supports OAuth2 (Application Name EQUALS OAuth2)
## Quick Start

### 1. Configure ClearPass API Access

Create an API Client in ClearPass:
1. Navigate to **Guest** → **Administration** → **API Services**
2. Create a new **API Client** with appropriate permissions
3. Note the **Client ID** and **Client Secret**. Client secret will be shown only once.

### 2. Configure the Provider

```hcl
terraform {
  required_providers {
    clearpass = {
      source  = "i-am-smolli/clearpass"
      version = "~> 0.0.1"
    }
  }
}

provider "clearpass" {
  host          = "clearpass.example.com"
  client_id     = "YourClientID"
  client_secret = "YourClientSecret"
  insecure      = false  # Set to true for self-signed certificates
}
```

### 3. Create Your First Resource

```hcl
# Define a guest role
resource "clearpass_role" "guest" {
  name        = "Guest"
  description = "Limited access for guest users"
}

# Create a local user
resource "clearpass_local_user" "john_doe" {
  user_id  = "jdoe"
  password = "SecurePassword123!"
  username = "John Doe"
  role_name = clearpass_role.guest.name
  enabled  = true
}
```

### 4. Apply Configuration

```bash
terraform init
terraform plan
terraform apply
```

## Authentication

The provider supports OAuth2 client credentials authentication. Configure using:

**Provider Configuration**:
```hcl
provider "clearpass" {
  host          = "clearpass.example.com"
  client_id     = "your-client-id"
  client_secret = "your-client-secret"
}
```

**Terraform Variables**:
```hcl
variable "clearpass_client_secret" {
  type      = string
  sensitive = true
}

provider "clearpass" {
  host          = var.clearpass_host
  client_id     = var.clearpass_client_id
  client_secret = var.clearpass_client_secret
}
```

## Examples

### 802.1X Authentication Service

```hcl
resource "clearpass_service" "dot1x" {
  name         = "802.1X Wireless Authentication"
  description  = "Enterprise wireless authentication"
  enabled      = true
  service_type = "802.1X"

  monitor_mode     = false
  audit_enabled    = true
  profiler_enabled = true
}
```

### Role-Based Access Control

```hcl
resource "clearpass_role_mapping" "device_based" {
  name              = "Device-Based Role Assignment"
  description       = "Assign roles based on device type"
  default_role_name = "Guest"
  rule_combine_algo = "first-applicable"

  rules = [
    {
      match_type = "OR"
      role_name  = "[Employee]"
      condition = [
        {
          type  = "Connection"
          name  = "SSID"
          oper  = "EQUALS"
          value = "Corporate-WiFi"
        }
      ]
    }
  ]
}
```

### RADIUS Enforcement Profile

```hcl
resource "clearpass_enforcement_profile" "radius_profile" {
  name        = "TF RADIUS Profile"
  description = "Created via Terraform"
  type        = "RADIUS"
  action      = "Accept"

  attributes = [
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Type"
      value = "VLAN (13)"
    },
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Medium-Type"
      value = "IEEE-802 (6)"
    },
    {
      type  = "Radius:IETF"
      name  = "Tunnel-Private-Group-Id"
      value = "450"
    },
  ]
}
```

See the [examples](./examples) directory for more complete examples.

## Documentation

Full documentation is available in the [docs](./docs) directory or on the [Terraform Registry](https://registry.terraform.io/providers/i-am-smolli/clearpass/latest/docs).

- [Provider Configuration](./docs/index.md)
- [Resource Documentation](./docs/resources/)
- [Import Guide](./docs/guides/import.md)

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/i-am-smolli/terraform-provider-clearpass.git
cd terraform-provider-clearpass

# Build the provider
go build -o terraform-provider-clearpass

# Install locally for testing (on macOS)
mkdir -p ~/.terraform.d/plugins/local/dev/clearpass/0.0.1/darwin_arm64
cp terraform-provider-clearpass ~/.terraform.d/plugins/local/dev/clearpass/0.0.1/darwin_arm64/
```


### Running Tests

> **⚠️ TESTING WARNING**: Always run tests against a dev/lab ClearPass instance. Never test against production. Seriously.

**Unit Tests**:
```bash
go test ./...
```

**Acceptance Tests** (requires a **TEST** ClearPass instance - reminder: do not use production):
```bash
export CLEARPASS_HOST="your-dev-clearpass-host"  # DEV! NOT PRODUCTION!
export CLEARPASS_CLIENT_ID="your-client-id"
export CLEARPASS_CLIENT_SECRET="your-client-secret"
export TF_ACC=1

go test -v ./internal/provider/test/ -timeout 30m
```

### Generating Documentation

```bash
go generate ./...
```

This regenerates the documentation in `docs/` from the schema definitions and examples.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow the existing code style
- Add tests for new features
- Update documentation for any changes
- Run `go generate` to update docs before committing
- Ensure all tests pass before submitting PR

## Troubleshooting

### Self-Signed Certificates

If your ClearPass instance uses self-signed certificates:

```hcl
provider "clearpass" {
  host     = "clearpass.example.com"
  insecure = true  # Skip certificate verification
  # ... other config
}
```

### Debug Logging

Enable Terraform debug logging:

```bash
export TF_LOG=DEBUG
export TF_LOG_PATH=./terraform-debug.log
terraform apply
```

### Common Issues

**Error: authentication failed**
- Verify your Client ID and Client Secret
- Ensure the API client has appropriate permissions
- Check the ClearPass API service is enabled

**Error: connection refused**
- Verify the ClearPass host is reachable
- Check firewall rules allow HTTPS (443) traffic
- Ensure you're using the correct hostname/IP

**Import errors**
- Verify the resource ID exists in ClearPass
- Check your API client has read permissions
- Use numeric IDs, not resource names

## Project Structure

```
.
├── docs/                    # Auto-generated documentation
├── examples/                # Example Terraform configurations
│   ├── provider/           # Provider configuration examples
│   └── resources/          # Resource examples
├── internal/
│   ├── client/             # ClearPass API client
│   └── provider/           # Terraform provider implementation
│       └── test/           # Acceptance tests
├── feature_specs/          # API specifications
└── tools.go                # Build tools
```

## API Coverage

This provider is built against the ClearPass API v1.2 specification with support for:

- ✅ Roles
- ✅ Local Users  
- ✅ Role Mappings
- ✅ Services 
- ✅ Enforcement Profiles
- ✅ Enforcement Policies

## Versioning

This project follows [Semantic Versioning](https://semver.org/). For available versions, see the [tags on this repository](https://github.com/i-am-smolli/terraform-provider-clearpass/tags).

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.

## "Support" (Read: Community Help)

Let's be honest - there's no official support here. But you can try:

- 📖 [Documentation](./docs) - Auto-generated, so it's at least accurate
- 🐛 [Issue Tracker](https://github.com/i-am-smolli/terraform-provider-clearpass/issues) - File bugs
- 💬 [Discussions](https://github.com/i-am-smolli/terraform-provider-clearpass/discussions) - Ask questions, share tips, commiserate

## A Challenge to Real Developers

If you're reading this and thinking "I could make a better provider," you're probably right! This was built to address immediate automation needs, not by Terraform experts. 

Contributions are welcome for:
- A more complete ClearPass API implementation
- Better error handling
- More sophisticated state management
- Actual testing infrastructure
- Maybe even official Aruba support?

## Acknowledgments

Built with:
- [terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework) - The actual experts
- [terraform-plugin-docs](https://github.com/hashicorp/terraform-plugin-docs) - For professional-looking documentation
- Coffee ☕ - Lots of it
- Stack Overflow - You know why

---

**Final Note**: This provider was built to solve a specific problem. It works for specific use cases. It might work for yours. It might not. Test it first, use it at your own risk, and if you improve it, please share! Community contributions are highly valued.

**Not affiliated with, endorsed by, or supported by**: Aruba Networks, HPE, or anyone else who might actually know what they're doing. This is pure community effort from folks who just needed ClearPass automation yesterday.