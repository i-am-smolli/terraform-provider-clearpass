# Terraform Provider for Aruba ClearPass

A Terraform provider for managing [Aruba ClearPass Policy Manager](https://www.arubanetworks.com/products/security/network-access-control/). This provider enables Infrastructure as Code (IaC) for ClearPass configurations including users, roles, services, and enforcement policies.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/i-am-smolli/terraform-provider-clearpass)](https://goreportcard.com/report/github.com/i-am-smolli/terraform-provider-clearpass)

## Features

- ✅ **Complete Resource Coverage**: Manage roles, users, services, enforcement profiles, and policies
- ✅ **Full CRUD Operations**: Create, Read, Update, and Delete support for all resources
- ✅ **Import Support**: Import existing ClearPass configurations into Terraform
- ✅ **Type Safety**: Built with terraform-plugin-framework for robust type handling
- ✅ **Comprehensive Documentation**: Auto-generated docs with examples for every resource

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
- Aruba ClearPass Policy Manager 6.9+ with API access

## Quick Start

### 1. Configure ClearPass API Access

Create an API Client in ClearPass:
1. Navigate to **Guest** → **Administration** → **API Services**
2. Create a new **API Client** with appropriate permissions
3. Note the **Client ID** and **Client Secret**

### 2. Configure the Provider

```hcl
terraform {
  required_providers {
    clearpass = {
      source  = "i-am-smolli/clearpass"
      version = "~> 1.0"
    }
  }
}

provider "clearpass" {
  host          = "clearpass.example.com"
  client_id     = var.clearpass_client_id
  client_secret = var.clearpass_client_secret
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
      match_type = "AND"
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
resource "clearpass_enforcement_profile" "employee_access" {
  name        = "Employee Full Access"
  description = "Full network access for employees"
  type        = "RADIUS"
  action      = "Accept"

  attributes = [
    {
      type  = "Radius:IETF"
      name  = "Filter-Id"
      value = "employee-acl"
    },
    {
      type  = "Radius:IETF"
      name  = "Session-Timeout"
      value = "28800"  # 8 hours
    }
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

# Install locally for testing
mkdir -p ~/.terraform.d/plugins/local/dev/clearpass/1.0.0/darwin_arm64
cp terraform-provider-clearpass ~/.terraform.d/plugins/local/dev/clearpass/1.0.0/darwin_arm64/
```

### Running Tests

**Unit Tests**:
```bash
go test ./...
```

**Acceptance Tests** (requires ClearPass instance):
```bash
export CLEARPASS_HOST="your-clearpass-host"
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
- ✅ Services (with full field coverage including monitoring, audit, profiler)
- ✅ Enforcement Profiles (including templates and device groups)
- ✅ Enforcement Policies

## Versioning

This project follows [Semantic Versioning](https://semver.org/). For available versions, see the [tags on this repository](https://github.com/i-am-smolli/terraform-provider-clearpass/tags).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](./docs)
- 🐛 [Issue Tracker](https://github.com/i-am-smolli/terraform-provider-clearpass/issues)
- 💬 [Discussions](https://github.com/i-am-smolli/terraform-provider-clearpass/discussions)

## Acknowledgments

Built with:
- [terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework)
- [terraform-plugin-docs](https://github.com/hashicorp/terraform-plugin-docs)

---

**Note**: This is a community-developed provider and is not officially supported by Aruba Networks or HPE. Use at your own risk in production environments.