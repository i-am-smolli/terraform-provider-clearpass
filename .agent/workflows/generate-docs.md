---
description: Generate and improve Terraform Registry documentation for all resources
---

# Documentation Generation Workflow

This workflow guides you through generating complete Terraform Registry documentation for the provider, including enhancing schema descriptions and creating example HCL files.

## Prerequisites

- All resources should be implemented and tested
- Provider code should be in a stable state

## Steps

### 1. Create Examples Directory Structure

// turbo
```bash
mkdir -p examples/provider
mkdir -p examples/resources
```

### 2. Create Provider Example

Create `examples/provider/provider.tf` with a basic provider configuration example:

```hcl
terraform {
  required_providers {
    clearpass = {
      source = "registry.terraform.io/hashicorp/clearpass"
    }
  }
}

provider "clearpass" {
  host          = "clearpass.example.com"
  client_id     = "your-oauth-client-id"
  client_secret = "your-oauth-client-secret"
  insecure      = false
}
```

### 3. For Each Resource, Create Examples

For each resource in `internal/provider/resource_*.go`:

#### 3a. Create Resource Example Directory
```bash
# Example for clearpass_role resource
mkdir -p examples/resources/clearpass_role
```

#### 3b. Create `resource.tf` Example File

Create `examples/resources/clearpass_RESOURCENAME/resource.tf` with:
- A complete, working example showing all common use cases
- Comments explaining important fields
- Realistic values (not just "test" everywhere)

Example for `clearpass_role`:
```hcl
resource "clearpass_role" "employee" {
  name        = "[Employee]"
  description = "Role assigned to company employees with full network access"
}

resource "clearpass_role" "guest" {
  name        = "Guest"
  description = "Limited access role for guest users"
}
```

#### 3c. Create `import.sh` for Import Documentation

Create `examples/resources/clearpass_RESOURCENAME/import.sh`:
```bash
# Role can be imported by ID
terraform import clearpass_role.employee 123
```

### 4. Enhance Schema Descriptions in Resource Files

For each `internal/provider/resource_*.go` file, improve the `Description` fields:

#### 4a. Resource-level Description
Update the main schema description to be comprehensive:
```go
resp.Schema = schema.Schema{
    Description: "Manages a user role in ClearPass. Roles are used to define access levels " +
                 "and permissions for authenticated users. Common roles include [Employee], " +
                 "Guest, and custom roles for specific access requirements.",
    Attributes: map[string]schema.Attribute{
        // ...
    },
}
```

#### 4b. Attribute Descriptions
For each attribute, provide clear, helpful descriptions:

**Good descriptions include:**
- What the field does
- Valid values or format (if applicable)  
- Whether it's commonly used
- Examples in parentheses

**Example:**
```go
"name": schema.StringAttribute{
    Description: "The unique name of the role (e.g., 'Guest', '[Employee]', '[Contractor]'). " +
                 "Note: System roles typically use square brackets.",
    Required:    true,
},
"description": schema.StringAttribute{
    Description: "Human-readable description of the role's purpose and intended use.",
    Optional:    true,
},
```

### 5. Review Existing Generated Docs

Check the current documentation:
```bash
ls -la docs/resources/
```

Review each generated `.md` file to identify resources that need better descriptions or examples.

### 6. Run Documentation Generation

// turbo
```bash
go generate ./...
```

This runs the `tfplugindocs` command defined in `doc.go`, which:
- Reads schema descriptions from resource files
- Includes examples from `examples/` directory
- Generates markdown files in `docs/` directory

### 7. Verify Generated Documentation

Check the generated documentation:
```bash
ls -la docs/resources/
cat docs/resources/clearpass_role.md
```

Ensure:
- ✅ Schema has all attributes documented
- ✅ Examples are included
- ✅ Import documentation is present (if import.sh exists)
- ✅ Descriptions are clear and helpful

### 8. Iterate on Quality

For each resource, ask:
1. **Is the resource description clear about what it manages?**
2. **Do attribute descriptions help users understand how to use them?**
3. **Are examples realistic and useful?**
4. **Is import documentation included?**

If not, go back to steps 3-4 and improve, then re-run `go generate`.

### 9. Commit Changes

```bash
git add examples/ docs/ internal/provider/resource_*.go
git commit -m "docs: Add comprehensive examples and improve schema descriptions"
```

## Resources to Document

Current resources in provider:
- `clearpass_role`
- `clearpass_local_user`
- `clearpass_role_mapping`
- `clearpass_enforcement_profile`
- `clearpass_enforcement_policy`
- `clearpass_service`

## Quality Standards

### Schema Descriptions Should:
- Be 1-3 sentences
- Explain WHAT the field is and WHY you'd use it
- Include examples of valid values when helpful
- Use proper terminology from ClearPass documentation

### Examples Should:
- Show realistic use cases
- Include comments for non-obvious configurations
- Use meaningful names (not "test", "foo", etc.)
- Demonstrate common patterns
- Be syntactically correct HCL

## Terraform Registry Documentation Standards

Reference: https://developer.hashicorp.com/terraform/registry/providers/docs

Key requirements:
- All resources must have examples
- Descriptions should be user-friendly, not just field names
- Import examples help users migrate existing infrastructure
- Examples should follow Terraform best practices

## Additional Notes

- The `// turbo` annotation allows auto-running safe commands
- `go generate` should be run after ANY changes to descriptions or examples
- Generated docs go in `docs/` directory (committed to git)
- Examples go in `examples/` directory (committed to git)
- Both directories are required for Terraform Registry publishing
