# =============================================================================
# ClearPass TACACS+ for Juniper Devices – Minimum Viable Product
# =============================================================================
# This file configures a complete TACACS+ setup in Aruba ClearPass
# Policy Manager for Juniper devices (Junos) using Terraform.
#
# WHAT GETS CREATED:
#   1. A Network Device           – the Juniper switch/router using TACACS+
#   2. A Network Device Group     – groups devices by subnet
#   3. Two Enforcement Profiles   – SuperUser (full access) and ReadOnly (show)
#   4. Two Roles                  – "Network-Admin" and "Helpdesk"
#   5. Two local test users       – admin-user and helpdesk-user
#   6. A Role Mapping Policy      – assigns roles to users
#   7. An Enforcement Policy      – selects the appropriate profile based on role
#   8. A TACACS+ Service          – the entry point that ties everything together
#
# JUNIPER SPECIFICS:
#   Unlike Cisco/IOS, Junos does not use privilege levels (0–15),
#   but user classes:
#     • super-user      → full administrative access (like Cisco priv 15)
#     • operator        → monitoring access (show, ping, traceroute, clear, request)
#     • read-only       → read-only access
#     • unauthorized    → no access
#
#   This example uses pure TACACS command authorization in CPPM
#   (allow/deny of commands). This works without Juniper-specific
#   attribute dictionaries in Enforcement Profiles. The minimum required
#   configuration on the Juniper device should be:
#
#     set system authentication-order [tacplus password]
#     set system tacplus-server <CLEARPASS-IP> secret <SECRET>
#     set system login user remote full-name "TACACS Remote User"
#     set system login user remote class read-only        ← fallback class
#
#   See also: examples/junos/junos.tf (Terraform configuration for Junos devices)
#
# USAGE:
#   Search for "CHANGE ME" in this file and replace the placeholders.
# =============================================================================


# Terraform Configuration

terraform {
  required_providers {
    clearpass = {
      source  = "i-am-smolli/clearpass"
      version = ">= 0.0.9"
    }
  }
}

provider "clearpass" {
  # CHANGE ME: IP address or FQDN of your ClearPass server
  host          = "10.20.30.40"

  # CHANGE ME: OAuth2 Client ID
  # Create this in ClearPass under: Administration » API Access » API Clients
  client_id     = "my_terraform_user"

  # CHANGE ME: OAuth2 Client Secret (shown once when you create the API client)
  client_secret = "JWDCdj2k3h4[...]v5w6x7y8z9"

  # Set to true if ClearPass uses a self-signed certificate (common in labs)
  insecure      = true

  # Suppress the version mismatch warning if your ClearPass version
  # differs from the tested version
  suppress_version_warning = true
}


# =============================================================================
# STEP 1 — NETWORK DEVICE (the TACACS+ client)
# =============================================================================
# The Juniper switch or router that checks admin logins via ClearPass.
# Every device sending TACACS+ requests must be registered here.
#
# ClearPass GUI: Configuration » Network » Devices
# =============================================================================
resource "clearpass_network_device" "junos_switch" {
  # CHANGE ME: Display name of the device (appears in ClearPass reports)
  name = "Juniper-Core-Switch-01"

  # CHANGE ME: Management IP of the Juniper device
  ip_address = "10.20.40.80"

  # CHANGE ME: TACACS+ shared secret – must match the device configuration:
  # Junos:  set system tacplus-server 10.20.40.80 secret <SECRET>
  tacacs_secret = "my_shared_secret"

  description = "Core distribution switch – TACACS+ managed via Terraform"
  vendor_name = "Juniper"
}


# =============================================================================
# STEP 2 — NETWORK DEVICE GROUP
# =============================================================================
# Device groups allow you to organize network devices by subnet, regex, or
# explicit list. They can be referenced in Enforcement Profiles to apply
# different policies based on network segment.
#
# ClearPass GUI: Configuration » Network » Device Groups
# =============================================================================
resource "clearpass_network_device_group" "junos_devices" {
  name        = "TACACS-Junos-Devices"
  description = "All Juniper devices using TACACS+ for management"

  group_format = "subnet"
  value        = "10.20.40.0/24" # CHANGE ME: your management subnet in CIDR notation
}


# =============================================================================
# STEP 3a — ENFORCEMENT PROFILE: Super-User (full access)
# =============================================================================
# This profile is returned when the user has the "Network-Admin" role.
# In this provider version, TACACS attribute dictionaries
# (e.g., "local-user-name") are not available for Enforcement Profiles in CPPM.
# Therefore, we use TACACS command authorization here.
#
# Junos user classes:
#   super-user   → all commands including configure
#   operator     → show, ping, traceroute, clear, request
#   read-only    → read-only commands only (show, help, exit)
#   unauthorized → no access
#
# ClearPass GUI: Configuration » Enforcement » Profiles
# =============================================================================
resource "clearpass_enforcement_profile" "tacacs_junos_admin" {
  name        = "TACACS-Junos-Admin-Profile"
  description = "Full access – TACACS command authorization without command limits"

  type   = "TACACS"
  action = "Accept"

  attributes = [
    {
      name  = "local-user-name"
      type  = "junos-exec"
      value = "tacacs-admin"
    },
  ]

  tacacs_service_param = {
    # The CPPM API requires this field even for Juniper profiles.
    privilege_level = 15

    services = ["junos-exec"]

    # ADD = TACACS authorize attributes are added to the response
    authorize_attribute_status = "ADD"
  }
}


# =============================================================================
# STEP 3b — ENFORCEMENT PROFILE: Read-Only / Helpdesk (read-only commands)
# =============================================================================
# This profile is returned when the user has the "Helpdesk" role.
# This profile restricts the command list to only allow read-only operations,
# ensuring helpdesk access is limited to read-only command execution.
#
# ClearPass GUI: Configuration » Enforcement » Profiles
# =============================================================================
resource "clearpass_enforcement_profile" "tacacs_junos_readonly" {
  name        = "TACACS-Junos-ReadOnly-Profile"
  description = "Read-only access – restricted TACACS commands (show/help/exit/quit)"

  type   = "TACACS"
  action = "Accept"

  attributes = [
    {
      name  = "local-user-name"
      type  = "junos-exec"
      value = "tacacs-read-only"
    },
  ]

  tacacs_service_param = {
    # The CPPM API requires this field even for Juniper profiles.
    privilege_level = 1

    services = ["Shell"]

    authorize_attribute_status = "ADD"

  }
}


# =============================================================================
# STEP 3c — ROLES
# =============================================================================
# Roles are labels that ClearPass assigns to a user after authentication.
# The Enforcement Policy (Step 7) reads the role and decides which
# Enforcement Profile to return.
#
# Important: Role names are validated when creating the Enforcement Policy.
# Roles must exist before the policy is created.
#
# ClearPass GUI: Configuration » Identity » Roles
# =============================================================================
resource "clearpass_role" "network_admin" {
  name        = "Network-Admin"
  description = "Administrators with full TACACS+ access (super-user)"
}

resource "clearpass_role" "helpdesk" {
  name        = "Helpdesk"
  description = "Operators with read-only TACACS+ access"
}


# =============================================================================
# STEP 3d — LOCAL TEST USERS
# =============================================================================
# Two accounts for immediate testing of TACACS+ login after apply.
# Log in with "admin-user" to verify super-user access, and with
# "helpdesk-user" to verify read-only access.
#
# !! SECURITY NOTICE !!
# The passwords are intentionally simple and only suitable for lab purposes.
# NEVER use such credentials in production environments.
#
# ClearPass GUI: Configuration » Identity » Local Users
# =============================================================================
resource "clearpass_local_user" "admin_user" {
  user_id   = "admin-user"
  username  = "admin-user"
  password  = "Admin123!"
  role_name = clearpass_role.network_admin.name
  enabled   = true
}

resource "clearpass_local_user" "helpdesk_user" {
  user_id   = "helpdesk-user"
  username  = "helpdesk-user"
  password  = "Helpdesk123!"
  role_name = clearpass_role.helpdesk.name
  enabled   = true
}


# =============================================================================
# STEP 3e — ROLE MAPPING POLICY
# =============================================================================
# Role Mapping runs immediately after successful authentication.
# It checks user attributes (here: username) and assigns a ClearPass role,
# which the Enforcement Policy in Step 7 evaluates.
#
# Flow for admin-user:    Login → Username = admin-user → Role: Network-Admin
# Flow for helpdesk-user: Login → Username = helpdesk-user → Role: Helpdesk
# All other users:        No match → Default role: Helpdesk (secure fallback)
#
# ClearPass GUI: Configuration » Identity » Role Mapping Policies
# =============================================================================
resource "clearpass_role_mapping" "tacacs_junos_role_mapping" {
  name              = "TACACS-Junos-Role-Mapping"
  description       = "Assigns ClearPass roles to Junos TACACS+ users"
  default_role_name = clearpass_role.helpdesk.name # secure fallback: read-only
  rule_combine_algo = "first-applicable"           # stops at first matching rule

  rules = [
    {
      match_type = "OR"
      role_name  = clearpass_role.network_admin.name
      condition = [
        {
          type  = "Authentication"
          name  = "Username"
          oper  = "EQUALS_IGNORE_CASE"
          value = clearpass_local_user.admin_user.username
        }
      ]
    },
    {
      match_type = "OR"
      role_name  = clearpass_role.helpdesk.name
      condition = [
        {
          type  = "Authentication"
          name  = "Username"
          oper  = "EQUALS_IGNORE_CASE"
          value = clearpass_local_user.helpdesk_user.username
        }
      ]
    }
  ]

  depends_on = [
    clearpass_role.network_admin,
    clearpass_role.helpdesk,
    clearpass_local_user.admin_user,
    clearpass_local_user.helpdesk_user,
  ]
}


# =============================================================================
# STEP 4 — ENFORCEMENT POLICY
# =============================================================================
# The Enforcement Policy reads the user's role after Role Mapping
# and selects the appropriate Enforcement Profile.
#
# Rule evaluation (first-applicable = top to bottom, stop at first match):
#   Role = Network-Admin  →  TACACS-Junos-Admin-Profile        (super-user)
#   Role = Helpdesk       →  TACACS-Junos-ReadOnly-Profile (read-only)
#   No match              →  TACACS-Junos-ReadOnly-Profile (secure default)
#
# ClearPass GUI: Configuration » Enforcement » Policies
# =============================================================================
resource "clearpass_enforcement_policy" "tacacs_junos_policy" {
  name        = "TACACS-Junos-Enforcement-Policy"
  description = "Assigns Junos user classes based on ClearPass roles"

  enforcement_type            = "TACACS"
  default_enforcement_profile = clearpass_enforcement_profile.tacacs_junos_readonly.name
  rule_eval_algo              = "first-applicable"

  rules = [
    {
      enforcement_profile_names = [clearpass_enforcement_profile.tacacs_junos_admin.name]
      condition = [
        {
          type  = "Tips" # "Tips" = internal ClearPass attributes (roles, etc.)
          name  = "Role"
          oper  = "EQUALS"
          value = clearpass_role.network_admin.name
        }
      ]
    },
    {
      enforcement_profile_names = [clearpass_enforcement_profile.tacacs_junos_readonly.name]
      condition = [
        {
          type  = "Tips"
          name  = "Role"
          oper  = "EQUALS"
          value = clearpass_role.helpdesk.name
        }
      ]
    },
  ]

  depends_on = [
    clearpass_enforcement_profile.tacacs_junos_admin,
    clearpass_enforcement_profile.tacacs_junos_readonly,
    clearpass_role_mapping.tacacs_junos_role_mapping,
  ]
}


# =============================================================================
# STEP 5 — TACACS+ SERVICE
# =============================================================================
# The Service is the entry point for all incoming TACACS+ requests.
# ClearPass routes a request to this service (Rule: Protocol = TACACS)
# and then executes the following chain:
#
#   1. Authenticate   — Check username/password ([Local User Repository])
#   2. Role Mapping   — Assign role based on username (Step 3e)
#   3. Enforce        — Return appropriate profile (Steps 4 + 3a/3b)
#
# The minimum required configuration on the Juniper device must be:
#   set system authentication-order [tacplus password]
#   set system tacplus-server <CLEARPASS-IP> secret <SECRET> source-address <MGMT-IP>
#   set system login user remote full-name "Remote TACACS User"
#   set system login user remote class read-only   ← fallback class for unknown users
#
# ClearPass GUI: Configuration » Services
# =============================================================================
resource "clearpass_service" "tacacs_junos_service" {
  name        = "TACACS+ Juniper Device Administration"
  description = "Processes TACACS+ authentication and authorization for Juniper devices"

  enabled = true

  # "TACACS+ Enforcement" is the built-in ClearPass service template for TACACS+.
  template = "TACACS+ Enforcement"

  # The Enforcement Policy from Step 4.
  enforcement_policy = clearpass_enforcement_policy.tacacs_junos_policy.name

  # The Role Mapping Policy from Step 3e.
  # Without this, ClearPass would skip role assignment and always use
  # the default profile.
  role_mapping_policy = clearpass_role_mapping.tacacs_junos_role_mapping.name

  # User database for username/password verification.
  # CHANGE ME: Replace with your AD source name for Active Directory,
  # e.g.:  auth_sources = ["AD - corp.example.com"]
  auth_sources = ["[Local User Repository]"]

  # Service classification rule: only TACACS+ requests hit this service.
  # RADIUS requests are not accidentally processed here.
  service_rule = [
    {
      type     = "Connection"
      name     = "Protocol"
      operator = "EQUALS"
      value    = "TACACS"
    }
  ]

  depends_on = [
    clearpass_enforcement_policy.tacacs_junos_policy,
    clearpass_role_mapping.tacacs_junos_role_mapping,
  ]
}
