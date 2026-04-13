# =============================================================================
# ClearPass TACACS+ MVP - Minimum Viable Product
# =============================================================================
# This file configures a complete TACACS+ setup in Aruba ClearPass Policy
# Manager using Terraform. Read it top to bottom like a configuration guide.
#
# WHAT THIS CREATES:
#   1. A Network Device          — the switch/router that talks TACACS+ to ClearPass
#   2. A Network Device Group    — groups devices by subnet for easy management
#   3. Two Enforcement Profiles  — Admin (full access) and ReadOnly (show commands only)
#   4. Two Roles                 — "Network-Admin" and "Helpdesk"
#   5. Two Local Test Users      — admin-user (priv 15) and helpdesk-user (priv 1)
#   6. A Role Mapping Policy     — maps usernames to roles at login time
#   7. An Enforcement Policy     — picks the right profile based on the user's role
#   8. A TACACS+ Service         — the entry point that wires everything together
#
# HOW TO USE:
#   Search for "CHANGE ME" in this file and replace those values with your own.
# =============================================================================


# -----------------------------------------------------------------------------
# PROVIDER CONFIGURATION
# This block tells Terraform which provider plugin to use and how to connect
# to your ClearPass server.
# -----------------------------------------------------------------------------

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
# STEP 1 — NETWORK DEVICE (your TACACS+ client)
# =============================================================================
# This is the switch or router that will authenticate admin logins via ClearPass.
# Every device that sends TACACS+ requests MUST be registered here.
#
# ClearPass GUI: Configuration » Network » Devices
# =============================================================================
resource "clearpass_network_device" "tacacs_switch" {
  # CHANGE ME: A friendly name for your device (shown in ClearPass reports)
  name = "Cisco-Switch-01"

  # CHANGE ME: The management IP address of your switch/router
  ip_address = "10.10.10.10"

  # CHANGE ME: The TACACS+ shared secret — must match what is configured
  # on the device itself (e.g., "tacacs-server key my_shared_secret" on Cisco IOS)
  tacacs_secret = "my_shared_secret"

  description = "Core distribution switch — TACACS+ managed via Terraform"
  vendor_name = "Aruba"
}


# =============================================================================
# STEP 2 — NETWORK DEVICE GROUP
# =============================================================================
# Device groups let you organise your network devices by subnet, regex pattern,
# or an explicit list. They can be referenced in enforcement profiles to apply
# different policies to different parts of your network.
#
# This example creates a subnet-based group for your management network.
# CHANGE ME: Adjust the subnet to match your environment.
#
# ClearPass GUI: Configuration » Network » Device Groups
# =============================================================================
resource "clearpass_network_device_group" "tacacs_devices" {
  name         = "TACACS-Devices"
  description  = "All switches and routers managed via TACACS+"

  # "subnet" means every device in this IP range is part of the group.
  group_format = "subnet"
  value        = "10.10.0.0/24" # CHANGE ME: your management network in CIDR notation
}


# =============================================================================
# STEP 3a — ENFORCEMENT PROFILE: Network Administrator (Full Access)
# =============================================================================
# This profile is returned to the device when a user is a Network-Admin.
# Privilege level 15 is the highest level on Cisco IOS/IOS-XE/NX-OS.
# The device will allow the user to run every command, including config mode.
#
# ClearPass GUI: Configuration » Enforcement » Profiles
# =============================================================================
resource "clearpass_enforcement_profile" "tacacs_admin" {
  name        = "TACACS-Admin-Profile"
  description = "Full admin access — privilege level 15 (all commands permitted)"

  # Must be "TACACS" for TACACS+ enforcement
  type = "TACACS"

  # Required by ClearPass API for TACACS profiles
  action = "Accept"

  tacacs_service_param = {
    # Privilege level 15 = full admin on Cisco IOS/IOS-XE/NX-OS
    privilege_level = 15

    # Which TACACS+ service(s) this profile applies to
    services = ["Shell"]

    # ADD = add these attributes to the TACACS+ authorization response
    authorize_attribute_status = "ADD"

    tacacs_command_config = {
      service_type = "Shell"

      # true = any command not explicitly listed is PERMITTED
      permit_unmatched_cmds = true

      # API requires command config details to be present for TACACS profile
      commands = [
        {
          command               = "show"
          permit_unmatched_args = true
        }
      ]
    }
  }
}


# =============================================================================
# STEP 3b — ENFORCEMENT PROFILE: Read-Only / Helpdesk (View Only)
# =============================================================================
# This profile is returned to the device when a user is a Helpdesk member.
# Privilege level 1 prevents access to configuration mode on Cisco devices.
# Only the commands explicitly listed below (show, exit) are permitted.
#
# ClearPass GUI: Configuration » Enforcement » Profiles
# =============================================================================
resource "clearpass_enforcement_profile" "tacacs_readonly" {
  name        = "TACACS-ReadOnly-Profile"
  description = "Read-only access — privilege level 1 (show commands only)"

  type = "TACACS"

  # Required by ClearPass API for TACACS profiles
  action = "Accept"

  tacacs_service_param = {
    privilege_level = 1

    services = ["Shell"]

    authorize_attribute_status = "ADD"

    tacacs_command_config = {
      service_type = "Shell"

      # false = only explicitly listed commands are permitted
      permit_unmatched_cmds = false

      commands = [
        {
          # Allow "show" with any arguments
          command              = "show"
          permit_unmatched_args = true
        },
        {
          # Allow "exit" to close the session gracefully
          command              = "exit"
          permit_unmatched_args = true
        },
      ]
    }
  }
}


# =============================================================================
# STEP 3c — ROLES
# =============================================================================
# Roles are labels that ClearPass assigns to an authenticated user.
# The Enforcement Policy (Step 7) reads this label and decides which
# Enforcement Profile to send back to the device.
#
# Important: ClearPass validates role names in policy rules at creation time.
# The roles must exist before the enforcement policy is created.
#
# ClearPass GUI: Configuration » Identity » Roles
# =============================================================================
resource "clearpass_role" "network_admin" {
  name        = "Network-Admin"
  description = "Administrators with full TACACS+ privilege"
}

resource "clearpass_role" "helpdesk" {
  name        = "Helpdesk"
  description = "Operators with read-only TACACS+ privilege"
}


# =============================================================================
# STEP 3d — LOCAL TEST USERS
# =============================================================================
# These two accounts let you test TACACS+ login immediately after apply.
# Log into your switch with "admin-user" to get privilege 15, and with
# "helpdesk-user" to verify that read-only access (privilege 1) works.
#
# !! SECURITY WARNING !!
# The passwords below are intentionally trivial for lab use only.
# NEVER deploy these credentials in a production environment.
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
# Role mapping runs immediately after a user authenticates successfully.
# It inspects user attributes (here: the username) and assigns a ClearPass
# Role. That role is then read by the Enforcement Policy in Step 7.
#
# Flow for admin-user:   login → Username = admin-user → Role: Network-Admin
# Flow for helpdesk-user: login → Username = helpdesk-user → Role: Helpdesk
# Flow for any other user: no rule matches → default Role: Helpdesk (safe fallback)
#
# ClearPass GUI: Configuration » Identity » Role Mapping Policies
# =============================================================================
resource "clearpass_role_mapping" "tacacs_role_mapping" {
  name              = "TACACS-Role-Mapping"
  description       = "Maps usernames to TACACS roles for lab testing"
  default_role_name = clearpass_role.helpdesk.name # safe fallback: read-only
  rule_combine_algo = "first-applicable"            # stop at the first matching rule

  rules = [
    {
      match_type = "OR"
      role_name  = clearpass_role.network_admin.name
      condition = [
        {
          type  = "Authentication"
          name  = "Username"
          oper  = "EQUALS"
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
          oper  = "EQUALS"
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
# After role mapping assigns a role, the enforcement policy runs.
# It reads the role and selects the matching enforcement profile to return.
#
# Rule evaluation order (first-applicable = top-down, stop at first match):
#   Role = Network-Admin  →  TACACS-Admin-Profile   (privilege level 15)
#   Role = Helpdesk       →  TACACS-ReadOnly-Profile  (privilege level 1)
#   No match              →  TACACS-ReadOnly-Profile  (safe default)
#
# ClearPass GUI: Configuration » Enforcement » Policies
# =============================================================================
resource "clearpass_enforcement_policy" "tacacs_policy" {
  name        = "TACACS-Enforcement-Policy"
  description = "Assigns TACACS+ privilege levels based on ClearPass Roles"

  enforcement_type            = "TACACS"
  default_enforcement_profile = clearpass_enforcement_profile.tacacs_readonly.name
  rule_eval_algo              = "first-applicable"

  rules = [
    {
      enforcement_profile_names = [clearpass_enforcement_profile.tacacs_admin.name]
      condition = [
        {
          type  = "Tips"  # "Tips" = ClearPass internal attributes (Roles, etc.)
          name  = "Role"
          oper  = "EQUALS"
          value = clearpass_role.network_admin.name
        }
      ]
    },
    {
      enforcement_profile_names = [clearpass_enforcement_profile.tacacs_readonly.name]
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
    clearpass_enforcement_profile.tacacs_admin,
    clearpass_enforcement_profile.tacacs_readonly,
    clearpass_role_mapping.tacacs_role_mapping,
  ]
}


# =============================================================================
# STEP 5 — TACACS+ SERVICE
# =============================================================================
# The Service is the entry point for all incoming TACACS+ requests.
# ClearPass matches a request to this service using the service rule below
# (Protocol = TACACS), then runs the following chain:
#
#   1. Authenticate — check username/password against [Local User Repository]
#   2. Role Mapping — assign a role based on the username (Step 3e)
#   3. Enforce      — pick and return the right profile (Steps 4 + 3a/3b)
#
# ClearPass GUI: Configuration » Services
# =============================================================================
resource "clearpass_service" "tacacs_service" {
  name        = "TACACS+ Network Device Administration"
  description = "Handles all TACACS+ authentication and authorization requests"

  enabled = true

  # "TACACS+ Enforcement" is the built-in ClearPass service template for TACACS+.
  template = "TACACS+ Enforcement"

  # The enforcement policy selected in Step 4.
  enforcement_policy = clearpass_enforcement_policy.tacacs_policy.name

  # The role mapping policy from Step 3e.
  # Without this, ClearPass would skip role assignment and always hit the default.
  role_mapping_policy = clearpass_role_mapping.tacacs_role_mapping.name

  # Where ClearPass looks up usernames and passwords.
  # [Local User Repository] is the built-in ClearPass user store (with square brackets).
  # CHANGE ME: replace with your AD source name if you use Active Directory,
  # e.g. auth_sources = ["AD - corp.example.com"]
  auth_sources = ["[Local User Repository]"]

  # Service classification rule: only match requests coming in over TACACS+.
  # This prevents RADIUS requests from accidentally hitting this service.
  service_rule = [
    {
      type     = "Connection"
      name     = "Protocol"
      operator = "EQUALS"
      value    = "TACACS"
    }
  ]

  depends_on = [
    clearpass_enforcement_policy.tacacs_policy,
    clearpass_role_mapping.tacacs_role_mapping,
  ]
}
