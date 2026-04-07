---
page_title: "Changelog"
subcategory: "Release Notes"
description: |-
  Changelog for the ClearPass Terraform provider.
---

# Changelog

All notable changes to this project will be documented in this file. All dates are in dd-mm-yyyy format.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.0.9] - UNRELEASED

### Added
- Added tacacs resource for Enforcement Profiles.

### Changed
- Added validation for the `template` attribute in the `clearpass_service` resource to restrict choices to a predefined list of valid templates, and improved markdown documentation.

### Notes
- Updated provider internal dependencies.

## [v0.0.8] - 05-03-2026

### Added
- Added data sources for Authentication Methods.
- Added data sources for Certificate Trust Lists.
- Added data sources for Enforcement Policies.
- Added data sources for Enforcement Profiles.
- Added data sources for Local Users.
- Added data sources for Roles.
- Added data sources for Role Mappings.
- Added data sources for Services.

### Fixed
- Fixed Acceptance Tests for the entire provider.

### Notes
- Updated Go module dependencies.

## [v0.0.7] - 26-02-2026

### Added
- Added more verbose error messages to api client.

### Fixed
- Sometimes `clearpass_service_cert` resource failed to import certificates from a local file.

## [v0.0.6] - 26-02-2026

### Security
- Marked `public_password` as sensitive in `clearpass_auth_method` resource to prevent credential leakage in Terraform state and logs.
- Sanitized API client error messages to prevent potential leakage of raw HTTP response bodies containing sensitive session or token data.

### Added
- Added this changelog.

### Fixed
- Fixed race condition in `clearpass_service_cert` file fetching logic during certificate import.

### Notes
- Updated provider internal dependencies.
