# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.0.6]

### Security
- Marked `public_password` as sensitive in `clearpass_auth_method` resource to prevent credential leakage in Terraform state and logs.
- Sanitized API client error messages to prevent potential leakage of raw HTTP response bodies containing sensitive session or token data.

### Added
- Added this changelog.

### Fixed
- Fixed race condition in `clearpass_service_cert` file fetching logic during certificate import.
- Updated provider internal dependencies.
