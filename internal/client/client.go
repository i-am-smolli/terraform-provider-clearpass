package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ClientInterface defines the contract for our API client.
// The Terraform provider will only ever use this interface.
type ClientInterface interface {
	// Local User
	CreateLocalUser(ctx context.Context, user *LocalUserCreate) (*LocalUserResult, error)
	GetLocalUser(ctx context.Context, id int) (*LocalUserResult, error)
	UpdateLocalUser(ctx context.Context, id int, user *LocalUserUpdate) (*LocalUserResult, error)
	DeleteLocalUser(ctx context.Context, id int) error

	// Role
	CreateRole(ctx context.Context, role *RoleCreate) (*RoleResult, error)
	GetRole(ctx context.Context, id int) (*RoleResult, error)
	UpdateRole(ctx context.Context, id int, role *RoleUpdate) (*RoleResult, error)
	DeleteRole(ctx context.Context, id int) error

	// RoleMapping
	CreateRoleMapping(ctx context.Context, roleMap *RoleMappingCreate) (*RoleMappingResult, error)
	GetRoleMapping(ctx context.Context, id int) (*RoleMappingResult, error)
	UpdateRoleMapping(ctx context.Context, id int, roleMap *RoleMappingUpdate) (*RoleMappingResult, error)
	DeleteRoleMapping(ctx context.Context, id int) error

	// EnforcementProfile
	CreateEnforcementProfile(ctx context.Context, profile *EnforcementProfileCreate) (*EnforcementProfileResult, error)
	GetEnforcementProfile(ctx context.Context, id int) (*EnforcementProfileResult, error)
	UpdateEnforcementProfile(ctx context.Context, id int, profile *EnforcementProfileUpdate) (*EnforcementProfileResult, error)
	DeleteEnforcementProfile(ctx context.Context, id int) error

	// EnforcementPolicy
	CreateEnforcementPolicy(ctx context.Context, policy *EnforcementPolicyCreate) (*EnforcementPolicyResult, error)
	GetEnforcementPolicy(ctx context.Context, id int) (*EnforcementPolicyResult, error)
	UpdateEnforcementPolicy(ctx context.Context, id int, policy *EnforcementPolicyUpdate) (*EnforcementPolicyResult, error)
	DeleteEnforcementPolicy(ctx context.Context, id int) error

	//Service
	CreateService(ctx context.Context, service *ServiceCreate) (*ServiceResult, error)
	GetService(ctx context.Context, id int) (*ServiceResult, error)
	UpdateService(ctx context.Context, id int, service *ServiceUpdate) (*ServiceResult, error)
	DeleteService(ctx context.Context, id int) error

	// ServiceCert
	CreateServiceCert(ctx context.Context, cert *ServiceCertCreate) (*ServiceCertResult, error)
	GetServiceCert(ctx context.Context, id int) (*ServiceCertResult, error)
	DeleteServiceCert(ctx context.Context, id int) error

	// CertTrustList
	CreateCertTrustList(ctx context.Context, cert *CertTrustListCreate) (*CertTrustList, error)
	GetCertTrustList(ctx context.Context, id int) (*CertTrustList, error)
	UpdateCertTrustList(ctx context.Context, id int, cert *CertTrustListUpdate) (*CertTrustList, error)
	DeleteCertTrustList(ctx context.Context, id int) error

	// AuthMethod
	CreateAuthMethod(ctx context.Context, authMethod *AuthMethodCreate) (*AuthMethodResult, error)
	GetAuthMethod(ctx context.Context, id int) (*AuthMethodResult, error)
	UpdateAuthMethod(ctx context.Context, id int, authMethod *AuthMethodUpdate) (*AuthMethodResult, error)
	DeleteAuthMethod(ctx context.Context, id int) error

	// Helper
	GetHost() string
	GetServerVersion(ctx context.Context) (*ServerVersionResult, error)
}

// apiClient is the concrete implementation of our ClientInterface.
// It is kept private (lowercase 'a') to force creation via NewClient.
type apiClient struct {
	host       string
	token      string
	httpClient *http.Client
}

// NewClient is the factory function for our API client.
// It takes the host and the *already-fetched* access token.
func NewClient(host, token string, insecure bool) ClientInterface {

	// Create a transport that trusts self-signed certs if insecure is true
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	return &apiClient{
		host:  host,
		token: token,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second, // Always set a timeout!
		},
	}
}

func (c *apiClient) GetHost() string {
	return c.host
}

// GetServerVersion retrieves the ClearPass server version.
func (c *apiClient) GetServerVersion(ctx context.Context) (*ServerVersionResult, error) {
	// Endpoint based on standard ClearPass API structure
	path := "/api/server/version"

	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result ServerVersionResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// --- API Methods ---

// CreateLocalUser creates a new local user.
func (c *apiClient) CreateLocalUser(ctx context.Context, user *LocalUserCreate) (*LocalUserResult, error) {

	payloadBytes, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateLocalUser payload: %w", err)
	}

	// Use our DRY helpers
	req, err := c.newRequest(ctx, "POST", "/api/local-user", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result LocalUserResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetLocalUser retrieves a local user by its numeric ID.
func (c *apiClient) GetLocalUser(ctx context.Context, id int) (*LocalUserResult, error) {
	// Path from Swagger 1.2 spec: /local-user/{local_user_id}
	path := fmt.Sprintf("/api/local-user/%d", id)

	req, err := c.newRequest(ctx, "GET", path, nil) // GET has no body
	if err != nil {
		return nil, err
	}

	var result LocalUserResult
	if err := c.do(req, &result); err != nil {
		// Handle 404 (Not Found) specifically
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil // Return nil, nil to indicate "not found"
		}
		return nil, err // Other errors
	}

	return &result, nil
}

// UpdateLocalUser updates an existing local user using PATCH.
func (c *apiClient) UpdateLocalUser(ctx context.Context, id int, user *LocalUserUpdate) (*LocalUserResult, error) {
	path := fmt.Sprintf("/api/local-user/%d", id)

	payloadBytes, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateLocalUser payload: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result LocalUserResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteLocalUser deletes an existing local user by its numeric ID.
func (c *apiClient) DeleteLocalUser(ctx context.Context, id int) error {
	// Build the path from the Swagger 1.2 spec: /local-user/{local_user_id}
	path := fmt.Sprintf("/api/local-user/%d", id)

	// Create the request (DELETE has no body, so we pass 'nil')
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}

	// Execute the request.
	// We pass 'nil' for the response struct 'v' because the API
	// returns 'void' (no content), and our 'do' helper will handle this.
	if err := c.do(req, nil); err != nil {
		return err
	}

	// If 'do' returned no error, the 2xx status was received.
	return nil
}

// CreateRole creates a new role.
func (c *apiClient) CreateRole(ctx context.Context, role *RoleCreate) (*RoleResult, error) {
	payloadBytes, err := json.Marshal(role)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateRole payload: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/role", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result RoleResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRole retrieves a role by its numeric ID.
func (c *apiClient) GetRole(ctx context.Context, id int) (*RoleResult, error) {
	path := fmt.Sprintf("/api/role/%d", id)

	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result RoleResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil // Not found
		}
		return nil, err
	}

	return &result, nil
}

// UpdateRole updates an existing role using PATCH.
func (c *apiClient) UpdateRole(ctx context.Context, id int, role *RoleUpdate) (*RoleResult, error) {
	path := fmt.Sprintf("/api/role/%d", id)

	payloadBytes, err := json.Marshal(role)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateRole payload: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result RoleResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteRole deletes an existing role by its numeric ID.
func (c *apiClient) DeleteRole(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/role/%d", id)

	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}

	if err := c.do(req, nil); err != nil {
		return err
	}

	return nil
}

// --- DRY Helper Functions ---

// newRequest is a private helper to build and configure a new HTTP request.
// It automatically adds the base URL, auth token, and required headers.
func (c *apiClient) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	url := "https://" + c.host + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return req, nil
}

// do is a private helper to execute an HTTP request.
func (c *apiClient) do(req *http.Request, v interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		cerr := resp.Body.Close()
		if cerr != nil {
			// Optionally log or handle the error, but do not shadow the main error
			fmt.Printf("warning: error closing response body: %v\n", cerr)
		}
	}()

	// Wir lesen den GANZEN Body in den Speicher, um ihn im Fehlerfall auszugeben
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Debug-Ausgabe (optional, entfernen Sie das später)
	// log.Printf("DEBUG API RESPONSE: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))

	// --- Robust Error Handling ---
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr ApiError
		// Wir nutzen json.Unmarshal statt Decoder, weil wir die Bytes schon haben
		if err = json.Unmarshal(bodyBytes, &apiErr); err != nil {
			// Wenn kein JSON, geben wir einen generischen Fehler zurück!
			// We avoid dumping the raw body Bytes directly to prevent leaking
			// sensitive data like session tokens that might appear in HTML error pages.
			snippet := string(bodyBytes)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "... (truncated)"
			}
			return &ApiError{
				StatusCode: resp.StatusCode,
				Title:      "Unknown API Error (Non-JSON)",
				Detail:     snippet,
			}
		}

		// Some ClearPass API endpoints return errors in unexpected formats.
		// Append the raw body to the detail so we can always see it during debugging.
		snippet := string(bodyBytes)
		if len(snippet) > 500 {
			snippet = snippet[:500] + "... (truncated)"
		}
		apiErr.Detail = apiErr.Detail + "\nRaw Response: " + snippet
		apiErr.StatusCode = resp.StatusCode
		return &apiErr
	}

	// --- Success Handling ---
	if v == nil {
		return nil
	}

	if err = json.Unmarshal(bodyBytes, v); err != nil {
		snippet := string(bodyBytes)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "... (truncated)"
		}
		return fmt.Errorf("failed to decode successful response. Body snippet: %s. Error: %w", snippet, err)
	}

	return nil
}

// --- Role Mapping API Methods ---

// CreateRoleMapping creates a new role mapping policy.
func (c *apiClient) CreateRoleMapping(ctx context.Context, roleMap *RoleMappingCreate) (*RoleMappingResult, error) {
	payloadBytes, err := json.Marshal(roleMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateRoleMapping payload: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/role-mapping", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result RoleMappingResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRoleMapping retrieves a role mapping by its numeric ID.
func (c *apiClient) GetRoleMapping(ctx context.Context, id int) (*RoleMappingResult, error) {
	path := fmt.Sprintf("/api/role-mapping/%d", id)

	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result RoleMappingResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil // Not found
		}
		return nil, err
	}

	return &result, nil
}

// UpdateRoleMapping updates an existing role mapping using PATCH.
func (c *apiClient) UpdateRoleMapping(ctx context.Context, id int, roleMap *RoleMappingUpdate) (*RoleMappingResult, error) {
	path := fmt.Sprintf("/api/role-mapping/%d", id)

	payloadBytes, err := json.Marshal(roleMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateRoleMapping payload: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result RoleMappingResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteRoleMapping deletes an existing role mapping by its numeric ID.
func (c *apiClient) DeleteRoleMapping(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/role-mapping/%d", id)

	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}

	if err := c.do(req, nil); err != nil {
		return err
	}

	return nil
}

// --- Enforcement Profile API Methods ---

func (c *apiClient) CreateEnforcementProfile(ctx context.Context, profile *EnforcementProfileCreate) (*EnforcementProfileResult, error) {
	payloadBytes, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateEnforcementProfile: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/enforcement-profile", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result EnforcementProfileResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) GetEnforcementProfile(ctx context.Context, id int) (*EnforcementProfileResult, error) {
	path := fmt.Sprintf("/api/enforcement-profile/%d", id)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result EnforcementProfileResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) UpdateEnforcementProfile(ctx context.Context, id int, profile *EnforcementProfileUpdate) (*EnforcementProfileResult, error) {
	path := fmt.Sprintf("/api/enforcement-profile/%d", id)
	payloadBytes, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateEnforcementProfile: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result EnforcementProfileResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) DeleteEnforcementProfile(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/enforcement-profile/%d", id)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// --- Enforcement Policy API Methods ---

func (c *apiClient) CreateEnforcementPolicy(ctx context.Context, policy *EnforcementPolicyCreate) (*EnforcementPolicyResult, error) {
	payloadBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateEnforcementPolicy: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/enforcement-policy", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result EnforcementPolicyResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) GetEnforcementPolicy(ctx context.Context, id int) (*EnforcementPolicyResult, error) {
	path := fmt.Sprintf("/api/enforcement-policy/%d", id)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result EnforcementPolicyResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) UpdateEnforcementPolicy(ctx context.Context, id int, policy *EnforcementPolicyUpdate) (*EnforcementPolicyResult, error) {
	path := fmt.Sprintf("/api/enforcement-policy/%d", id)
	payloadBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateEnforcementPolicy: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result EnforcementPolicyResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) DeleteEnforcementPolicy(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/enforcement-policy/%d", id)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// --- Service API Methods ---

func (c *apiClient) CreateService(ctx context.Context, service *ServiceCreate) (*ServiceResult, error) {
	payloadBytes, err := json.Marshal(service)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateService: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/config/service", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result ServiceResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) GetService(ctx context.Context, id int) (*ServiceResult, error) {
	path := fmt.Sprintf("/api/config/service/%d", id)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result ServiceResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) UpdateService(ctx context.Context, id int, service *ServiceUpdate) (*ServiceResult, error) {
	path := fmt.Sprintf("/api/config/service/%d", id)
	payloadBytes, err := json.Marshal(service)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateService: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result ServiceResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) DeleteService(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/config/service/%d", id)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// --- ServiceCert API Methods ---

func (c *apiClient) CreateServiceCert(ctx context.Context, cert *ServiceCertCreate) (*ServiceCertResult, error) {
	payloadBytes, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateServiceCert: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/service-cert", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result ServiceCertResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) GetServiceCert(ctx context.Context, id int) (*ServiceCertResult, error) {
	path := fmt.Sprintf("/api/service-cert/%d", id)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result ServiceCertResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) DeleteServiceCert(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/service-cert/%d", id)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// --- CertTrustList API Methods ---

func (c *apiClient) CreateCertTrustList(ctx context.Context, cert *CertTrustListCreate) (*CertTrustList, error) {
	payloadBytes, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateCertTrustList: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/cert-trust-list", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result CertTrustList
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) GetCertTrustList(ctx context.Context, id int) (*CertTrustList, error) {
	path := fmt.Sprintf("/api/cert-trust-list/%d", id)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result CertTrustList
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) UpdateCertTrustList(ctx context.Context, id int, cert *CertTrustListUpdate) (*CertTrustList, error) {
	path := fmt.Sprintf("/api/cert-trust-list/%d", id)
	payloadBytes, err := json.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateCertTrustList: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result CertTrustList
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) DeleteCertTrustList(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/cert-trust-list/%d", id)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// --- AuthMethod API Methods ---

func (c *apiClient) CreateAuthMethod(ctx context.Context, authMethod *AuthMethodCreate) (*AuthMethodResult, error) {
	payloadBytes, err := json.Marshal(authMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CreateAuthMethod: %w", err)
	}

	req, err := c.newRequest(ctx, "POST", "/api/auth-method", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result AuthMethodResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) GetAuthMethod(ctx context.Context, id int) (*AuthMethodResult, error) {
	path := fmt.Sprintf("/api/auth-method/%d", id)
	req, err := c.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result AuthMethodResult
	if err := c.do(req, &result); err != nil {
		if apiErr, ok := err.(*ApiError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) UpdateAuthMethod(ctx context.Context, id int, authMethod *AuthMethodUpdate) (*AuthMethodResult, error) {
	path := fmt.Sprintf("/api/auth-method/%d", id)
	payloadBytes, err := json.Marshal(authMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal UpdateAuthMethod: %w", err)
	}

	req, err := c.newRequest(ctx, "PATCH", path, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	var result AuthMethodResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *apiClient) DeleteAuthMethod(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/auth-method/%d", id)
	req, err := c.newRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
