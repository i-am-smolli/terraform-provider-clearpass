package client

import "fmt"

// AuthRequest defines the structure for the OAuth2 token request body.
type AuthRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// AuthResponse defines the structure for a successful OAuth2 token response.
type AuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// ApiError defines the structure for a generic API error response.
// We will try to parse any non-2xx response into this struct.
type ApiError struct {
	StatusCode int    `json:"-"`      // We manually fill this from the HTTP response
	Title      string `json:"title"`  // Example field, adjust to ClearPass's real errors
	Detail     string `json:"detail"` // Example field, adjust to ClearPass's real errors
}

// Error makes ApiError satisfy the 'error' interface.
func (e *ApiError) Error() string {
	return fmt.Sprintf("API Error (Status %d): %s - %s", e.StatusCode, e.Title, e.Detail)
}

// --- Local User Models (from cppm Swagger 1.2 JSON) ---

// LocalUserCreate defines the payload for creating a new local user.
type LocalUserCreate struct {
	UserID             string            `json:"user_id"`
	Username           string            `json:"username"`
	Password           string            `json:"password"`
	RoleName           string            `json:"role_name"`
	Enabled            *bool             `json:"enabled,omitempty"` // Use pointer for optional fields
	PasswordHash       string            `json:"password_hash,omitempty"`
	PasswordNTLMHash   string            `json:"password_ntlm_hash,omitempty"`
	ChangePwdNextLogin *bool             `json:"change_pwd_next_login,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

type LocalUserUpdate struct {
	UserID             string            `json:"user_id,omitempty"`
	Username           string            `json:"username,omitempty"`
	Password           string            `json:"password,omitempty"`
	RoleName           string            `json:"role_name,omitempty"`
	Enabled            *bool             `json:"enabled,omitempty"`
	PasswordHash       string            `json:"password_hash,omitempty"`
	PasswordNTLMHash   string            `json:"password_ntlm_hash,omitempty"`
	ChangePwdNextLogin *bool             `json:"change_pwd_next_login,omitempty"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

// LocalUserResult defines the payload returned for a local user.
type LocalUserResult struct {
	ID                 int               `json:"id"`
	UserID             string            `json:"user_id"`
	Username           string            `json:"username"`
	RoleName           string            `json:"role_name"`
	Enabled            bool              `json:"enabled"`
	ChangePwdNextLogin bool              `json:"change_pwd_next_login"`
	Attributes         map[string]string `json:"attributes"`
	// Add other fields from the "LocalUserResult" model here
}

// --- Role Models (from Swagger 1.2) ---

// RoleCreate defines the payload for creating a new role.
type RoleCreate struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// RoleUpdate defines the payload for updating an existing role.
type RoleUpdate struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// RoleResult defines the payload returned for a role.
type RoleResult struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RoleMappingCreate defines the payload for creating a new role mapping.
type RoleMappingCreate struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description,omitempty"`
	DefaultRoleName string                 `json:"default_role_name"`
	RuleCombineAlgo string                 `json:"rule_combine_algo"` // "first-applicable" or "evaluate-all"
	Rules           []*RulesSettingsCreate `json:"rules"`             // NOTE: API docs say "List", so we use a slice
}

// RulesSettingsCreate defines the nested "rules" block for creation.
type RulesSettingsCreate struct {
	MatchType string                          `json:"match_type"` // "AND" or "OR"
	RoleName  string                          `json:"role_name"`
	Condition []*RulesConditionSettingsCreate `json:"condition"` // NOTE: API docs say "List", so we use a slice
}

// RulesConditionSettingsCreate defines the nested "condition" block for creation.
type RulesConditionSettingsCreate struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Oper  string `json:"oper"` // 'oper' is 'operator'
	Value string `json:"value"`
}

// RoleMappingUpdate defines the payload for updating a role mapping.
type RoleMappingUpdate struct {
	Name            string                 `json:"name,omitempty"`
	Description     string                 `json:"description,omitempty"`
	DefaultRoleName string                 `json:"default_role_name,omitempty"`
	RuleCombineAlgo string                 `json:"rule_combine_algo,omitempty"`
	Rules           []*RulesSettingsUpdate `json:"rules,omitempty"`
}

// RulesSettingsUpdate defines the nested "rules" block for updating.
type RulesSettingsUpdate struct {
	MatchType string                          `json:"match_type,omitempty"`
	RoleName  string                          `json:"role_name,omitempty"`
	Condition []*RulesConditionSettingsUpdate `json:"condition,omitempty"`
}

// RulesConditionSettingsUpdate defines the nested "condition" block for updating.
type RulesConditionSettingsUpdate struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	Oper  string `json:"oper,omitempty"`
	Value string `json:"value,omitempty"`
}

// RoleMappingResult defines the payload returned for a role mapping.
type RoleMappingResult struct {
	ID              int                    `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	DefaultRoleName string                 `json:"default_role_name"`
	RuleCombineAlgo string                 `json:"rule_combine_algo"`
	Rules           []*RulesSettingsResult `json:"rules"`
}

// RulesSettingsResult defines the returned "rules" block.
type RulesSettingsResult struct {
	MatchType string                          `json:"match_type"`
	RoleName  string                          `json:"role_name"`
	Condition []*RulesConditionSettingsResult `json:"condition"`
}

// RulesConditionSettingsResult defines the returned "condition" block.
type RulesConditionSettingsResult struct {
	Type          string `json:"type"`
	Name          string `json:"name"`
	Oper          string `json:"oper"`
	Value         string `json:"value"`
	ValueDispName string `json:"value_disp_name"`
}

type EnforcementProfileCreate struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Type        string              `json:"type"`             // RADIUS, TACACS, Agent, etc.
	Action      string              `json:"action,omitempty"` // Accept, Reject, Drop
	Attributes  []*ProfileAttribute `json:"attributes,omitempty"`
	// We can add DUR/TACACS specific structs here later as needed
}

type EnforcementProfileUpdate struct {
	Name        string              `json:"name,omitempty"`
	Description string              `json:"description,omitempty"`
	Type        string              `json:"type,omitempty"`
	Action      string              `json:"action,omitempty"`
	Attributes  []*ProfileAttribute `json:"attributes,omitempty"`
}

type EnforcementProfileResult struct {
	ID          int                 `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"`
	Action      string              `json:"action"`
	Attributes  []*ProfileAttribute `json:"attributes"`
}

// ProfileAttribute is the generic key-value pair used for RADIUS, etc.
type ProfileAttribute struct {
	Type  string `json:"type"`  // e.g., "Radius:IETF"
	Name  string `json:"name"`  // e.g., "Filter-Id"
	Value string `json:"value"` // e.g., "Employee-Allow-All"
}

// --- Enforcement Policy Models ---

type EnforcementPolicyCreate struct {
	Name                      string                         `json:"name"`
	Description               string                         `json:"description,omitempty"`
	EnforcementType           string                         `json:"enforcement_type"` // RADIUS, TACACS, WEBAUTH, etc.
	DefaultEnforcementProfile string                         `json:"default_enforcement_profile"`
	RuleEvalAlgo              string                         `json:"rule_eval_algo"` // first-applicable, evaluate-all
	Rules                     []*EnforcementPolicyRuleCreate `json:"rules"`
}

type EnforcementPolicyRuleCreate struct {
	EnforcementProfileNames []string                            `json:"enforcement_profile_names"` // List of strings (Profile Names)
	Condition               []*EnforcementPolicyConditionCreate `json:"condition"`
}

type EnforcementPolicyConditionCreate struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Oper  string `json:"oper"`
	Value string `json:"value"`
}

type EnforcementPolicyUpdate struct {
	Name                      string                         `json:"name,omitempty"`
	Description               string                         `json:"description,omitempty"`
	EnforcementType           string                         `json:"enforcement_type,omitempty"`
	DefaultEnforcementProfile string                         `json:"default_enforcement_profile,omitempty"`
	RuleEvalAlgo              string                         `json:"rule_eval_algo,omitempty"`
	Rules                     []*EnforcementPolicyRuleUpdate `json:"rules,omitempty"`
}

type EnforcementPolicyRuleUpdate struct {
	EnforcementProfileNames []string                            `json:"enforcement_profile_names,omitempty"`
	Condition               []*EnforcementPolicyConditionUpdate `json:"condition,omitempty"`
}

type EnforcementPolicyConditionUpdate struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	Oper  string `json:"oper,omitempty"`
	Value string `json:"value,omitempty"`
}

type EnforcementPolicyResult struct {
	ID                        int                            `json:"id"`
	Name                      string                         `json:"name"`
	Description               string                         `json:"description"`
	EnforcementType           string                         `json:"enforcement_type"`
	DefaultEnforcementProfile string                         `json:"default_enforcement_profile"`
	RuleEvalAlgo              string                         `json:"rule_eval_algo"`
	Rules                     []*EnforcementPolicyRuleResult `json:"rules"`
}

type EnforcementPolicyRuleResult struct {
	EnforcementProfileNames []string                            `json:"enforcement_profile_names"`
	Condition               []*EnforcementPolicyConditionResult `json:"condition"`
}

type EnforcementPolicyConditionResult struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Oper  string `json:"oper"`
	Value string `json:"value"`
}

// --- Service Models ---

type ServiceCreate struct {
	Name              string         `json:"name"`
	Type              string         `json:"type,omitempty"` // Often auto-set by template, but can be sent
	Template          string         `json:"template"`
	Description       string         `json:"description,omitempty"`
	Enabled           *bool          `json:"enabled,omitempty"`
	AuthMethods       []string       `json:"auth_methods,omitempty"`
	AuthSources       []string       `json:"auth_sources,omitempty"`
	RoleMappingPolicy string         `json:"role_mapping_policy,omitempty"`
	EnfPolicy         string         `json:"enf_policy,omitempty"` // This is "Enforcement Policy"
	StripUsername     *bool          `json:"strip_username,omitempty"`
	RulesMatchType    string         `json:"rules_match_type,omitempty"` // MATCHES_ANY oder MATCHES_ALL
	RulesConditions   []*ServiceRule `json:"rules_conditions,omitempty"`
}

type ServiceUpdate struct {
	Name              string         `json:"name,omitempty"`
	Template          string         `json:"template,omitempty"`
	Description       string         `json:"description,omitempty"`
	Enabled           *bool          `json:"enabled,omitempty"`
	AuthMethods       []string       `json:"auth_methods,omitempty"`
	AuthSources       []string       `json:"auth_sources,omitempty"`
	RoleMappingPolicy string         `json:"role_mapping_policy,omitempty"`
	EnfPolicy         string         `json:"enf_policy,omitempty"`
	StripUsername     *bool          `json:"strip_username,omitempty"`
	RulesMatchType    string         `json:"rules_match_type,omitempty"`
	RulesConditions   []*ServiceRule `json:"rules_conditions,omitempty"`
}

type ServiceResult struct {
	ID                int            `json:"id"`
	Name              string         `json:"name"`
	Type              string         `json:"type"`
	Template          string         `json:"template"`
	Description       string         `json:"description"`
	Enabled           bool           `json:"enabled"`
	AuthMethods       []string       `json:"auth_methods"`
	AuthSources       []string       `json:"auth_sources"`
	RoleMappingPolicy string         `json:"role_mapping_policy"`
	EnfPolicy         string         `json:"enf_policy"`
	StripUsername     bool           `json:"strip_username"`
	RulesMatchType    string         `json:"rules_match_type"`
	RulesConditions   []*ServiceRule `json:"rules_conditions"`
}

type ServiceRule struct {
	Type     string `json:"type"`     // "Radius:IETF"
	Name     string `json:"name"`     // "NAS-Port-Type"
	Operator string `json:"operator"` // "EQUALS"
	Value    string `json:"value"`    // "15"
}
