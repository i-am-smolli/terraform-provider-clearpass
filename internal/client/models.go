package client

import (
	"encoding/json"
	"fmt"
	"strconv"
)

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
	Name                   string              `json:"name"`
	Description            string              `json:"description,omitempty"`
	Type                   string              `json:"type"`             // RADIUS, TACACS, Agent, etc.
	Action                 string              `json:"action,omitempty"` // Accept, Reject, Drop
	DeviceGroupList        []string            `json:"device_group_list,omitempty"`
	AgentTemplate          string              `json:"agent_template,omitempty"`
	PostAuthTemplate       string              `json:"post_auth_template,omitempty"`
	RadiusDynAuthzTemplate string              `json:"radius_dyn_authz_template,omitempty"`
	Attributes             []*ProfileAttribute `json:"attributes,omitempty"`
	// Complex nested structures - storing as JSON for now
	TacacsServiceParams interface{} `json:"tacacs_service_params,omitempty"`
	DurConfig           interface{} `json:"dur_config,omitempty"`
}

type EnforcementProfileUpdate struct {
	Name                   string              `json:"name,omitempty"`
	Description            string              `json:"description,omitempty"`
	Type                   string              `json:"type,omitempty"`
	Action                 string              `json:"action,omitempty"`
	DeviceGroupList        []string            `json:"device_group_list,omitempty"`
	AgentTemplate          string              `json:"agent_template,omitempty"`
	PostAuthTemplate       string              `json:"post_auth_template,omitempty"`
	RadiusDynAuthzTemplate string              `json:"radius_dyn_authz_template,omitempty"`
	Attributes             []*ProfileAttribute `json:"attributes,omitempty"`
	TacacsServiceParams    interface{}         `json:"tacacs_service_params,omitempty"`
	DurConfig              interface{}         `json:"dur_config,omitempty"`
}

type EnforcementProfileResult struct {
	ID                     int                 `json:"id"`
	Name                   string              `json:"name"`
	Description            string              `json:"description"`
	Type                   string              `json:"type"`
	Action                 string              `json:"action"`
	DeviceGroupList        []string            `json:"device_group_list"`
	AgentTemplate          string              `json:"agent_template"`
	PostAuthTemplate       string              `json:"post_auth_template"`
	RadiusDynAuthzTemplate string              `json:"radius_dyn_authz_template"`
	Attributes             []*ProfileAttribute `json:"attributes"`
	TacacsServiceParams    interface{}         `json:"tacacs_service_params"`
	DurConfig              interface{}         `json:"dur_config"`
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
	Name                           string         `json:"name"`
	Type                           string         `json:"type,omitempty"` // Often auto-set by template, but can be sent
	Template                       string         `json:"template"`
	Description                    string         `json:"description,omitempty"`
	Enabled                        *bool          `json:"enabled,omitempty"`
	AuthMethods                    []string       `json:"auth_methods,omitempty"`
	AuthSources                    []string       `json:"auth_sources,omitempty"`
	RoleMappingPolicy              string         `json:"role_mapping_policy,omitempty"`
	EnfPolicy                      string         `json:"enf_policy,omitempty"` // This is "Enforcement Policy"
	StripUsername                  *bool          `json:"strip_username,omitempty"`
	RulesMatchType                 string         `json:"rules_match_type,omitempty"` // MATCHES_ANY oder MATCHES_ALL
	RulesConditions                []*ServiceRule `json:"rules_conditions,omitempty"`
	DefaultPostureToken            string         `json:"default_posture_token,omitempty"`
	PosturePolicies                []string       `json:"posture_policies,omitempty"`
	MonitorMode                    *bool          `json:"monitor_mode,omitempty"`
	StripUsernameCSV               string         `json:"strip_username_csv,omitempty"`
	ServiceCertCN                  string         `json:"service_cert_cn,omitempty"`
	UseCachedPolicyResults         *bool          `json:"use_cached_policy_results,omitempty"`
	AuthzSources                   []string       `json:"authz_sources,omitempty"`
	PostureEnabled                 *bool          `json:"posture_enabled,omitempty"`
	RemediateEndHosts              *bool          `json:"remediate_end_hosts,omitempty"`
	RemediationURL                 string         `json:"remediation_url,omitempty"`
	AuditEnabled                   *bool          `json:"audit_enabled,omitempty"`
	AuditServer                    string         `json:"audit_server,omitempty"`
	AuditTriggerCondition          string         `json:"audit_trigger_condition,omitempty"`
	AuditMacAuthClientType         string         `json:"audit_mac_auth_client_type,omitempty"`
	ActionAfterAudit               string         `json:"action_after_audit,omitempty"`
	AuditCoaAction                 string         `json:"audit_coa_acton,omitempty"` // Note: API typo 'acton'
	ProfilerEnabled                *bool          `json:"profiler_enabled,omitempty"`
	ProfilerEndpointClassification []string       `json:"profiler_endpoint_classification,omitempty"`
	ProfilerCoaAction              string         `json:"profiler_coa_action,omitempty"`
	AcctProxyEnabled               *bool          `json:"acct_proxy_enabled,omitempty"`
	AcctProxyTargets               []string       `json:"acct_proxy_targets,omitempty"`
	RadiusProxyScheme              string         `json:"radius_proxy_scheme,omitempty"`
	RadiusProxyTargets             []string       `json:"radius_proxy_targets,omitempty"`
	RadiusProxyEnableForAcct       *bool          `json:"radius_proxy_enable_for_acct,omitempty"`
}

type ServiceUpdate struct {
	Name                           string         `json:"name,omitempty"`
	Template                       string         `json:"template,omitempty"`
	Description                    string         `json:"description,omitempty"`
	Enabled                        *bool          `json:"enabled,omitempty"`
	AuthMethods                    []string       `json:"auth_methods,omitempty"`
	AuthSources                    []string       `json:"auth_sources,omitempty"`
	RoleMappingPolicy              string         `json:"role_mapping_policy,omitempty"`
	EnfPolicy                      string         `json:"enf_policy,omitempty"`
	StripUsername                  *bool          `json:"strip_username,omitempty"`
	RulesMatchType                 string         `json:"rules_match_type,omitempty"`
	RulesConditions                []*ServiceRule `json:"rules_conditions,omitempty"`
	DefaultPostureToken            string         `json:"default_posture_token,omitempty"`
	PosturePolicies                []string       `json:"posture_policies,omitempty"`
	MonitorMode                    *bool          `json:"monitor_mode,omitempty"`
	StripUsernameCSV               string         `json:"strip_username_csv,omitempty"`
	ServiceCertCN                  string         `json:"service_cert_cn,omitempty"`
	UseCachedPolicyResults         *bool          `json:"use_cached_policy_results,omitempty"`
	AuthzSources                   []string       `json:"authz_sources,omitempty"`
	PostureEnabled                 *bool          `json:"posture_enabled,omitempty"`
	RemediateEndHosts              *bool          `json:"remediate_end_hosts,omitempty"`
	RemediationURL                 string         `json:"remediation_url,omitempty"`
	AuditEnabled                   *bool          `json:"audit_enabled,omitempty"`
	AuditServer                    string         `json:"audit_server,omitempty"`
	AuditTriggerCondition          string         `json:"audit_trigger_condition,omitempty"`
	AuditMacAuthClientType         string         `json:"audit_mac_auth_client_type,omitempty"`
	ActionAfterAudit               string         `json:"action_after_audit,omitempty"`
	AuditCoaAction                 string         `json:"audit_coa_acton,omitempty"` // Note: API typo 'acton'
	ProfilerEnabled                *bool          `json:"profiler_enabled,omitempty"`
	ProfilerEndpointClassification []string       `json:"profiler_endpoint_classification,omitempty"`
	ProfilerCoaAction              string         `json:"profiler_coa_action,omitempty"`
	AcctProxyEnabled               *bool          `json:"acct_proxy_enabled,omitempty"`
	AcctProxyTargets               []string       `json:"acct_proxy_targets,omitempty"`
	RadiusProxyScheme              string         `json:"radius_proxy_scheme,omitempty"`
	RadiusProxyTargets             []string       `json:"radius_proxy_targets,omitempty"`
	RadiusProxyEnableForAcct       *bool          `json:"radius_proxy_enable_for_acct,omitempty"`
}

type ServiceResult struct {
	ID                             int            `json:"id"`
	Name                           string         `json:"name"`
	Type                           string         `json:"type"`
	Template                       string         `json:"template"`
	Description                    string         `json:"description"`
	Enabled                        bool           `json:"enabled"`
	AuthMethods                    []string       `json:"auth_methods"`
	AuthSources                    []string       `json:"auth_sources"`
	RoleMappingPolicy              string         `json:"role_mapping_policy"`
	EnfPolicy                      string         `json:"enf_policy"`
	StripUsername                  bool           `json:"strip_username"`
	RulesMatchType                 string         `json:"rules_match_type"`
	RulesConditions                []*ServiceRule `json:"rules_conditions"`
	DefaultPostureToken            string         `json:"default_posture_token"`
	PosturePolicies                []string       `json:"posture_policies"`
	MonitorMode                    bool           `json:"monitor_mode"`
	StripUsernameCSV               string         `json:"strip_username_csv"`
	ServiceCertCN                  string         `json:"service_cert_cn"`
	UseCachedPolicyResults         bool           `json:"use_cached_policy_results"`
	AuthzSources                   []string       `json:"authz_sources"`
	PostureEnabled                 bool           `json:"posture_enabled"`
	RemediateEndHosts              bool           `json:"remediate_end_hosts"`
	RemediationURL                 string         `json:"remediation_url"`
	AuditEnabled                   bool           `json:"audit_enabled"`
	AuditServer                    string         `json:"audit_server"`
	AuditTriggerCondition          string         `json:"audit_trigger_condition"`
	AuditMacAuthClientType         string         `json:"audit_mac_auth_client_type"`
	ActionAfterAudit               string         `json:"action_after_audit"`
	AuditCoaAction                 string         `json:"audit_coa_acton"` // Note: API typo 'acton'
	ProfilerEnabled                bool           `json:"profiler_enabled"`
	ProfilerEndpointClassification []string       `json:"profiler_endpoint_classification"`
	ProfilerCoaAction              string         `json:"profiler_coa_action"`
	AcctProxyEnabled               bool           `json:"acct_proxy_enabled"`
	AcctProxyTargets               []string       `json:"acct_proxy_targets"`
	RadiusProxyScheme              string         `json:"radius_proxy_scheme"`
	RadiusProxyTargets             []string       `json:"radius_proxy_targets"`
	RadiusProxyEnableForAcct       bool           `json:"radius_proxy_enable_for_acct"`
}

type ServiceRule struct {
	Type     string `json:"type"`     // "Radius:IETF"
	Name     string `json:"name"`     // "NAS-Port-Type"
	Operator string `json:"operator"` // "EQUALS"
	Value    string `json:"value"`    // "15"
}

// --- Service Certificate Models ---

type ServiceCertCreate struct {
	CertificateURL   string `json:"certificate_url,omitempty"`
	PKCS12FileURL    string `json:"pkcs12_file_url,omitempty"`
	PKCS12Passphrase string `json:"pkcs12_passphrase,omitempty"`
}

type ServiceCertResult struct {
	ID                 int         `json:"id"`
	Subject            string      `json:"subject"`
	ExpiryDate         string      `json:"expiry_date"`
	IssueDate          string      `json:"issue_date"`
	IssueBy            string      `json:"issue_by"`
	Validity           string      `json:"validity"`
	RootCACert         interface{} `json:"root_ca_cert"`         // Object in spec, keeping generic
	IntermediateCACert interface{} `json:"intermediate_ca_cert"` // Object in spec, keeping generic
	CertFile           string      `json:"cert_file"`
}

// --- CertTrustList Models ---

type CertTrustList struct {
	ID        int      `json:"id"`
	CertFile  string   `json:"cert_file"`
	Enabled   bool     `json:"enabled"`
	CertUsage []string `json:"cert_usage"`
}

type CertTrustListCreate struct {
	CertFile  string   `json:"cert_file"`
	Enabled   bool     `json:"enabled"`
	CertUsage []string `json:"cert_usage"`
}

type CertTrustListUpdate struct {
	CertFile  string   `json:"cert_file,omitempty"`
	Enabled   bool     `json:"enabled,omitempty"`
	CertUsage []string `json:"cert_usage,omitempty"`
}

// --- AuthMethod Models ---

type FlexBool bool

func (b *FlexBool) UnmarshalJSON(data []byte) error {
	var txt string
	if err := json.Unmarshal(data, &txt); err == nil {
		*b = FlexBool(txt == "true")
		return nil
	}
	var boolean bool
	if err := json.Unmarshal(data, &boolean); err == nil {
		*b = FlexBool(boolean)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into FlexBool", string(data))
}

func (b FlexBool) MarshalJSON() ([]byte, error) {
	return json.Marshal(bool(b))
}

type FlexInt int64

func (i *FlexInt) UnmarshalJSON(data []byte) error {
	var txt string
	if err := json.Unmarshal(data, &txt); err == nil {
		val, err := strconv.ParseInt(txt, 10, 64)
		if err != nil {
			return err
		}
		*i = FlexInt(val)
		return nil
	}
	var num int64
	if err := json.Unmarshal(data, &num); err == nil {
		*i = FlexInt(num)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into FlexInt", string(data))
}

func (i FlexInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(int64(i))
}

type AuthMethodDetails struct {
	TunnelPACLifetime                 FlexInt  `json:"tunnel_pac_lifetime,omitempty"`
	TunnelPACLifetimeUnits            string   `json:"tunnel_pac_lifetime_units,omitempty"`
	UserAuthPACEnable                 FlexBool `json:"user_auth_pac_enable,omitempty"`
	UserAuthPACLifetime               FlexInt  `json:"user_auth_pac_lifetime,omitempty"`
	UserAuthPACLifetimeUnits          string   `json:"user_auth_pac_lifetime_units,omitempty"`
	MachinePACEnable                  FlexBool `json:"machine_pac_enable,omitempty"`
	MachinePACLifetime                FlexInt  `json:"machine_pac_lifetime,omitempty"`
	MachinePACLifetimeUnits           string   `json:"machine_pac_lifetime_units,omitempty"`
	PosturePACEnable                  FlexBool `json:"posture_pac_enable,omitempty"`
	PosturePACLifetime                FlexInt  `json:"posture_pac_lifetime,omitempty"`
	PosturePACLifetimeUnits           string   `json:"posture_pac_lifetime_units,omitempty"`
	AllowAnonymousProvisioning        FlexBool `json:"allow_anonymous_provisioning,omitempty"`
	AuthProvisioningRequireClientCert FlexBool `json:"auth_provisioning_require_client_cert,omitempty"`
	ClientCertificateAuth             FlexBool `json:"client_certificate_auth,omitempty"`
	AllowAuthenticatedProvisioning    FlexBool `json:"allow_authenticated_provisioning,omitempty"`
	CertificateComparison             string   `json:"certificate_comparison,omitempty"`
	SessionTimeout                    FlexInt  `json:"session_timeout,omitempty"`
	SessionCacheEnable                FlexBool `json:"session_cache_enable,omitempty"`
	Challenge                         string   `json:"challenge,omitempty"`
	AllowFastReconnect                FlexBool `json:"allow_fast_reconnect,omitempty"`
	NAPSupportEnable                  FlexBool `json:"nap_support_enable,omitempty"`
	EnforceCryptoBinding              string   `json:"enforce_crypto_binding,omitempty"`
	PublicPassword                    string   `json:"public_password,omitempty"`
	PublicUsername                    string   `json:"public_username,omitempty"`
	GroupName                         string   `json:"group_name,omitempty"`
	ServerID                          string   `json:"server_id,omitempty"`
	AutzRequired                      FlexBool `json:"autz_required,omitempty"`
	OCSPEnable                        string   `json:"ocsp_enable,omitempty"`
	OCSPURL                           string   `json:"ocsp_url,omitempty"`
	OverrideCertURL                   FlexBool `json:"override_cert_url,omitempty"`
	EncryptionScheme                  string   `json:"encryption_scheme,omitempty"`
	AllowUnknownClients               FlexBool `json:"allow_unknown_clients,omitempty"`
	PassResetFlow                     string   `json:"pass_reset_flow,omitempty"`
	NoOfRetries                       FlexInt  `json:"no_of_retries,omitempty"`
}

type AuthMethodCreate struct {
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	MethodType   string             `json:"method_type"`
	Details      *AuthMethodDetails `json:"details,omitempty"`
	InnerMethods []string           `json:"inner_methods,omitempty"`
}

type AuthMethodUpdate struct {
	Name         string             `json:"name,omitempty"`
	Description  string             `json:"description,omitempty"`
	MethodType   string             `json:"method_type,omitempty"`
	Details      *AuthMethodDetails `json:"details,omitempty"`
	InnerMethods []string           `json:"inner_methods,omitempty"`
}

type AuthMethodResult struct {
	ID           int                `json:"id"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	MethodType   string             `json:"method_type"`
	Details      *AuthMethodDetails `json:"details"`
	InnerMethods []string           `json:"inner_methods"`
}
