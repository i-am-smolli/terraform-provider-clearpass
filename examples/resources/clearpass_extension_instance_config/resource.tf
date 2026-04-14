resource "clearpass_extension_instance" "intune" {
  store_id = "a5cb26bd-ea5f-450b-8338-cf750df74ae5"
  state    = "stopped"
}

resource "clearpass_extension_instance_config" "intune_config" {
  instance_id = clearpass_extension_instance.intune.id

  # Configuration is extension-specific. Check the extension's documentation
  # for available settings. Provide as a JSON-encoded string.
  config_json = jsonencode({
    azureADEndpoint           = "login.microsoftonline.com"
    bypassProxy               = false
    clientId                  = ""
    clientSecret              = ""
    enableEndpointCache       = false
    enableStats               = false
    enableSyncAll             = true
    enableUserGroups          = false
    endpointCacheTimeSeconds  = 300
    graphEndpoint             = "graph.microsoft.com"
    ignoreEndpointDifferences = "Last Sync Date Time, Free Storage Space in Bytes"
    intuneAttributes          = null
    logLevel                  = "INFO"
    statsPassword             = ""
    statsUsername             = ""
    syncAllOnStart            = false
    syncAllSchedule           = "*/30 * * * *"
    syncPageSize              = 50
    syncUpdatedOnly           = true
    tenantId                  = ""
    userGroupUpdateSchedule   = "*/30 * * * *"
    verifySSLCerts            = false
  })
}
