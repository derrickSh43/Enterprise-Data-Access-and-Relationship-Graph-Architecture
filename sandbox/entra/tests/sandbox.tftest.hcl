mock_provider "azuread" {}
override_data {
  target = data.azuread_client_config.operator
  values = { object_id = "11111111-1111-4111-8111-111111111111" }
}
override_data {
  target = data.azuread_application_published_app_ids.known
  values = { result = { MicrosoftGraph = "00000003-0000-0000-c000-000000000000" } }
}
override_data {
  target = data.azuread_service_principal.graph
  values = {
    client_id = "00000003-0000-0000-c000-000000000000"
    object_id = "22222222-2222-4222-8222-222222222222"
    app_role_ids = {
      "User.Read.All"        = "df021288-bdef-4463-88db-98f22de89214"
      "GroupMember.Read.All" = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
    }
  }
}
variables {
  tenant_id                   = "33333333-3333-4333-8333-333333333333"
  collector_secret_expires_at = "2027-01-01T00:00:00Z"
}
run "separate_user_and_collector_identity" {
  command = plan
  assert {
    condition     = azuread_application.api.sign_in_audience == "AzureADMyOrg" && azuread_application.api.api[0].requested_access_token_version == 2
    error_message = "API must use single-tenant version 2 tokens."
  }
  assert {
    condition     = length(azuread_app_role_assignment.graph_read) == 2 && !azuread_application.collector.fallback_public_client_enabled
    error_message = "Collector permissions and interactive sign-in must remain separate."
  }
  assert {
    condition     = azuread_application.login.fallback_public_client_enabled && length(azuread_group.test_users.members) == 0
    error_message = "Login requires a person; no test users are implicitly enrolled."
  }
}
