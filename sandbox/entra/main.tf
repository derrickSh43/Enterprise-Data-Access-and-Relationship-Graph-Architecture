terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    azuread = { source = "hashicorp/azuread", version = "~> 3.0" }
  }
}

# Configures resources INSIDE your existing test tenant; does not create a tenant.
variable "tenant_id" { type = string }
variable "name" {
  type    = string
  default = "eda-sandbox"
}
variable "test_user_object_ids" {
  description = "Existing test users to place in the sandbox group. No user passwords are created."
  type        = set(string)
  default     = []
}
variable "collector_secret_expires_at" {
  description = "Explicit future RFC3339 expiry, for example 2026-10-06T00:00:00Z."
  type        = string
  validation {
    condition     = can(formatdate("YYYY", var.collector_secret_expires_at))
    error_message = "Supply a valid RFC3339 expiry."
  }
}
provider "azuread" { tenant_id = var.tenant_id }
data "azuread_client_config" "operator" {}
data "azuread_application_published_app_ids" "known" {}
data "azuread_service_principal" "graph" {
  client_id = data.azuread_application_published_app_ids.known.result.MicrosoftGraph
}
locals {
  graph_permissions = toset(["User.Read.All", "GroupMember.Read.All"])
  scope_id          = "6b853512-ae83-4b04-89a9-33cf1b46ad79"
}
resource "azuread_application" "collector" {
  fallback_public_client_enabled = false
  display_name                   = "${var.name}-collector"
  sign_in_audience               = "AzureADMyOrg"
  owners                         = [data.azuread_client_config.operator.object_id]
  required_resource_access {
    resource_app_id = data.azuread_service_principal.graph.client_id
    dynamic "resource_access" {
      for_each = local.graph_permissions
      content {
        id   = data.azuread_service_principal.graph.app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }
}
resource "azuread_service_principal" "collector" {
  client_id = azuread_application.collector.client_id
}
# This IS administrative consent to read users/groups throughout the test tenant.
resource "azuread_app_role_assignment" "graph_read" {
  for_each            = local.graph_permissions
  app_role_id         = data.azuread_service_principal.graph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.collector.object_id
  resource_object_id  = data.azuread_service_principal.graph.object_id
}
resource "azuread_application_password" "collector" {
  application_id = azuread_application.collector.id
  display_name   = "local-sandbox-expiring"
  end_date       = var.collector_secret_expires_at
}
resource "azuread_application" "api" {
  display_name     = "${var.name}-api"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azuread_client_config.operator.object_id]
  api {
    requested_access_token_version = 2
    oauth2_permission_scope {
      id                         = local.scope_id
      value                      = "access_as_user"
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Access the local EDA sandbox"
      admin_consent_description  = "Authenticate to EDA as the signed-in user; EDA separately authorizes resources."
      user_consent_display_name  = "Access the local EDA sandbox"
      user_consent_description   = "Authenticate to EDA with your identity."
    }
  }
}
resource "azuread_application_identifier_uri" "api" {
  application_id = azuread_application.api.id
  identifier_uri = "api://${azuread_application.api.client_id}"
}
resource "azuread_service_principal" "api" { client_id = azuread_application.api.client_id }
resource "azuread_application" "login" {
  display_name                   = "${var.name}-interactive-login"
  sign_in_audience               = "AzureADMyOrg"
  owners                         = [data.azuread_client_config.operator.object_id]
  fallback_public_client_enabled = true
  public_client { redirect_uris = ["http://localhost"] }
  required_resource_access {
    resource_app_id = azuread_application.api.client_id
    resource_access {
      id   = local.scope_id
      type = "Scope"
    }
  }
}
resource "azuread_service_principal" "login" { client_id = azuread_application.login.client_id }
resource "azuread_service_principal_delegated_permission_grant" "login" {
  service_principal_object_id          = azuread_service_principal.login.object_id
  resource_service_principal_object_id = azuread_service_principal.api.object_id
  claim_values                         = ["access_as_user"]
}
resource "azuread_group" "test_users" {
  display_name     = "${var.name}-test-users"
  security_enabled = true
  owners           = [data.azuread_client_config.operator.object_id]
  members          = var.test_user_object_ids
}
resource "azuread_group" "nested" {
  display_name     = "${var.name}-nested-test-group"
  security_enabled = true
  owners           = [data.azuread_client_config.operator.object_id]
  members          = [azuread_group.test_users.object_id]
}
output "local_settings" {
  value = {
    ENTRA_TENANT_ID           = var.tenant_id
    ENTRA_COLLECTOR_CLIENT_ID = azuread_application.collector.client_id
    EDA_OIDC_AUDIENCE         = azuread_application.api.client_id
    ENTRA_LOGIN_CLIENT_ID     = azuread_application.login.client_id
    ENTRA_LOGIN_SCOPE         = "api://${azuread_application.api.client_id}/access_as_user"
  }
}
output "collector_client_secret" {
  value     = azuread_application_password.collector.value
  sensitive = true
}
