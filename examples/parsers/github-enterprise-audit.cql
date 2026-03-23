// GitHub Enterprise Audit Log Parser
// Type: github-enterprise-audit
// Purpose: Parse GitHub Enterprise audit log events (authentication, IAM, repo management, etc.)
// Source: GitHub Enterprise Audit Log Streaming → Cribl (github_audit_logs pipeline) → CrowdStrike NGSIEM
//
// NOTE: This parser handles AUDIT LOG events, NOT webhook events.
// Audit log events have dotted actions (repo.create, org.add_member, user.login) and
// flat identity fields (actor, actor_id, actor_ip).
// For webhook events (push, release, dependabot alerts), use the
// github-enterprise-crowdstream parser instead.
//
// Reference: https://docs.github.com/en/enterprise-cloud@latest/authentication/keeping-your-account-and-data-secure/security-log-events

// #region PREPARSE
/************************************************************
****** Parse timestamp and JSON structure
****** Extract message field for parsing
****** Parse structured data
************************************************************/
| parseJson(field=@rawstring, prefix="Vendor.", excludeEmpty=true)
| parseTimestamp(field="Vendor.@timestamp", format="millis")

// #endregion

// #region METADATA
/************************************************************
****** Static Metadata Definitions
************************************************************/
| ecs.version := "9.0.0"
| Cps.version := "1.1.0"
| Parser.version := "1.0.0"
| Vendor := "microsoft"
| event.module := "github"
| event.kind := "event"

// #endregion

// #region DATASET CLASSIFICATION
/************************************************************
****** Classify audit log event type from dotted action
****** Audit log actions are formatted as "category.action"
****** e.g., repo.create, org.add_member, user.login
************************************************************/
| case {
    Vendor.action=*
      | regex(field=Vendor.action, regex="^(?<__temp_dataset>.+?)\\.")
      | format(format="github.%s", field=[__temp_dataset], as="event.dataset")
      | drop(__temp_dataset) ;
    *
      | event.dataset := "github.audit" ;
}

// #endregion

// #region NORMALIZATION
/************************************************************
****** Normalize fields to ECS data model
****** Map audit-log-specific field paths to standard ECS fields
************************************************************/

// ---- User / Actor Fields ----
// Audit log events use flat actor/actor_id fields
| user.name := Vendor.actor
| user.id := Vendor.actor_id

// Extract user.email and user.domain if user.name is an email
| regex(field=user.name, regex="^(?<user.email>(?<__temp_user_name>\\S+?)@(?<user.domain>.*))$", strict=false)
| case {
    __temp_user_name=* | user.name := __temp_user_name | drop(__temp_user_name) ;
    * ;
}

// User Agent fields
| user_agent.original := Vendor.user_agent

// User roles/scopes
| case {
    Vendor.token_scopes=*
      | user.roles := splitString(field=Vendor.token_scopes, by=",") ;
    * ;
}

// ---- Event Action ----
| event.action := Vendor.action

// ---- Event Start Time ----
| case {
    Vendor.started_at=* | event.start := Vendor.started_at ;
    * ;
}

// ---- Source / Network Fields ----
// Audit log events HAVE source IP (unlike webhooks)
| case {
    Vendor.actor_ip=*
      | source.address := Vendor.actor_ip
      | source.ip := source.address ;
    * ;
}
| case {
    Vendor.actor_location.country_code=*
      | source.geo.country_iso_code := Vendor.actor_location.country_code ;
    * ;
}

// Network protocol
| case {
    Vendor.transport_protocol_name=*
      | network.protocol := Vendor.transport_protocol_name ;
    * ;
}

// ---- Organization Fields ----
| case {
    Vendor.business=* | organization.name := Vendor.business ;
    Vendor.org=* | organization.name := Vendor.org ;
    * ;
}
| organization.id := Vendor.business_id

// ---- URL Fields ----
| case {
    Vendor.pull_request_url=*
      | url.original := Vendor.pull_request_url
      | parseUrl(url.original, as="url")
      | url.domain := rename(url.host) ;
    * ;
}

// #endregion

// #region EVENT CATEGORIZATION
/************************************************************
****** Assign ECS event.category[] and event.type[]
****** Based on audit log event.dataset (action prefix)
************************************************************/

| event.dataset match {

    // ---- Repository Events ----
    "github.repo" => event.action match {
        // Member management
        in(values=["repo.add_member", "repo.remove_member", "repo.update_member"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "change"])
          | event.outcome := "success" ;

        // Repository creation
        "repo.*create*"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;

        // Repository destruction
        in(values=["repo.*destroy*", "repo.pages_soft_delete"])
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;

        // Download/export
        "repo.download_zip"
          => array:append(array="event.category[]", values=["file", "network"])
          | array:append(array="event.type[]", values=["access", "creation"])
          | event.outcome := "success" ;

        // Configuration changes (catch most repo actions)
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Organization Events ----
    "github.org" => event.action match {
        in(values=["org.add_member", "org.add_outside_collaborator", "org.remove_member"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "change"])
          | event.outcome := "success" ;

        "org.update*"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "change"])
          | event.outcome := "success" ;

        "*export_*"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["access"])
          | event.outcome := "success" ;

        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Team Events ----
    "github.team" => event.action match {
        in(values=["team.add_member", "team.remove_member"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "group", "change"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["group", "change"])
          | event.outcome := "success" ;
    } ;

    // ---- User Events ----
    "github.user" => event.action match {
        // Authentication - failures
        in(values=["user.failed_login", "user.login_failed", "user.two_factor_challenge_failure"])
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "failure" ;

        // Authentication - success
        in(values=["user.login", "user.credential_authorized", "user.two_factor_challenge_success"])
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "success" ;

        // Logout
        "user.logout"
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["end"])
          | event.outcome := "success" ;

        // User creation
        in(values=["user.create", "user.public_key.create"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;

        // User deletion
        in(values=["user.destroy", "user.*delete"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;

        // Rate limiting
        "user.creation_rate_limit_exceeded"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "creation"])
          | event.outcome := "failure" ;

        // Audit log export
        "user.audit_log_export"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["access"])
          | event.outcome := "success" ;

        // Informational events
        in(values=["user.forgot_password", "user.new_device_used", "user.sign_in_from*",
                    "user.two_factor_recover*", "user.two_factor_requested"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "info"])
          | event.outcome := "success" ;

        // General user changes
        *
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "change"])
          | event.outcome := "success" ;
    } ;

    // ---- OAuth Access Events ----
    "github.oauth_access" => event.action match {
        "oauth_access.create"
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "oauth_access.destroy"
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- OAuth Application Events ----
    "github.oauth_application" => event.action match {
        in(values=["oauth_application.create", "oauth_application.generate_client_secret"])
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        in(values=["oauth_application.destroy", "oauth_application.remove_client_secret"])
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Personal Access Token Events ----
    "github.personal_access_token" => event.action match {
        in(values=["personal_access_token.create", "personal_access_token.request_created"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "personal_access_token.destroy"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        "personal_access_token.request_denied"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "failure" ;
        "personal_access_token.access_granted"
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Hook (Webhook) Events ----
    "github.hook" => event.action match {
        "hook.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "hook.destroy"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Integration Events ----
    "github.integration" => event.action match {
        "integration.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "integration.destroy"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Integration Installation Events ----
    "github.integration_installation" => event.action match {
        "integration_installation.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "integration_installation.destroy"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Branch Protection Events ----
    "github.branch_protection_rule" => event.action match {
        "*create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "*delete"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Protected Branch Events ----
    "github.protected_branch" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Repository Ruleset Events ----
    "github.repository_ruleset" => event.action match {
        "repository_ruleset.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "repository_ruleset.delete"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Public Key Events ----
    "github.public_key" => event.action match {
        "public_key.create"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "public_key.delete"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        in(values=["public_key.unverification_failure", "public_key.verification_failure"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "failure" ;
        *
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Git Events (clone, fetch, push) ----
    "github.git" => event.action match {
        "git.clone"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["access"])
          | event.outcome := "success" ;
        "git.push"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        "git.fetch"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["access"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Business/Enterprise Events ----
    "github.business" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Environment Events ----
    "github.environment" => event.action match {
        in(values=["environment.add_protection_rule", "environment.create_actions_secret",
                    "environment.create_actions_variable"])
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        in(values=["environment.delete", "environment.remove_actions_secret",
                    "environment.remove_actions_variable", "environment.remove_protection_rule"])
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Codespaces Events ----
    "github.codespaces" => event.action match {
        "codespaces.connect"
          => array:append(array="event.category[]", values=["authentication", "session"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "success" ;
        "codespaces.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "codespaces.destroy"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Copilot Events ----
    "github.copilot" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Dependabot Configuration Events ----
    "github.dependabot_alerts" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    "github.dependabot_alerts_new_repos" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    "github.dependabot_security_updates" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    "github.dependabot_security_updates_new_repos" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    "github.dependabot_repository_access" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Dependency Graph Events ----
    "github.dependency_graph" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    "github.dependency_graph_new_repos" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Vulnerability Alert Events ----
    "github.repository_vulnerability_alert" => event.action match {
        "*create"
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "*delete"
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Workflow Events (audit log level) ----
    "github.workflows" => event.action match {
        "workflows.delete_workflow_run"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Migration Events ----
    "github.migration" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["creation"])
      | event.outcome := "success" ;

    // ---- Security Key Events ----
    "github.security_key" =>
        array:append(array="event.category[]", values=["iam"])
      | array:append(array="event.type[]", values=["user", "change"])
      | event.outcome := "success" ;

    // ---- Passkey Events ----
    "github.passkey" => event.action match {
        "passkey.register"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "passkey.remove"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Two Factor Authentication ----
    "github.two_factor_authentication" =>
        array:append(array="event.category[]", values=["iam", "authentication"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Trusted Device Events ----
    "github.trusted_device" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- User Email Events ----
    "github.user_email" =>
        array:append(array="event.category[]", values=["iam"])
      | array:append(array="event.type[]", values=["user", "change"])
      | event.outcome := "success" ;

    // ---- Profile Picture Events ----
    "github.profile_picture" =>
        array:append(array="event.category[]", values=["iam"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Project Events ----
    "github.project" => event.action match {
        "project.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "project.delete"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        in(values=["project.update_org_permission", "project.update_team_permission"])
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["group", "change"])
          | event.outcome := "success" ;
        "project.update_user_permission"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "change"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Gist Events ----
    "github.gist" => event.action match {
        "gist.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "gist.destroy"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Payment Method Events ----
    "github.payment_method" => event.action match {
        "payment_method.create"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "payment_method.destroy"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Marketplace Events ----
    "github.marketplace_listing" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    "github.marketplace_agreement_signature" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["creation"])
      | event.outcome := "success" ;

    // ---- OAuth Authorization Events ----
    "github.oauth_authorization" => event.action match {
        "oauth_authorization.create"
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "oauth_authorization.destroy"
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["authentication"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Billing Events ----
    "github.billing" =>
        array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["change"])
      | event.outcome := "success" ;

    // ---- Catch-all for uncategorized audit log events ----
    *
      => array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["info"])
      | event.outcome := "success" ;
}

// #endregion

// #region POST-NORMALIZATION
/************************************************************
****** Post Normalization
****** Add network category if IP present, dedup arrays
************************************************************/

// If we have an IP, add network category
| case {
    source.address=*
      | array:append(array="event.category[]", values=["network"])
      | array:append(array="event.type[]", values=["connection"]) ;
    * ;
}

// Dedup category and type arrays
| array:dedup("event.category[]")
| array:dedup("event.type[]")

// #endregion
