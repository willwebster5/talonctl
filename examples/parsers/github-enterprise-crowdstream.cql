// GitHub Enterprise Webhook Parser
// Type: github-enterprise-crowdstream
// Purpose: Parse GitHub webhook events (push, release, alert, workflow, secret scanning, etc.)
// Source: GitHub Enterprise → Cribl (github_logs pipeline) → CrowdStrike NGSIEM
//
// NOTE: This parser handles WEBHOOK events, NOT audit log events.
// Webhook events have flat actions (create, completed, fixed) and nested objects
// (Vendor.sender.*, Vendor.repository.*, Vendor.alert.*).
// For audit log events (dotted actions like repo.create, user.login), use the
// github-enterprise-audit parser instead.

// #region PREPARSE
/************************************************************
****** Parse timestamp and JSON structure
****** Extract message field for parsing
****** Parse structured data
************************************************************/
| parseJson(field=@rawstring, prefix="Vendor.", excludeEmpty=true)

// Webhook events use head_commit.timestamp or other timestamp fields
// Parse from @rawstring timestamp if available, otherwise fall back to ingest time
| case {
    Vendor.head_commit.timestamp=*
      | parseTimestamp(field="Vendor.head_commit.timestamp", format="yyyy-MM-dd'T'HH:mm:ssXXX") ;
    Vendor.release.published_at=*
      | parseTimestamp(field="Vendor.release.published_at", format="yyyy-MM-dd'T'HH:mm:ssXXX") ;
    Vendor.alert.created_at=*
      | parseTimestamp(field="Vendor.alert.created_at", format="yyyy-MM-dd'T'HH:mm:ssXXX") ;
    Vendor.workflow_run.created_at=*
      | parseTimestamp(field="Vendor.workflow_run.created_at", format="yyyy-MM-dd'T'HH:mm:ssXXX") ;
    Vendor.workflow_job.started_at=*
      | parseTimestamp(field="Vendor.workflow_job.started_at", format="yyyy-MM-dd'T'HH:mm:ssXXX") ;
    * ;
}

// #endregion

// #region METADATA
/************************************************************
****** Static Metadata Definitions
************************************************************/
| ecs.version := "9.0.0"
| Cps.version := "1.1.0"
| Parser.version := "3.0.0"
| Vendor := "microsoft"
| event.module := "github"
| event.kind := "event"

// #endregion

// #region DATASET CLASSIFICATION
/************************************************************
****** Classify webhook event type by payload shape
****** Webhook events have flat actions, not dotted actions
****** We detect event type by which nested objects are present
************************************************************/

// Push events have Vendor.ref but no Vendor.action
// Alert events (dependabot, secret scanning alerts) have Vendor.alert.number
// Release events have Vendor.release.id
// Secret scanning backfills have Vendor.type containing "backfill"
// Workflow run events have Vendor.workflow_run.id
// Workflow job events have Vendor.workflow_job.id
// Check suite events have Vendor.check_suite.id
// Check run events have Vendor.check_run.id
// Pull request events have Vendor.pull_request.id
// Issue events have Vendor.issue.id
// Member events have Vendor.member.login
// Repository events have Vendor.action = archived/unarchived/deleted/etc. with no nested objects

| case {
    // Push events (no Vendor.action, identified by Vendor.ref)
    Vendor.ref=* AND NOT Vendor.action=*
      | event.dataset := "github.push" ;

    // Dependabot / security alerts
    Vendor.alert.number=*
      | event.dataset := "github.alert" ;

    // Secret scanning backfills
    Vendor.type=/backfill/
      | event.dataset := "github.secret_scanning" ;

    // Release events
    Vendor.release.id=*
      | event.dataset := "github.release" ;

    // Workflow run events
    Vendor.workflow_run.id=*
      | event.dataset := "github.workflow_run" ;

    // Workflow job events
    Vendor.workflow_job.id=*
      | event.dataset := "github.workflow_job" ;

    // Check suite events
    Vendor.check_suite.id=*
      | event.dataset := "github.check_suite" ;

    // Check run events
    Vendor.check_run.id=*
      | event.dataset := "github.check_run" ;

    // Pull request events
    Vendor.pull_request.id=*
      | event.dataset := "github.pull_request" ;

    // Issue events
    Vendor.issue.id=*
      | event.dataset := "github.issue" ;

    // Member events (org/repo member added/removed)
    Vendor.member.login=*
      | event.dataset := "github.member" ;

    // Organization invite events
    Vendor.action="member_invited"
      | event.dataset := "github.org" ;

    // Repository lifecycle events (archived, unarchived, deleted, etc.)
    Vendor.action=in(values=["archived", "unarchived", "deleted", "created", "edited", "transferred", "publicized", "privatized"])
    AND NOT Vendor.alert.number=*
    AND NOT Vendor.release.id=*
      | event.dataset := "github.repository" ;

    // Catch-all for unclassified webhook events
    *
      | event.dataset := "github.webhook" ;
}

// #endregion

// #region NORMALIZATION
/************************************************************
****** Normalize fields to ECS data model
****** Map webhook-specific field paths to standard ECS fields
************************************************************/

// ---- User / Actor Fields ----
// Webhook events use Vendor.sender.* for the actor
// Push events also have Vendor.pusher.* with email
| user.name := Vendor.sender.login
| user.id := Vendor.sender.id

// Extract user email from pusher (only available on push events)
| case {
    Vendor.pusher.email=*
      | user.email := Vendor.pusher.email ;
    * ;
}

// ---- Event Action ----
// Push events don't have Vendor.action; synthesize from push flags
| case {
    event.dataset="github.push" AND Vendor.forced="true"
      | event.action := "force_push" ;
    event.dataset="github.push" AND Vendor.deleted="true"
      | event.action := "branch_delete" ;
    event.dataset="github.push" AND Vendor.created="true"
      | event.action := "branch_create" ;
    event.dataset="github.push"
      | event.action := "push" ;
    Vendor.action=*
      | event.action := Vendor.action ;
    * ;
}

// ---- Organization Fields ----
| organization.name := Vendor.organization.login
| organization.id := Vendor.organization.id

// ---- URL Fields ----
// Extract relevant URLs based on event type
| case {
    Vendor.compare=*
      | url.original := Vendor.compare ;
    Vendor.release.html_url=*
      | url.original := Vendor.release.html_url ;
    Vendor.pull_request.html_url=*
      | url.original := Vendor.pull_request.html_url ;
    Vendor.alert.html_url=*
      | url.original := Vendor.alert.html_url ;
    * ;
}

// ---- Network Fields ----
// NOTE: Webhook events do NOT contain source IP addresses.
// source.ip is NOT available in this data stream.
// For IP visibility, enable GitHub Enterprise Audit Log streaming.

// #endregion

// #region EVENT CATEGORIZATION
/************************************************************
****** Assign ECS event.category[] and event.type[]
****** Based on dataset classification and action
************************************************************/

| event.dataset match {

    // ---- Push Events ----
    "github.push" => case {
        Vendor.forced="true"
          | array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        Vendor.deleted="true"
          | array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        Vendor.created="true"
          | array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        *
          | array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
    } ;

    // ---- Security Alerts (Dependabot, Code Scanning, Secret Scanning) ----
    "github.alert" => event.action match {
        // Alert lifecycle: created, fixed, resolved, dismissed, reopened, etc.
        in(values=["created", "create"])
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        in(values=["fixed", "resolve", "resolved"])
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        in(values=["dismissed", "closed_by_user"])
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        in(values=["reopened", "auto_reopened", "reintroduced"])
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        "appeared_in_branch"
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["vulnerability"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Secret Scanning Backfills ----
    "github.secret_scanning" =>
        array:append(array="event.category[]", values=["intrusion_detection"])
      | array:append(array="event.type[]", values=["info"])
      | event.outcome := "success" ;

    // ---- Releases ----
    "github.release" =>
        array:append(array="event.category[]", values=["package"])
      | array:append(array="event.type[]", values=["creation"])
      | event.outcome := "success" ;

    // ---- Workflow Runs ----
    "github.workflow_run" => event.action match {
        "requested"
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "success" ;
        "completed"
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["end"])
          | case {
              Vendor.workflow_run.conclusion="success" | event.outcome := "success" ;
              Vendor.workflow_run.conclusion="failure" | event.outcome := "failure" ;
              * | event.outcome := "unknown" ;
          } ;
        *
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Workflow Jobs ----
    "github.workflow_job" => event.action match {
        "queued"
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "success" ;
        "in_progress"
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["start"])
          | event.outcome := "success" ;
        "completed"
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["end"])
          | case {
              Vendor.workflow_job.conclusion="success" | event.outcome := "success" ;
              Vendor.workflow_job.conclusion="failure" | event.outcome := "failure" ;
              * | event.outcome := "unknown" ;
          } ;
        *
          => array:append(array="event.category[]", values=["process"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Check Suites ----
    "github.check_suite" =>
        array:append(array="event.category[]", values=["process"])
      | array:append(array="event.type[]", values=["info"])
      | event.outcome := "success" ;

    // ---- Check Runs ----
    "github.check_run" =>
        array:append(array="event.category[]", values=["process"])
      | array:append(array="event.type[]", values=["info"])
      | event.outcome := "success" ;

    // ---- Pull Requests ----
    "github.pull_request" => event.action match {
        "opened"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        in(values=["closed", "merged"])
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        "synchronize"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Issues ----
    "github.issue" => event.action match {
        "opened"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        "closed"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Member Events ----
    "github.member" => event.action match {
        "added"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "creation"])
          | event.outcome := "success" ;
        "removed"
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "deletion"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["iam"])
          | array:append(array="event.type[]", values=["user", "change"])
          | event.outcome := "success" ;
    } ;

    // ---- Organization Events ----
    "github.org" =>
        array:append(array="event.category[]", values=["iam"])
      | array:append(array="event.type[]", values=["user", "change"])
      | event.outcome := "success" ;

    // ---- Repository Lifecycle ----
    "github.repository" => event.action match {
        in(values=["archived", "unarchived", "edited", "transferred", "publicized", "privatized"])
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["change"])
          | event.outcome := "success" ;
        "deleted"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["deletion"])
          | event.outcome := "success" ;
        "created"
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["creation"])
          | event.outcome := "success" ;
        *
          => array:append(array="event.category[]", values=["configuration"])
          | array:append(array="event.type[]", values=["info"])
          | event.outcome := "success" ;
    } ;

    // ---- Catch-all ----
    *
      => array:append(array="event.category[]", values=["configuration"])
      | array:append(array="event.type[]", values=["info"])
      | event.outcome := "success" ;
}

// #endregion

// #region POST-NORMALIZATION
/************************************************************
****** Post Normalization
****** Deduplication and cleanup
************************************************************/

// Dedup category and type arrays
| array:dedup("event.category[]")
| array:dedup("event.type[]")

// #endregion
