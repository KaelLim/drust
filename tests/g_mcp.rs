//! #925 — merged harness for the mcp test group.
//! Each module is one former standalone integration-test binary, unchanged.

#[path = "mcp_aggregate.rs"]
mod mcp_aggregate;
#[path = "mcp_cron_resource_redaction.rs"]
mod mcp_cron_resource_redaction;
#[path = "mcp_dry_run.rs"]
mod mcp_dry_run;
#[path = "mcp_exploration.rs"]
mod mcp_exploration;
#[path = "mcp_factory.rs"]
mod mcp_factory;
#[path = "mcp_file_policy.rs"]
mod mcp_file_policy;
#[path = "mcp_list_records.rs"]
mod mcp_list_records;
#[path = "mcp_merged_tools.rs"]
mod mcp_merged_tools;
#[path = "mcp_owner_field_required.rs"]
mod mcp_owner_field_required;
#[path = "mcp_prompts.rs"]
mod mcp_prompts;
#[path = "mcp_protocol.rs"]
mod mcp_protocol;
#[path = "mcp_read.rs"]
mod mcp_read;
#[path = "mcp_realtime_tool.rs"]
mod mcp_realtime_tool;
#[path = "mcp_recent_writes.rs"]
mod mcp_recent_writes;
#[path = "mcp_recent_writes_limit.rs"]
mod mcp_recent_writes_limit;
#[path = "mcp_resource_uri.rs"]
mod mcp_resource_uri;
#[path = "mcp_resources.rs"]
mod mcp_resources;
#[path = "mcp_toctou_writes.rs"]
mod mcp_toctou_writes;
#[path = "mcp_vector.rs"]
mod mcp_vector;
#[path = "mcp_write_schema.rs"]
mod mcp_write_schema;
