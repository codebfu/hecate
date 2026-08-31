// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

export interface MachineSummary {
  id: string;
  hostname: string;
  os: string;
  arch: string;
  tags: string[];
  agent_tags?: string[];
  operator_tags?: string[];
  status: string;
  agent_version?: string | null;
  desktop_version?: string | null;
  proxmox_version?: string | null;
  last_seen_at?: string | null;
  agent_healthy?: boolean | null;
  agent_secs_since_last_pull?: number | null;
  agent_current_command_id?: string | null;
  agent_runtime?: Record<string, unknown>;
}

export type CommandStatus =
  | "pending_approval"
  | "queued"
  | "dispatched"
  | "running"
  | "completed"
  | "failed"
  | "expired"
  | "cancelled";

export interface CommandEnqueueResponse {
  command_id: string;
  status: CommandStatus;
}

export interface CommandResultPayload {
  command_id: string;
  stdout: string;
  stderr: string;
  exit_code?: number | null;
  truncated: boolean;
}

export interface CommandDetail {
  command_id: string;
  machine_id: string;
  command_name: string;
  status: CommandStatus;
  result?: CommandResultPayload | null;
}

export interface ElevationPolicy {
  enabled: boolean;
  allowed_binaries: string[];
}

export interface ShellPolicy {
  allowed_binaries: string[];
  allowed_cwd: string[];
  allowed_env: string[];
}

/** @deprecated Legacy monolithic rules — use grant assignments and authz entities instead. */
export interface AiPermissionRules {
  machine_ids: string[];
  machine_tags: string[];
  allowed_commands: string[];
  allowed_admin_commands?: string[];
  shell_policy: ShellPolicy;
  elevation_policy?: ElevationPolicy;
  max_output_bytes: number;
  max_file_bytes?: number;
  timeout_secs: number;
  max_concurrent: number;
}

export interface AiIdentitySummary {
  id: string;
  name: string;
  active: boolean;
}

export interface AiContextCapabilities {
  elevation_enabled: boolean;
  elevation_allowed_binaries: string[];
  shell_run_max_timeout_secs: number;
  max_output_bytes: number;
  max_file_bytes?: number;
}

export interface AiContextAdminCapabilities {
  allowed_admin_commands: string[];
}

export type TagMatchMode = "any" | "all";

export type AuthzProvenance = "operator" | "permission_request" | "import" | "seed" | "system";

export interface FleetScope {
  id: string;
  name: string;
  description?: string;
  tag_match_mode?: TagMatchMode;
  provenance?: AuthzProvenance;
  request_scoped?: boolean;
  owner_ai_identity_id?: string | null;
  machine_ids: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface CapabilityProfile {
  id: string;
  name: string;
  description?: string;
  provenance?: AuthzProvenance;
  request_scoped?: boolean;
  owner_ai_identity_id?: string | null;
  allowed_commands: string[];
  allowed_admin_commands: string[];
  shell_policy?: ShellPolicy;
  elevation_policy?: ElevationPolicy;
  max_output_bytes: number;
  max_file_bytes: number;
  timeout_secs: number;
  max_concurrent: number;
  created_at: string;
  updated_at: string;
}

export interface AccessGrant {
  id: string;
  name: string;
  description?: string;
  provenance?: AuthzProvenance;
  request_scoped?: boolean;
  owner_ai_identity_id?: string | null;
  fleet_scope_id: string;
  capability_profile_id: string;
  created_at: string;
  updated_at: string;
}

export interface FleetScopeSummary {
  id: string;
  name: string;
  tag_match_mode: TagMatchMode;
  machine_count: number;
  tag_count: number;
}

export interface CapabilityProfileSummary {
  id: string;
  name: string;
  command_count: number;
  admin_command_count: number;
}

export interface AccessGrantSummary {
  id: string;
  name: string;
  fleet_scope: FleetScopeSummary;
  capability_profile: CapabilityProfileSummary;
}

export interface ResolvedGrantAssignment {
  id: string;
  access_grant: AccessGrantSummary;
  requires_approval_for_shell: boolean;
  requires_approval_for_elevated: boolean;
  enabled: boolean;
}

export interface EffectiveRightsSummary {
  assignment_count: number;
  machine_scope_count: number;
  allowed_command_count: number;
  allowed_admin_command_count: number;
  max_concurrent_limit: number;
}

export interface EffectiveRightsReport {
  summary: EffectiveRightsSummary;
  assignments: ResolvedGrantAssignment[];
  allowed_commands: string[];
  allowed_admin_commands: string[];
  machine_ids: string[];
  machine_tags: string[];
}

export interface FleetScopePreviewMachine {
  id: string;
  hostname: string;
  tags: string[];
}

export interface FleetScopePreview {
  fleet_scope_id: string;
  machines: FleetScopePreviewMachine[];
}

export interface AccessGrantDetail {
  id: string;
  name: string;
  description?: string;
  provenance?: AuthzProvenance;
  request_scoped?: boolean;
  owner_ai_identity_id?: string | null;
  fleet_scope_id: string;
  capability_profile_id: string;
  created_at: string;
  updated_at: string;
  fleet_scope: FleetScope;
  capability_profile: CapabilityProfile;
}

export interface AuthzCatalogResponse {
  fleet_scopes: FleetScope[];
  capability_profiles: CapabilityProfile[];
  access_grants: AccessGrantDetail[];
}

export type EntityRef =
  | { kind: "id"; id: string }
  | { kind: "proposed"; key: string };

export interface ProposedFleetScope {
  key: string;
  name: string;
  description?: string;
  tag_match_mode?: TagMatchMode;
  machine_ids?: string[];
  tags?: string[];
}

export interface ProposedCapabilityProfile {
  key: string;
  name: string;
  description?: string;
  allowed_commands?: string[];
  allowed_admin_commands?: string[];
  shell_policy?: ShellPolicy;
  elevation_policy?: ElevationPolicy;
  max_output_bytes?: number;
  max_file_bytes?: number;
  timeout_secs?: number;
  max_concurrent?: number;
}

export interface ProposedAccessGrant {
  key: string;
  name: string;
  description?: string;
  fleet_scope: EntityRef;
  capability_profile: EntityRef;
}

export interface RequestedAssignment {
  access_grant: EntityRef;
  requires_approval_for_shell?: boolean;
  requires_approval_for_elevated?: boolean;
}

export interface PermissionRequestChanges {
  propose_fleet_scopes?: ProposedFleetScope[];
  propose_capability_profiles?: ProposedCapabilityProfile[];
  propose_access_grants?: ProposedAccessGrant[];
  add_assignments?: RequestedAssignment[];
  remove_assignment_ids?: string[];
}

export interface AiContextResponse {
  identity: AiIdentitySummary;
  grant_assignments: ResolvedGrantAssignment[];
  effective_summary: EffectiveRightsSummary;
  capabilities: AiContextCapabilities;
  admin_capabilities: AiContextAdminCapabilities;
}

export interface PlatformCommandResponse {
  command_name: string;
  result: unknown;
}

export interface AdminCommandResponse {
  command_name: string;
  result: unknown;
}

export interface CommandArtifactUploadResponse {
  artifact_id: string;
  sha256: string;
  size_bytes: number;
  original_name: string;
}

export interface CommandArtifactDownloadResponse {
  command_id: string;
  sha256: string;
  size_bytes: number;
  content_base64: string;
}

export interface ToolAnnotationSpec {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
}

export interface RegisteredToolSpec {
  name: string;
  annotations: ToolAnnotationSpec;
}
