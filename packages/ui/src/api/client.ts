// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { getCsrfToken } from "../csrf.js";
import { extractApiErrorMessage } from "../utils/apiErrorMessage.js";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface ApiClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  getCsrfToken?: () => string | undefined;
}

export interface SessionInfo {
  authenticated: boolean;
  role?: "admin" | "operator";
  login?: string;
  onboarding_required?: boolean;
  must_change_password?: boolean;
  auth_stage?: "password" | "full";
  csrf_token?: string;
}

export interface AuthStatus {
  bootstrap_required: boolean;
  authenticated: boolean;
  onboarding_required: boolean;
  role?: "admin" | "operator" | null;
}

export interface SystemVersion {
  hecate_version: string;
  schema_version: number;
  backup_format_version_current: number;
  api_version: string;
}

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
  agent_state?: string | null;
  attestation_json?: unknown;
  enrolled_at?: string | null;
  revoked_at?: string | null;
  agent_update_status?: AgentUpdateStatus;
  latest_agent_version?: string | null;
  agent_busy?: boolean;
  agent_update_requested_at?: string | null;
  desktop_update_status?: AgentUpdateStatus;
  latest_desktop_version?: string | null;
  proxmox_update_status?: AgentUpdateStatus;
  latest_proxmox_version?: string | null;
  installable_helpers?: InstallableHelper[];
}

export interface InstallableHelper {
  component: string;
  version: string;
}

export type AgentUpdateStatus =
  | "not_applicable"
  | "not_installed"
  | "unknown"
  | "up_to_date"
  | "outdated"
  | "update_pending"
  | "blocked_busy";

export interface ServerUpdateStatus {
  hecate_version: string;
  hecate_app_tag: string;
  update_requested: boolean;
  update_requested_at?: string | null;
  fleet_busy: boolean;
  can_apply: boolean;
}

export interface AgentUpdateAllResult {
  requested: number;
  skipped_busy: number;
  skipped_up_to_date: number;
}

export interface LatestAgentRelease {
  version: string;
  os: string;
  arch: string;
  component: "agent" | "desktop" | string;
  filename: string;
  sha256: string;
  published_at: string;
  download_path: string;
}

export interface AiIdentitySummary {
  id: string;
  name: string;
  description?: string;
  active: boolean;
  requires_approval_for_shell: boolean;
  requires_approval_for_elevated?: boolean;
  created_at?: string;
  content_policy_locked?: boolean;
  content_policy_violation_count?: number;
  content_policy_locked_until?: string | null;
}

export interface AiApiKeySummary {
  id: string;
  prefix: string;
  active: boolean;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
}

export type TagMatchMode = "any" | "all";

export type AuthzProvenance = "operator" | "permission_request" | "import" | "seed" | "system";

export interface ShellPolicy {
  allowed_binaries: string[];
  allowed_cwd: string[];
  allowed_env: string[];
}

export interface ElevationPolicy {
  enabled: boolean;
  allowed_binaries: string[];
}

export interface FleetScope {
  id: string;
  name: string;
  description: string;
  tag_match_mode: TagMatchMode;
  provenance: AuthzProvenance;
  request_scoped: boolean;
  owner_ai_identity_id?: string | null;
  machine_ids: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface CapabilityProfile {
  id: string;
  name: string;
  description: string;
  provenance: AuthzProvenance;
  request_scoped: boolean;
  owner_ai_identity_id?: string | null;
  allowed_commands: string[];
  allowed_admin_commands: string[];
  shell_policy: ShellPolicy;
  elevation_policy: ElevationPolicy;
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
  description: string;
  provenance: AuthzProvenance;
  request_scoped: boolean;
  owner_ai_identity_id?: string | null;
  fleet_scope_id: string;
  capability_profile_id: string;
  created_at: string;
  updated_at: string;
}

export interface AccessGrantDetail extends AccessGrant {
  fleet_scope: FleetScope;
  capability_profile: CapabilityProfile;
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

export interface AuthzCatalogResponse {
  fleet_scopes: FleetScope[];
  capability_profiles: CapabilityProfile[];
  access_grants: AccessGrantDetail[];
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

export interface FleetScopeInput {
  name: string;
  description?: string;
  tag_match_mode?: TagMatchMode;
  machine_ids?: string[];
  tags?: string[];
}

export interface FleetScopePatch {
  name?: string;
  description?: string;
  tag_match_mode?: TagMatchMode;
  machine_ids?: string[];
  tags?: string[];
}

export interface CapabilityProfileInput {
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

export interface CapabilityProfilePatch {
  name?: string;
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

export interface AccessGrantInput {
  name: string;
  description?: string;
  fleet_scope_id: string;
  capability_profile_id: string;
}

export interface AccessGrantPatch {
  name?: string;
  description?: string;
  fleet_scope_id?: string;
  capability_profile_id?: string;
}

export interface GrantAssignmentInput {
  access_grant_id: string;
  requires_approval_for_shell?: boolean;
  requires_approval_for_elevated?: boolean;
  enabled?: boolean;
}

export interface SetGrantAssignmentsInput {
  assignments: GrantAssignmentInput[];
}

export interface RemoveAssignmentsInput {
  assignment_ids: string[];
  reason?: string;
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

export type PermissionRequestClass = "standard" | "admin";

export interface AutoApproveWarning {
  kind: string;
  message: string;
  assignment_labels: string[];
}

export interface PermissionRequestEntitiesToCreate {
  fleet_scopes: ProposedFleetScope[];
  capability_profiles: ProposedCapabilityProfile[];
  access_grants: ProposedAccessGrant[];
}

export interface PermissionRequestPreview {
  entities_to_create: PermissionRequestEntitiesToCreate;
  assignments_to_add: RequestedAssignment[];
  assignments_to_remove: string[];
  effective_rights_before: EffectiveRightsSummary;
  effective_rights_after: EffectiveRightsSummary;
  auto_approve_warnings: AutoApproveWarning[];
}

export interface CommandDefinitionSummary {
  name: string;
  description: string;
  risk_level: string;
}

export type PermissionRequestStatus = "pending" | "approved" | "rejected";

export interface PermissionRequestDetail {
  id: string;
  ai_identity_id: string;
  ai_identity_name: string;
  status: PermissionRequestStatus;
  reason: string;
  request_class: PermissionRequestClass;
  created_at: string;
  reviewed_at?: string | null;
  reviewed_by?: string | null;
  current_assignments: ResolvedGrantAssignment[];
  requested_changes: PermissionRequestChanges;
  request_preview: PermissionRequestPreview;
  review_reason?: string | null;
}

export interface BackupPreview {
  backup_format_version: number;
  hecate_version: string;
  schema_version_at_export: number;
  upgrade_required: boolean;
  sections: Array<{
    id: string;
    label: string;
    present: boolean;
    restorable: boolean;
    default_selected: boolean;
    warnings: string[];
  }>;
}

export interface EnrollmentSettings {
  auto_approve: boolean;
}

export interface AdminSettings {
  release_signing_public_key_b64: string;
  release_signing_public_key_previous_b64?: string | null;
  release_signing_key_overlap_until?: string | null;
  release_key_continuity_sig_b64?: string | null;
  enrollment_auto_approve: boolean;
  proxy_enrollment_auto_approve: boolean;
  enrollment_token_ttl_minutes: number;
  proxy_enrollment_token_ttl_minutes: number;
  authz_tags_include_auto: boolean;
  authz_tags_include_operator: boolean;
  authz_tags_include_agent_custom: boolean;
  content_policy_lockout_seconds: number;
  key_rotation_overlap_secs: number;
  key_rotation_interval_secs: number;
  task_signing_last_rotated_at?: string | null;
  credential_rotation_last_requested_at?: string | null;
}

export interface UpdateAdminSettingsBody {
  release_signing_public_key_b64?: string;
  /** Required when rotating the release public key (offline continuity signature). */
  release_key_continuity_sig_b64?: string;
  enrollment_auto_approve?: boolean;
  proxy_enrollment_auto_approve?: boolean;
  enrollment_token_ttl_minutes?: number;
  proxy_enrollment_token_ttl_minutes?: number;
  authz_tags_include_auto?: boolean;
  authz_tags_include_operator?: boolean;
  authz_tags_include_agent_custom?: boolean;
  content_policy_lockout_seconds?: number;
  key_rotation_overlap_secs?: number;
  key_rotation_interval_secs?: number;
}

export interface RotateKeysBody {
  machine_id?: string;
}

export interface RotateKeysResult {
  ok: boolean;
  agents: number;
}

export interface AdminCommandResponse<T = unknown> {
  command_name: string;
  result: T;
}

export interface ProxySummary {
  id: string;
  hostname: string;
  state: "pending_approval" | "active" | "revoked";
  version?: string | null;
  enrolled_at: string;
  last_seen_at?: string | null;
  revoked_at?: string | null;
  attestation?: unknown;
}

export type AuditRefKind =
  | "ai_identity"
  | "operator"
  | "machine"
  | "command"
  | "ai_api_key"
  | "agent";

export interface AuditEventRef {
  label: string;
  id?: string | null;
  kind?: AuditRefKind | null;
  related_id?: string | null;
  detail?: string | null;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditEvent {
  id: string;
  actor: AuditEventRef;
  action: string;
  target?: AuditEventRef | null;
  created_at: string;
}

export interface BackupSection {
  id: string;
  label: string;
  default_selected: boolean;
  exportable: boolean;
}

export interface OperatorSummary {
  id: string;
  login: string;
  role: "admin" | "operator";
  active: boolean;
}

export type CommandQueueStatus =
  | "pending_approval"
  | "queued"
  | "dispatched"
  | "running"
  | "completed"
  | "failed"
  | "expired"
  | "cancelled";

export interface CommandQueueItem {
  id: string;
  machine_id: string;
  machine_hostname: string;
  ai_identity_id?: string | null;
  ai_identity_name?: string | null;
  command_name: string;
  params: Record<string, unknown>;
  status: CommandQueueStatus;
  /** Present for in-flight system.reboot (`initiated` | `agent_down`). */
  reboot_phase?: string | null;
  created_at: string;
  dispatched_at?: string | null;
  finished_at?: string | null;
}

const DEFAULT_BASE = "/api/v1";

/** webauthn-rs wraps options in `{ publicKey }`; @simplewebauthn/browser expects the inner object. */
export function normalizeRegistrationOptions(
  options: Record<string, unknown>,
): PublicKeyCredentialCreationOptionsJSON {
  const nested = options.publicKey;
  if (nested && typeof nested === "object") {
    return nested as PublicKeyCredentialCreationOptionsJSON;
  }
  return options as unknown as PublicKeyCredentialCreationOptionsJSON;
}

/** webauthn-rs may wrap authentication options in `{ publicKey }`. */
export function normalizeAuthenticationOptions(
  options: Record<string, unknown>,
): PublicKeyCredentialRequestOptionsJSON {
  const nested = options.publicKey;
  if (nested && typeof nested === "object") {
    return nested as PublicKeyCredentialRequestOptionsJSON;
  }
  return options as unknown as PublicKeyCredentialRequestOptionsJSON;
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly getCsrfToken?: () => string | undefined;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE).replace(/\/$/, "");
    // fetch must keep its Window/globalThis receiver when called indirectly.
    this.fetchImpl = options.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
    this.getCsrfToken = options.getCsrfToken;
  }

  async getSession(): Promise<SessionInfo> {
    return this.request<SessionInfo>("GET", "/auth/session");
  }

  async getAuthStatus(): Promise<AuthStatus> {
    return this.request<AuthStatus>("GET", "/auth/status");
  }

  async bootstrap(login: string, password: string): Promise<SessionInfo> {
    return this.request<SessionInfo>("POST", "/auth/bootstrap", { login, password });
  }

  async login(login: string, password: string): Promise<SessionInfo> {
    return this.request<SessionInfo>("POST", "/auth/login", { login, password });
  }

  async logout(): Promise<void> {
    await this.request("POST", "/auth/logout");
  }

  async onboardingPassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request("POST", "/auth/onboarding/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  async webauthnRegisterOptions(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/auth/webauthn/register/options");
  }

  async webauthnRegisterVerify(
    credential: Record<string, unknown>,
    name?: string,
  ): Promise<void> {
    await this.request("POST", "/auth/webauthn/register/verify", { credential, name });
  }

  async webauthnAuthenticateOptions(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/auth/webauthn/authenticate/options");
  }

  async webauthnAuthenticateVerify(credential: Record<string, unknown>): Promise<void> {
    await this.request("POST", "/auth/webauthn/authenticate/verify", { credential });
  }

  async completeOnboarding(): Promise<void> {
    await this.request("POST", "/auth/onboarding/complete");
  }

  async changePassword(currentPassword: string | undefined, newPassword: string): Promise<void> {
    await this.request("POST", "/auth/password/change", {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  async getSystemVersion(): Promise<SystemVersion> {
    return this.request<SystemVersion>("GET", "/system/version");
  }

  async getServerUpdateStatus(): Promise<ServerUpdateStatus> {
    return this.request<ServerUpdateStatus>("GET", "/admin/system/update-status");
  }

  async requestServerUpdate(): Promise<{
    ok: boolean;
    update_requested: boolean;
    fleet_busy: boolean;
    can_apply: boolean;
    applied?: boolean;
  }> {
    return this.request("POST", "/admin/system/update");
  }

  async listLatestAgentReleases(): Promise<LatestAgentRelease[]> {
    const data = await this.request<LatestAgentRelease[] | null>("GET", "/admin/releases/latest");
    return Array.isArray(data) ? data : [];
  }

  async requestMachineAgentUpdate(id: string): Promise<MachineSummary> {
    return this.request<MachineSummary>("POST", `/admin/machines/${id}/update-agent`);
  }

  async requestMachineHelperInstall(id: string, component: string): Promise<MachineSummary> {
    return this.request<MachineSummary>("POST", `/admin/machines/${id}/install-helper`, {
      component,
    });
  }

  async requestAllAgentUpdates(): Promise<AgentUpdateAllResult> {
    return this.request<AgentUpdateAllResult>("POST", "/admin/machines/update-agents");
  }

  async listMachines(): Promise<MachineSummary[]> {
    // Backend returns a JSON array. Keep compatibility with an older `{ machines: [...] }` wrapper.
    const data = await this.request<MachineSummary[] | { machines: MachineSummary[] } | null>(
      "GET",
      "/admin/machines",
    );
    if (Array.isArray(data)) {
      return data;
    }
    if (data && typeof data === "object" && "machines" in data) {
      return (data as { machines: MachineSummary[] }).machines ?? [];
    }
    return [];
  }

  async getMachine(id: string): Promise<MachineSummary> {
    return this.request<MachineSummary>("GET", `/admin/machines/${id}`);
  }

  async updateMachineAgent(id: string, action: "approve" | "revoke"): Promise<void> {
    await this.request("PATCH", `/admin/machines/${id}/agent`, { action });
  }

  async deleteMachine(id: string): Promise<void> {
    await this.request("DELETE", `/admin/machines/${id}`);
  }

  async updateMachineTags(
    id: string,
    patch: { add?: string[]; remove?: string[] },
  ): Promise<MachineSummary> {
    return this.request<MachineSummary>("PATCH", `/admin/machines/${id}/tags`, patch);
  }

  async listCommandQueue(params: {
    limit?: number;
    offset?: number;
    command_id?: string;
    machine_id?: string;
    include_recent?: boolean;
  } = {}): Promise<PaginatedResponse<CommandQueueItem>> {
    const query = new URLSearchParams();
    if (params.limit !== undefined) {
      query.set("limit", String(params.limit));
    }
    if (params.offset !== undefined) {
      query.set("offset", String(params.offset));
    }
    if (params.command_id) {
      query.set("command_id", params.command_id);
    }
    if (params.machine_id) {
      query.set("machine_id", params.machine_id);
    }
    if (params.include_recent) {
      query.set("include_recent", "true");
    }
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return this.request<PaginatedResponse<CommandQueueItem>>("GET", `/admin/commands${suffix}`);
  }

  async approveCommand(commandId: string): Promise<void> {
    await this.request("POST", `/admin/commands/${commandId}/approve`);
  }

  async cancelCommand(commandId: string): Promise<void> {
    await this.request("POST", `/admin/commands/${commandId}/cancel`);
  }

  async listPermissionRequests(params: {
    limit?: number;
    offset?: number;
    status?: PermissionRequestStatus;
    request_id?: string;
  } = {}): Promise<PaginatedResponse<PermissionRequestDetail>> {
    const query = new URLSearchParams();
    if (params.limit !== undefined) {
      query.set("limit", String(params.limit));
    }
    if (params.offset !== undefined) {
      query.set("offset", String(params.offset));
    }
    if (params.status) {
      query.set("status", params.status);
    }
    if (params.request_id) {
      query.set("request_id", params.request_id);
    }
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return this.request<PaginatedResponse<PermissionRequestDetail>>(
      "GET",
      `/admin/permission-requests${suffix}`,
    );
  }

  async approvePermissionRequest(requestId: string): Promise<void> {
    await this.request("POST", `/admin/permission-requests/${requestId}/approve`);
  }

  async rejectPermissionRequest(requestId: string, reason?: string): Promise<void> {
    await this.request("POST", `/admin/permission-requests/${requestId}/reject`, {
      reason: reason ?? null,
    });
  }

  async createEnrollmentToken(
    options: { boundTags?: string[]; machineId?: string } = {},
  ): Promise<{ id: string; token: string; expires_at: string }> {
    const body: Record<string, unknown> = {};
    if (options.boundTags?.length) {
      body.bound_tags = options.boundTags;
    }
    if (options.machineId) {
      body.machine_id = options.machineId;
    }
    return this.request("POST", "/admin/enrollment-tokens", body);
  }

  async listProxies(): Promise<ProxySummary[]> {
    const data = await this.request<ProxySummary[] | null>("GET", "/admin/proxies");
    return Array.isArray(data) ? data : [];
  }

  async getProxy(id: string): Promise<ProxySummary> {
    return this.request<ProxySummary>("GET", `/admin/proxies/${id}`);
  }

  async updateProxyState(id: string, action: "approve" | "revoke"): Promise<void> {
    await this.request("PATCH", `/admin/proxies/${id}/state`, { action });
  }

  async deleteProxy(id: string): Promise<void> {
    await this.request("DELETE", `/admin/proxies/${id}`);
  }

  async createProxyEnrollmentToken(
    options: { boundTags?: string[]; proxyId?: string } = {},
  ): Promise<{ id: string; token: string; expires_at: string }> {
    const body: Record<string, unknown> = {};
    if (options.boundTags?.length) {
      body.bound_tags = options.boundTags;
    }
    if (options.proxyId) {
      body.proxy_id = options.proxyId;
    }
    return this.request("POST", "/admin/proxy-enrollment-tokens", body);
  }

  async getProxyEnrollmentSettings(): Promise<EnrollmentSettings> {
    return this.request<EnrollmentSettings>("GET", "/admin/proxy-enrollment/settings");
  }

  async updateProxyEnrollmentSettings(autoApprove: boolean): Promise<EnrollmentSettings> {
    return this.request<EnrollmentSettings>("PATCH", "/admin/proxy-enrollment/settings", {
      auto_approve: autoApprove,
    });
  }

  async getEnrollmentSettings(): Promise<EnrollmentSettings> {
    return this.request<EnrollmentSettings>("GET", "/admin/enrollment/settings");
  }

  async updateEnrollmentSettings(autoApprove: boolean): Promise<EnrollmentSettings> {
    return this.request<EnrollmentSettings>("PATCH", "/admin/enrollment/settings", {
      auto_approve: autoApprove,
    });
  }

  async getAdminSettings(): Promise<AdminSettings> {
    return this.request<AdminSettings>("GET", "/admin/settings");
  }

  async executeAdminCommand<T = unknown>(
    commandName: string,
    params: Record<string, unknown> = {},
  ): Promise<T> {
    const response = await this.request<AdminCommandResponse<T>>("POST", "/admin/repo/commands", {
      command_name: commandName,
      params,
    });
    return response.result;
  }

  async updateAdminSettings(body: UpdateAdminSettingsBody): Promise<AdminSettings> {
    return this.request<AdminSettings>("PATCH", "/admin/settings", body);
  }

  async rotateTaskSigning(body: RotateKeysBody = {}): Promise<RotateKeysResult> {
    return this.request<RotateKeysResult>("POST", "/admin/settings/rotate-task-signing", body);
  }

  async requestCredentialRotation(body: RotateKeysBody = {}): Promise<RotateKeysResult> {
    return this.request<RotateKeysResult>(
      "POST",
      "/admin/settings/request-credential-rotation",
      body,
    );
  }

  async listAiIdentities(): Promise<AiIdentitySummary[]> {
    // If the backend returns a raw array, it will be handled by the `Array.isArray` branch below.
    const data = await this.request<AiIdentitySummary[] | { identities: AiIdentitySummary[] } | null>(
      "GET",
      "/admin/ai-identities",
    );
    if (Array.isArray(data)) {
      return data;
    }
    if (data && typeof data === "object" && "identities" in data) {
      return (data as { identities: AiIdentitySummary[] }).identities ?? [];
    }
    return [];
  }

  async createAiIdentity(
    name: string,
    description = "",
    requiresApprovalForShell = true,
  ): Promise<{ id: string }> {
    return this.request("POST", "/admin/ai-identities", {
      name,
      description,
      requires_approval_for_shell: requiresApprovalForShell,
    });
  }

  async updateAiIdentity(
    id: string,
    patch: {
      name?: string;
      description?: string;
      active?: boolean;
      requires_approval_for_shell?: boolean;
      requires_approval_for_elevated?: boolean;
    },
  ): Promise<void> {
    await this.request("PATCH", `/admin/ai-identities/${id}`, patch);
  }

  async deleteAiIdentity(id: string): Promise<void> {
    await this.request("DELETE", `/admin/ai-identities/${id}`);
  }

  async unlockAiContentPolicy(id: string): Promise<void> {
    await this.request("POST", `/admin/ai-identities/${id}/content-policy/unlock`);
  }

  async listAiApiKeys(identityId: string): Promise<AiApiKeySummary[]> {
    return this.request<AiApiKeySummary[]>("GET", `/admin/ai-identities/${identityId}/api-keys`);
  }

  async createAiApiKey(identityId: string): Promise<{ id: string; api_key: string; prefix: string }> {
    return this.request("POST", `/admin/ai-identities/${identityId}/api-keys`);
  }

  async revokeAiApiKey(identityId: string, keyId: string): Promise<void> {
    await this.request("DELETE", `/admin/ai-identities/${identityId}/api-keys/${keyId}`);
  }

  async listCommandDefinitions(): Promise<CommandDefinitionSummary[]> {
    return this.request<CommandDefinitionSummary[]>("GET", "/admin/command-definitions");
  }

  async getAuthzCatalog(): Promise<AuthzCatalogResponse> {
    return this.request<AuthzCatalogResponse>("GET", "/admin/authz-catalog");
  }

  async listFleetScopes(): Promise<FleetScope[]> {
    return this.request<FleetScope[]>("GET", "/admin/fleet-scopes");
  }

  async createFleetScope(input: FleetScopeInput): Promise<FleetScope> {
    return this.request<FleetScope>("POST", "/admin/fleet-scopes", input);
  }

  async updateFleetScope(id: string, patch: FleetScopePatch): Promise<FleetScope> {
    return this.request<FleetScope>("PATCH", `/admin/fleet-scopes/${id}`, patch);
  }

  async deleteFleetScope(id: string): Promise<void> {
    await this.request("DELETE", `/admin/fleet-scopes/${id}`);
  }

  async previewFleetScope(id: string): Promise<FleetScopePreview> {
    return this.request<FleetScopePreview>("GET", `/admin/fleet-scopes/${id}/preview`);
  }

  async listCapabilityProfiles(): Promise<CapabilityProfile[]> {
    return this.request<CapabilityProfile[]>("GET", "/admin/capability-profiles");
  }

  async createCapabilityProfile(input: CapabilityProfileInput): Promise<CapabilityProfile> {
    return this.request<CapabilityProfile>("POST", "/admin/capability-profiles", input);
  }

  async updateCapabilityProfile(
    id: string,
    patch: CapabilityProfilePatch,
  ): Promise<CapabilityProfile> {
    return this.request<CapabilityProfile>("PATCH", `/admin/capability-profiles/${id}`, patch);
  }

  async deleteCapabilityProfile(id: string): Promise<void> {
    await this.request("DELETE", `/admin/capability-profiles/${id}`);
  }

  async listAccessGrants(): Promise<AccessGrantDetail[]> {
    return this.request<AccessGrantDetail[]>("GET", "/admin/access-grants");
  }

  async createAccessGrant(input: AccessGrantInput): Promise<AccessGrantDetail> {
    return this.request<AccessGrantDetail>("POST", "/admin/access-grants", input);
  }

  async updateAccessGrant(id: string, patch: AccessGrantPatch): Promise<AccessGrantDetail> {
    return this.request<AccessGrantDetail>("PATCH", `/admin/access-grants/${id}`, patch);
  }

  async deleteAccessGrant(id: string): Promise<void> {
    await this.request("DELETE", `/admin/access-grants/${id}`);
  }

  async getGrantAssignments(identityId: string): Promise<ResolvedGrantAssignment[]> {
    return this.request<ResolvedGrantAssignment[]>(
      "GET",
      `/admin/ai-identities/${identityId}/grant-assignments`,
    );
  }

  async updateGrantAssignments(
    identityId: string,
    input: SetGrantAssignmentsInput,
  ): Promise<ResolvedGrantAssignment[]> {
    return this.request<ResolvedGrantAssignment[]>(
      "PUT",
      `/admin/ai-identities/${identityId}/grant-assignments`,
      input,
    );
  }

  async removeGrantAssignments(
    identityId: string,
    input: RemoveAssignmentsInput,
  ): Promise<ResolvedGrantAssignment[]> {
    return this.request<ResolvedGrantAssignment[]>(
      "POST",
      `/admin/ai-identities/${identityId}/grant-assignments/remove`,
      input,
    );
  }

  async getEffectiveRights(identityId: string): Promise<EffectiveRightsReport> {
    return this.request<EffectiveRightsReport>(
      "GET",
      `/admin/ai-identities/${identityId}/effective-rights`,
    );
  }

  async listAuditEvents(params: { limit?: number; offset?: number } = {}): Promise<PaginatedResponse<AuditEvent>> {
    const query = new URLSearchParams();
    if (params.limit !== undefined) {
      query.set("limit", String(params.limit));
    }
    if (params.offset !== undefined) {
      query.set("offset", String(params.offset));
    }
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return this.request<PaginatedResponse<AuditEvent>>("GET", `/admin/audit/events${suffix}`);
  }

  async listBackupSections(): Promise<BackupSection[]> {
    const data = await this.request<BackupSection[] | { sections: BackupSection[] } | null>(
      "GET",
      "/admin/backup/sections",
    );
    if (Array.isArray(data)) {
      return data;
    }
    if (data && typeof data === "object" && "sections" in data) {
      return (data as { sections: BackupSection[] }).sections ?? [];
    }
    return [];
  }

  async exportBackup(sections: string[], password: string): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/backup/export", { sections, password });
  }

  async previewBackup(
    encryptedBackup: Record<string, unknown>,
    password: string,
  ): Promise<BackupPreview> {
    return this.request<BackupPreview>("POST", "/admin/backup/preview", {
      encrypted_backup: encryptedBackup,
      password,
    });
  }

  async restoreBackup(
    sections: string[],
    encryptedBackup: Record<string, unknown>,
    password: string,
  ): Promise<void> {
    await this.request("POST", "/admin/backup/restore", {
      sections,
      encrypted_backup: encryptedBackup,
      password,
    });
  }

  async listOperators(): Promise<OperatorSummary[]> {
    const data = await this.request<
      Array<OperatorSummary & { disabled_at?: string | null }> | { operators: OperatorSummary[] } | null
    >("GET", "/admin/operators");
    if (Array.isArray(data)) {
      return data.map(normalizeOperator);
    }
    if (data && typeof data === "object" && "operators" in data) {
      return ((data as { operators: OperatorSummary[] }).operators ?? []).map(normalizeOperator);
    }
    return [];
  }

  async createOperator(
    login: string,
    password: string,
    role: "admin" | "operator",
  ): Promise<{ id: string }> {
    return this.request<{ id: string }>("POST", "/admin/operators", { login, password, role });
  }

  async updateOperator(
    id: string,
    patch: { role?: "admin" | "operator"; active?: boolean },
  ): Promise<void> {
    await this.request("PATCH", `/admin/operators/${id}`, patch);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      Accept: "application/json",
    };

    const csrf = this.getCsrfToken?.();
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }

    let payload: string | undefined;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }

    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: payload,
      credentials: "include",
    });

    const text = await response.text();
    const parsed = text.length > 0 ? safeJsonParse(text) : undefined;

    if (text.trimStart().startsWith("<")) {
      throw new ApiError(
        `API ${method} ${path} returned HTML instead of JSON (route missing or misconfigured)`,
        response.status,
      );
    }

    if (!response.ok) {
      throw new ApiError(
        extractApiErrorMessage(response.status, parsed ?? text),
        response.status,
        parsed ?? text,
      );
    }

    if (parsed !== undefined && typeof parsed !== "object") {
      throw new ApiError(
        `API ${method} ${path} returned non-JSON payload`,
        response.status,
        parsed,
      );
    }

    return parsed as T;
  }
}

function normalizeOperator(
  row: OperatorSummary & { disabled_at?: string | null },
): OperatorSummary {
  return {
    id: row.id,
    login: row.login,
    role: row.role,
    active: row.active ?? row.disabled_at == null,
  };
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

export const apiClient = new ApiClient({ getCsrfToken });
