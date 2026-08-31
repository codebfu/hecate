// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
import { findToolSpec } from "./specs.js";
import { formatUntrustedToolResult } from "./untrusted.js";

const permissionChangesSchema = z.record(z.string(), z.unknown());

export function registerRequestPermissionsTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("request_permissions")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Submit a permanent permission change request for operator approval. Additive payload (grant assignments, not monolithic rules). One pending standard request per identity. Read hecate://skill/authz-model and hecate://skill/permission-requests first.",
      inputSchema: z.object({
        reason: z.string().min(8),
        requested_changes: permissionChangesSchema,
      }),
      annotations: spec.annotations,
    },
    async ({ reason, requested_changes }) => {
      const response = await client.executePlatformCommand("permissions.request", {
        reason,
        requested_changes,
      });
      return formatUntrustedToolResult(
        { command: "permissions.request" },
        response.result,
      );
    },
  );

  return spec;
}

export function registerReadGrantAssignmentsTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("read_grant_assignments")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Read grant assignments for the current identity or another identity (requires admin.authz.assignments.read). See hecate://skill/authz-model.",
      inputSchema: z.object({
        identity_id: z.string().uuid().optional(),
      }),
      annotations: spec.annotations,
    },
    async ({ identity_id }) => {
      const response = await client.executeAdminCommand("admin.authz.assignments.read", {
        identity_id,
      });
      return formatUntrustedToolResult(
        { command: "admin.authz.assignments.read" },
        response.result,
      );
    },
  );

  return spec;
}

export function registerReadEffectiveRightsTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("read_effective_rights")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Read the computed effective rights matrix for self or another identity (requires admin.authz.effective_rights.read). Prefer hecate://context/effective-rights for self.",
      inputSchema: z.object({
        identity_id: z.string().uuid().optional(),
      }),
      annotations: spec.annotations,
    },
    async ({ identity_id }) => {
      const response = await client.executeAdminCommand("admin.authz.effective_rights.read", {
        identity_id,
      });
      return formatUntrustedToolResult(
        { command: "admin.authz.effective_rights.read" },
        response.result,
      );
    },
  );

  return spec;
}

export function registerListPermissionRequestsTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("list_permission_requests")!;

  server.registerTool(
    spec.name,
    {
      description: "List paginated permission change requests (requires admin.permissions.requests.list).",
      inputSchema: z.object({
        limit: z.number().int().min(1).max(100).optional(),
        offset: z.number().int().min(0).optional(),
        status: z.enum(["pending", "approved", "rejected"]).optional(),
      }),
      annotations: spec.annotations,
    },
    async ({ limit, offset, status }) => {
      const response = await client.executeAdminCommand("admin.permissions.requests.list", {
        limit,
        offset,
        status,
      });
      const { metadata, untrustedOutput } = splitPermissionRequests(response.result);
      return formatUntrustedToolResult(metadata, untrustedOutput);
    },
  );

  return spec;
}

export function registerApprovePermissionRequestTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("approve_permission_request")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Approve a pending permission request and apply requested rules permanently. Cannot approve own requests.",
      inputSchema: z.object({
        request_id: z.string().uuid(),
      }),
      annotations: spec.annotations,
    },
    async ({ request_id }) => {
      const response = await client.executeAdminCommand("admin.permissions.request.approve", {
        request_id,
      });
      return formatUntrustedToolResult(
        { command: "admin.permissions.request.approve", request_id },
        response.result,
      );
    },
  );

  return spec;
}

export function registerRejectPermissionRequestTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("reject_permission_request")!;

  server.registerTool(
    spec.name,
    {
      description: "Reject a pending permission request without changing current rules.",
      inputSchema: z.object({
        request_id: z.string().uuid(),
        reason: z.string().optional(),
      }),
      annotations: spec.annotations,
    },
    async ({ request_id, reason }) => {
      const response = await client.executeAdminCommand("admin.permissions.request.reject", {
        request_id,
        reason,
      });
      return formatUntrustedToolResult(
        { command: "admin.permissions.request.reject", request_id },
        response.result,
      );
    },
  );

  return spec;
}

export function registerListAuditEventsTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("list_audit_events")!;

  server.registerTool(
    spec.name,
    {
      description: "List paginated audit log events (requires admin.audit.list).",
      inputSchema: z.object({
        limit: z.number().int().min(1).max(100).optional(),
        offset: z.number().int().min(0).optional(),
      }),
      annotations: spec.annotations,
    },
    async ({ limit, offset }) => {
      const response = await client.executeAdminCommand("admin.audit.list", { limit, offset });
      const { metadata, untrustedOutput } = splitAuditList(response.result);
      return formatUntrustedToolResult(metadata, untrustedOutput);
    },
  );

  return spec;
}

export function registerListActionQueueTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("list_action_queue")!;

  server.registerTool(
    spec.name,
    {
      description: "List paginated fleet action queue entries (requires admin.queue.list).",
      inputSchema: z.object({
        limit: z.number().int().min(1).max(100).optional(),
        offset: z.number().int().min(0).optional(),
        command_id: z.string().uuid().optional(),
        machine_id: z.string().uuid().optional(),
        include_recent: z.boolean().optional(),
      }),
      annotations: spec.annotations,
    },
    async ({ limit, offset, command_id, machine_id, include_recent }) => {
      const response = await client.executeAdminCommand("admin.queue.list", {
        limit,
        offset,
        command_id,
        machine_id,
        include_recent,
      });
      const { metadata, untrustedOutput } = splitActionQueue(response.result);
      return formatUntrustedToolResult(metadata, untrustedOutput);
    },
  );

  return spec;
}

export function registerApproveQueueCommandTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("approve_queue_command")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Approve a pending_approval command into the queue. Cannot approve commands enqueued by the current identity.",
      inputSchema: z.object({
        command_id: z.string().uuid(),
      }),
      annotations: spec.annotations,
    },
    async ({ command_id }) => {
      const response = await client.executeAdminCommand("admin.queue.approve", { command_id });
      return formatUntrustedToolResult(
        { command: "admin.queue.approve", command_id },
        response.result,
      );
    },
  );

  return spec;
}

export function registerCancelQueueCommandTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("cancel_queue_command")!;

  server.registerTool(
    spec.name,
    {
      description:
        "Cancel a pending_approval, queued, dispatched, or running command in the fleet action queue.",
      inputSchema: z.object({
        command_id: z.string().uuid(),
      }),
      annotations: spec.annotations,
    },
    async ({ command_id }) => {
      const response = await client.executeAdminCommand("admin.queue.cancel", { command_id });
      return formatUntrustedToolResult(
        { command: "admin.queue.cancel", command_id },
        response.result,
      );
    },
  );

  return spec;
}

/** AI-authored reason / requested_changes must not drive the model as instructions. */
export function splitPermissionRequests(result: unknown): {
  metadata: unknown;
  untrustedOutput: unknown;
} {
  if (!result || typeof result !== "object") {
    return { metadata: result, untrustedOutput: null };
  }
  const page = result as { items?: unknown[] } & Record<string, unknown>;
  const items = Array.isArray(page.items) ? page.items : [];
  const metadataItems: unknown[] = [];
  const untrustedItems: unknown[] = [];
  for (const item of items) {
    if (!item || typeof item !== "object") {
      metadataItems.push(item);
      continue;
    }
    const row = item as Record<string, unknown>;
    const { reason, requested_changes, requested_rules, ...rest } = row;
    metadataItems.push(rest);
    untrustedItems.push({
      id: rest.id,
      reason,
      requested_changes: requested_changes ?? requested_rules,
    });
  }
  return {
    metadata: { ...page, items: metadataItems },
    untrustedOutput: { items: untrustedItems },
  };
}

/** Hostnames and command params are agent-origin; keep ids/status as metadata. */
export function splitActionQueue(result: unknown): {
  metadata: unknown;
  untrustedOutput: unknown;
} {
  if (!result || typeof result !== "object") {
    return { metadata: result, untrustedOutput: null };
  }
  const page = result as { items?: unknown[] } & Record<string, unknown>;
  const items = Array.isArray(page.items) ? page.items : [];
  const metadataItems: unknown[] = [];
  const untrustedItems: unknown[] = [];
  for (const item of items) {
    if (!item || typeof item !== "object") {
      metadataItems.push(item);
      continue;
    }
    const row = item as Record<string, unknown>;
    const { machine_hostname, params, ...rest } = row;
    metadataItems.push(rest);
    untrustedItems.push({
      id: rest.id,
      machine_hostname,
      params,
    });
  }
  return {
    metadata: { ...page, items: metadataItems },
    untrustedOutput: { items: untrustedItems },
  };
}

/** Machine/operator labels in audit refs can carry hostnames or attacker-controlled names. */
export function splitAuditList(result: unknown): {
  metadata: unknown;
  untrustedOutput: unknown;
} {
  if (!result || typeof result !== "object") {
    return { metadata: result, untrustedOutput: null };
  }
  const page = result as { items?: unknown[] } & Record<string, unknown>;
  const items = Array.isArray(page.items) ? page.items : [];
  const metadataItems: unknown[] = [];
  const untrustedItems: unknown[] = [];
  for (const item of items) {
    if (!item || typeof item !== "object") {
      metadataItems.push(item);
      continue;
    }
    const row = item as Record<string, unknown>;
    const actor = stripRefLabels(row.actor);
    const target = stripRefLabels(row.target);
    metadataItems.push({ ...row, actor: actor.metadata, target: target.metadata });
    untrustedItems.push({
      id: row.id,
      actor: actor.untrusted,
      target: target.untrusted,
    });
  }
  return {
    metadata: { ...page, items: metadataItems },
    untrustedOutput: { items: untrustedItems },
  };
}

function stripRefLabels(ref: unknown): { metadata: unknown; untrusted: unknown } {
  if (!ref || typeof ref !== "object") {
    return { metadata: ref, untrusted: null };
  }
  const row = ref as Record<string, unknown>;
  const { label, detail, ...rest } = row;
  return {
    metadata: rest,
    untrusted: { label, detail },
  };
}

const repoToolDefinitions = [
  {
    tool: "list_repo_sources",
    command: "admin.repo.sources.list",
    description: "List configured signed feature repository sources.",
    inputSchema: z.object({}),
  },
  {
    tool: "add_repo_source",
    command: "admin.repo.sources.add",
    description: "Add a signed feature repository source.",
    inputSchema: z.object({
      id: z.string().min(1),
      url: z.string().url(),
      public_key_b64: z.string().min(1),
      priority: z.number().int().optional(),
    }),
  },
  {
    tool: "update_repo_source",
    command: "admin.repo.sources.update",
    description:
      "Update a feature repository source public key or priority. Official source URL is read-only.",
    inputSchema: z.object({
      id: z.string().min(1),
      url: z.string().url().optional(),
      public_key_b64: z.string().min(1).optional(),
      priority: z.number().int().optional(),
    }),
  },
  {
    tool: "enable_repo_source",
    command: "admin.repo.sources.enable",
    description: "Enable a feature repository source.",
    inputSchema: z.object({ id: z.string().min(1) }),
  },
  {
    tool: "disable_repo_source",
    command: "admin.repo.sources.disable",
    description: "Disable a feature repository source.",
    inputSchema: z.object({ id: z.string().min(1) }),
  },
  {
    tool: "remove_repo_source",
    command: "admin.repo.sources.remove",
    description:
      "Remove a feature repository source. The official source cannot be removed. Installed features prevent removal.",
    inputSchema: z.object({ id: z.string().min(1) }),
  },
  {
    tool: "list_repo_features",
    command: "admin.repo.list",
    description: "List available catalogue features and installed features.",
    inputSchema: z.object({}),
  },
  {
    tool: "install_repo_feature",
    command: "admin.repo.install",
    description: "Install a feature from a signed repository (tracks latest unless version is set).",
    inputSchema: z.object({
      id: z.string().min(1),
      version: z.string().min(1).optional(),
      source_id: z.string().min(1).optional(),
    }),
  },
  {
    tool: "upgrade_repo_feature",
    command: "admin.repo.upgrade",
    description: "Upgrade a single installed feature, optionally to a specific version.",
    inputSchema: z.object({
      id: z.string().min(1),
      version: z.string().min(1).optional(),
    }),
  },
  {
    tool: "upgrade_all_repo_features",
    command: "admin.repo.upgrade_all",
    description:
      "Upgrade all installed features that track latest to the newest published version. Pinned features are skipped.",
    inputSchema: z.object({}),
  },
  {
    tool: "pin_repo_feature",
    command: "admin.repo.pin",
    description: "Pin an installed feature to an explicit version.",
    inputSchema: z.object({
      id: z.string().min(1),
      version: z.string().min(1),
    }),
  },
  {
    tool: "unpin_repo_feature",
    command: "admin.repo.unpin",
    description: "Remove a version pin and resume tracking the newest published release.",
    inputSchema: z.object({ id: z.string().min(1) }),
  },
  {
    tool: "uninstall_repo_feature",
    command: "admin.repo.uninstall",
    description: "Uninstall a feature and remove it from the local catalogue.",
    inputSchema: z.object({ id: z.string().min(1) }),
  },
  {
    tool: "get_repo_status",
    command: "admin.repo.status",
    description: "Show repository sources, installed features, and cached artifact count.",
    inputSchema: z.object({}),
  },
  {
    tool: "refresh_repo",
    command: "admin.repo.refresh",
    description: "Refresh feature repository catalogue metadata only. Does not upgrade installs.",
    inputSchema: z.object({}),
  },
] as const;

const authzToolDefinitions = [
  {
    tool: "list_authz_catalog",
    command: "admin.authz.catalog",
    description:
      "List the aggregated authz catalog (fleet scopes, capability profiles, access grants). Requires admin.authz.catalog.",
    inputSchema: z.object({}),
  },
  {
    tool: "list_fleet_scopes",
    command: "admin.authz.fleet_scopes.list",
    description: "List fleet scopes. See hecate://skill/authz-model.",
    inputSchema: z.object({}),
  },
  {
    tool: "get_fleet_scope",
    command: "admin.authz.fleet_scopes.read",
    description: "Read fleet scope detail including explicit machines and tags.",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "preview_fleet_scope",
    command: "admin.authz.fleet_scopes.preview",
    description: "Preview resolved fleet scope membership (machines matched by scope rules).",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "create_fleet_scope",
    command: "admin.authz.fleet_scopes.create",
    description: "Create a fleet scope. Wildcard machine_ids are operator-only.",
    inputSchema: z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      tag_match_mode: z.enum(["any", "all"]).optional(),
      machine_ids: z.array(z.string()).optional(),
      tags: z.array(z.string()).optional(),
    }),
  },
  {
    tool: "update_fleet_scope",
    command: "admin.authz.fleet_scopes.update",
    description: "Update a fleet scope.",
    inputSchema: z.object({
      id: z.string().uuid(),
      name: z.string().min(1).optional(),
      description: z.string().optional(),
      tag_match_mode: z.enum(["any", "all"]).optional(),
      machine_ids: z.array(z.string()).optional(),
      tags: z.array(z.string()).optional(),
    }),
  },
  {
    tool: "delete_fleet_scope",
    command: "admin.authz.fleet_scopes.delete",
    description: "Delete a fleet scope. Fails when referenced by an access grant.",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "list_capability_profiles",
    command: "admin.authz.capability_profiles.list",
    description: "List capability profiles.",
    inputSchema: z.object({}),
  },
  {
    tool: "get_capability_profile",
    command: "admin.authz.capability_profiles.read",
    description: "Read capability profile detail (commands, shell/elevation policy, limits).",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "create_capability_profile",
    command: "admin.authz.capability_profiles.create",
    description: "Create a capability profile.",
    inputSchema: z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      allowed_commands: z.array(z.string()).optional(),
      allowed_admin_commands: z.array(z.string()).optional(),
      shell_policy: z.record(z.string(), z.unknown()).optional(),
      elevation_policy: z.record(z.string(), z.unknown()).optional(),
      max_output_bytes: z.number().int().optional(),
      max_file_bytes: z.number().int().optional(),
      timeout_secs: z.number().int().optional(),
      max_concurrent: z.number().int().optional(),
    }),
  },
  {
    tool: "update_capability_profile",
    command: "admin.authz.capability_profiles.update",
    description: "Update a capability profile.",
    inputSchema: z.object({
      id: z.string().uuid(),
      name: z.string().min(1).optional(),
      description: z.string().optional(),
      allowed_commands: z.array(z.string()).optional(),
      allowed_admin_commands: z.array(z.string()).optional(),
      shell_policy: z.record(z.string(), z.unknown()).optional(),
      elevation_policy: z.record(z.string(), z.unknown()).optional(),
      max_output_bytes: z.number().int().optional(),
      max_file_bytes: z.number().int().optional(),
      timeout_secs: z.number().int().optional(),
      max_concurrent: z.number().int().optional(),
    }),
  },
  {
    tool: "delete_capability_profile",
    command: "admin.authz.capability_profiles.delete",
    description: "Delete a capability profile. Fails when referenced by an access grant.",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "list_access_grants",
    command: "admin.authz.access_grants.list",
    description: "List access grants.",
    inputSchema: z.object({}),
  },
  {
    tool: "get_access_grant",
    command: "admin.authz.access_grants.read",
    description: "Read access grant detail with resolved fleet scope and capability profile.",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "create_access_grant",
    command: "admin.authz.access_grants.create",
    description: "Create an access grant linking a fleet scope and capability profile.",
    inputSchema: z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      fleet_scope_id: z.string().uuid(),
      capability_profile_id: z.string().uuid(),
    }),
  },
  {
    tool: "update_access_grant",
    command: "admin.authz.access_grants.update",
    description: "Update an access grant.",
    inputSchema: z.object({
      id: z.string().uuid(),
      name: z.string().min(1).optional(),
      description: z.string().optional(),
      fleet_scope_id: z.string().uuid().optional(),
      capability_profile_id: z.string().uuid().optional(),
    }),
  },
  {
    tool: "delete_access_grant",
    command: "admin.authz.access_grants.delete",
    description: "Delete an access grant. Fails when assigned to an identity.",
    inputSchema: z.object({ id: z.string().uuid() }),
  },
  {
    tool: "add_grant_assignments",
    command: "admin.authz.assignments.add",
    description:
      "Add or update grant assignments on a target identity (immediate effect). Requires admin.authz.assignments.add. See hecate://rule/authz-admin.",
    inputSchema: z.object({
      identity_id: z.string().uuid().optional(),
      access_grant_id: z.string().uuid(),
      requires_approval_for_shell: z.boolean().optional(),
      requires_approval_for_elevated: z.boolean().optional(),
      enabled: z.boolean().optional(),
    }),
  },
  {
    tool: "remove_grant_assignments",
    command: "admin.authz.assignments.remove",
    description:
      "Remove grant assignments from a target identity (immediate effect). Cannot target self. Requires admin.authz.assignments.remove.",
    inputSchema: z.object({
      identity_id: z.string().uuid().optional(),
      assignment_ids: z.array(z.string().uuid()).min(1),
      reason: z.string().optional(),
    }),
  },
] as const;

export function registerAuthzTools(server: McpServer, client: HecateApiClient) {
  return authzToolDefinitions.map((definition) => {
    const spec = findToolSpec(definition.tool)!;
    server.registerTool(
      spec.name,
      {
        description: definition.description,
        inputSchema: definition.inputSchema,
        annotations: spec.annotations,
      },
      async (params: Record<string, unknown>) => {
        const response = await client.executeAdminCommand(
          definition.command,
          params,
        );
        return formatUntrustedToolResult(
          { command: definition.command },
          response.result,
        );
      },
    );
    return spec;
  });
}

export function registerRepoTools(server: McpServer, client: HecateApiClient) {
  return repoToolDefinitions.map((definition) => {
    const spec = findToolSpec(definition.tool)!;
    server.registerTool(
      spec.name,
      {
        description: definition.description,
        inputSchema: definition.inputSchema,
        annotations: spec.annotations,
      },
      async (params: Record<string, unknown>) => {
        const response = await client.executeAdminCommand(
          definition.command,
          params,
        );
        return formatUntrustedToolResult(
          { command: definition.command },
          response.result,
        );
      },
    );
    return spec;
  });
}
