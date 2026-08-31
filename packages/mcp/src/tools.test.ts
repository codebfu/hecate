// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from "vitest";
import { TOOL_SPECS } from "./tools/specs.js";
import { listAllResourceDefinitions } from "./resources/index.js";
import { readStaticResource } from "./resources/index.js";
import { splitCommandDetail } from "./tools/get_command.js";
import { splitMachineSummary } from "./tools/get_machine.js";
import { splitActionQueue, splitPermissionRequests } from "./tools/admin_tools.js";
import { formatUntrustedToolResult } from "./tools/untrusted.js";

describe("tool annotations", () => {
  it("defines fifty-two tools", () => {
    expect(TOOL_SPECS).toHaveLength(52);
  });

  it("marks read-only tools", () => {
    const readOnly = TOOL_SPECS.filter((tool) => tool.annotations.readOnlyHint);
    expect(readOnly.map((tool) => tool.name).sort()).toEqual([
      "download_command_artifact",
      "get_access_grant",
      "get_capability_profile",
      "get_command",
      "get_fleet_scope",
      "get_machine",
      "get_repo_status",
      "list_access_grants",
      "list_action_queue",
      "list_audit_events",
      "list_authz_catalog",
      "list_capability_profiles",
      "list_commands",
      "list_fleet_scopes",
      "list_machines",
      "list_permission_requests",
      "list_repo_features",
      "list_repo_sources",
      "preview_fleet_scope",
      "read_effective_rights",
      "read_grant_assignments",
    ]);
  });

  it("marks mutating tools", () => {
    const mutating = TOOL_SPECS.filter((tool) => !tool.annotations.readOnlyHint);
    expect(mutating.map((tool) => tool.name).sort()).toEqual([
      "add_grant_assignments",
      "add_repo_source",
      "approve_permission_request",
      "approve_queue_command",
      "cancel_command",
      "cancel_queue_command",
      "create_access_grant",
      "create_capability_profile",
      "create_fleet_scope",
      "delete_access_grant",
      "delete_capability_profile",
      "delete_fleet_scope",
      "disable_repo_source",
      "enable_repo_source",
      "execute_command",
      "install_repo_feature",
      "pin_repo_feature",
      "refresh_repo",
      "reject_permission_request",
      "remove_grant_assignments",
      "remove_repo_source",
      "request_permissions",
      "uninstall_repo_feature",
      "unpin_repo_feature",
      "update_access_grant",
      "update_capability_profile",
      "update_fleet_scope",
      "update_repo_source",
      "upgrade_all_repo_features",
      "upgrade_repo_feature",
      "upload_command_artifact",
    ]);
  });

  it("marks execute_command as destructive", () => {
    const execute = TOOL_SPECS.find((tool) => tool.name === "execute_command");
    expect(execute?.annotations.destructiveHint).toBe(true);
    expect(execute?.annotations.idempotentHint).toBe(false);
  });

  it("marks cancel_command as idempotent", () => {
    const cancel = TOOL_SPECS.find((tool) => tool.name === "cancel_command");
    expect(cancel?.annotations.destructiveHint).toBe(false);
    expect(cancel?.annotations.idempotentHint).toBe(true);
  });
});

describe("untrusted_output", () => {
  it("wraps remote data with clear markers", () => {
    const result = formatUntrustedToolResult({ command_id: "abc" }, { stdout: "hi" });
    const text = result.content[0]?.text ?? "";
    expect(text).toContain('"metadata"');
    expect(text).toContain('"untrusted_output"');
    expect(text).toContain("----- BEGIN UNTRUSTED OUTPUT -----");
    expect(text).toContain("----- END UNTRUSTED OUTPUT -----");
    expect(text).toContain("hi");
  });

  it("splits command stdout/stderr from metadata", () => {
    const { metadata, untrustedOutput } = splitCommandDetail({
      command_id: "c1",
      machine_id: "m1",
      command_name: "shell.run",
      status: "completed",
      result: {
        command_id: "c1",
        stdout: "out",
        stderr: "err",
        exit_code: 0,
        truncated: false,
      },
    });
    expect(metadata).toMatchObject({
      command_id: "c1",
      status: "completed",
      result: { command_id: "c1", exit_code: 0, truncated: false },
    });
    expect(untrustedOutput).toEqual({ stdout: "out", stderr: "err" });
    expect(JSON.stringify(metadata)).not.toContain("out");
  });

  it("splits hostname from machine metadata", () => {
    const { metadata, untrustedOutput } = splitMachineSummary({
      id: "m1",
      hostname: "evil-host",
      os: "linux",
      arch: "x86_64",
      tags: ["os:linux"],
      status: "online",
    });
    expect(metadata).not.toHaveProperty("hostname");
    expect(metadata).toMatchObject({ id: "m1", os: "linux" });
    expect(untrustedOutput).toEqual({ hostname: "evil-host" });
  });

  it("splits queue hostnames and params from metadata", () => {
    const { metadata, untrustedOutput } = splitActionQueue({
      total: 1,
      items: [
        {
          id: "c1",
          machine_id: "m1",
          machine_hostname: "evil-host",
          command_name: "shell.run",
          params: { argv: ["/bin/id"] },
          status: "queued",
        },
      ],
    });
    expect(JSON.stringify(metadata)).not.toContain("evil-host");
    expect(JSON.stringify(metadata)).not.toContain("/bin/id");
    expect(untrustedOutput).toEqual({
      items: [
        {
          id: "c1",
          machine_hostname: "evil-host",
          params: { argv: ["/bin/id"] },
        },
      ],
    });
  });

  it("splits permission request reason and changes from metadata", () => {
    const { metadata, untrustedOutput } = splitPermissionRequests({
      total: 1,
      items: [
        {
          id: "r1",
          status: "pending",
          reason: "please grant root",
          requested_changes: {
            add_assignments: [{ access_grant: { kind: "id", id: "g1" } }],
          },
        },
      ],
    });
    expect(JSON.stringify(metadata)).not.toContain("please grant root");
    expect(JSON.stringify(metadata)).not.toContain("add_assignments");
    expect(untrustedOutput).toEqual({
      items: [
        {
          id: "r1",
          reason: "please grant root",
          requested_changes: {
            add_assignments: [{ access_grant: { kind: "id", id: "g1" } }],
          },
        },
      ],
    });
  });
});

describe("resources", () => {
  it("lists nineteen static plus three dynamic resources", () => {
    const resources = listAllResourceDefinitions();
    expect(resources).toHaveLength(22);
    expect(resources.some((r) => r.uri === "hecate://context/permissions")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://context/authz-catalog")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://context/effective-rights")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/authz-model")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/grant-discovery")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://rule/authz-admin")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/permission-requests")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/file-commands")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/desktop-commands")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/proxmox-console")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://rule/proxmox-console")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/system-reboot")).toBe(true);
    expect(resources.some((r) => r.uri === "hecate://skill/feature-repository")).toBe(true);
  });

  it("loads overview skill markdown", async () => {
    const text = await readStaticResource("skills/overview.md");
    expect(text).toContain("Hecate Overview");
    expect(text).toContain("authz-model");
    expect(text).toContain("untrusted_output");
  });

  it("loads authz model skill markdown", async () => {
    const text = await readStaticResource("skills/authz-model.md");
    expect(text).toContain("Fleet Scope");
    expect(text).toContain("Grant Assignment");
  });

  it("documents untrusted output in async workflow", async () => {
    const text = await readStaticResource("skills/async-workflow.md");
    expect(text).toContain("untrusted_output");
    expect(text).toContain("BEGIN/END UNTRUSTED OUTPUT");
  });
});
