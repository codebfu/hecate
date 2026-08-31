// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from "vitest";
import {
  allowedCommandsAllowAll,
  capabilityToFormState,
  formStateToCapability,
} from "./authz/capabilityForm.js";
import { machineIdsAllowAll, MACHINE_IDS_WILDCARD } from "./authz/fleetScope.js";
import { collectFleetTagOptions, filterMachines, groupTagsByNamespace } from "./authz/fleetTags.js";
import {
  partitionCommandCatalogue,
  type CommandOption,
} from "./authz/commandCatalog.js";
import type { MachineSummary } from "../api/client.js";

const machines: MachineSummary[] = [
  {
    id: "m1",
    hostname: "host-a",
    os: "linux",
    arch: "x86_64",
    tags: ["os:linux", "arch:x86_64"],
    status: "online",
  },
  {
    id: "m2",
    hostname: "host-b",
    os: "linux",
    arch: "aarch64",
    tags: ["os:linux", "virt:vm"],
    status: "online",
  },
];

const testAgentCommands: CommandOption[] = [
  { id: "permissions.request", description: "Request permission changes" },
  { id: "system.info", description: "Read-only system information" },
  { id: "shell.run", description: "Execute explicit argv via execve" },
];

const testAdminCommands: CommandOption[] = [
  { id: "admin.audit.list", description: "Read audit log" },
  { id: "admin.queue.list", description: "Read fleet action queue" },
];

describe("authz utils", () => {
  it("collects unique fleet tags sorted", () => {
    expect(collectFleetTagOptions(machines)).toEqual([
      "arch:x86_64",
      "os:linux",
      "virt:vm",
    ]);
  });

  it("groups tags by namespace", () => {
    const groups = groupTagsByNamespace(collectFleetTagOptions(machines));
    expect(groups.get("os")).toEqual(["os:linux"]);
    expect(groups.get("arch")).toEqual(["arch:x86_64"]);
    expect(groups.get("virt")).toEqual(["virt:vm"]);
  });

  it("filters machines by hostname or tag", () => {
    expect(filterMachines(machines, "host-a")).toHaveLength(1);
    expect(filterMachines(machines, "virt:vm")).toHaveLength(1);
    expect(filterMachines(machines, "missing")).toHaveLength(0);
  });

  it("detects command wildcard", () => {
    expect(allowedCommandsAllowAll(["*"])).toBe(true);
    expect(allowedCommandsAllowAll(["system.info"])).toBe(false);
  });

  it("detects machine id wildcard", () => {
    expect(machineIdsAllowAll([MACHINE_IDS_WILDCARD])).toBe(true);
    expect(machineIdsAllowAll(["m1"])).toBe(false);
  });

  it("partitions command catalogue by admin prefix", () => {
    const { agentCommands, adminCommands } = partitionCommandCatalogue([
      { name: "shell.run", description: "Shell", risk_level: "high" },
      { name: "admin.audit.list", description: "Audit", risk_level: "low" },
    ]);
    expect(agentCommands).toEqual([{ id: "shell.run", description: "Shell", riskLevel: "high" }]);
    expect(adminCommands).toEqual([{ id: "admin.audit.list", description: "Audit", riskLevel: "low" }]);
  });

  it("round-trips capability profile through form state", () => {
    const profile = {
      allowed_commands: ["permissions.request", "custom.command"],
      allowed_admin_commands: ["admin.queue.list"],
      shell_policy: {
        allowed_binaries: ["/usr/bin/uptime"],
        allowed_cwd: ["/tmp"],
        allowed_env: [],
      },
      elevation_policy: { enabled: false, allowed_binaries: [] },
      max_output_bytes: 2048,
      max_file_bytes: 52_428_800,
      timeout_secs: 10,
      max_concurrent: 2,
    };

    const formState = capabilityToFormState(profile, testAgentCommands, testAdminCommands);
    expect(formState.allowedCommands.has("permissions.request")).toBe(true);
    expect(formState.customCommandsText).toBe("custom.command");
    expect(formStateToCapability(formState)).toEqual(profile);
  });
});
