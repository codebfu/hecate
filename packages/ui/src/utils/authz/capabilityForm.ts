// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { CapabilityProfile, ShellPolicy, ElevationPolicy } from "../../api/client.js";
import type { CommandOption } from "./commandCatalog.js";

export const ALLOWLIST_WILDCARD = "*";

export const DEFAULT_CAPABILITY_PROFILE: Pick<
  CapabilityProfile,
  | "allowed_commands"
  | "allowed_admin_commands"
  | "shell_policy"
  | "elevation_policy"
  | "max_output_bytes"
  | "max_file_bytes"
  | "timeout_secs"
  | "max_concurrent"
> = {
  allowed_commands: ["permissions.request"],
  allowed_admin_commands: [],
  shell_policy: { allowed_binaries: [], allowed_cwd: [], allowed_env: [] },
  elevation_policy: { enabled: false, allowed_binaries: [] },
  max_output_bytes: 1_048_576,
  max_file_bytes: 52_428_800,
  timeout_secs: 30,
  max_concurrent: 4,
};

export function parseLineList(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

export function formatLineList(values: string[]): string {
  return values.join("\n");
}

export function allowedCommandsAllowAll(allowedCommands: string[]): boolean {
  return allowedCommands.includes(ALLOWLIST_WILDCARD);
}

export function allowedAdminCommandsAllowAll(allowedAdminCommands: string[]): boolean {
  return allowedAdminCommands.includes(ALLOWLIST_WILDCARD);
}

export function allowedBinariesAllowAll(allowedBinaries: string[]): boolean {
  return allowedBinaries.includes(ALLOWLIST_WILDCARD);
}

export function splitAllowedCommands(allowedCommands: string[], knownCommands: CommandOption[]) {
  if (allowedCommandsAllowAll(allowedCommands)) {
    return { known: new Set<string>(), custom: [] as string[] };
  }

  const knownIds = new Set(knownCommands.map((command) => command.id));
  const known = new Set<string>();
  const custom: string[] = [];

  for (const command of allowedCommands) {
    if (command === ALLOWLIST_WILDCARD) {
      continue;
    }
    if (knownIds.has(command)) {
      known.add(command);
    } else {
      custom.push(command);
    }
  }

  return { known, custom };
}

export function splitAllowedAdminCommands(
  allowedAdminCommands: string[],
  knownCommands: CommandOption[],
) {
  if (allowedAdminCommandsAllowAll(allowedAdminCommands)) {
    return { known: new Set<string>(), custom: [] as string[] };
  }

  const knownIds = new Set(knownCommands.map((command) => command.id));
  const known = new Set<string>();
  const custom: string[] = [];

  for (const command of allowedAdminCommands) {
    if (command === ALLOWLIST_WILDCARD) {
      continue;
    }
    if (knownIds.has(command)) {
      known.add(command);
    } else {
      custom.push(command);
    }
  }

  return { known, custom };
}

export function buildAllowedCommands(
  allowAll: boolean,
  known: Set<string>,
  customText: string,
): string[] {
  if (allowAll) {
    return [ALLOWLIST_WILDCARD];
  }
  return [...known, ...parseLineList(customText)];
}

export function buildAllowedAdminCommands(
  allowAll: boolean,
  known: Set<string>,
  customText: string,
): string[] {
  if (allowAll) {
    return [ALLOWLIST_WILDCARD];
  }
  return [...known, ...parseLineList(customText)];
}

export function capabilityToFormState(
  profile: Pick<
    CapabilityProfile,
    | "allowed_commands"
    | "allowed_admin_commands"
    | "shell_policy"
    | "elevation_policy"
    | "max_output_bytes"
    | "max_file_bytes"
    | "timeout_secs"
    | "max_concurrent"
  >,
  agentCommands: CommandOption[],
  adminCommands: CommandOption[],
) {
  const { known, custom } = splitAllowedCommands(profile.allowed_commands, agentCommands);
  const adminSplit = splitAllowedAdminCommands(profile.allowed_admin_commands, adminCommands);

  return {
    allowedCommandsAllowAll: allowedCommandsAllowAll(profile.allowed_commands),
    allowedCommands: known,
    customCommandsText: formatLineList(custom),
    allowedAdminCommandsAllowAll: allowedAdminCommandsAllowAll(profile.allowed_admin_commands),
    allowedAdminCommands: adminSplit.known,
    customAdminCommandsText: formatLineList(adminSplit.custom),
    allowedBinariesAllowAll: allowedBinariesAllowAll(profile.shell_policy.allowed_binaries),
    allowedBinariesText: formatLineList(
      profile.shell_policy.allowed_binaries.filter((binary) => binary !== ALLOWLIST_WILDCARD),
    ),
    allowedCwdText: formatLineList(profile.shell_policy.allowed_cwd),
    elevationEnabled: profile.elevation_policy.enabled,
    elevationBinariesAllowAll: allowedBinariesAllowAll(profile.elevation_policy.allowed_binaries),
    elevationBinariesText: formatLineList(
      profile.elevation_policy.allowed_binaries.filter((binary) => binary !== ALLOWLIST_WILDCARD),
    ),
    maxOutputBytes: profile.max_output_bytes,
    maxFileBytes: profile.max_file_bytes,
    timeoutSecs: profile.timeout_secs,
    maxConcurrent: profile.max_concurrent,
  };
}

export function formStateToCapability(
  state: ReturnType<typeof capabilityToFormState>,
): Pick<
  CapabilityProfile,
  | "allowed_commands"
  | "allowed_admin_commands"
  | "shell_policy"
  | "elevation_policy"
  | "max_output_bytes"
  | "max_file_bytes"
  | "timeout_secs"
  | "max_concurrent"
> {
  const shellPolicy: ShellPolicy = {
    allowed_binaries: state.allowedBinariesAllowAll
      ? [ALLOWLIST_WILDCARD]
      : parseLineList(state.allowedBinariesText),
    allowed_cwd: parseLineList(state.allowedCwdText),
    allowed_env: [],
  };
  const elevationPolicy: ElevationPolicy = {
    enabled: state.elevationEnabled,
    allowed_binaries: state.elevationBinariesAllowAll
      ? [ALLOWLIST_WILDCARD]
      : parseLineList(state.elevationBinariesText),
  };

  return {
    allowed_commands: buildAllowedCommands(
      state.allowedCommandsAllowAll,
      state.allowedCommands,
      state.customCommandsText,
    ),
    allowed_admin_commands: buildAllowedAdminCommands(
      state.allowedAdminCommandsAllowAll,
      state.allowedAdminCommands,
      state.customAdminCommandsText,
    ),
    shell_policy: shellPolicy,
    elevation_policy: elevationPolicy,
    max_output_bytes: state.maxOutputBytes,
    max_file_bytes: state.maxFileBytes,
    timeout_secs: state.timeoutSecs,
    max_concurrent: state.maxConcurrent,
  };
}

export function shellRunEnabled(formState: ReturnType<typeof capabilityToFormState>): boolean {
  return formState.allowedCommandsAllowAll || formState.allowedCommands.has("shell.run");
}

export function pathSensitiveWarning(formState: ReturnType<typeof capabilityToFormState>): boolean {
  if (formState.allowedCommandsAllowAll) {
    return parseLineList(formState.allowedCwdText).length === 0;
  }
  const pathCommands = [
    "shell.run",
    "desktop.shell.run",
    "file.pull",
    "file.push",
    "file.copy",
    "file.move",
    "file.rename",
    "file.delete",
    "folder.mkdir",
    "folder.rmdir",
    "folder.rename",
    "folder.move",
    "folder.copy",
    "remote.download",
  ];
  const hasPathCommand =
    [...formState.allowedCommands].some((cmd) => pathCommands.includes(cmd)) ||
    parseLineList(formState.customCommandsText).some((cmd) => pathCommands.includes(cmd));
  return hasPathCommand && parseLineList(formState.allowedCwdText).length === 0;
}
