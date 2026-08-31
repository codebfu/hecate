// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  allowedAdminCommandsAllowAll,
  allowedCommandsAllowAll,
} from "./capabilityForm.js";

export const SYSTEM_CAPABILITY_PROFILE_ALL_USER_COMMANDS_ID =
  "00000000-0000-4000-8000-000000000005";
export const SYSTEM_CAPABILITY_PROFILE_ALL_ADMIN_COMMANDS_ID =
  "00000000-0000-4000-8000-000000000006";

export function isSystemCapabilityProfile(profile: { id: string; provenance?: string }): boolean {
  return (
    profile.provenance === "system" ||
    profile.id === SYSTEM_CAPABILITY_PROFILE_ALL_USER_COMMANDS_ID ||
    profile.id === SYSTEM_CAPABILITY_PROFILE_ALL_ADMIN_COMMANDS_ID
  );
}

export function formatCommandCount(allowedCommands: string[]): string {
  return allowedCommandsAllowAll(allowedCommands) ? "All" : String(allowedCommands.length);
}

export function formatAdminCommandCount(allowedAdminCommands: string[]): string {
  return allowedAdminCommandsAllowAll(allowedAdminCommands)
    ? "All"
    : String(allowedAdminCommands.length);
}
