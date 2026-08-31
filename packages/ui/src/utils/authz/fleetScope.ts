// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

export const MACHINE_IDS_WILDCARD = "*";
export const SYSTEM_FLEET_SCOPE_ALL_ID = "00000000-0000-4000-8000-000000000004";

export function machineIdsAllowAll(machineIds: string[]): boolean {
  return machineIds.includes(MACHINE_IDS_WILDCARD);
}

export function isSystemFleetScope(scope: { id: string; provenance?: string }): boolean {
  return scope.id === SYSTEM_FLEET_SCOPE_ALL_ID || scope.provenance === "system";
}
