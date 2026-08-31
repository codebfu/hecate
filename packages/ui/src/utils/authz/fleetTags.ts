// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { MachineSummary } from "../../api/client.js";

export function filterMachines(machines: MachineSummary[], query: string): MachineSummary[] {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return machines;
  }

  return machines.filter((machine) => {
    if (machine.hostname.toLowerCase().includes(needle)) {
      return true;
    }
    return machine.tags.some((tag) => tag.toLowerCase().includes(needle));
  });
}

export function collectFleetTagOptions(machines: MachineSummary[]): string[] {
  const tags = new Set<string>();
  for (const machine of machines) {
    for (const tag of machine.tags) {
      tags.add(tag);
    }
  }
  return [...tags].sort();
}

export function groupTagsByNamespace(tags: string[]): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  for (const tag of tags) {
    const namespace = tag.includes(":") ? tag.split(":")[0]! : "other";
    const list = groups.get(namespace) ?? [];
    list.push(tag);
    groups.set(namespace, list);
  }
  return new Map([...groups.entries()].sort(([a], [b]) => a.localeCompare(b)));
}
