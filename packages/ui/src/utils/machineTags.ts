// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

const TAG_PATTERN = /^[a-z][a-z0-9_-]*:[a-z][a-z0-9_.-]*$/;
const RESERVED_NAMESPACES = new Set(["os", "arch", "distro", "virt", "init"]);

export function validateCustomTagInput(raw: string): string | null {
  const tag = raw.trim();
  if (!tag) {
    return "Tag is required.";
  }
  if (tag.length > 64) {
    return "Tag must be at most 64 characters.";
  }
  if (!TAG_PATTERN.test(tag)) {
    return "Use namespace:value (lowercase letters, digits, _, -, .).";
  }
  const namespace = tag.split(":")[0]!;
  if (RESERVED_NAMESPACES.has(namespace)) {
    return `Namespace "${namespace}" is reserved for agent auto-detection.`;
  }
  return null;
}
