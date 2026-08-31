// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

const DEFAULT_PREVIEW_MAX_LEN = 80;

export function formatJsonPreview(value: unknown, maxLen = DEFAULT_PREVIEW_MAX_LEN): string {
  const text = JSON.stringify(value).replace(/\s+/g, " ").trim();
  return text.length > maxLen ? `${text.slice(0, maxLen - 1)}…` : text;
}

export function formatJsonFull(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
