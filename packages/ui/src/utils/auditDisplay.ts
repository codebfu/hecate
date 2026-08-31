// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { AuditEventRef } from "../api/client.js";

const DETAIL_PREVIEW_MAX_LEN = 80;

export function formatAuditDetailPreview(detail: string, maxLen = DETAIL_PREVIEW_MAX_LEN): string {
  const text = detail.replace(/\s+/g, " ").trim();
  return text.length > maxLen ? `${text.slice(0, maxLen - 1)}…` : text;
}

export function formatAuditDetailFull(detail: string): string {
  try {
    return JSON.stringify(JSON.parse(detail), null, 2);
  } catch {
    return detail;
  }
}

export function auditRefHref(ref: AuditEventRef): string | null {
  if (!ref.kind) {
    return null;
  }

  switch (ref.kind) {
    case "ai_identity":
      return ref.id ? `/ai-identities?identity=${encodeURIComponent(ref.id)}` : null;
    case "operator":
      if (ref.id) {
        return `/users?operator=${encodeURIComponent(ref.id)}`;
      }
      return ref.label ? `/users?login=${encodeURIComponent(ref.label)}` : null;
    case "machine":
      return ref.id ? `/machines/${encodeURIComponent(ref.id)}` : null;
    case "command":
      return ref.id ? `/action-queue?command=${encodeURIComponent(ref.id)}` : null;
    case "ai_api_key":
      return ref.related_id
        ? `/ai-identities?identity=${encodeURIComponent(ref.related_id)}`
        : null;
    case "agent":
      return null;
    default:
      return null;
  }
}
