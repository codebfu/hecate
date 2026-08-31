// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

const API_MESSAGE_LABELS: Record<string, string> = {
  "invalid login length": "Login must be 3–32 characters.",
  "invalid login chars": "Login may only contain letters, numbers, underscores, and hyphens.",
  "password too short": "Password must be at least 12 characters.",
  "bootstrap already done": "Initial setup was already completed. Sign in instead.",
};

export function humanizeApiMessage(message: string): string {
  const trimmed = message.trim();
  if (!trimmed) {
    return "Request failed.";
  }
  return API_MESSAGE_LABELS[trimmed] ?? trimmed.replace(/^bad request:\s*/i, "");
}

export function extractApiErrorMessage(status: number, body: unknown): string {
  if (body && typeof body === "object" && "message" in body) {
    const message = (body as { message?: unknown }).message;
    if (typeof message === "string" && message.trim().length > 0) {
      return humanizeApiMessage(message);
    }
  }

  if (typeof body === "string" && body.trim().length > 0) {
    return humanizeApiMessage(body);
  }

  switch (status) {
    case 401:
      return "Invalid login or password.";
    case 403:
      return "You do not have permission to perform this action.";
    case 409:
      return "This action conflicts with the current server state.";
    default:
      return `Request failed (${status}).`;
  }
}

export function getApiErrorMessage(error: unknown, fallback: string): string {
  if (error && typeof error === "object" && "message" in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message.trim().length > 0) {
      return message;
    }
  }
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }
  return fallback;
}
