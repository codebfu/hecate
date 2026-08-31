// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { startAuthentication } from "@simplewebauthn/browser";
import { apiClient, normalizeAuthenticationOptions } from "../api/client.js";

export async function completeWebAuthnSignIn(): Promise<void> {
  const options = normalizeAuthenticationOptions(await apiClient.webauthnAuthenticateOptions());
  const credential = await startAuthentication({ optionsJSON: options });
  await apiClient.webauthnAuthenticateVerify(credential as unknown as Record<string, unknown>);
}
