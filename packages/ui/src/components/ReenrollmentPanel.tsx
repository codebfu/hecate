// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { apiClient } from "../api/client.js";
import { useToast } from "./ToastProvider.js";

type ReenrollmentPanelProps = {
  kind: "agent" | "proxy";
  entityId: string;
  os?: string;
  serverUrl: string;
};

function enrollCommand(os: string | undefined, serverUrl: string, token: string): string {
  if (os === "windows") {
    return `hecate-lampad.exe enroll --server-url ${serverUrl} --token ${token}`;
  }
  return `sudo hecate-lampad enroll --server-url ${serverUrl} --token ${token}`;
}

function proxyReenrollHint(token: string): string {
  return `Set PROXY_ENROLLMENT_TOKEN=${token} and restart the Propylaea service.`;
}

export function ReenrollmentPanel({ kind, entityId, os, serverUrl }: ReenrollmentPanelProps) {
  const toast = useToast();
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () =>
      kind === "agent"
        ? apiClient.createEnrollmentToken({ machineId: entityId })
        : apiClient.createProxyEnrollmentToken({ proxyId: entityId }),
    onSuccess: (data) => {
      setToken(data.token);
      setExpiresAt(data.expires_at);
    },
    onError: (error) => {
      toast.error(
        error instanceof Error ? error.message : "Failed to create re-enrollment token.",
      );
    },
  });

  const title = kind === "agent" ? "Re-enroll agent" : "Re-enroll proxy";
  const helpText =
    kind === "agent"
      ? "Re-attach this machine with a fresh credential key (lost keys, missed rotation, or migration). Requires shell access on the host; restart the agent service after running the command if it is already installed."
      : "Re-attach this proxy with a fresh credential key. Set the token in the environment and restart Propylaea.";

  return (
    <section className="card stack">
      <h2>{title}</h2>
      <p className="muted">{helpText}</p>
      <button
        type="button"
        onClick={() => createMutation.mutate()}
        disabled={createMutation.isPending}
      >
        Create re-enrollment token
      </button>
      {token ? (
        <>
          <p className="muted">
            Token (copy now): <code>{token}</code>
          </p>
          {expiresAt ? (
            <p className="muted">
              Expires at: <code>{expiresAt}</code>
            </p>
          ) : null}
          {kind === "agent" ? (
            <>
              <p className="muted">Run on the host:</p>
              <pre className="code-block">{enrollCommand(os, serverUrl, token)}</pre>
              <p className="muted">
                After re-enroll, restart the agent service (e.g.{" "}
                <code>systemctl restart hecate-lampad</code> on Linux).
              </p>
            </>
          ) : (
            <>
              <p className="muted">Configure and restart:</p>
              <pre className="code-block">{proxyReenrollHint(token)}</pre>
            </>
          )}
        </>
      ) : null}
    </section>
  );
}
