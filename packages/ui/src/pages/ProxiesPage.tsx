// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiClient } from "../api/client.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";
import { ReenrollmentPanel } from "../components/ReenrollmentPanel.js";
import { useSession } from "../hooks/useSession.js";

const LIST_REFETCH_MS = 15_000;

export function ProxiesPage() {
  const { proxyId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";

  const listQuery = useQuery({
    queryKey: ["proxies"],
    queryFn: () => apiClient.listProxies(),
    enabled: !proxyId,
    refetchInterval: LIST_REFETCH_MS,
  });

  const detailQuery = useQuery({
    queryKey: ["proxy", proxyId],
    queryFn: () => apiClient.getProxy(proxyId!),
    enabled: Boolean(proxyId),
    refetchInterval: LIST_REFETCH_MS,
  });

  const stateMutation = useMutation({
    mutationFn: (action: "approve" | "revoke") => apiClient.updateProxyState(proxyId!, action),
    onSuccess: async (_data, action) => {
      toast.success(action === "approve" ? "Proxy approved." : "Proxy revoked.");
      await queryClient.invalidateQueries({ queryKey: ["proxy", proxyId] });
      await queryClient.invalidateQueries({ queryKey: ["proxies"] });
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to update proxy.");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteProxy(proxyId!),
    onSuccess: async () => {
      toast.success("Proxy revoked and removed from active use.");
      await queryClient.invalidateQueries({ queryKey: ["proxies"] });
      navigate("/proxies");
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to delete proxy.");
    },
  });

  if (proxyId) {
    if (detailQuery.isLoading) {
      return <LoadingState />;
    }
    if (detailQuery.error || !detailQuery.data) {
      return <ErrorState message="Failed to load proxy." />;
    }
    const proxy = detailQuery.data;
    return (
      <section>
        <PageHeader title={proxy.hostname} subtitle={`Propylaea · ${proxy.state}`} />
        <p>
          <Link to="/proxies">← Back to proxies</Link>
        </p>
        <dl className="details">
          <div>
            <dt>State</dt>
            <dd>{proxy.state}</dd>
          </div>
          <div>
            <dt>Version</dt>
            <dd>{proxy.version ?? "—"}</dd>
          </div>
          <div>
            <dt>Enrolled</dt>
            <dd>{proxy.enrolled_at}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{proxy.last_seen_at ?? "—"}</dd>
          </div>
          <div>
            <dt>Proxy ID</dt>
            <dd>
              <code>{proxy.id}</code>
            </dd>
          </div>
        </dl>
        {isAdmin && proxy.state === "pending_approval" ? (
          <div className="actions">
            <button
              type="button"
              disabled={stateMutation.isPending}
              onClick={() => stateMutation.mutate("approve")}
            >
              Approve proxy
            </button>
          </div>
        ) : null}
        {isAdmin && proxy.state === "active" ? (
          <div className="actions">
            <button
              type="button"
              disabled={stateMutation.isPending}
              onClick={() => stateMutation.mutate("revoke")}
            >
              Revoke proxy
            </button>
          </div>
        ) : null}
        {isAdmin && (proxy.state === "active" || proxy.state === "pending_approval") ? (
          <ReenrollmentPanel
            kind="proxy"
            entityId={proxy.id}
            serverUrl={
              typeof window !== "undefined" ? window.location.origin : "https://hecate.example:18443"
            }
          />
        ) : null}
        {isAdmin ? (
          <div className="actions">
            <button
              type="button"
              disabled={deleteMutation.isPending}
              onClick={() => {
                if (window.confirm("Revoke this proxy?")) {
                  deleteMutation.mutate();
                }
              }}
            >
              Remove proxy
            </button>
          </div>
        ) : null}
      </section>
    );
  }

  if (listQuery.isLoading) {
    return <LoadingState />;
  }
  if (listQuery.error) {
    return <ErrorState message="Failed to load proxies." />;
  }

  const proxies = listQuery.data ?? [];

  return (
    <section className="stack">
      <PageHeader
        title="Proxies"
        subtitle="Propylaea edge proxies that validate agent traffic before forwarding to Hecate."
      />
      <table className="data-table">
        <thead>
          <tr>
            <th>Hostname</th>
            <th>State</th>
            <th>Version</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {proxies.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No proxies enrolled yet.
              </td>
            </tr>
          ) : (
            proxies.map((proxy) => (
              <tr key={proxy.id}>
                <td>
                  <Link to={`/proxies/${proxy.id}`}>{proxy.hostname}</Link>
                </td>
                <td>{proxy.state}</td>
                <td>{proxy.version ?? "—"}</td>
                <td>{proxy.last_seen_at ?? "—"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
      {isAdmin ? <ProxyEnrollmentPanel /> : null}
    </section>
  );
}

function ProxyEnrollmentPanel() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);

  const settingsQuery = useQuery({
    queryKey: ["proxy-enrollment-settings"],
    queryFn: () => apiClient.getProxyEnrollmentSettings(),
  });

  const createMutation = useMutation({
    mutationFn: () => apiClient.createProxyEnrollmentToken(),
    onSuccess: (data) => {
      setToken(data.token);
      setExpiresAt(data.expires_at);
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to create proxy enrollment token.");
    },
  });

  const autoApproveMutation = useMutation({
    mutationFn: (autoApprove: boolean) => apiClient.updateProxyEnrollmentSettings(autoApprove),
    onSuccess: async () => {
      toast.success("Proxy enrollment settings updated.");
      await queryClient.invalidateQueries({ queryKey: ["proxy-enrollment-settings"] });
      await queryClient.invalidateQueries({ queryKey: ["admin-settings"] });
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to update settings.");
    },
  });

  return (
    <section className="card stack">
      <h2>Proxy enrollment</h2>
      <p className="muted">
        Create one-time tokens for new Propylaea instances only. To re-attach an existing proxy,
        open its detail page and use <strong>Re-enroll proxy</strong>. Tokens use the{" "}
        <code>penr_</code> prefix. Token TTL is configured on the Settings page.
      </p>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={settingsQuery.data?.auto_approve ?? false}
          disabled={settingsQuery.isLoading || autoApproveMutation.isPending}
          onChange={(event) => autoApproveMutation.mutate(event.target.checked)}
        />
        Auto-approve new proxies
      </label>
      <h3>Enrollment tokens</h3>
      <button type="button" onClick={() => createMutation.mutate()} disabled={createMutation.isPending}>
        Create proxy enrollment token
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
        </>
      ) : null}
    </section>
  );
}
