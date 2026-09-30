// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  apiClient,
  type ProxyRateLimitClass,
  type ProxyRateLimitEntry,
} from "../api/client.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";
import { ReenrollmentPanel } from "../components/ReenrollmentPanel.js";
import { useSession } from "../hooks/useSession.js";

const LIST_REFETCH_MS = 15_000;
const RATE_LIMIT_REFETCH_MS = 60_000;
const RATE_LIMIT_CLASSES: ProxyRateLimitClass[] = ["enroll", "allowed", "unrecognized"];

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
        <ProxyRateLimitsPanel proxyId={proxy.id} isAdmin={Boolean(isAdmin)} />
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

function ProxyRateLimitsPanel({
  proxyId,
  isAdmin,
}: {
  proxyId: string;
  isAdmin: boolean;
}) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const rateLimitsQuery = useQuery({
    queryKey: ["proxy-rate-limits", proxyId],
    queryFn: () => apiClient.getProxyRateLimits(proxyId),
    refetchInterval: RATE_LIMIT_REFETCH_MS,
  });

  const unbanMutation = useMutation({
    mutationFn: (entry: { ip: string; class: ProxyRateLimitClass }) =>
      apiClient.unbanProxyRateLimit(proxyId, entry),
    onSuccess: async () => {
      toast.success("Unban queued for next proxy sync.");
      await queryClient.invalidateQueries({ queryKey: ["proxy-rate-limits", proxyId] });
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to queue unban.");
    },
  });

  const byClass = useMemo(() => {
    const map: Record<ProxyRateLimitClass, ProxyRateLimitEntry[]> = {
      enroll: [],
      allowed: [],
      unrecognized: [],
    };
    for (const entry of rateLimitsQuery.data?.entries ?? []) {
      if (entry.class in map) {
        map[entry.class].push(entry);
      }
    }
    return map;
  }, [rateLimitsQuery.data?.entries]);

  return (
    <section className="card stack" style={{ marginTop: "1.5rem" }}>
      <h2>Rate limits</h2>
      <p className="muted">
        Client IPs currently over quota on this Propylaea (per class, 60s window). Unban resets the
        counter on the next proxy sync.
      </p>
      {rateLimitsQuery.data?.updated_at ? (
        <p className="muted">
          Snapshot updated: <code>{rateLimitsQuery.data.updated_at}</code>
        </p>
      ) : (
        <p className="muted">No rate-limit snapshot yet (waiting for proxy heartbeat).</p>
      )}
      {rateLimitsQuery.isLoading ? <LoadingState /> : null}
      {rateLimitsQuery.error ? <ErrorState message="Failed to load rate limits." /> : null}
      {!rateLimitsQuery.isLoading && !rateLimitsQuery.error
        ? RATE_LIMIT_CLASSES.map((className) => (
            <div key={className} className="stack">
              <h3>{className}</h3>
              {byClass[className].length === 0 ? (
                <p className="muted">No limited IPs.</p>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>Count</th>
                      <th>Window started</th>
                      {isAdmin ? <th /> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {byClass[className].map((entry) => (
                      <tr key={`${entry.class}:${entry.ip}`}>
                        <td>
                          <code>{entry.ip}</code>
                        </td>
                        <td>
                          {entry.count}/{entry.limit}
                        </td>
                        <td>{entry.window_started_at}</td>
                        {isAdmin ? (
                          <td>
                            <button
                              type="button"
                              disabled={unbanMutation.isPending}
                              onClick={() =>
                                unbanMutation.mutate({ ip: entry.ip, class: entry.class })
                              }
                            >
                              Unban
                            </button>
                          </td>
                        ) : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ))
        : null}
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
