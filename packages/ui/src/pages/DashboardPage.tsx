// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { apiClient, ApiError } from "../api/client.js";
import { FLEET_LIST_REFETCH_MS } from "../queries/refetch.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";
import { useSession } from "../hooks/useSession.js";

export function DashboardPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";
  const [restartPending, setRestartPending] = useState(false);

  useEffect(() => {
    if (!restartPending) {
      return;
    }
    const timeout = window.setTimeout(() => setRestartPending(false), 120_000);
    return () => window.clearTimeout(timeout);
  }, [restartPending]);

  const versionQuery = useQuery({
    queryKey: ["system-version"],
    queryFn: () => apiClient.getSystemVersion(),
  });

  const serverUpdateQuery = useQuery({
    queryKey: ["server-update-status"],
    queryFn: () => apiClient.getServerUpdateStatus(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
    enabled: isAdmin,
  });

  const machinesQuery = useQuery({
    queryKey: ["machines"],
    queryFn: () => apiClient.listMachines(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const serverUpdateMutation = useMutation({
    mutationFn: () => apiClient.requestServerUpdate(),
    onSuccess: async (result) => {
      if (result.applied) {
        setRestartPending(true);
        toast.success("Server restart triggered — pulling latest images.");
        window.setTimeout(() => {
          void queryClient.invalidateQueries({ queryKey: ["system-version"] });
          void queryClient.invalidateQueries({ queryKey: ["server-update-status"] });
        }, 15_000);
      } else if (result.fleet_busy) {
        toast.success("Server update queued; will restart when the fleet is idle.");
      } else if (result.update_requested) {
        toast.success("Server update requested.");
      } else {
        toast.success("Server update request recorded.");
      }
      await queryClient.invalidateQueries({ queryKey: ["server-update-status"] });
    },
    onError: (error) => {
      const body =
        error instanceof ApiError &&
        error.body &&
        typeof error.body === "object" &&
        "message" in error.body &&
        typeof error.body.message === "string"
          ? error.body.message
          : null;
      toast.error(body ?? (error instanceof Error ? error.message : "Failed to request server update."));
    },
  });

  if (versionQuery.isLoading || machinesQuery.isLoading || (isAdmin && serverUpdateQuery.isLoading)) {
    return <LoadingState />;
  }

  if (versionQuery.error || machinesQuery.error || serverUpdateQuery.error) {
    const parts: string[] = [];
    if (versionQuery.error) {
      parts.push(versionQuery.error instanceof Error ? versionQuery.error.message : String(versionQuery.error));
    }
    if (machinesQuery.error) {
      parts.push(machinesQuery.error instanceof Error ? machinesQuery.error.message : String(machinesQuery.error));
    }
    if (serverUpdateQuery.error) {
      parts.push(
        serverUpdateQuery.error instanceof Error ? serverUpdateQuery.error.message : String(serverUpdateQuery.error),
      );
    }
    const details = parts.join(" | ");

    return <ErrorState message={`Failed to load dashboard data.${details ? ` ${details}` : ""}`} />;
  }

  const machines = machinesQuery.data ?? [];
  const online = machines.filter((m) => m.status === "online").length;
  const offline = machines.length - online;
  const serverUpdate = serverUpdateQuery.data;
  const outdatedHelpers = machines.filter(
    (m) =>
      m.agent_update_status === "outdated" ||
      m.desktop_update_status === "outdated" ||
      m.proxmox_update_status === "outdated",
  ).length;

  return (
    <section>
      <PageHeader title="Dashboard" subtitle="Fleet overview and server version." />
      <div className="grid">
        <article className="card">
          <h2>Fleet</h2>
          <p>{machines.length} machines</p>
          <p>{online} online · {offline} offline</p>
          {isAdmin && outdatedHelpers > 0 ? (
            <p className="muted">{outdatedHelpers} helper(s) outdated</p>
          ) : null}
        </article>
        <article className="card">
          <h2>Server</h2>
          <p>Version {versionQuery.data?.hecate_version}</p>
          <p>Schema {versionQuery.data?.schema_version}</p>
          {serverUpdate ? <p className="muted">Image tag {serverUpdate.hecate_app_tag}</p> : null}
          {isAdmin && serverUpdate ? (
            <div className="actions">
              <button
                type="button"
                disabled={serverUpdateMutation.isPending}
                title={
                  serverUpdate.update_requested
                    ? serverUpdate.fleet_busy
                      ? "Update queued; waiting for idle fleet"
                      : "Restart pending"
                    : serverUpdate.fleet_busy
                      ? "Will apply when fleet is idle"
                      : "Restart server to pull latest images"
                }
                onClick={() => serverUpdateMutation.mutate()}
              >
                {serverUpdateMutation.isPending
                  ? "Requesting…"
                  : serverUpdate.update_requested
                    ? "Update queued"
                    : "Update server"}
              </button>
            </div>
          ) : null}
          {isAdmin && restartPending ? (
            <p className="muted">Restart in progress — the page may reload when the server comes back.</p>
          ) : null}
          {isAdmin && serverUpdate?.update_requested && serverUpdate.fleet_busy ? (
            <p className="muted">Waiting for idle fleet before restart.</p>
          ) : null}
          {isAdmin && serverUpdate?.update_requested && !serverUpdate.fleet_busy ? (
            <p className="muted">Restart will apply within a few seconds once the trigger is picked up.</p>
          ) : null}
        </article>
      </div>
    </section>
  );
}
