// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiClient, ApiError, type AgentUpdateStatus, type MachineSummary } from "../api/client.js";
import { FLEET_LIST_REFETCH_MS } from "../queries/refetch.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";
import { MachineTagsEditor } from "../components/MachineTagsEditor.js";
import {
  helperComponentLabel,
  HelpersSummary,
  InstallHelperControl,
} from "../components/InstallHelperControl.js";
import { ReenrollmentPanel } from "../components/ReenrollmentPanel.js";
import { useSession } from "../hooks/useSession.js";

function formatAgentVersion(machine: MachineSummary, isAdmin: boolean): string {
  const current = machine.agent_version ?? "—";
  if (!isAdmin) {
    return current;
  }
  if (
    machine.agent_update_status === "outdated" ||
    machine.agent_update_status === "update_pending" ||
    machine.agent_update_status === "blocked_busy"
  ) {
    if (machine.latest_agent_version) {
      return `${current} → ${machine.latest_agent_version}`;
    }
  }
  return current;
}

function componentNeedsUpdate(status?: AgentUpdateStatus): boolean {
  return status === "outdated" || status === "blocked_busy";
}

function canRequestComponentUpdate(machine: MachineSummary): boolean {
  return (
    componentNeedsUpdate(machine.agent_update_status) ||
    componentNeedsUpdate(machine.desktop_update_status) ||
    componentNeedsUpdate(machine.proxmox_update_status)
  );
}

function updateIsPending(machine: MachineSummary): boolean {
  return (
    machine.agent_update_status === "update_pending" ||
    machine.desktop_update_status === "update_pending" ||
    machine.proxmox_update_status === "update_pending"
  );
}

function updateIsBusy(machine: MachineSummary): boolean {
  return (
    machine.agent_update_status === "blocked_busy" ||
    machine.desktop_update_status === "blocked_busy" ||
    machine.proxmox_update_status === "blocked_busy" ||
    Boolean(machine.agent_busy)
  );
}

function updateStatusLabel(machine: MachineSummary): string | null {
  if (updateIsPending(machine)) {
    return "Update queued";
  }
  if (updateIsBusy(machine) && canRequestComponentUpdate(machine)) {
    return "Waiting for idle (machine busy with AI commands)";
  }
  const agentOutdated = machine.agent_update_status === "outdated";
  const desktopOutdated = machine.desktop_update_status === "outdated";
  if (agentOutdated) {
    if (desktopOutdated && machine.proxmox_update_status === "outdated") {
      return "Agent, desktop, and Proxmox helper outdated";
    }
    if (desktopOutdated) {
      return "Agent and desktop helper outdated";
    }
    if (machine.proxmox_update_status === "outdated") {
      return "Agent and Proxmox helper outdated";
    }
    return "Agent outdated";
  }
  if (desktopOutdated) {
    return "Desktop helper outdated";
  }
  if (machine.proxmox_update_status === "outdated") {
    return "Proxmox helper outdated";
  }
  return null;
}

function apiErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    const body = error.body;
    if (body && typeof body === "object" && "message" in body && typeof body.message === "string") {
      return body.message;
    }
  }
  return error instanceof Error ? error.message : fallback;
}

export function MachinesPage() {
  const { machineId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";

  const listQuery = useQuery({
    queryKey: ["machines"],
    queryFn: () => apiClient.listMachines(),
    enabled: !machineId,
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const detailQuery = useQuery({
    queryKey: ["machine", machineId],
    queryFn: () => apiClient.getMachine(machineId!),
    enabled: Boolean(machineId),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const agentMutation = useMutation({
    mutationFn: (action: "approve" | "revoke") => apiClient.updateMachineAgent(machineId!, action),
    onSuccess: async (_data, action) => {
      toast.success(action === "approve" ? "Agent approved." : "Agent revoked.");
      await queryClient.invalidateQueries({ queryKey: ["machine", machineId] });
      await queryClient.invalidateQueries({ queryKey: ["machines"] });
    },
  });

  const updateAgentMutation = useMutation({
    mutationFn: (id: string) => apiClient.requestMachineAgentUpdate(id),
    onSuccess: async (machine) => {
      const agentTarget = machine.latest_agent_version;
      const desktopTarget = machine.latest_desktop_version;
          const proxmoxTarget = machine.latest_proxmox_version;
      const parts = [
        agentTarget && machine.agent_update_status !== "up_to_date"
          ? `agent ${agentTarget}`
          : null,
        desktopTarget && machine.desktop_update_status !== "up_to_date"
          ? `desktop ${desktopTarget}`
          : null,
            proxmoxTarget && machine.proxmox_update_status !== "up_to_date"
              ? `proxmox ${proxmoxTarget}`
              : null,
      ].filter(Boolean);
      toast.success(
        parts.length > 0
          ? `Update queued — will apply on the next pull when idle (${parts.join(", ")}).`
          : "Update queued — will apply on the next pull when idle.",
      );
      await queryClient.invalidateQueries({ queryKey: ["machines"] });
      await queryClient.invalidateQueries({ queryKey: ["machine", machineId] });
    },
    onError: (error) => {
      toast.error(apiErrorMessage(error, "Failed to request update."));
    },
  });

  const installHelperMutation = useMutation({
    mutationFn: ({ id, component }: { id: string; component: string }) =>
      apiClient.requestMachineHelperInstall(id, component),
    onSuccess: async (_machine, vars) => {
      toast.success(
        `Install queued for ${helperComponentLabel(vars.component)} — will apply on the next pull when idle.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["machines"] });
      await queryClient.invalidateQueries({ queryKey: ["machine", machineId] });
    },
    onError: (error) => {
      toast.error(apiErrorMessage(error, "Failed to request helper install."));
    },
  });

  const updateAllMutation = useMutation({
    mutationFn: () => apiClient.requestAllAgentUpdates(),
    onSuccess: async (result) => {
      toast.success(
        `Requested ${result.requested} update(s); skipped ${result.skipped_busy} busy, ${result.skipped_up_to_date} up to date.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["machines"] });
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to request updates.");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteMachine(machineId!),
    onSuccess: async () => {
      toast.success("Machine removed.");
      await queryClient.invalidateQueries({ queryKey: ["machines"] });
      navigate("/machines");
    },
  });

  if (machineId) {
    if (detailQuery.isLoading) {
      return <LoadingState />;
    }
    if (detailQuery.error || !detailQuery.data) {
      return <ErrorState message="Failed to load machine." />;
    }
    const machine = detailQuery.data;
    const statusLabel = updateStatusLabel(machine);
    return (
      <section>
        <PageHeader
          title={machine.hostname}
          subtitle={`${machine.os}/${machine.arch} · agent ${machine.agent_state ?? "unknown"}`}
        />
        <p>
          <Link to="/machines">← Back to fleet</Link>
        </p>
        <dl className="details">
          <div>
            <dt>Status</dt>
            <dd>{machine.status}</dd>
          </div>
          {!isAdmin ? (
            <div>
              <dt>Tags</dt>
              <dd>{machine.tags.join(", ") || "—"}</dd>
            </div>
          ) : null}
          <div>
            <dt>Agent version</dt>
            <dd>{formatAgentVersion(machine, isAdmin)}</dd>
          </div>
          <div>
            <dt>Helpers</dt>
            <dd>
              <HelpersSummary machine={machine} isAdmin={isAdmin} />
            </dd>
          </div>
          {isAdmin && statusLabel ? (
            <div>
              <dt>Update status</dt>
              <dd>{statusLabel}</dd>
            </div>
          ) : null}
          <div>
            <dt>Last seen</dt>
            <dd>{machine.last_seen_at ?? "—"}</dd>
          </div>
          <div>
            <dt>Agent health</dt>
            <dd>
              {machine.agent_healthy === false
                ? "unhealthy (pull loop not draining)"
                : machine.agent_healthy === true
                  ? machine.agent_busy
                    ? "healthy (busy)"
                    : "healthy"
                  : "—"}
            </dd>
          </div>
        </dl>
        {isAdmin ? (
          <MachineTagsEditor
            machineId={machine.id}
            operatorTags={machine.operator_tags ?? []}
            agentTags={machine.agent_tags ?? machine.tags}
            effectiveTags={machine.tags}
          />
        ) : null}
        {isAdmin ? (
          <div className="actions">
            {canRequestComponentUpdate(machine) ? (
              <button
                type="button"
                disabled={
                  updateAgentMutation.isPending ||
                  machine.agent_busy ||
                  machine.status !== "online" ||
                  updateIsPending(machine)
                }
                title={
                  machine.agent_busy
                    ? "Machine busy with AI commands"
                    : machine.status !== "online"
                      ? "Agent must be online"
                      : undefined
                }
                onClick={() => updateAgentMutation.mutate(machine.id)}
              >
                Update
              </button>
            ) : null}
            <div className="install-helper-block">
              <span className="install-helper-label">Install helper</span>
              <InstallHelperControl
                machine={machine}
                disabled={
                  installHelperMutation.isPending || Boolean(helperInstallDisabledReason(machine))
                }
                disabledTitle={helperInstallDisabledReason(machine)}
                pending={installHelperMutation.isPending}
                showEmptyMessage
                onInstall={(id, component) => installHelperMutation.mutate({ id, component })}
              />
            </div>
          </div>
        ) : null}
        {machine.agent_healthy === false ? (
          <p className="muted">
            Agent is heartbeating but not draining the command queue
            {machine.agent_secs_since_last_pull != null
              ? ` (last pull ${machine.agent_secs_since_last_pull}s ago)`
              : ""}
            .
          </p>
        ) : null}
        {machine.agent_busy ? (
          <p className="muted">
            Machine is busy with AI command(s).{" "}
            <Link to={`/action-queue?machine=${encodeURIComponent(machine.id)}&recent=1`}>
              View action queue
            </Link>
          </p>
        ) : null}
        {isAdmin && machine.agent_state === "pending_approval" ? (
          <div className="actions">
            <button type="button" disabled={agentMutation.isPending} onClick={() => agentMutation.mutate("approve")}>
              Approve agent
            </button>
          </div>
        ) : null}
        {isAdmin && machine.agent_state === "active" ? (
          <div className="actions">
            <button type="button" disabled={agentMutation.isPending} onClick={() => agentMutation.mutate("revoke")}>
              Revoke agent
            </button>
          </div>
        ) : null}
        {isAdmin &&
        (machine.agent_state === "active" || machine.agent_state === "pending_approval") ? (
          <ReenrollmentPanel
            kind="agent"
            entityId={machine.id}
            os={machine.os}
            serverUrl={agentServerUrl()}
          />
        ) : null}
        {isAdmin ? (
          <div className="actions">
            <button
              type="button"
              className="button-danger"
              disabled={deleteMutation.isPending}
              onClick={() => {
                const ok = window.confirm(
                  "Remove this machine? This will revoke the agent and remove explicit permissions references.",
                );
                if (ok) {
                  deleteMutation.mutate();
                }
              }}
            >
              Remove machine
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
    return <ErrorState message="Failed to load machines." />;
  }

  const machines = listQuery.data ?? [];
  const outdatedUpdatable = machines.filter(
    (machine) =>
      isAdmin &&
      canRequestComponentUpdate(machine) &&
      !machine.agent_busy &&
      machine.status === "online" &&
      !updateIsPending(machine),
  );

  return (
    <section>
      <PageHeader title="Machines" subtitle="Enrolled fleet members and agent status." />
      {isAdmin ? (
        <div className="actions">
          <button
            type="button"
            disabled={updateAllMutation.isPending || outdatedUpdatable.length === 0}
            onClick={() => updateAllMutation.mutate()}
          >
            Update all outdated
          </button>
        </div>
      ) : null}
      <table className="data-table">
        <thead>
          <tr>
            <th>Hostname</th>
            <th>OS</th>
            <th>Status</th>
            <th>Agent</th>
            <th>Version</th>
            <th>Helpers</th>
            {isAdmin ? <th>Update</th> : null}
            <th>Tags</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {machines.map((machine) => (
            <tr key={machine.id}>
              <td>
                <Link to={`/machines/${machine.id}`}>{machine.hostname}</Link>
              </td>
              <td>
                {machine.os}/{machine.arch}
              </td>
              <td>
                {machine.status}
                {machine.agent_healthy === false ? (
                  <span className="muted" title="Heartbeating but pull loop not draining">
                    {" "}
                    · unhealthy
                  </span>
                ) : null}
              </td>
              <td>{machine.agent_state ?? "—"}</td>
              <td>{formatAgentVersion(machine, isAdmin)}</td>
              <td>
                <div className="helpers-cell">
                  <HelpersSummary machine={machine} isAdmin={isAdmin} />
                  {isAdmin ? (
                    <InstallHelperControl
                      machine={machine}
                      disabled={
                        installHelperMutation.isPending ||
                        Boolean(helperInstallDisabledReason(machine))
                      }
                      disabledTitle={helperInstallDisabledReason(machine)}
                      pending={installHelperMutation.isPending}
                      onInstall={(id, component) =>
                        installHelperMutation.mutate({ id, component })
                      }
                    />
                  ) : null}
                </div>
              </td>
              {isAdmin ? (
                <td>
                  {updateIsPending(machine) ? (
                    <span className="muted">Pending</span>
                  ) : updateIsBusy(machine) && canRequestComponentUpdate(machine) ? (
                    <Link
                      className="muted"
                      to={`/action-queue?machine=${encodeURIComponent(machine.id)}&recent=1`}
                      title="View blocking AI commands"
                    >
                      Busy
                    </Link>
                  ) : canRequestComponentUpdate(machine) ? (
                    <button
                      type="button"
                      disabled={
                        updateAgentMutation.isPending ||
                        machine.agent_busy ||
                        machine.status !== "online"
                      }
                      title={machine.agent_busy ? "Machine busy with AI commands" : undefined}
                      onClick={() => updateAgentMutation.mutate(machine.id)}
                    >
                      Update
                    </button>
                  ) : (
                    "—"
                  )}
                </td>
              ) : null}
              <td>{machine.tags.join(", ") || "—"}</td>
              <td>{machine.last_seen_at ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {isAdmin ? <EnrollmentTokensPanel /> : null}
    </section>
  );
}

function agentServerUrl(): string {
  if (typeof window === "undefined") {
    return "https://hecate.example:18443";
  }
  return window.location.origin;
}

function enrollCommand(os: string, serverUrl: string, token: string): string {
  if (os === "windows") {
    return `hecate-lampad.exe enroll --server-url ${serverUrl} --token ${token}`;
  }
  return `sudo hecate-lampad enroll --server-url ${serverUrl} --token ${token}`;
}

function helperInstallDisabledReason(machine: MachineSummary): string | undefined {
  if (machine.agent_busy) {
    return "Machine busy with AI commands";
  }
  if (machine.status !== "online") {
    return "Agent must be online";
  }
  if (updateIsPending(machine)) {
    return "A package update is already queued";
  }
  return undefined;
}

function formatReleaseLabel(release: { os: string; arch: string; component: string; version: string }): string {
  const component =
    release.component === "agent" ? "agent" : helperComponentLabel(release.component);
  return `${release.os}/${release.arch} ${component} v${release.version}`;
}

function EnrollmentTokensPanel() {
  const toast = useToast();
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const serverUrl = agentServerUrl();

  const latestReleasesQuery = useQuery({
    queryKey: ["agent-releases-latest"],
    queryFn: () => apiClient.listLatestAgentReleases(),
  });

  const createMutation = useMutation({
    mutationFn: () => apiClient.createEnrollmentToken(),
    onSuccess: (data) => {
      setToken(data.token);
      setExpiresAt(data.expires_at);
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to create enrollment token.");
    },
  });

  const releases = latestReleasesQuery.data ?? [];
  const enrollTargets = [
    { os: "linux", label: "Linux / macOS" },
    { os: "windows", label: "Windows" },
  ] as const;

  return (
    <section className="card stack">
      <h2>Enrollment</h2>
      <p className="muted">
        Create one-time tokens for new agents. Auto-approve and token TTL are configured on the
        Settings page.
      </p>

      <h3>Latest packages</h3>
      <p className="muted">
        Download the pinned agent and helper installers mirrored from the feature repository.
      </p>
      {latestReleasesQuery.isLoading ? <LoadingState /> : null}
      {latestReleasesQuery.isError ? (
        <ErrorState message="Failed to load package releases." />
      ) : null}
      {!latestReleasesQuery.isLoading && !latestReleasesQuery.isError && releases.length === 0 ? (
        <p className="muted">
          No mirrored packages yet. Install or upgrade features from Settings → Feature repository,
          then refresh.
        </p>
      ) : null}
      {releases.length > 0 ? (
        <ul className="enrollment-download-list">
          {releases.map((release) => (
            <li key={`${release.os}:${release.arch}:${release.component}`}>
              <a href={release.download_path} download={release.filename}>
                {formatReleaseLabel(release)}
              </a>
              <span className="muted"> ({release.filename})</span>
            </li>
          ))}
        </ul>
      ) : null}

      <h3>Enrollment tokens</h3>
      <button type="button" onClick={() => createMutation.mutate()} disabled={createMutation.isPending}>
        Create enrollment token
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
          <h3>Enroll commands</h3>
          <p className="muted">
            After installing the package on the host, enroll against{" "}
            <code>{serverUrl}</code>:
          </p>
          {enrollTargets.map((target) => (
            <p key={target.os}>
              <span className="muted">{target.label}: </span>
              <code className="enrollment-command">{enrollCommand(target.os, serverUrl, token)}</code>
            </p>
          ))}
        </>
      ) : null}
    </section>
  );
}
