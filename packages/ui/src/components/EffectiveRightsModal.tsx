// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client.js";
import { ErrorState, LoadingState } from "./Layout.js";
import { formatJsonFull } from "../utils/jsonDisplay.js";

type RightsView = "matrix" | "by_grant" | "flat";

interface EffectiveRightsModalProps {
  identityId: string;
  onClose: () => void;
}

export function EffectiveRightsModal({ identityId, onClose }: EffectiveRightsModalProps) {
  const [view, setView] = useState<RightsView>("matrix");
  const [search, setSearch] = useState("");
  const [approvalOnly, setApprovalOnly] = useState(false);

  const rightsQuery = useQuery({
    queryKey: ["effective-rights", identityId],
    queryFn: () => apiClient.getEffectiveRights(identityId),
  });

  const filteredCommands = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const commands = rightsQuery.data?.allowed_commands ?? [];
    if (!needle) {
      return commands;
    }
    return commands.filter((command) => command.toLowerCase().includes(needle));
  }, [rightsQuery.data, search]);

  if (rightsQuery.isLoading) {
    return (
      <ModalShell onClose={onClose} title="Effective rights">
        <LoadingState />
      </ModalShell>
    );
  }

  if (rightsQuery.error || !rightsQuery.data) {
    return (
      <ModalShell onClose={onClose} title="Effective rights">
        <ErrorState message="Failed to load effective rights." />
      </ModalShell>
    );
  }

  const report = rightsQuery.data;

  async function copySummary() {
    const summary = [
      `# Effective rights`,
      `- Assignments: ${report.summary.assignment_count}`,
      `- Machines in scope: ${report.summary.machine_scope_count}`,
      `- Commands: ${report.allowed_commands.join(", ") || "—"}`,
      `- Admin commands: ${report.allowed_admin_commands.join(", ") || "—"}`,
    ].join("\n");
    await navigator.clipboard.writeText(summary);
  }

  return (
    <ModalShell
      onClose={onClose}
      title="Effective rights"
      subtitle={`${report.summary.assignment_count} assignments · ${report.summary.machine_scope_count} machines`}
    >
      <div className="effective-rights-toolbar stack">
        <div className="authz-segmented">
          <button type="button" className={view === "matrix" ? "active" : undefined} onClick={() => setView("matrix")}>
            Matrix
          </button>
          <button type="button" className={view === "by_grant" ? "active" : undefined} onClick={() => setView("by_grant")}>
            By grant
          </button>
          <button type="button" className={view === "flat" ? "active" : undefined} onClick={() => setView("flat")}>
            Flat list
          </button>
        </div>
        <label>
          Search
          <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label>
          <input
            type="checkbox"
            checked={approvalOnly}
            onChange={(e) => setApprovalOnly(e.target.checked)}
          />{" "}
          Show approval required only
        </label>
        <div className="actions">
          <button type="button" onClick={() => rightsQuery.refetch()}>
            Refresh
          </button>
          <button type="button" onClick={() => void copySummary()}>
            Copy summary
          </button>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard.writeText(formatJsonFull(report));
            }}
          >
            Export JSON
          </button>
        </div>
      </div>

      {view === "matrix" ? (
        <div className="audit-log-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Scope</th>
                {filteredCommands.map((command) => (
                  <th key={command}>
                    <code>{command}</code>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  {report.machine_ids.length > 0 ? (
                    <span>{report.machine_ids.length} explicit IDs</span>
                  ) : (
                    <span className="muted">Tag-based scope</span>
                  )}
                  {report.machine_tags.length > 0 ? (
                    <p className="muted">{report.machine_tags.join(", ")}</p>
                  ) : null}
                </td>
                {filteredCommands.map((command) => {
                  const requiresApproval = report.assignments.some(
                    (assignment) =>
                      !assignment.requires_approval_for_shell &&
                      assignment.enabled,
                  );
                  return (
                    <td
                      key={command}
                      className={requiresApproval ? "rights-cell rights-cell--approval" : "rights-cell rights-cell--ok"}
                      title={requiresApproval ? "Approval may be required depending on grant" : "Allowed"}
                    >
                      ✓
                    </td>
                  );
                })}
              </tr>
            </tbody>
          </table>
        </div>
      ) : null}

      {view === "by_grant" ? (
        <div className="stack">
          {report.assignments
            .filter((assignment) => !approvalOnly || !assignment.requires_approval_for_shell)
            .map((assignment) => (
              <details key={assignment.id} className="card" open>
                <summary>
                  {assignment.access_grant.name} — {assignment.access_grant.fleet_scope.name} ×{" "}
                  {assignment.access_grant.capability_profile.name}
                </summary>
                <p className="muted">
                  Shell approval: {assignment.requires_approval_for_shell ? "required" : "auto"} · Elevated:{" "}
                  {assignment.requires_approval_for_elevated ? "required" : "auto"} ·{" "}
                  {assignment.enabled ? "enabled" : "disabled"}
                </p>
                <p>
                  Commands: {assignment.access_grant.capability_profile.command_count} · Admin:{" "}
                  {assignment.access_grant.capability_profile.admin_command_count}
                </p>
              </details>
            ))}
        </div>
      ) : null}

      {view === "flat" ? (
        <div className="audit-log-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Command</th>
                <th>Grant</th>
                <th>Shell approval</th>
                <th>Elevated approval</th>
              </tr>
            </thead>
            <tbody>
              {filteredCommands.flatMap((command) =>
                report.assignments.map((assignment) => (
                  <tr key={`${command}-${assignment.id}`}>
                    <td>
                      <code>{command}</code>
                    </td>
                    <td>{assignment.access_grant.name}</td>
                    <td>{assignment.requires_approval_for_shell ? "required" : "auto"}</td>
                    <td>{assignment.requires_approval_for_elevated ? "required" : "auto"}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      ) : null}
    </ModalShell>
  );
}

function ModalShell({
  title,
  subtitle,
  onClose,
  children,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="modal-dialog card stack effective-rights-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="effective-rights-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="effective-rights-header">
          <div>
            <h2 id="effective-rights-title">{title}</h2>
            {subtitle ? <p className="muted">{subtitle}</p> : null}
          </div>
          <button type="button" onClick={onClose}>
            Close
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}
