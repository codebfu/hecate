// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { Fragment, useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient, type CommandQueueItem, type CommandQueueStatus } from "../api/client.js";
import { ListPaginationBar } from "../components/ListPaginationBar.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";
import {
  listQueryParams,
  paginationFromResponse,
  type ListPageSize,
} from "../hooks/usePaginatedList.js";
import { useSession } from "../hooks/useSession.js";
import { FLEET_LIST_REFETCH_MS } from "../queries/refetch.js";
import { formatJsonFull, formatJsonPreview } from "../utils/jsonDisplay.js";

const CANCELLABLE_STATUSES = new Set<CommandQueueStatus>([
  "pending_approval",
  "queued",
  "dispatched",
  "running",
]);

const ACTIVE_STATUSES = new Set<CommandQueueStatus>([
  "pending_approval",
  "queued",
  "dispatched",
  "running",
]);

function stopRowToggle(event: { stopPropagation: () => void }) {
  event.stopPropagation();
}

function statusLabel(command: CommandQueueItem): string {
  if (command.reboot_phase) {
    return `${command.status} (${command.reboot_phase})`;
  }
  return command.status;
}

function CommandDetailPanel({ command }: { command: CommandQueueItem }) {
  return (
    <div className="audit-event-panel">
      <dl className="details">
        <div>
          <dt>Command ID</dt>
          <dd>
            <code>{command.id}</code>
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{command.created_at}</dd>
        </div>
        {command.dispatched_at ? (
          <div>
            <dt>Dispatched</dt>
            <dd>{command.dispatched_at}</dd>
          </div>
        ) : null}
        {command.finished_at ? (
          <div>
            <dt>Finished</dt>
            <dd>{command.finished_at}</dd>
          </div>
        ) : null}
        <div>
          <dt>Machine</dt>
          <dd>
            <Link to={`/machines/${command.machine_id}`} onClick={stopRowToggle}>
              {command.machine_hostname}
            </Link>
          </dd>
        </div>
        <div>
          <dt>AI identity</dt>
          <dd>{command.ai_identity_name ?? "—"}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{statusLabel(command)}</dd>
        </div>
        <div>
          <dt>Command</dt>
          <dd>
            <code>{command.command_name}</code>
          </dd>
        </div>
        <div className="audit-event-detail-field">
          <dt>Request</dt>
          <dd>
            <pre className="audit-event-detail-pre">{formatJsonFull(command.params)}</pre>
          </dd>
        </div>
      </dl>
    </div>
  );
}

export function ActionQueuePage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";
  const canManageQueue = session?.role === "admin" || session?.role === "operator";
  const [searchParams, setSearchParams] = useSearchParams();
  const highlightedRowRef = useRef<HTMLTableRowElement | null>(null);
  const selectedCommandId = searchParams.get("command");
  const machineFilter = searchParams.get("machine");
  const [anchoredCommandId, setAnchoredCommandId] = useState<string | null>(selectedCommandId);
  const [expandedId, setExpandedId] = useState<string | null>(selectedCommandId);
  const [pageSize, setPageSize] = useState<ListPageSize>(20);
  const [page, setPage] = useState(1);
  const [includeRecent, setIncludeRecent] = useState(
    () => searchParams.get("recent") === "1" || Boolean(selectedCommandId),
  );

  const queryParams = listQueryParams(pageSize, page);
  const queueQuery = useQuery({
    queryKey: [
      "command-queue",
      pageSize,
      page,
      anchoredCommandId,
      machineFilter,
      includeRecent,
    ],
    queryFn: () =>
      apiClient.listCommandQueue({
        ...queryParams,
        command_id: anchoredCommandId ?? undefined,
        machine_id: machineFilter ?? undefined,
        include_recent: includeRecent,
      }),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const pagination = paginationFromResponse<CommandQueueItem>(
    queueQuery.data ?? { items: [], total: 0, limit: queryParams.limit, offset: queryParams.offset },
  );

  const approveMutation = useMutation({
    mutationFn: (commandId: string) => apiClient.approveCommand(commandId),
    onSuccess: async () => {
      toast.success("Command approved.");
      await queryClient.invalidateQueries({ queryKey: ["command-queue"] });
    },
    onError: () => {
      toast.error("Failed to approve command.");
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (commandId: string) => apiClient.cancelCommand(commandId),
    onSuccess: async () => {
      toast.success("Command cancelled.");
      await queryClient.invalidateQueries({ queryKey: ["command-queue"] });
    },
    onError: () => {
      toast.error("Failed to cancel command.");
    },
  });

  const actionPending = approveMutation.isPending || cancelMutation.isPending;

  useEffect(() => {
    setAnchoredCommandId(selectedCommandId);
    setExpandedId(selectedCommandId);
    setPage(1);
    if (selectedCommandId) {
      setIncludeRecent(true);
    }
  }, [selectedCommandId]);

  useEffect(() => {
    setPage(1);
  }, [pageSize, machineFilter, includeRecent]);

  useEffect(() => {
    if (!queueQuery.data) {
      return;
    }

    if (anchoredCommandId) {
      setPage(pagination.page);
      setExpandedId(anchoredCommandId);
      setAnchoredCommandId(null);
      return;
    }

    if (page > pagination.totalPages) {
      setPage(pagination.totalPages);
    }
  }, [queueQuery.data, anchoredCommandId, pagination.page, pagination.totalPages, page]);

  useEffect(() => {
    if (!selectedCommandId) {
      return;
    }
    highlightedRowRef.current?.scrollIntoView({ block: "center" });
  }, [selectedCommandId, pagination.items, expandedId]);

  if (queueQuery.isLoading) {
    return <LoadingState />;
  }

  if (queueQuery.error) {
    return <ErrorState message="Failed to load action queue." />;
  }

  return (
    <section className="action-queue-page">
      <PageHeader
        title="Action queue"
        subtitle="In-flight fleet commands. Enable “Include last 24h” to also see completed, failed, expired, and cancelled rows (Audit deep-links always resolve)."
      />
      <div className="actions" style={{ marginBottom: "1rem", gap: "1rem", flexWrap: "wrap" }}>
        <label className="muted" style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem" }}>
          <input
            type="checkbox"
            checked={includeRecent}
            onChange={(event) => {
              const checked = event.target.checked;
              setIncludeRecent(checked);
              const next = new URLSearchParams(searchParams);
              if (checked) {
                next.set("recent", "1");
              } else {
                next.delete("recent");
              }
              setSearchParams(next, { replace: true });
            }}
          />
          Include last 24h (completed / failed / expired / cancelled)
        </label>
        {machineFilter ? (
          <span className="muted">
            Filtered by machine{" "}
            <Link to={`/machines/${machineFilter}`}>
              <code>{machineFilter.slice(0, 8)}…</code>
            </Link>{" "}
            <button
              type="button"
              className="button-link"
              onClick={() => {
                const next = new URLSearchParams(searchParams);
                next.delete("machine");
                setSearchParams(next, { replace: true });
              }}
            >
              Clear
            </button>
          </span>
        ) : null}
      </div>
      <ListPaginationBar
        pageSize={pageSize}
        onPageSizeChange={setPageSize}
        page={pagination.page}
        onPageChange={setPage}
        totalItems={pagination.totalItems}
        visibleStart={pagination.visibleStart}
        visibleEnd={pagination.visibleEnd}
        totalPages={pagination.totalPages}
      />
      {pagination.totalItems === 0 ? (
        selectedCommandId ? (
          <p className="muted">
            No matching command. It may have been purged or the id is invalid.
          </p>
        ) : (
          <p className="muted">
            {includeRecent ? "No commands in the last 24 hours." : "No pending actions."}
          </p>
        )
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Created</th>
                <th>Machine</th>
                <th>Command</th>
                <th>AI identity</th>
                <th>Status</th>
                {canManageQueue ? <th>Actions</th> : null}
              </tr>
            </thead>
            <tbody>
              {pagination.items.map((command) => {
                const needsApproval = command.status === "pending_approval";
                const cancellable = CANCELLABLE_STATUSES.has(command.status);
                const isActive = ACTIVE_STATUSES.has(command.status);
                const isExpanded = expandedId === command.id;
                const isHighlighted = selectedCommandId === command.id;
                return (
                  <Fragment key={command.id}>
                    <tr
                      ref={isHighlighted ? highlightedRowRef : null}
                      className={[
                        "audit-event-row",
                        isExpanded ? "is-expanded" : "",
                        isHighlighted ? "is-highlighted" : "",
                        !isActive ? "muted" : "",
                      ]
                        .filter(Boolean)
                        .join(" ")}
                      onClick={() => setExpandedId(isExpanded ? null : command.id)}
                    >
                      <td>{command.created_at}</td>
                      <td>
                        <Link to={`/machines/${command.machine_id}`} onClick={stopRowToggle}>
                          {command.machine_hostname}
                        </Link>
                      </td>
                      <td>
                        <div className="audit-target-cell">
                          <code>{command.command_name}</code>
                          <code className="audit-target-detail audit-target-detail-preview muted">
                            {formatJsonPreview(command.params)}
                          </code>
                        </div>
                      </td>
                      <td>{command.ai_identity_name ?? "—"}</td>
                      <td>
                        <code>{statusLabel(command)}</code>
                      </td>
                      {canManageQueue ? (
                        <td onClick={stopRowToggle}>
                          <div className="actions">
                            {needsApproval ? (
                              <button
                                type="button"
                                disabled={actionPending}
                                onClick={() => {
                                  const ok = window.confirm("Approve this command for execution?");
                                  if (ok) {
                                    approveMutation.mutate(command.id);
                                  }
                                }}
                              >
                                Approve
                              </button>
                            ) : null}
                            {isAdmin && cancellable ? (
                              <button
                                type="button"
                                className="button-danger"
                                disabled={actionPending}
                                onClick={() => {
                                  const inFlight =
                                    command.status === "dispatched" || command.status === "running";
                                  const ok = window.confirm(
                                    inFlight
                                      ? "Cancel this in-flight command? The agent may still be executing."
                                      : "Cancel this command?",
                                  );
                                  if (ok) {
                                    cancelMutation.mutate(command.id);
                                  }
                                }}
                              >
                                Cancel
                              </button>
                            ) : null}
                          </div>
                        </td>
                      ) : null}
                    </tr>
                    {isExpanded ? (
                      <tr className="audit-event-detail-row">
                        <td colSpan={canManageQueue ? 6 : 5}>
                          <CommandDetailPanel command={command} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
