// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiClient, type PermissionRequestDetail } from "../api/client.js";
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
import { formatJsonFull } from "../utils/jsonDisplay.js";

type ClassFilter = "all" | "standard" | "admin";

function stopRowToggle(event: { stopPropagation: () => void }) {
  event.stopPropagation();
}

function requestTier(request: PermissionRequestDetail): number {
  const changes = request.requested_changes;
  if (
    (changes.propose_fleet_scopes?.length ?? 0) > 0 ||
    (changes.propose_capability_profiles?.length ?? 0) > 0
  ) {
    return (changes.propose_access_grants?.length ?? 0) > 0 ? 4 : 3;
  }
  if ((changes.propose_access_grants?.length ?? 0) > 0) {
    return 2;
  }
  return 1;
}

function RequestDetailPanel({
  request,
  onApprove,
  onReject,
  actionPending,
}: {
  request: PermissionRequestDetail;
  onApprove: () => void;
  onReject: () => void;
  actionPending: boolean;
}) {
  const warnings = request.request_preview.auto_approve_warnings;
  const [ackShell, setAckShell] = useState(false);
  const [ackElevated, setAckElevated] = useState(false);

  const shellWarning = warnings.some((warning) => warning.kind.includes("shell"));
  const elevatedWarning = warnings.some((warning) => warning.kind.includes("elevated"));
  const approveEnabled =
    warnings.length === 0 ||
    ((!shellWarning || ackShell) && (!elevatedWarning || ackElevated));

  const isAdminRequest = request.request_class === "admin";

  return (
    <div className="audit-event-panel stack">
      {isAdminRequest ? (
        <div className="card card--danger authz-banner authz-banner--danger">
          <strong>Human approval required</strong> — AI identities cannot approve admin permission
          requests.
        </div>
      ) : null}

      {warnings.length > 0 ? (
        <div className="card card--danger authz-banner authz-banner--danger">
          <strong>Auto-approval requested</strong>
          <ul>
            {warnings.map((warning) => (
              <li key={`${warning.kind}-${warning.message}`}>{warning.message}</li>
            ))}
          </ul>
          {shellWarning ? (
            <label>
              <input type="checkbox" checked={ackShell} onChange={(e) => setAckShell(e.target.checked)} /> I
              understand this identity will run high-risk commands without queue approval
            </label>
          ) : null}
          {elevatedWarning ? (
            <label>
              <input
                type="checkbox"
                checked={ackElevated}
                onChange={(e) => setAckElevated(e.target.checked)}
              />{" "}
              I understand this identity will run elevated commands without queue approval
            </label>
          ) : null}
        </div>
      ) : null}

      <dl className="details">
        <div>
          <dt>Request ID</dt>
          <dd>
            <code>{request.id}</code>
          </dd>
        </div>
        <div>
          <dt>AI identity</dt>
          <dd>
            <Link to={`/ai-identities?identity=${request.ai_identity_id}`} onClick={stopRowToggle}>
              {request.ai_identity_name}
            </Link>
          </dd>
        </div>
        <div>
          <dt>Class</dt>
          <dd>
            <span className={isAdminRequest ? "badge badge--admin" : "badge badge--standard"}>
              {request.request_class.toUpperCase()}
            </span>{" "}
            · Tier {requestTier(request)}
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{request.created_at}</dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd>{request.status}</dd>
        </div>
        <div>
          <dt>Reason</dt>
          <dd>{request.reason}</dd>
        </div>
        {request.review_reason ? (
          <div>
            <dt>Review reason</dt>
            <dd>{request.review_reason}</dd>
          </div>
        ) : null}
      </dl>

      <section>
        <h4>Current assignments</h4>
        {request.current_assignments.length === 0 ? (
          <p className="muted">No assignments.</p>
        ) : (
          <ul>
            {request.current_assignments.map((assignment) => (
              <li key={assignment.id}>
                {assignment.access_grant.name} — {assignment.access_grant.fleet_scope.name} ×{" "}
                {assignment.access_grant.capability_profile.name}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h4>Requested changes</h4>
        <pre className="audit-event-detail-pre">{formatJsonFull(request.requested_changes)}</pre>
      </section>

      <section>
        <h4>Preview impact</h4>
        <p className="muted">
          Assignments before: {request.request_preview.effective_rights_before.assignment_count} → after:{" "}
          {request.request_preview.effective_rights_after.assignment_count}
        </p>
        {(request.requested_changes.remove_assignment_ids?.length ?? 0) > 0 ? (
          <p className="authz-banner authz-banner--warning">
            This request removes {request.requested_changes.remove_assignment_ids?.length} assignment(s).
          </p>
        ) : null}
      </section>

      {request.status === "pending" ? (
        <div className="table-actions">
          <button type="button" disabled={actionPending || !approveEnabled} onClick={onApprove}>
            Approve
          </button>
          <button type="button" className="danger" disabled={actionPending} onClick={onReject}>
            Reject
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function PermissionRequestsPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";
  const [searchParams] = useSearchParams();
  const highlightedRowRef = useRef<HTMLTableRowElement | null>(null);
  const selectedRequestId = searchParams.get("request");
  const [anchoredRequestId, setAnchoredRequestId] = useState<string | null>(selectedRequestId);
  const [expandedId, setExpandedId] = useState<string | null>(selectedRequestId);
  const [pageSize, setPageSize] = useState<ListPageSize>(20);
  const [page, setPage] = useState(1);
  const [classFilter, setClassFilter] = useState<ClassFilter>("all");

  const queryParams = listQueryParams(pageSize, page);
  const requestsQuery = useQuery({
    queryKey: ["permission-requests", pageSize, page, anchoredRequestId],
    queryFn: () =>
      apiClient.listPermissionRequests({
        ...queryParams,
        status: "pending",
        request_id: anchoredRequestId ?? undefined,
      }),
    refetchInterval: FLEET_LIST_REFETCH_MS,
    enabled: isAdmin,
  });

  const pagination = paginationFromResponse<PermissionRequestDetail>(
    requestsQuery.data ?? { items: [], total: 0, limit: queryParams.limit, offset: queryParams.offset },
  );

  const filteredItems = useMemo(() => {
    if (classFilter === "all") {
      return pagination.items;
    }
    return pagination.items.filter((request) => request.request_class === classFilter);
  }, [pagination.items, classFilter]);

  const approveMutation = useMutation({
    mutationFn: (requestId: string) => apiClient.approvePermissionRequest(requestId),
    onSuccess: async () => {
      toast.success("Permission request approved.");
      await queryClient.invalidateQueries({ queryKey: ["permission-requests"] });
    },
    onError: () => {
      toast.error("Failed to approve permission request.");
    },
  });

  const rejectMutation = useMutation({
    mutationFn: ({ requestId, reason }: { requestId: string; reason?: string }) =>
      apiClient.rejectPermissionRequest(requestId, reason),
    onSuccess: async () => {
      toast.success("Permission request rejected.");
      await queryClient.invalidateQueries({ queryKey: ["permission-requests"] });
    },
    onError: () => {
      toast.error("Failed to reject permission request.");
    },
  });

  const actionPending = approveMutation.isPending || rejectMutation.isPending;

  useEffect(() => {
    setAnchoredRequestId(selectedRequestId);
    setExpandedId(selectedRequestId);
    setPage(1);
  }, [selectedRequestId]);

  useEffect(() => {
    setPage(1);
  }, [pageSize, classFilter]);

  useEffect(() => {
    if (!requestsQuery.data) {
      return;
    }

    if (anchoredRequestId) {
      setPage(pagination.page);
      setExpandedId(anchoredRequestId);
      setAnchoredRequestId(null);
      return;
    }

    if (page > pagination.totalPages) {
      setPage(pagination.totalPages);
    }
  }, [requestsQuery.data, anchoredRequestId, pagination.page, pagination.totalPages, page]);

  useEffect(() => {
    if (!selectedRequestId) {
      return;
    }
    highlightedRowRef.current?.scrollIntoView({ block: "center" });
  }, [selectedRequestId, filteredItems, expandedId]);

  if (!isAdmin) {
    return <ErrorState message="Admin access required." />;
  }

  if (requestsQuery.isLoading) {
    return <LoadingState />;
  }

  if (requestsQuery.error) {
    return <ErrorState message="Failed to load permission requests." />;
  }

  function onReject(requestId: string) {
    const reason = window.prompt("Optional rejection reason:");
    if (reason === null) {
      return;
    }
    rejectMutation.mutate({ requestId, reason: reason.trim() || undefined });
  }

  return (
    <section className="permission-requests-page">
      <PageHeader
        title="Permission requests"
        subtitle="Pending AI permission change requests awaiting admin review."
      />

      <nav className="permissions-tab-bar" aria-label="Request class filter">
        {(["all", "standard", "admin"] as const).map((filter) => (
          <button
            key={filter}
            type="button"
            className={classFilter === filter ? "permissions-tab permissions-tab--active" : "permissions-tab"}
            onClick={() => setClassFilter(filter)}
          >
            {filter === "all" ? "All" : filter.charAt(0).toUpperCase() + filter.slice(1)}
          </button>
        ))}
      </nav>

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
      {filteredItems.length === 0 ? (
        selectedRequestId ? (
          <p className="muted">
            No pending permission requests. The selected request may have been reviewed already.
          </p>
        ) : (
          <p className="muted">No pending permission requests.</p>
        )
      ) : (
        <div className="audit-log-table-wrap">
          <table className="data-table audit-log-table">
            <thead>
              <tr>
                <th>Created</th>
                <th>AI identity</th>
                <th>Class</th>
                <th>Reason</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredItems.map((request) => {
                const isExpanded = expandedId === request.id;
                const isHighlighted = selectedRequestId === request.id;
                const isPending = request.status === "pending";
                const hasAutoApproveWarning = request.request_preview.auto_approve_warnings.length > 0;

                return (
                  <Fragment key={request.id}>
                    <tr
                      id={`permission-request-row-${request.id}`}
                      ref={isHighlighted ? highlightedRowRef : undefined}
                      className={
                        isExpanded || isHighlighted ? "audit-log-row row-highlight" : "audit-log-row"
                      }
                      onClick={() => setExpandedId(isExpanded ? null : request.id)}
                    >
                      <td>{request.created_at}</td>
                      <td>{request.ai_identity_name}</td>
                      <td>
                        <span
                          className={
                            request.request_class === "admin" ? "badge badge--admin" : "badge badge--standard"
                          }
                        >
                          {request.request_class.toUpperCase()}
                        </span>
                        {hasAutoApproveWarning ? <span title="Auto-approval requested"> ⚠</span> : null}
                      </td>
                      <td>{request.reason}</td>
                      <td>{request.status}</td>
                      <td>
                        {isPending ? (
                          <div className="table-actions" onClick={stopRowToggle}>
                            <button
                              type="button"
                              disabled={actionPending}
                              onClick={() => approveMutation.mutate(request.id)}
                            >
                              Approve
                            </button>
                            <button
                              type="button"
                              className="danger"
                              disabled={actionPending}
                              onClick={() => onReject(request.id)}
                            >
                              Reject
                            </button>
                          </div>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                    {isExpanded ? (
                      <tr className="audit-log-detail-row">
                        <td colSpan={6}>
                          <RequestDetailPanel
                            request={request}
                            actionPending={actionPending}
                            onApprove={() => approveMutation.mutate(request.id)}
                            onReject={() => onReject(request.id)}
                          />
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
