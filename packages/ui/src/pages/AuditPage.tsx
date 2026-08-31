// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { Fragment, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiClient, type AuditEvent, type AuditEventRef } from "../api/client.js";
import { ListPaginationBar } from "../components/ListPaginationBar.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import {
  listQueryParams,
  paginationFromResponse,
  type ListPageSize,
} from "../hooks/usePaginatedList.js";
import { LIST_REFETCH_MS } from "../queries/refetch.js";
import {
  auditRefHref,
  formatAuditDetailFull,
  formatAuditDetailPreview,
} from "../utils/auditDisplay.js";

function stopRowToggle(event: { stopPropagation: () => void }) {
  event.stopPropagation();
}

function AuditActorCell({ actor }: { actor: AuditEventRef }) {
  const href = auditRefHref(actor);

  if (href) {
    return (
      <Link to={href} title={actor.id ?? undefined} onClick={stopRowToggle}>
        {actor.label}
      </Link>
    );
  }

  return <span title={actor.id ?? undefined}>{actor.label}</span>;
}

function AuditTargetCell({ target }: { target?: AuditEventRef | null }) {
  if (!target) {
    return <>—</>;
  }

  const href = auditRefHref(target);
  const label = href ? (
    <Link to={href} className="audit-target-link" onClick={stopRowToggle}>
      <code>{target.label}</code>
    </Link>
  ) : (
    <code>{target.label}</code>
  );

  return (
    <div className="audit-target-cell" title={target.id ?? undefined}>
      {label}
      {target.detail ? (
        <code className="audit-target-detail audit-target-detail-preview muted">
          {formatAuditDetailPreview(target.detail)}
        </code>
      ) : null}
    </div>
  );
}

function AuditRefMeta({ label, ref }: { label: string; ref: AuditEventRef }) {
  return (
    <>
      <div>
        <dt>{label}</dt>
        <dd>
          <AuditActorCell actor={ref} />
        </dd>
      </div>
      {ref.id ? (
        <div>
          <dt>{label} ID</dt>
          <dd>
            <code>{ref.id}</code>
          </dd>
        </div>
      ) : null}
      {ref.kind ? (
        <div>
          <dt>{label} kind</dt>
          <dd>{ref.kind}</dd>
        </div>
      ) : null}
      {ref.related_id ? (
        <div>
          <dt>{label} related ID</dt>
          <dd>
            <code>{ref.related_id}</code>
          </dd>
        </div>
      ) : null}
    </>
  );
}

function AuditEventDetailPanel({ event }: { event: AuditEvent }) {
  return (
    <div className="audit-event-panel">
      <dl className="details">
        <div>
          <dt>Event ID</dt>
          <dd>
            <code>{event.id}</code>
          </dd>
        </div>
        <div>
          <dt>Time</dt>
          <dd>{event.created_at}</dd>
        </div>
        <AuditRefMeta label="Actor" ref={event.actor} />
        <div>
          <dt>Action</dt>
          <dd>{event.action}</dd>
        </div>
        {event.target ? (
          <>
            <AuditRefMeta label="Target" ref={event.target} />
            {event.target.detail ? (
              <div className="audit-event-detail-field">
                <dt>Args</dt>
                <dd>
                  <pre className="audit-event-detail-pre">{formatAuditDetailFull(event.target.detail)}</pre>
                </dd>
              </div>
            ) : null}
          </>
        ) : (
          <div>
            <dt>Target</dt>
            <dd>—</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

export function AuditPage() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [pageSize, setPageSize] = useState<ListPageSize>(20);
  const [page, setPage] = useState(1);

  const queryParams = listQueryParams(pageSize, page);
  const query = useQuery({
    queryKey: ["audit-events", pageSize, page],
    queryFn: () => apiClient.listAuditEvents(queryParams),
    refetchInterval: LIST_REFETCH_MS,
  });

  const pagination = paginationFromResponse<AuditEvent>(
    query.data ?? { items: [], total: 0, limit: queryParams.limit, offset: queryParams.offset },
  );

  useEffect(() => {
    setPage(1);
  }, [pageSize]);

  useEffect(() => {
    if (query.data && page > pagination.totalPages) {
      setPage(pagination.totalPages);
    }
  }, [query.data, page, pagination.totalPages]);

  if (query.isLoading) {
    return <LoadingState />;
  }

  if (query.error) {
    return <ErrorState message="Failed to load audit events." />;
  }

  return (
    <section className="audit-page">
      <PageHeader title="Audit log" subtitle="Append-only events with hash-chain integrity (server-side)." />
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
      <div className="audit-log-table-wrap">
        <table className="data-table audit-log-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {pagination.items.map((event) => (
              <Fragment key={event.id}>
                <tr
                  id={`audit-event-row-${event.id}`}
                  className={expandedId === event.id ? "audit-log-row row-highlight" : "audit-log-row"}
                  onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
                >
                  <td>
                    <span className="audit-log-expand-icon" aria-hidden="true">
                      {expandedId === event.id ? "▾" : "▸"}
                    </span>
                    {event.created_at}
                  </td>
                  <td>
                    <AuditActorCell actor={event.actor} />
                  </td>
                  <td>{event.action}</td>
                  <td>
                    <AuditTargetCell target={event.target} />
                  </td>
                </tr>
                {expandedId === event.id ? (
                  <tr key={`${event.id}-panel`}>
                    <td colSpan={4}>
                      <AuditEventDetailPanel event={event} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
