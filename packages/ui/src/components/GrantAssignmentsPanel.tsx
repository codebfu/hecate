// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { DragEndEvent } from "@dnd-kit/core";
import { Link } from "react-router-dom";
import {
  apiClient,
  type GrantAssignmentInput,
  type ResolvedGrantAssignment,
} from "../api/client.js";
import { FLEET_LIST_REFETCH_MS } from "../queries/refetch.js";
import { ErrorState, LoadingState } from "./Layout.js";
import { useToast } from "./ToastProvider.js";
import { AuthzDndProvider, DraggableChip, DropZone, SortableContext, SortableListItem, arrayMove, verticalListSortingStrategy } from "./authz/DndHelpers.js";
import { EffectiveRightsModal } from "./EffectiveRightsModal.js";

interface LocalAssignment {
  key: string;
  access_grant_id: string;
  grant_name: string;
  grant_summary: string;
  requires_approval_for_shell: boolean;
  requires_approval_for_elevated: boolean;
  enabled: boolean;
}

interface GrantAssignmentsPanelProps {
  identityId: string;
  isLoading?: boolean;
}

export function GrantAssignmentsPanel({ identityId, isLoading }: GrantAssignmentsPanelProps) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [showRights, setShowRights] = useState(false);
  const [localAssignments, setLocalAssignments] = useState<LocalAssignment[] | null>(null);
  const [paletteSearch, setPaletteSearch] = useState("");

  const assignmentsQuery = useQuery({
    queryKey: ["grant-assignments", identityId],
    queryFn: () => apiClient.getGrantAssignments(identityId),
    enabled: Boolean(identityId),
  });

  const catalogQuery = useQuery({
    queryKey: ["authz-catalog"],
    queryFn: () => apiClient.getAuthzCatalog(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const assignments = useMemo(() => {
    if (localAssignments) {
      return localAssignments;
    }
    return (assignmentsQuery.data ?? []).map((assignment) => toLocalAssignment(assignment));
  }, [assignmentsQuery.data, localAssignments]);

  const assignedGrantIds = new Set(assignments.map((assignment) => assignment.access_grant_id));

  const availableGrants = useMemo(() => {
    const needle = paletteSearch.trim().toLowerCase();
    return (catalogQuery.data?.access_grants ?? []).filter((grant) => {
      if (assignedGrantIds.has(grant.id)) {
        return false;
      }
      if (!needle) {
        return true;
      }
      return (
        grant.name.toLowerCase().includes(needle) ||
        grant.fleet_scope.name.toLowerCase().includes(needle) ||
        grant.capability_profile.name.toLowerCase().includes(needle)
      );
    });
  }, [catalogQuery.data, paletteSearch, assignedGrantIds]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: GrantAssignmentInput[] = assignments.map((assignment) => ({
        access_grant_id: assignment.access_grant_id,
        requires_approval_for_shell: assignment.requires_approval_for_shell,
        requires_approval_for_elevated: assignment.requires_approval_for_elevated,
        enabled: assignment.enabled,
      }));
      return apiClient.updateGrantAssignments(identityId, { assignments: payload });
    },
    onSuccess: async () => {
      toast.success("Grant assignments saved.");
      setLocalAssignments(null);
      await queryClient.invalidateQueries({ queryKey: ["grant-assignments", identityId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to save assignments."),
  });

  function onDragEnd(event: DragEndEvent) {
    const activeId = String(event.active.id);
    const overId = event.over ? String(event.over.id) : null;

    if (activeId.startsWith("palette-grant:") && overId) {
      const droppedOnAssignments =
        overId === "assignment-drop-zone" ||
        assignments.some((assignment) => assignment.key === overId);
      if (!droppedOnAssignments) {
        return;
      }
      const grantId = activeId.slice("palette-grant:".length);
      const grant = catalogQuery.data?.access_grants.find((entry) => entry.id === grantId);
      if (!grant || assignedGrantIds.has(grantId)) {
        return;
      }
      const next: LocalAssignment = {
        key: `new-${grantId}-${Date.now()}`,
        access_grant_id: grant.id,
        grant_name: grant.name,
        grant_summary: `${grant.fleet_scope.name} × ${grant.capability_profile.name}`,
        requires_approval_for_shell: true,
        requires_approval_for_elevated: true,
        enabled: true,
      };
      setLocalAssignments([...assignments, next]);
      return;
    }

    if (assignments.some((assignment) => assignment.key === activeId) && overId) {
      const oldIndex = assignments.findIndex((assignment) => assignment.key === activeId);
      const newIndex = assignments.findIndex((assignment) => assignment.key === overId);
      if (oldIndex >= 0 && newIndex >= 0 && oldIndex !== newIndex) {
        setLocalAssignments(arrayMove(assignments, oldIndex, newIndex));
      }
    }
  }

  function updateAssignment(key: string, patch: Partial<LocalAssignment>) {
    setLocalAssignments(
      assignments.map((assignment) =>
        assignment.key === key ? { ...assignment, ...patch } : assignment,
      ),
    );
  }

  function removeAssignment(key: string) {
    setLocalAssignments(assignments.filter((assignment) => assignment.key !== key));
  }

  if (isLoading || assignmentsQuery.isLoading || catalogQuery.isLoading) {
    return <LoadingState />;
  }

  if (assignmentsQuery.error || catalogQuery.error) {
    return <ErrorState message="Failed to load grant assignments." />;
  }

  return (
    <>
      <AuthzDndProvider onDragEnd={onDragEnd}>
        <div className="grant-assignments-panel">
          <div className="grant-assignments-main">
            <div className="grant-assignments-header">
              <h4>Grant assignments</h4>
              <button type="button" onClick={() => setShowRights(true)}>
                View effective rights
              </button>
            </div>

            <DropZone
              id="assignment-drop-zone"
              label="Assigned grants (drag to reorder or add from palette)"
              emptyHint={
                assignments.length === 0
                  ? "No grant assignments yet — drag an access grant from the palette."
                  : undefined
              }
            >
              {assignments.length === 0 ? (
                <p className="muted">
                  Or{" "}
                  <Link to="/permissions?tab=access-grants">create grants in Permissions</Link>.
                </p>
              ) : (
                <SortableContext
                  items={assignments.map((assignment) => assignment.key)}
                  strategy={verticalListSortingStrategy}
                >
                  <ul className="grant-assignment-list">
                    {assignments.map((assignment) => (
                      <SortableListItem key={assignment.key} id={assignment.key} label={assignment.grant_name}>
                        <div className="grant-assignment-card">
                          <div>
                            <strong>{assignment.grant_name}</strong>
                            <p className="muted">{assignment.grant_summary}</p>
                          </div>
                          <label>
                            <input
                              type="checkbox"
                              checked={assignment.enabled}
                              onChange={(e) =>
                                updateAssignment(assignment.key, { enabled: e.target.checked })
                              }
                              disabled={saveMutation.isPending}
                            />{" "}
                            Enabled
                          </label>
                          <label>
                            <input
                              type="checkbox"
                              checked={assignment.requires_approval_for_shell}
                              onChange={(e) =>
                                updateAssignment(assignment.key, {
                                  requires_approval_for_shell: e.target.checked,
                                })
                              }
                              disabled={saveMutation.isPending}
                            />{" "}
                            Require approval for high-risk commands
                          </label>
                          <label>
                            <input
                              type="checkbox"
                              checked={assignment.requires_approval_for_elevated}
                              onChange={(e) =>
                                updateAssignment(assignment.key, {
                                  requires_approval_for_elevated: e.target.checked,
                                })
                              }
                              disabled={saveMutation.isPending}
                            />{" "}
                            Require approval for elevated execution
                          </label>
                          <button
                            type="button"
                            className="tag-chip-remove"
                            onClick={() => removeAssignment(assignment.key)}
                            disabled={saveMutation.isPending}
                          >
                            Remove
                          </button>
                        </div>
                      </SortableListItem>
                    ))}
                  </ul>
                </SortableContext>
              )}
            </DropZone>

            <div className="actions">
              <button
                type="button"
                disabled={saveMutation.isPending || localAssignments === null}
                onClick={() => saveMutation.mutate()}
              >
                {saveMutation.isPending ? "Saving…" : "Save assignments"}
              </button>
            </div>
          </div>

          <aside className="grant-assignments-palette card stack">
            <h4>Available grants</h4>
            <label>
              Search
              <input
                type="search"
                value={paletteSearch}
                onChange={(e) => setPaletteSearch(e.target.value)}
              />
            </label>
            <ul className="authz-entity-list">
              {availableGrants.map((grant) => (
                <li key={grant.id}>
                  <DraggableChip
                    id={`palette-grant:${grant.id}`}
                    label={grant.name}
                    disabled={saveMutation.isPending}
                  />
                  <span className="muted">
                    {grant.fleet_scope.name} × {grant.capability_profile.name}
                  </span>
                </li>
              ))}
            </ul>
          </aside>
        </div>
      </AuthzDndProvider>

      {showRights ? (
        <EffectiveRightsModal identityId={identityId} onClose={() => setShowRights(false)} />
      ) : null}
    </>
  );
}

function toLocalAssignment(assignment: ResolvedGrantAssignment): LocalAssignment {
  return {
    key: assignment.id,
    access_grant_id: assignment.access_grant.id,
    grant_name: assignment.access_grant.name,
    grant_summary: `${assignment.access_grant.fleet_scope.name} × ${assignment.access_grant.capability_profile.name}`,
    requires_approval_for_shell: assignment.requires_approval_for_shell,
    requires_approval_for_elevated: assignment.requires_approval_for_elevated,
    enabled: assignment.enabled,
  };
}
