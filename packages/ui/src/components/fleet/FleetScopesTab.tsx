// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { DragEndEvent } from "@dnd-kit/core";
import {
  apiClient,
  type FleetScope,
  type FleetScopeInput,
  type FleetScopePatch,
  type TagMatchMode,
} from "../../api/client.js";
import { FLEET_LIST_REFETCH_MS } from "../../queries/refetch.js";
import { ErrorState, LoadingState } from "../Layout.js";
import { useToast } from "../ToastProvider.js";
import {
  collectFleetTagOptions,
  filterMachines,
  groupTagsByNamespace,
} from "../../utils/authz/fleetTags.js";
import { MACHINE_IDS_WILDCARD, isSystemFleetScope, machineIdsAllowAll } from "../../utils/authz/fleetScope.js";
import { AuthzDndProvider, DraggableChip, DropZone } from "../authz/DndHelpers.js";

function FleetScopeEditor({
  scope,
  onSaved,
  onDeleted,
}: {
  scope: FleetScope | null;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tagMatchMode, setTagMatchMode] = useState<TagMatchMode>("any");
  const [machineIds, setMachineIds] = useState<string[]>([]);
  const [allMachinesSelected, setAllMachinesSelected] = useState(false);
  const [tags, setTags] = useState<string[]>([]);
  const [machineSearch, setMachineSearch] = useState("");
  const [previewOpen, setPreviewOpen] = useState(true);

  const machinesQuery = useQuery({
    queryKey: ["machines"],
    queryFn: () => apiClient.listMachines(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const previewQuery = useQuery({
    queryKey: ["fleet-scope-preview", scope?.id],
    queryFn: () => apiClient.previewFleetScope(scope!.id),
    enabled: Boolean(scope?.id),
  });

  useEffect(() => {
    if (scope) {
      setName(scope.name);
      setDescription(scope.description);
      setTagMatchMode(scope.tag_match_mode);
      setMachineIds(scope.machine_ids.filter((id) => id !== MACHINE_IDS_WILDCARD));
      setAllMachinesSelected(machineIdsAllowAll(scope.machine_ids));
      setTags([...scope.tags]);
    }
  }, [scope]);

  const fleetTags = collectFleetTagOptions(machinesQuery.data ?? []);
  const tagGroups = groupTagsByNamespace(fleetTags);
  const filteredMachines = useMemo(
    () => filterMachines(machinesQuery.data ?? [], machineSearch),
    [machinesQuery.data, machineSearch],
  );
  const allMachines = allMachinesSelected;
  const readOnly = scope ? isSystemFleetScope(scope) : false;

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload = {
        name,
        description,
        tag_match_mode: tagMatchMode,
        machine_ids: allMachines ? [MACHINE_IDS_WILDCARD] : machineIds,
        tags,
      };
      if (scope) {
        return apiClient.updateFleetScope(scope.id, payload as FleetScopePatch);
      }
      return apiClient.createFleetScope(payload as FleetScopeInput);
    },
    onSuccess: async () => {
      toast.success(scope ? "Fleet scope saved." : "Fleet scope created.");
      await queryClient.invalidateQueries({ queryKey: ["fleet-scopes"] });
      await queryClient.invalidateQueries({ queryKey: ["authz-catalog"] });
      onSaved();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to save fleet scope."),
  });

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteFleetScope(scope!.id),
    onSuccess: async () => {
      toast.success("Fleet scope deleted.");
      await queryClient.invalidateQueries({ queryKey: ["fleet-scopes"] });
      onDeleted();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to delete fleet scope."),
  });

  function onDragEnd(event: DragEndEvent) {
    const activeId = String(event.active.id);
    if (!event.over) {
      return;
    }
    if (activeId.startsWith("machine:") && event.over.id === "explicit-machines") {
      const machineId = activeId.slice(8);
      setMachineIds((current) => (current.includes(machineId) ? current : [...current, machineId]));
    }
    if (activeId.startsWith("tag:") && event.over.id === "tag-rules") {
      const tag = activeId.slice(4);
      setTags((current) => (current.includes(tag) ? current : [...current, tag]));
    }
  }

  const machineLabel = (id: string) =>
    machinesQuery.data?.find((machine) => machine.id === id)?.hostname ?? id;

  return (
    <AuthzDndProvider onDragEnd={onDragEnd}>
      <form
        className="stack permissions-form"
        onSubmit={(event) => {
          event.preventDefault();
          saveMutation.mutate();
        }}
      >
        {scope?.request_scoped ? (
          <p className="authz-banner authz-banner--info">Request-scoped fleet scope.</p>
        ) : null}
        {readOnly ? (
          <p className="authz-banner authz-banner--info">
            System fleet scope — dynamically includes every machine in the fleet. Cannot be modified.
          </p>
        ) : null}
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required disabled={saveMutation.isPending || readOnly} />
        </label>
        <label>
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} disabled={saveMutation.isPending || readOnly} />
        </label>
        <fieldset className="authz-segmented" disabled={readOnly}>
          <legend className="permissions-hint">Tag match mode</legend>
          <label>
            <input
              type="radio"
              name="tagMatchMode"
              checked={tagMatchMode === "any"}
              onChange={() => setTagMatchMode("any")}
              disabled={saveMutation.isPending}
            />{" "}
            Any tag
          </label>
          <label>
            <input
              type="radio"
              name="tagMatchMode"
              checked={tagMatchMode === "all"}
              onChange={() => setTagMatchMode("all")}
              disabled={saveMutation.isPending}
            />{" "}
            All tags
          </label>
        </fieldset>

        <section className="permissions-section">
          <h4>Explicit machines</h4>
          <label>
            <input
              type="checkbox"
              checked={allMachines}
              onChange={(e) => {
                setAllMachinesSelected(e.target.checked);
                if (e.target.checked) {
                  setMachineIds([]);
                }
              }}
              disabled={saveMutation.isPending || readOnly}
            />{" "}
            All machines (wildcard)
          </label>
          <DropZone id="explicit-machines" label="Pinned machines" emptyHint="Drag machines from the palette">
            <ul className="tag-chip-list">
              {machineIds.map((id) => (
                <li key={id}>
                  <span className="tag-chip">
                    {machineLabel(id)}
                    <button
                      type="button"
                      className="tag-chip-remove"
                      onClick={() => setMachineIds((current) => current.filter((entry) => entry !== id))}
                    >
                      ×
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </DropZone>
          <label>
            Search machines
            <input type="search" value={machineSearch} onChange={(e) => setMachineSearch(e.target.value)} />
          </label>
          <ul className="permissions-checklist permissions-checklist-scroll">
            {filteredMachines.map((machine) => (
              <li key={machine.id}>
                <DraggableChip id={`machine:${machine.id}`} label={machine.hostname} disabled={saveMutation.isPending || readOnly} />
                {machine.tags.length > 0 ? (
                  <span className="muted"> ({machine.tags.join(", ")})</span>
                ) : null}
              </li>
            ))}
          </ul>
        </section>

        <section className="permissions-section">
          <h4>Tag rules</h4>
          <DropZone id="tag-rules" label="Scope tags" emptyHint="Drag tags from the palette">
            <ul className="tag-chip-list">
              {tags.map((tag) => (
                <li key={tag}>
                  <span className="tag-chip">
                    <code>{tag}</code>
                    <button
                      type="button"
                      className="tag-chip-remove"
                      onClick={() => setTags((current) => current.filter((entry) => entry !== tag))}
                    >
                      ×
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </DropZone>
          {[...tagGroups.entries()].map(([namespace, groupTags]) => (
            <div key={namespace} className="permissions-tag-group">
              <p className="permissions-tag-namespace">{namespace}</p>
              <ul className="tag-chip-list">
                {groupTags.map((tag) => (
                  <li key={tag}>
                    <DraggableChip id={`tag:${tag}`} label={tag} disabled={saveMutation.isPending || readOnly} />
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </section>

        {scope ? (
          <details open={previewOpen} onToggle={(event) => setPreviewOpen(event.currentTarget.open)}>
            <summary>Live preview ({previewQuery.data?.machines.length ?? "…"} machines)</summary>
            {previewQuery.isLoading ? <LoadingState /> : null}
            {previewQuery.data && previewQuery.data.machines.length === 0 ? (
              <p className="authz-banner authz-banner--warning">This scope matches no machines.</p>
            ) : null}
            <ul className="permissions-checklist permissions-checklist-scroll">
              {(previewQuery.data?.machines ?? []).map((machine) => (
                <li key={machine.id}>
                  {machine.hostname}
                  {machine.tags.length > 0 ? (
                    <span className="muted"> ({machine.tags.join(", ")})</span>
                  ) : null}
                </li>
              ))}
            </ul>
          </details>
        ) : null}

        <div className="actions">
          {!readOnly ? (
            <button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending ? "Saving…" : scope ? "Save scope" : "Create scope"}
            </button>
          ) : null}
          {scope && !readOnly ? (
            <button
              type="button"
              className="danger"
              disabled={deleteMutation.isPending}
              onClick={() => {
                if (window.confirm("Delete this fleet scope?")) {
                  deleteMutation.mutate();
                }
              }}
            >
              Delete
            </button>
          ) : null}
        </div>
      </form>
    </AuthzDndProvider>
  );
}

export function FleetScopesTab() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");

  const scopesQuery = useQuery({
    queryKey: ["fleet-scopes"],
    queryFn: () => apiClient.listFleetScopes(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const items = scopesQuery.data ?? [];
    if (!needle) {
      return items;
    }
    return items.filter(
      (scope) =>
        scope.name.toLowerCase().includes(needle) ||
        scope.description.toLowerCase().includes(needle) ||
        scope.tags.some((tag) => tag.toLowerCase().includes(needle)),
    );
  }, [scopesQuery.data, search]);

  const selected = filtered.find((scope) => scope.id === selectedId) ?? null;

  if (scopesQuery.isLoading) {
    return <LoadingState />;
  }

  if (scopesQuery.error) {
    return <ErrorState message="Failed to load fleet scopes." />;
  }

  return (
    <div className="authz-master-detail">
      <aside className="authz-master-panel card stack">
        <button
          type="button"
          onClick={() => {
            setCreating(true);
            setSelectedId(null);
          }}
        >
          + New fleet scope
        </button>
        <label>
          Search
          <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <ul className="authz-entity-list">
          {filtered.map((scope) => (
            <li key={scope.id}>
              <button
                type="button"
                className={selectedId === scope.id ? "authz-entity-item authz-entity-item--active" : "authz-entity-item"}
                onClick={() => {
                  setSelectedId(scope.id);
                  setCreating(false);
                }}
              >
                <strong>{scope.name}</strong>
                {isSystemFleetScope(scope) ? <span className="badge badge--standard">System</span> : null}
                <span className="muted">
                  {machineIdsAllowAll(scope.machine_ids)
                    ? "All machines"
                    : `${scope.machine_ids.length} machines`}{" "}
                  · {scope.tags.length} tags
                </span>
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <div className="authz-detail-panel card">
        {creating || selected ? (
          <FleetScopeEditor
            scope={creating ? null : selected}
            onSaved={() => setCreating(false)}
            onDeleted={() => setSelectedId(null)}
          />
        ) : (
          <p className="muted">Select a fleet scope or create a new one.</p>
        )}
      </div>
    </div>
  );
}
