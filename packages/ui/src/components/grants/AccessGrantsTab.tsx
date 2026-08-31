// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { DragEndEvent } from "@dnd-kit/core";
import {
  apiClient,
  type AccessGrantDetail,
  type AccessGrantInput,
  type AccessGrantPatch,
} from "../../api/client.js";
import { FLEET_LIST_REFETCH_MS } from "../../queries/refetch.js";
import { ErrorState, LoadingState } from "../Layout.js";
import { useToast } from "../ToastProvider.js";
import { AuthzDndProvider, DraggableChip, DropZone } from "../authz/DndHelpers.js";

function AccessGrantEditor({
  grant,
  catalog,
  onSaved,
  onDeleted,
}: {
  grant: AccessGrantDetail | null;
  catalog: { fleetScopes: { id: string; name: string }[]; capabilityProfiles: { id: string; name: string }[] };
  onSaved: () => void;
  onDeleted: () => void;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState(grant?.name ?? "");
  const [description, setDescription] = useState(grant?.description ?? "");
  const [fleetScopeId, setFleetScopeId] = useState(grant?.fleet_scope_id ?? "");
  const [capabilityProfileId, setCapabilityProfileId] = useState(grant?.capability_profile_id ?? "");

  useEffect(() => {
    if (grant) {
      setName(grant.name);
      setDescription(grant.description);
      setFleetScopeId(grant.fleet_scope_id);
      setCapabilityProfileId(grant.capability_profile_id);
    }
  }, [grant]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (grant) {
        const patch: AccessGrantPatch = { name, description, fleet_scope_id: fleetScopeId, capability_profile_id: capabilityProfileId };
        return apiClient.updateAccessGrant(grant.id, patch);
      }
      const input: AccessGrantInput = {
        name,
        description,
        fleet_scope_id: fleetScopeId,
        capability_profile_id: capabilityProfileId,
      };
      return apiClient.createAccessGrant(input);
    },
    onSuccess: async () => {
      toast.success(grant ? "Access grant saved." : "Access grant created.");
      await queryClient.invalidateQueries({ queryKey: ["access-grants"] });
      await queryClient.invalidateQueries({ queryKey: ["authz-catalog"] });
      onSaved();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to save access grant."),
  });

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteAccessGrant(grant!.id),
    onSuccess: async () => {
      toast.success("Access grant deleted.");
      await queryClient.invalidateQueries({ queryKey: ["access-grants"] });
      onDeleted();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to delete access grant."),
  });

  function onDragEnd(event: DragEndEvent) {
    const activeId = String(event.active.id);
    if (!event.over) {
      return;
    }
    if (activeId.startsWith("scope:") && event.over.id === "grant-fleet-scope") {
      setFleetScopeId(activeId.slice(6));
    }
    if (activeId.startsWith("profile:") && event.over.id === "grant-capability-profile") {
      setCapabilityProfileId(activeId.slice(8));
    }
  }

  const scopeName =
    catalog.fleetScopes.find((scope) => scope.id === fleetScopeId)?.name ??
    grant?.fleet_scope.name ??
    "—";
  const profileName =
    catalog.capabilityProfiles.find((profile) => profile.id === capabilityProfileId)?.name ??
    grant?.capability_profile.name ??
    "—";

  const canSave = name.trim().length > 0 && fleetScopeId && capabilityProfileId;

  return (
    <AuthzDndProvider onDragEnd={onDragEnd}>
      <form
        className="stack permissions-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (canSave) {
            saveMutation.mutate();
          }
        }}
      >
        <div className="authz-grant-builder">
          <DropZone id="grant-fleet-scope" label="Fleet scope" emptyHint="Drop a fleet scope">
            <p>
              <strong>{scopeName}</strong>
            </p>
          </DropZone>
          <span className="authz-grant-plus">+</span>
          <DropZone id="grant-capability-profile" label="Capability profile" emptyHint="Drop a capability profile">
            <p>
              <strong>{profileName}</strong>
            </p>
          </DropZone>
        </div>

        <div className="authz-palette">
          <div>
            <p className="permissions-hint">Fleet scopes</p>
            <ul className="tag-chip-list">
              {catalog.fleetScopes.map((scope) => (
                <li key={scope.id}>
                  <DraggableChip id={`scope:${scope.id}`} label={scope.name} />
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="permissions-hint">Capability profiles</p>
            <ul className="tag-chip-list">
              {catalog.capabilityProfiles.map((profile) => (
                <li key={profile.id}>
                  <DraggableChip id={`profile:${profile.id}`} label={profile.name} />
                </li>
              ))}
            </ul>
          </div>
        </div>

        <label>
          Grant name
          <input value={name} onChange={(e) => setName(e.target.value)} required disabled={saveMutation.isPending} />
        </label>
        <label>
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} disabled={saveMutation.isPending} />
        </label>

        <div className="actions">
          <button type="submit" disabled={!canSave || saveMutation.isPending}>
            {saveMutation.isPending ? "Saving…" : grant ? "Save grant" : "Create grant"}
          </button>
          {grant ? (
            <button
              type="button"
              className="danger"
              disabled={deleteMutation.isPending}
              onClick={() => {
                if (window.confirm("Delete this access grant?")) {
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

export function AccessGrantsTab() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");

  const grantsQuery = useQuery({
    queryKey: ["access-grants"],
    queryFn: () => apiClient.listAccessGrants(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const catalogQuery = useQuery({
    queryKey: ["authz-catalog"],
    queryFn: () => apiClient.getAuthzCatalog(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const items = grantsQuery.data ?? [];
    if (!needle) {
      return items;
    }
    return items.filter(
      (grant) =>
        grant.name.toLowerCase().includes(needle) ||
        grant.fleet_scope.name.toLowerCase().includes(needle) ||
        grant.capability_profile.name.toLowerCase().includes(needle),
    );
  }, [grantsQuery.data, search]);

  const selected = filtered.find((grant) => grant.id === selectedId) ?? null;

  if (grantsQuery.isLoading || catalogQuery.isLoading) {
    return <LoadingState />;
  }

  if (grantsQuery.error || catalogQuery.error) {
    return <ErrorState message="Failed to load access grants." />;
  }

  const catalog = {
    fleetScopes: catalogQuery.data?.fleet_scopes ?? [],
    capabilityProfiles: catalogQuery.data?.capability_profiles ?? [],
  };

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
          + New access grant
        </button>
        <label>
          Search
          <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <ul className="authz-entity-list">
          {filtered.map((grant) => (
            <li key={grant.id}>
              <button
                type="button"
                className={selectedId === grant.id ? "authz-entity-item authz-entity-item--active" : "authz-entity-item"}
                onClick={() => {
                  setSelectedId(grant.id);
                  setCreating(false);
                }}
              >
                <strong>{grant.name}</strong>
                <span className="muted">
                  {grant.fleet_scope.name} × {grant.capability_profile.name}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <div className="authz-detail-panel card">
        {creating || selected ? (
          <AccessGrantEditor
            grant={creating ? null : selected}
            catalog={catalog}
            onSaved={() => setCreating(false)}
            onDeleted={() => setSelectedId(null)}
          />
        ) : (
          <p className="muted">Select an access grant or assemble a new one.</p>
        )}
      </div>
    </div>
  );
}
