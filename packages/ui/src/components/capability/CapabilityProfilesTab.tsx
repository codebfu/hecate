// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { DragEndEvent } from "@dnd-kit/core";
import {
  apiClient,
  type CapabilityProfile,
  type CapabilityProfileInput,
  type CapabilityProfilePatch,
} from "../../api/client.js";
import { FLEET_LIST_REFETCH_MS } from "../../queries/refetch.js";
import { ErrorState, LoadingState } from "../Layout.js";
import { useToast } from "../ToastProvider.js";
import {
  DEFAULT_CAPABILITY_PROFILE,
  capabilityToFormState,
  formStateToCapability,
  pathSensitiveWarning,
  shellRunEnabled,
} from "../../utils/authz/capabilityForm.js";
import {
  FALLBACK_AGENT_COMMANDS,
  partitionCommandCatalogue,
  type CommandOption,
} from "../../utils/authz/commandCatalog.js";
import {
  formatAdminCommandCount,
  formatCommandCount,
  isSystemCapabilityProfile,
} from "../../utils/authz/capabilityProfile.js";
import { AuthzDndProvider, DraggableChip, DropZone } from "../authz/DndHelpers.js";

interface CapabilityProfileEditorProps {
  profile: CapabilityProfile | null;
  agentCommands: readonly CommandOption[];
  adminCommands: readonly CommandOption[];
  onSaved: () => void;
  onDeleted: () => void;
}

export function CapabilityProfileEditor({
  profile,
  agentCommands,
  adminCommands,
  onSaved,
  onDeleted,
}: CapabilityProfileEditorProps) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [formState, setFormState] = useState(() =>
    capabilityToFormState(DEFAULT_CAPABILITY_PROFILE, [...agentCommands], [...adminCommands]),
  );

  useEffect(() => {
    if (profile) {
      setName(profile.name);
      setDescription(profile.description);
      setFormState(capabilityToFormState(profile, [...agentCommands], [...adminCommands]));
    }
  }, [profile, agentCommands, adminCommands]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body = formStateToCapability(formState);
      if (profile) {
        const patch: CapabilityProfilePatch = { name, description, ...body };
        return apiClient.updateCapabilityProfile(profile.id, patch);
      }
      const input: CapabilityProfileInput = { name, description, ...body };
      return apiClient.createCapabilityProfile(input);
    },
    onSuccess: async () => {
      toast.success(profile ? "Capability profile saved." : "Capability profile created.");
      await queryClient.invalidateQueries({ queryKey: ["capability-profiles"] });
      await queryClient.invalidateQueries({ queryKey: ["authz-catalog"] });
      onSaved();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to save profile."),
  });

  const deleteMutation = useMutation({
    mutationFn: () => apiClient.deleteCapabilityProfile(profile!.id),
    onSuccess: async () => {
      toast.success("Capability profile deleted.");
      await queryClient.invalidateQueries({ queryKey: ["capability-profiles"] });
      onDeleted();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to delete profile."),
  });

  function toggleSetValue(set: Set<string>, value: string): Set<string> {
    const next = new Set(set);
    if (next.has(value)) {
      next.delete(value);
    } else {
      next.add(value);
    }
    return next;
  }

  function onDragEnd(event: DragEndEvent) {
    const commandId = String(event.active.id);
    if (!event.over || !commandId.startsWith("cmd:")) {
      return;
    }
    const id = commandId.slice(4);
    if (id.startsWith("admin.")) {
      setFormState((current) => ({
        ...current,
        allowedAdminCommandsAllowAll: false,
        allowedAdminCommands: toggleSetValue(current.allowedAdminCommands, id),
      }));
    } else {
      setFormState((current) => ({
        ...current,
        allowedCommandsAllowAll: false,
        allowedCommands: toggleSetValue(current.allowedCommands, id),
      }));
    }
  }

  const cwdWarning = pathSensitiveWarning(formState);
  const showShell = shellRunEnabled(formState);
  const readOnly = profile ? isSystemCapabilityProfile(profile) : false;
  const controlsDisabled = saveMutation.isPending || readOnly;

  return (
    <AuthzDndProvider onDragEnd={onDragEnd}>
      <form
        className="stack permissions-form"
        onSubmit={(event) => {
          event.preventDefault();
          saveMutation.mutate();
        }}
      >
        {profile?.request_scoped ? (
          <p className="authz-banner authz-banner--info">Request-scoped profile (created via permission request).</p>
        ) : null}
        {readOnly ? (
          <p className="authz-banner authz-banner--info">
            System capability profile — cannot be modified.
          </p>
        ) : null}
        {cwdWarning && !readOnly ? (
          <p className="authz-banner authz-banner--warning">
            Path-sensitive commands are enabled without allowed working directories — executions will be denied.
          </p>
        ) : null}
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required disabled={controlsDisabled} />
        </label>
        <label>
          Description
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={controlsDisabled}
          />
        </label>

        <section className="permissions-section" aria-disabled={readOnly}>
          <h4>Agent commands</h4>
          <label>
            <input
              type="checkbox"
              checked={formState.allowedCommandsAllowAll}
              onChange={(e) =>
                setFormState((current) => ({
                  ...current,
                  allowedCommandsAllowAll: e.target.checked,
                  allowedCommands: new Set(),
                  customCommandsText: "",
                }))
              }
              disabled={controlsDisabled}
            />{" "}
            All commands
          </label>
          <DropZone id="included-commands" label="Included commands (drag from catalog below)" emptyHint="Drag commands here">
            <ul className="tag-chip-list">
              {formState.allowedCommandsAllowAll ? (
                <li>
                  <code>*</code>
                </li>
              ) : (
                [...formState.allowedCommands].map((cmd) => (
                  <li key={cmd}>
                    <span className="tag-chip">
                      <code>{cmd}</code>
                      <button
                        type="button"
                        className="tag-chip-remove"
                        onClick={() =>
                          setFormState((current) => ({
                            ...current,
                            allowedCommands: toggleSetValue(current.allowedCommands, cmd),
                          }))
                        }
                      >
                        ×
                      </button>
                    </span>
                  </li>
                ))
              )}
            </ul>
          </DropZone>
          <ul className="permissions-checklist">
            {agentCommands.map((command) => (
              <li key={command.id}>
                <DraggableChip id={`cmd:${command.id}`} label={command.id} disabled={controlsDisabled} />
                <span className="muted"> — {command.description}</span>
                {command.riskLevel ? (
                  <span className={`risk-badge risk-badge--${command.riskLevel}`}> {command.riskLevel}</span>
                ) : null}
              </li>
            ))}
          </ul>
          <label>
            Additional commands (one per line)
            <textarea
              rows={3}
              value={formState.customCommandsText}
              onChange={(e) =>
                setFormState((current) => ({
                  ...current,
                  allowedCommandsAllowAll: false,
                  customCommandsText: e.target.value,
                }))
              }
              disabled={controlsDisabled}
            />
          </label>
        </section>

        <section className="permissions-section">
          <h4>Admin commands</h4>
          <label>
            <input
              type="checkbox"
              checked={formState.allowedAdminCommandsAllowAll}
              onChange={(e) =>
                setFormState((current) => ({
                  ...current,
                  allowedAdminCommandsAllowAll: e.target.checked,
                  allowedAdminCommands: new Set(),
                  customAdminCommandsText: "",
                }))
              }
              disabled={controlsDisabled}
            />{" "}
            All admin commands
          </label>
          <ul className="permissions-checklist">
            {adminCommands.map((command) => (
              <li key={command.id}>
                <DraggableChip id={`cmd:${command.id}`} label={command.id} disabled={controlsDisabled} />
                <span className="muted"> — {command.description}</span>
              </li>
            ))}
          </ul>
          <label>
            Additional admin commands (one per line)
            <textarea
              rows={3}
              value={formState.customAdminCommandsText}
              onChange={(e) =>
                setFormState((current) => ({
                  ...current,
                  allowedAdminCommandsAllowAll: false,
                  customAdminCommandsText: e.target.value,
                }))
              }
              disabled={controlsDisabled}
            />
          </label>
        </section>

        {showShell ? (
          <section className="permissions-section">
            <h4>Shell modifiers</h4>
            <label>
              Allowed binaries (one per line)
              <textarea
                rows={4}
                value={formState.allowedBinariesText}
                onChange={(e) =>
                  setFormState((current) => ({
                    ...current,
                    allowedBinariesAllowAll: false,
                    allowedBinariesText: e.target.value,
                  }))
                }
                disabled={controlsDisabled}
              />
            </label>
            <label>
              Allowed working directories (one per line)
              <textarea
                rows={3}
                value={formState.allowedCwdText}
                onChange={(e) =>
                  setFormState((current) => ({ ...current, allowedCwdText: e.target.value }))
                }
                disabled={controlsDisabled}
              />
            </label>
          </section>
        ) : null}

        {showShell ? (
          <section className="permissions-section">
            <h4>Elevation</h4>
            <label>
              <input
                type="checkbox"
                checked={formState.elevationEnabled}
                onChange={(e) =>
                  setFormState((current) => ({ ...current, elevationEnabled: e.target.checked }))
                }
                disabled={controlsDisabled}
              />{" "}
              Allow elevated shell.run
            </label>
            {formState.elevationEnabled ? (
              <label>
                Allowed elevated binaries (one per line)
                <textarea
                  rows={3}
                  value={formState.elevationBinariesText}
                  onChange={(e) =>
                    setFormState((current) => ({
                      ...current,
                      elevationBinariesText: e.target.value,
                    }))
                  }
                  disabled={controlsDisabled}
                />
              </label>
            ) : null}
          </section>
        ) : null}

        <section className="permissions-section">
          <h4>Execution limits</h4>
          <div className="permissions-limits-grid">
            <label>
              Max output (bytes)
              <input
                type="number"
                min={1}
                value={formState.maxOutputBytes}
                onChange={(e) =>
                  setFormState((current) => ({ ...current, maxOutputBytes: Number(e.target.value) }))
                }
                disabled={controlsDisabled}
              />
            </label>
            <label>
              Max file (bytes)
              <input
                type="number"
                min={1}
                value={formState.maxFileBytes}
                onChange={(e) =>
                  setFormState((current) => ({ ...current, maxFileBytes: Number(e.target.value) }))
                }
                disabled={controlsDisabled}
              />
            </label>
            <label>
              Timeout (seconds)
              <input
                type="number"
                min={1}
                value={formState.timeoutSecs}
                onChange={(e) =>
                  setFormState((current) => ({ ...current, timeoutSecs: Number(e.target.value) }))
                }
                disabled={controlsDisabled}
              />
            </label>
            <label>
              Max concurrent
              <input
                type="number"
                min={1}
                value={formState.maxConcurrent}
                onChange={(e) =>
                  setFormState((current) => ({ ...current, maxConcurrent: Number(e.target.value) }))
                }
                disabled={controlsDisabled}
              />
            </label>
          </div>
        </section>

        <div className="actions">
          {!readOnly ? (
            <button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending ? "Saving…" : profile ? "Save profile" : "Create profile"}
            </button>
          ) : null}
          {profile && !readOnly ? (
            <button
              type="button"
              className="danger"
              disabled={deleteMutation.isPending}
              onClick={() => {
                if (window.confirm("Delete this capability profile?")) {
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

export function CapabilityProfilesTab() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");

  const profilesQuery = useQuery({
    queryKey: ["capability-profiles"],
    queryFn: () => apiClient.listCapabilityProfiles(),
    refetchInterval: FLEET_LIST_REFETCH_MS,
  });

  const commandsQuery = useQuery({
    queryKey: ["command-definitions"],
    queryFn: () => apiClient.listCommandDefinitions(),
  });

  const { agentCommands, adminCommands } = useMemo(() => {
    const definitions = commandsQuery.data ?? [];
    if (definitions.length === 0) {
      return { agentCommands: FALLBACK_AGENT_COMMANDS, adminCommands: [] as CommandOption[] };
    }
    return partitionCommandCatalogue(definitions);
  }, [commandsQuery.data]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const items = profilesQuery.data ?? [];
    if (!needle) {
      return items;
    }
    return items.filter(
      (profile) =>
        profile.name.toLowerCase().includes(needle) ||
        profile.description.toLowerCase().includes(needle),
    );
  }, [profilesQuery.data, search]);

  const selected = filtered.find((profile) => profile.id === selectedId) ?? null;

  if (profilesQuery.isLoading || commandsQuery.isLoading) {
    return <LoadingState />;
  }

  if (profilesQuery.error) {
    return <ErrorState message="Failed to load capability profiles." />;
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
          + New capability profile
        </button>
        <label>
          Search
          <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <ul className="authz-entity-list">
          {filtered.map((profile) => (
            <li key={profile.id}>
              <button
                type="button"
                className={selectedId === profile.id ? "authz-entity-item authz-entity-item--active" : "authz-entity-item"}
                onClick={() => {
                  setSelectedId(profile.id);
                  setCreating(false);
                }}
              >
                <strong>{profile.name}</strong>
                {isSystemCapabilityProfile(profile) ? (
                  <span className="badge badge--standard">System</span>
                ) : null}
                <span className="muted">
                  {formatCommandCount(profile.allowed_commands)} cmd ·{" "}
                  {formatAdminCommandCount(profile.allowed_admin_commands)} admin
                </span>
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <div className="authz-detail-panel card">
        {creating || selected ? (
          <CapabilityProfileEditor
            profile={creating ? null : selected}
            agentCommands={agentCommands}
            adminCommands={adminCommands}
            onSaved={() => {
              setCreating(false);
            }}
            onDeleted={() => {
              setSelectedId(null);
            }}
          />
        ) : (
          <p className="muted">Select a capability profile or create a new one.</p>
        )}
      </div>
    </div>
  );
}
