// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiClient } from "../api/client.js";
import { useSession } from "../hooks/useSession.js";
import { useToast } from "./ToastProvider.js";

const OFFICIAL_SOURCE_ID = "official";

type CatalogueFilter = "all" | "installed" | "available" | "pinned";

interface RepoSource {
  id: string;
  url: string;
  public_key_b64?: string;
  enabled: boolean;
  priority: number;
  last_sync_at?: string | null;
  last_error?: string | null;
}

interface FeatureVersion {
  version: string;
  manifest: string;
}

interface AvailableFeature {
  source_id: string;
  feature: {
    id: string;
    name?: string;
    latest?: string | null;
    version?: string | null;
    versions?: FeatureVersion[];
  };
}

interface InstalledFeature {
  id: string;
  pinned_version: string;
  source_id: string;
  track_latest?: boolean;
}

interface RepoCatalogue {
  available: AvailableFeature[];
  installed: InstalledFeature[];
  errors: Array<{ source_id: string; error: string }>;
}

interface RepoStatus {
  installed: InstalledFeature[];
}

interface CatalogueRow {
  id: string;
  name: string;
  source_id: string;
  versions: string[];
  latest: string;
  installed?: InstalledFeature;
  status: "available" | "installed" | "pinned";
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError && error.body && typeof error.body === "object") {
    const body = error.body as { message?: unknown };
    if (typeof body.message === "string") {
      return body.message;
    }
  }
  return error instanceof Error ? error.message : "Repository operation failed.";
}

function statusLabel(status: CatalogueRow["status"]): string {
  switch (status) {
    case "pinned":
      return "Pinned";
    case "installed":
      return "Installed";
    default:
      return "Available";
  }
}

export function FeatureRepositorySettings() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const csrfReady = Boolean(session?.csrf_token);
  const [sourceModalOpen, setSourceModalOpen] = useState(false);
  const [editingSourceId, setEditingSourceId] = useState<string | null>(null);
  const [sourceId, setSourceId] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [priority, setPriority] = useState("0");
  const [selectedVersions, setSelectedVersions] = useState<Record<string, string>>({});
  const [catalogueFilter, setCatalogueFilter] = useState<CatalogueFilter>("all");

  const sourcesQuery = useQuery({
    queryKey: ["feature-repo-sources"],
    queryFn: () =>
      apiClient.executeAdminCommand<RepoSource[]>("admin.repo.sources.list"),
    enabled: csrfReady,
  });
  const catalogueQuery = useQuery({
    queryKey: ["feature-repo-catalogue"],
    queryFn: () => apiClient.executeAdminCommand<RepoCatalogue>("admin.repo.list"),
    enabled: csrfReady,
  });
  const statusQuery = useQuery({
    queryKey: ["feature-repo-status"],
    queryFn: () => apiClient.executeAdminCommand<RepoStatus>("admin.repo.status"),
    enabled: csrfReady,
  });

  const mutation = useMutation({
    mutationFn: ({
      command,
      params,
    }: {
      command: string;
      params?: Record<string, unknown>;
    }) => apiClient.executeAdminCommand(command, params),
    onSuccess: async (_, variables) => {
      toast.success(`${variables.command.replace("admin.repo.", "Repository ")} completed.`);
      if (
        variables.command === "admin.repo.sources.add" ||
        variables.command === "admin.repo.sources.update"
      ) {
        closeSourceModal();
      }
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["feature-repo-sources"] }),
        queryClient.invalidateQueries({ queryKey: ["feature-repo-catalogue"] }),
        queryClient.invalidateQueries({ queryKey: ["feature-repo-status"] }),
        queryClient.invalidateQueries({ queryKey: ["command-definitions"] }),
      ]);
    },
    onError: (error) => toast.error(errorMessage(error)),
  });

  const installed = statusQuery.data?.installed ?? catalogueQuery.data?.installed ?? [];
  const installedById = useMemo(
    () => new Map(installed.map((feature) => [feature.id, feature])),
    [installed],
  );
  const busy = mutation.isPending;
  const editingOfficial = editingSourceId === OFFICIAL_SOURCE_ID;

  useEffect(() => {
    if (!sourceModalOpen) {
      return;
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) {
        closeSourceModal();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [sourceModalOpen, busy]);

  const catalogueRows = useMemo(() => {
    const rows = new Map<string, CatalogueRow>();
    for (const entry of catalogueQuery.data?.available ?? []) {
      const versions =
        entry.feature.versions?.map((item) => item.version).filter(Boolean) ?? [];
      const latest =
        entry.feature.latest ?? entry.feature.version ?? versions[0] ?? "";
      const installedFeature = installedById.get(entry.feature.id);
      const status: CatalogueRow["status"] = !installedFeature
        ? "available"
        : installedFeature.track_latest === false
          ? "pinned"
          : "installed";
      rows.set(entry.feature.id, {
        id: entry.feature.id,
        name: entry.feature.name || entry.feature.id,
        source_id: entry.source_id,
        versions,
        latest,
        installed: installedFeature,
        status,
      });
    }
    for (const feature of installed) {
      if (rows.has(feature.id)) {
        continue;
      }
      rows.set(feature.id, {
        id: feature.id,
        name: feature.id,
        source_id: feature.source_id,
        versions: [feature.pinned_version],
        latest: feature.pinned_version,
        installed: feature,
        status: feature.track_latest === false ? "pinned" : "installed",
      });
    }
    return [...rows.values()].sort((a, b) => a.id.localeCompare(b.id));
  }, [catalogueQuery.data?.available, installed, installedById]);

  const filteredRows = useMemo(() => {
    switch (catalogueFilter) {
      case "available":
        return catalogueRows.filter((row) => row.status === "available");
      case "installed":
        return catalogueRows.filter((row) => row.status !== "available");
      case "pinned":
        return catalogueRows.filter((row) => row.status === "pinned");
      default:
        return catalogueRows;
    }
  }, [catalogueFilter, catalogueRows]);

  function resetSourceForm() {
    setEditingSourceId(null);
    setSourceId("");
    setSourceUrl("");
    setPublicKey("");
    setPriority("0");
  }

  function closeSourceModal() {
    setSourceModalOpen(false);
    resetSourceForm();
  }

  function openAddSource() {
    resetSourceForm();
    setSourceModalOpen(true);
  }

  function beginEditSource(source: RepoSource) {
    setEditingSourceId(source.id);
    setSourceId(source.id);
    setSourceUrl(source.url);
    setPublicKey(source.public_key_b64 ?? "");
    setPriority(String(source.priority));
    setSourceModalOpen(true);
  }

  function submitSource(event: FormEvent) {
    event.preventDefault();
    if (editingSourceId) {
      const params: Record<string, unknown> = {
        id: editingSourceId,
        public_key_b64: publicKey.trim(),
        priority: Number(priority),
      };
      if (!editingOfficial) {
        params.url = sourceUrl.trim();
      }
      mutation.mutate({
        command: "admin.repo.sources.update",
        params,
      });
      return;
    }
    mutation.mutate({
      command: "admin.repo.sources.add",
      params: {
        id: sourceId.trim(),
        url: sourceUrl.trim(),
        public_key_b64: publicKey.trim(),
        priority: Number(priority),
      },
    });
  }

  function removeSource(source: RepoSource) {
    if (source.id === OFFICIAL_SOURCE_ID) {
      return;
    }
    if (window.confirm(`Remove repository source "${source.id}"?`)) {
      mutation.mutate({ command: "admin.repo.sources.remove", params: { id: source.id } });
    }
  }

  function selectedVersionFor(row: CatalogueRow): string {
    return selectedVersions[row.id] ?? row.latest;
  }

  function setSelectedVersion(featureId: string, version: string) {
    setSelectedVersions((current) => ({ ...current, [featureId]: version }));
  }

  return (
    <>
      <section className="card stack">
        <div className="actions" style={{ marginTop: 0 }}>
          <div>
            <h2>Feature repository sources</h2>
            <p className="muted">
              Manage signed catalogues used to install fleet features. The official source cannot be
              removed and its URL is read-only.
            </p>
          </div>
          <button type="button" disabled={busy} onClick={openAddSource}>
            Add source
          </button>
        </div>
        {sourcesQuery.isLoading ? <p>Loading sources…</p> : null}
        {sourcesQuery.error ? <p className="error">{errorMessage(sourcesQuery.error)}</p> : null}
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>URL</th>
                <th>Enabled</th>
                <th>Priority</th>
                <th>Last sync</th>
                <th>Last error</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(sourcesQuery.data ?? []).map((source) => (
                <tr key={source.id}>
                  <td>{source.id}</td>
                  <td>{source.url}</td>
                  <td>{source.enabled ? "Yes" : "No"}</td>
                  <td>{source.priority}</td>
                  <td>{source.last_sync_at ?? "Never"}</td>
                  <td>{source.last_error ?? "—"}</td>
                  <td>
                    <div className="actions" style={{ marginTop: 0 }}>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => beginEditSource(source)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          mutation.mutate({
                            command: `admin.repo.sources.${source.enabled ? "disable" : "enable"}`,
                            params: { id: source.id },
                          })
                        }
                      >
                        {source.enabled ? "Disable" : "Enable"}
                      </button>
                      {source.id === OFFICIAL_SOURCE_ID ? null : (
                        <button type="button" disabled={busy} onClick={() => removeSource(source)}>
                          Remove
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {sourceModalOpen ? (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={(event) => {
            if (event.target === event.currentTarget && !busy) {
              closeSourceModal();
            }
          }}
        >
          <div
            className="modal-dialog card stack"
            role="dialog"
            aria-modal="true"
            aria-labelledby="repo-source-modal-title"
          >
            <h3 id="repo-source-modal-title">
              {editingSourceId ? `Edit source ${editingSourceId}` : "Add source"}
            </h3>
            <form className="stack" onSubmit={submitSource}>
              <label>
                Source ID
                <input
                  value={sourceId}
                  required
                  disabled={busy || editingSourceId !== null}
                  onChange={(e) => setSourceId(e.target.value)}
                />
              </label>
              <label>
                URL
                <input
                  type="url"
                  value={sourceUrl}
                  required={!editingOfficial}
                  disabled={busy || editingOfficial}
                  onChange={(e) => setSourceUrl(e.target.value)}
                />
              </label>
              <label>
                Ed25519 public key (base64)
                <textarea
                  rows={2}
                  value={publicKey}
                  required
                  disabled={busy}
                  onChange={(e) => setPublicKey(e.target.value)}
                />
              </label>
              <label>
                Priority
                <input
                  type="number"
                  value={priority}
                  disabled={busy}
                  onChange={(e) => setPriority(e.target.value)}
                />
              </label>
              <div className="actions">
                <button type="submit" disabled={busy}>
                  {editingSourceId ? "Save changes" : "Add source"}
                </button>
                <button type="button" disabled={busy} onClick={closeSourceModal}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      <section className="card stack">
        <div>
          <h2>Feature catalogue</h2>
          <p className="muted">
            Refresh only reloads catalogue metadata. Upgrade all pulls the newest version for
            installs that track latest (pins are skipped).
          </p>
        </div>
        <div className="actions" style={{ marginTop: 0 }}>
          <select
            aria-label="Catalogue filter"
            value={catalogueFilter}
            disabled={busy}
            onChange={(event) => setCatalogueFilter(event.target.value as CatalogueFilter)}
          >
            <option value="all">All</option>
            <option value="installed">Installed</option>
            <option value="available">Available</option>
            <option value="pinned">Pinned</option>
          </select>
          <button
            type="button"
            disabled={busy}
            onClick={() => mutation.mutate({ command: "admin.repo.refresh" })}
          >
            Refresh catalogue
          </button>
          <button
            type="button"
            disabled={busy || installed.length === 0}
            onClick={() => mutation.mutate({ command: "admin.repo.upgrade_all" })}
          >
            Upgrade all to latest
          </button>
        </div>
        {catalogueQuery.isLoading || statusQuery.isLoading ? <p>Loading catalogue…</p> : null}
        {catalogueQuery.error ? <p className="error">{errorMessage(catalogueQuery.error)}</p> : null}
        {(catalogueQuery.data?.errors ?? []).map((error) => (
          <p className="error" key={error.source_id}>{error.source_id}: {error.error}</p>
        ))}
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Feature</th>
                <th>Status</th>
                <th>Version</th>
                <th>Source</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => {
                const currentVersion = row.installed?.pinned_version ?? "";
                const selectedVersion = selectedVersionFor(row);
                const upgradeAvailable =
                  Boolean(row.latest) &&
                  Boolean(currentVersion) &&
                  row.latest !== currentVersion;
                const versionChoices =
                  row.versions.length > 0
                    ? row.versions
                    : row.latest
                      ? [row.latest]
                      : currentVersion
                        ? [currentVersion]
                        : [];

                return (
                  <tr key={row.id}>
                    <td>
                      {row.name}
                      <br />
                      <span className="muted">{row.id}</span>
                    </td>
                    <td>{statusLabel(row.status)}</td>
                    <td>
                      {row.installed ? (
                        <>
                          <div>{currentVersion}</div>
                          {row.latest && row.latest !== currentVersion ? (
                            <span className="muted">latest {row.latest}</span>
                          ) : null}
                        </>
                      ) : (
                        <span className="muted">{row.latest || "—"}</span>
                      )}
                      {versionChoices.length > 0 ? (
                        <select
                          value={selectedVersion}
                          disabled={busy}
                          onChange={(event) => setSelectedVersion(row.id, event.target.value)}
                        >
                          {versionChoices.map((version) => (
                            <option key={version} value={version}>{version}</option>
                          ))}
                        </select>
                      ) : null}
                    </td>
                    <td>{row.installed?.source_id ?? row.source_id}</td>
                    <td>
                      <div className="actions">
                        {row.status === "available" ? (
                          <>
                            <button
                              type="button"
                              disabled={busy || !row.latest}
                              onClick={() => mutation.mutate({
                                command: "admin.repo.install",
                                params: { id: row.id, source_id: row.source_id },
                              })}
                            >
                              Install
                            </button>
                            <button
                              type="button"
                              disabled={busy || !selectedVersion}
                              onClick={() => mutation.mutate({
                                command: "admin.repo.install",
                                params: {
                                  id: row.id,
                                  source_id: row.source_id,
                                  version: selectedVersion,
                                },
                              })}
                            >
                              Pin
                            </button>
                          </>
                        ) : null}

                        {row.status === "installed" ? (
                          <>
                            <button
                              type="button"
                              disabled={busy || !upgradeAvailable}
                              onClick={() => mutation.mutate({
                                command: "admin.repo.upgrade",
                                params: { id: row.id },
                              })}
                            >
                              Upgrade
                            </button>
                            <button
                              type="button"
                              disabled={busy || !selectedVersion}
                              onClick={() => mutation.mutate({
                                command: "admin.repo.pin",
                                params: { id: row.id, version: selectedVersion },
                              })}
                            >
                              Pin
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => {
                                if (window.confirm(`Uninstall feature "${row.id}"?`)) {
                                  mutation.mutate({
                                    command: "admin.repo.uninstall",
                                    params: { id: row.id },
                                  });
                                }
                              }}
                            >
                              Uninstall
                            </button>
                          </>
                        ) : null}

                        {row.status === "pinned" ? (
                          <>
                            <button
                              type="button"
                              disabled={busy || !upgradeAvailable || !row.latest}
                              onClick={() => mutation.mutate({
                                command: "admin.repo.pin",
                                params: { id: row.id, version: row.latest },
                              })}
                            >
                              Force upgrade
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => mutation.mutate({
                                command: "admin.repo.unpin",
                                params: { id: row.id },
                              })}
                            >
                              Unpin
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => {
                                if (window.confirm(`Uninstall feature "${row.id}"?`)) {
                                  mutation.mutate({
                                    command: "admin.repo.uninstall",
                                    params: { id: row.id },
                                  });
                                }
                              }}
                            >
                              Uninstall
                            </button>
                          </>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted">No features match this filter.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
