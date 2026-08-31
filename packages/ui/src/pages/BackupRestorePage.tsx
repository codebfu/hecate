// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useRef, useState, type ChangeEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiClient } from "../api/client.js";
import { LIST_REFETCH_MS } from "../queries/refetch.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";

export function BackupRestorePage() {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [encryptedBackup, setEncryptedBackup] = useState<Record<string, unknown> | null>(null);
  const [previewSections, setPreviewSections] = useState<Record<string, boolean>>({});
  const [exportPassword, setExportPassword] = useState("");
  const [importPassword, setImportPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["backup-sections"],
    queryFn: () => apiClient.listBackupSections(),
    refetchInterval: LIST_REFETCH_MS,
  });

  const exportMutation = useMutation({
    mutationFn: ({ sections, password }: { sections: string[]; password: string }) =>
      apiClient.exportBackup(sections, password),
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `hecate-backup-${new Date().toISOString().slice(0, 10)}.hecate-backup`;
      anchor.click();
      URL.revokeObjectURL(url);
      toast.success("Backup exported.");
      setError(null);
    },
    onError: (err) => setError(err instanceof Error ? err.message : "Export failed"),
  });

  const previewMutation = useMutation({
    mutationFn: ({
      encryptedBackup: uploaded,
      password,
    }: {
      encryptedBackup: Record<string, unknown>;
      password: string;
    }) => apiClient.previewBackup(uploaded, password),
    onSuccess: (data) => {
      const next: Record<string, boolean> = {};
      for (const section of data.sections) {
        next[section.id] = section.default_selected;
      }
      setPreviewSections(next);
      toast.success(`Loaded backup ${data.hecate_version} (format v${data.backup_format_version}).`);
      setError(null);
    },
    onError: (err) => setError(err instanceof Error ? err.message : "Preview failed"),
  });

  const restoreMutation = useMutation({
    mutationFn: ({
      sections,
      encryptedBackup: backup,
      password,
    }: {
      sections: string[];
      encryptedBackup: Record<string, unknown>;
      password: string;
    }) => apiClient.restoreBackup(sections, backup, password),
    onSuccess: () => {
      toast.success("Restore completed.");
      setError(null);
      setEncryptedBackup(null);
      setPreviewSections({});
      setImportPassword("");
    },
    onError: (err) => setError(err instanceof Error ? err.message : "Restore failed"),
  });

  if (query.isLoading) {
    return <LoadingState />;
  }

  if (query.error) {
    return <ErrorState message="Failed to load backup sections." />;
  }

  const sections = query.data ?? [];

  function toggleExport(id: string) {
    setSelected((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  function toggleRestore(id: string) {
    setPreviewSections((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  function onExport() {
    const chosen = sections.filter((s) => selected[s.id] ?? s.default_selected).map((s) => s.id);
    if (chosen.length === 0) {
      setError("Select at least one section to export.");
      return;
    }
    if (exportPassword.length < 12) {
      setError("Export password must be at least 12 characters.");
      return;
    }
    exportMutation.mutate({ sections: chosen, password: exportPassword });
  }

  async function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    const text = await file.text();
    const parsed = JSON.parse(text) as Record<string, unknown>;
    setEncryptedBackup(parsed);
    if (importPassword.length < 12) {
      setError("Enter the backup password (min. 12 characters) before previewing.");
      return;
    }
    previewMutation.mutate({ encryptedBackup: parsed, password: importPassword });
  }

  function onRestore(event: FormEvent) {
    event.preventDefault();
    if (!encryptedBackup) {
      setError("Upload a backup file first.");
      return;
    }
    if (importPassword.length < 12) {
      setError("Import password must be at least 12 characters.");
      return;
    }
    const chosen = Object.entries(previewSections)
      .filter(([, enabled]) => enabled)
      .map(([id]) => id);
    if (chosen.length === 0) {
      setError("Select at least one section to restore.");
      return;
    }
    restoreMutation.mutate({
      sections: chosen,
      encryptedBackup,
      password: importPassword,
    });
  }

  const busy = exportMutation.isPending || previewMutation.isPending || restoreMutation.isPending;

  return (
    <section>
      <PageHeader
        title="Backup & Restore"
        subtitle="Export and import password-protected configuration backups."
      />
      {error ? <ErrorState message={error} /> : null}

      <h2>Export</h2>
      <ul className="checklist">
        {sections.map((section) => (
          <li key={section.id}>
            <label>
              <input
                type="checkbox"
                checked={selected[section.id] ?? section.default_selected}
                disabled={!section.exportable || busy}
                onChange={() => toggleExport(section.id)}
              />
              {section.label}
            </label>
          </li>
        ))}
      </ul>
      <label>
        Backup password
        <input
          type="password"
          value={exportPassword}
          disabled={busy}
          onChange={(event) => setExportPassword(event.target.value)}
          minLength={12}
          autoComplete="new-password"
        />
      </label>
      <div className="actions">
        <button type="button" onClick={onExport} disabled={busy}>
          Export backup
        </button>
      </div>

      <h2>Restore</h2>
      <label>
        Backup password
        <input
          type="password"
          value={importPassword}
          disabled={busy}
          onChange={(event) => setImportPassword(event.target.value)}
          minLength={12}
          autoComplete="current-password"
        />
      </label>
      <div className="actions">
        <input
          ref={fileInputRef}
          type="file"
          accept="application/json,.hecate-backup,.json"
          onChange={onFileChange}
        />
      </div>
      {encryptedBackup ? (
        <form onSubmit={onRestore} className="stack">
          <ul className="checklist">
            {Object.keys(previewSections).map((id) => (
              <li key={id}>
                <label>
                  <input
                    type="checkbox"
                    checked={previewSections[id] ?? false}
                    disabled={busy}
                    onChange={() => toggleRestore(id)}
                  />
                  {id}
                </label>
              </li>
            ))}
          </ul>
          <button type="submit" disabled={busy}>
            Restore selected sections
          </button>
        </form>
      ) : null}
    </section>
  );
}
