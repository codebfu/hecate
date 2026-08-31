// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiClient } from "../api/client.js";
import { useToast } from "./ToastProvider.js";
import { validateCustomTagInput } from "../utils/machineTags.js";

interface MachineTagsEditorProps {
  machineId: string;
  operatorTags: string[];
  agentTags: string[];
  effectiveTags: string[];
}

export function MachineTagsEditor({
  machineId,
  operatorTags,
  agentTags,
  effectiveTags,
}: MachineTagsEditorProps) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [draftTag, setDraftTag] = useState("");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (patch: { add?: string[]; remove?: string[] }) =>
      apiClient.updateMachineTags(machineId, patch),
    onSuccess: async () => {
      setDraftTag("");
      setError(null);
      toast.success("Tags updated.");
      await queryClient.invalidateQueries({ queryKey: ["machine", machineId] });
      await queryClient.invalidateQueries({ queryKey: ["machines"] });
    },
    onError: () => {
      setError("Failed to update tags.");
    },
  });

  function onAdd(event: FormEvent) {
    event.preventDefault();
    const validationError = validateCustomTagInput(draftTag);
    if (validationError) {
      setError(validationError);
      return;
    }
    const tag = draftTag.trim();
    if (operatorTags.includes(tag)) {
      setError("Tag already assigned to this machine.");
      return;
    }
    mutation.mutate({ add: [tag] });
  }

  function onRemove(tag: string) {
    mutation.mutate({ remove: [tag] });
  }

  return (
    <section className="card stack">
      <h2>Tags</h2>
      <dl className="details">
        <div>
          <dt>Effective tags</dt>
          <dd>{effectiveTags.join(", ") || "—"}</dd>
        </div>
        <div>
          <dt>Agent tags</dt>
          <dd>{agentTags.join(", ") || "—"}</dd>
        </div>
      </dl>

      <h3>Custom tags</h3>
      <p className="muted">Operator-managed tags (format namespace:value, e.g. env:prod).</p>
      {operatorTags.length > 0 ? (
        <ul className="tag-chip-list">
          {operatorTags.map((tag) => (
            <li key={tag} className="tag-chip">
              <code>{tag}</code>
              <button
                type="button"
                className="tag-chip-remove"
                disabled={mutation.isPending}
                onClick={() => onRemove(tag)}
                aria-label={`Remove ${tag}`}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">No custom tags yet.</p>
      )}

      <form onSubmit={onAdd} className="tag-add-form">
        <input
          type="text"
          value={draftTag}
          placeholder="env:prod"
          disabled={mutation.isPending}
          onChange={(event) => {
            setDraftTag(event.target.value);
            setError(null);
          }}
        />
        <button type="submit" disabled={mutation.isPending}>
          Add tag
        </button>
      </form>
      {error ? <p className="error-text">{error}</p> : null}
    </section>
  );
}
