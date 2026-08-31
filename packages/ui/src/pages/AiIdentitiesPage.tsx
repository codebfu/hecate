// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { Fragment, FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client.js";
import { LIST_REFETCH_MS } from "../queries/refetch.js";
import { GrantAssignmentsPanel } from "../components/GrantAssignmentsPanel.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useToast } from "../components/ToastProvider.js";
import { useSession } from "../hooks/useSession.js";

function IdentityPanel({ identityId, isAdmin }: { identityId: string; isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [newKey, setNewKey] = useState<string | null>(null);

  const keysQuery = useQuery({
    queryKey: ["ai-api-keys", identityId],
    queryFn: () => apiClient.listAiApiKeys(identityId),
    enabled: isAdmin,
    refetchInterval: LIST_REFETCH_MS,
  });

  const createKeyMutation = useMutation({
    mutationFn: () => apiClient.createAiApiKey(identityId),
    onSuccess: (data) => {
      setNewKey(data.api_key);
      void queryClient.invalidateQueries({ queryKey: ["ai-api-keys", identityId] });
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to create API key"),
  });

  const revokeKeyMutation = useMutation({
    mutationFn: (keyId: string) => apiClient.revokeAiApiKey(identityId, keyId),
    onSuccess: async () => {
      toast.success("API key revoked.");
      await queryClient.invalidateQueries({ queryKey: ["ai-api-keys", identityId] });
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to revoke API key"),
  });

  if (!isAdmin) {
    return null;
  }

  return (
    <div className="card stack">
      <h3>API keys</h3>
      {keysQuery.isLoading ? <LoadingState /> : null}
      <ul>
        {(keysQuery.data ?? []).map((key) => (
          <li key={key.id}>
            {key.prefix}… {key.active ? "active" : "revoked"}
            {key.active ? (
              <button type="button" onClick={() => revokeKeyMutation.mutate(key.id)}>
                Revoke
              </button>
            ) : null}
          </li>
        ))}
      </ul>
      <button type="button" onClick={() => createKeyMutation.mutate()} disabled={createKeyMutation.isPending}>
        Create API key
      </button>
      {newKey ? (
        <p className="muted">
          Copy now — shown once: <code>{newKey}</code>
        </p>
      ) : null}

      <h3>Grant assignments</h3>
      <GrantAssignmentsPanel identityId={identityId} />
    </div>
  );
}

export function AiIdentitiesPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";
  const [searchParams] = useSearchParams();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [shellApproval, setShellApproval] = useState(true);

  const query = useQuery({
    queryKey: ["ai-identities"],
    queryFn: () => apiClient.listAiIdentities(),
    refetchInterval: LIST_REFETCH_MS,
  });

  const selectedIdentityId = searchParams.get("identity");

  useEffect(() => {
    if (!selectedIdentityId || !query.data?.some((identity) => identity.id === selectedIdentityId)) {
      return;
    }
    setExpandedId(selectedIdentityId);
    const row = document.getElementById(`ai-identity-row-${selectedIdentityId}`);
    row?.scrollIntoView({ block: "center" });
  }, [selectedIdentityId, query.data]);

  const createMutation = useMutation({
    mutationFn: () => apiClient.createAiIdentity(name, description, shellApproval),
    onSuccess: async () => {
      setName("");
      setDescription("");
      setShellApproval(true);
      toast.success("AI identity created.");
      await queryClient.invalidateQueries({ queryKey: ["ai-identities"] });
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to create identity"),
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: {
        active?: boolean;
        requires_approval_for_shell?: boolean;
        requires_approval_for_elevated?: boolean;
      };
    }) => apiClient.updateAiIdentity(id, patch),
    onSuccess: async () => {
      toast.success("AI identity updated.");
      await queryClient.invalidateQueries({ queryKey: ["ai-identities"] });
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to update identity"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteAiIdentity(id),
    onSuccess: async () => {
      setExpandedId(null);
      toast.success("AI identity removed.");
      await queryClient.invalidateQueries({ queryKey: ["ai-identities"] });
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to remove identity"),
  });

  const unlockMutation = useMutation({
    mutationFn: (id: string) => apiClient.unlockAiContentPolicy(id),
    onSuccess: async () => {
      toast.success("Content policy lockout cleared.");
      await queryClient.invalidateQueries({ queryKey: ["ai-identities"] });
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : "Failed to clear lockout"),
  });

  if (query.isLoading) {
    return <LoadingState />;
  }

  if (query.error) {
    return <ErrorState message="Failed to load AI identities." />;
  }

  function onCreate(event: FormEvent) {
    event.preventDefault();
    createMutation.mutate();
  }

  return (
    <section>
      <PageHeader
        title="AI Identities"
        subtitle="Manage AI personas, API keys, and grant assignments."
      />

      {isAdmin ? (
        <form onSubmit={onCreate} className="stack card">
          <h2>Create identity</h2>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          <label>
            Description
            <input value={description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          <label>
            <input
              type="checkbox"
              checked={shellApproval}
              onChange={(e) => setShellApproval(e.target.checked)}
            />
            Require approval for shell.run permissions (legacy create flag)
          </label>
          <button type="submit" disabled={createMutation.isPending}>
            {createMutation.isPending ? "Creating…" : "Create"}
          </button>
        </form>
      ) : null}

      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Active</th>
            <th>Content policy</th>
            {isAdmin ? <th>Actions</th> : null}
          </tr>
        </thead>
        <tbody>
          {(query.data ?? []).map((identity) => (
            <Fragment key={identity.id}>
              <tr id={`ai-identity-row-${identity.id}`} className={expandedId === identity.id ? "row-highlight" : undefined}>
                <td>
                  <button type="button" onClick={() => setExpandedId(expandedId === identity.id ? null : identity.id)}>
                    {identity.name}
                  </button>
                </td>
                <td>{identity.active ? "yes" : "no"}</td>
                <td>
                  {identity.content_policy_locked ? (
                    <strong className="error">Locked</strong>
                  ) : (
                    "OK"
                  )}
                </td>
                {isAdmin ? (
                  <td>
                    <button
                      type="button"
                      onClick={() =>
                        updateMutation.mutate({
                          id: identity.id,
                          patch: { active: !identity.active },
                        })
                      }
                    >
                      {identity.active ? "Disable" : "Enable"}
                    </button>
                    {identity.content_policy_locked ? (
                      <button
                        type="button"
                        disabled={unlockMutation.isPending}
                        onClick={() => unlockMutation.mutate(identity.id)}
                      >
                        Clear lockout
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="button-danger"
                      disabled={deleteMutation.isPending}
                      onClick={() => {
                        const ok = window.confirm(
                          "Remove this AI identity? This will revoke all API keys and remove grant assignments.",
                        );
                        if (ok) {
                          deleteMutation.mutate(identity.id);
                        }
                      }}
                    >
                      Remove
                    </button>
                  </td>
                ) : null}
              </tr>
              {expandedId === identity.id ? (
                <tr key={`${identity.id}-panel`}>
                  <td colSpan={isAdmin ? 4 : 3}>
                    <IdentityPanel identityId={identity.id} isAdmin={isAdmin} />
                  </td>
                </tr>
              ) : null}
            </Fragment>
          ))}
        </tbody>
      </table>
    </section>
  );
}
