// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate } from "react-router-dom";
import { ApiError, apiClient, type UpdateAdminSettingsBody } from "../api/client.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { FeatureRepositorySettings } from "../components/FeatureRepositorySettings.js";
import { useToast } from "../components/ToastProvider.js";
import { useSession } from "../hooks/useSession.js";

function formatApiError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    const body = error.body;
    if (body && typeof body === "object" && "message" in body && typeof body.message === "string") {
      return body.message;
    }
  }
  return error instanceof Error ? error.message : fallback;
}

export function SettingsPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session, isLoading: sessionLoading } = useSession();

  const [releasePublicKey, setReleasePublicKey] = useState("");
  const [releaseKeyContinuitySig, setReleaseKeyContinuitySig] = useState("");
  const [enrollmentAutoApprove, setEnrollmentAutoApprove] = useState(false);
  const [proxyEnrollmentAutoApprove, setProxyEnrollmentAutoApprove] = useState(false);
  const [enrollmentTokenTtlMinutes, setEnrollmentTokenTtlMinutes] = useState("60");
  const [proxyEnrollmentTokenTtlMinutes, setProxyEnrollmentTokenTtlMinutes] = useState("60");
  const [authzTagsAuto, setAuthzTagsAuto] = useState(true);
  const [authzTagsOperator, setAuthzTagsOperator] = useState(true);
  const [authzTagsAgentCustom, setAuthzTagsAgentCustom] = useState(false);
  const [contentPolicyLockoutSecs, setContentPolicyLockoutSecs] = useState("3600");
  const [keyRotationOverlapSecs, setKeyRotationOverlapSecs] = useState("604800");
  const [keyRotationIntervalSecs, setKeyRotationIntervalSecs] = useState("0");
  const [formError, setFormError] = useState<string | null>(null);

  const settingsQuery = useQuery({
    queryKey: ["admin-settings"],
    queryFn: () => apiClient.getAdminSettings(),
    enabled: session?.role === "admin",
  });

  useEffect(() => {
    if (!settingsQuery.data) {
      return;
    }
    const settings = settingsQuery.data;
    setReleasePublicKey(settings.release_signing_public_key_b64);
    setReleaseKeyContinuitySig(settings.release_key_continuity_sig_b64 ?? "");
    setEnrollmentAutoApprove(settings.enrollment_auto_approve);
    setProxyEnrollmentAutoApprove(settings.proxy_enrollment_auto_approve);
    setEnrollmentTokenTtlMinutes(String(settings.enrollment_token_ttl_minutes));
    setProxyEnrollmentTokenTtlMinutes(String(settings.proxy_enrollment_token_ttl_minutes));
    setAuthzTagsAuto(settings.authz_tags_include_auto);
    setAuthzTagsOperator(settings.authz_tags_include_operator);
    setAuthzTagsAgentCustom(settings.authz_tags_include_agent_custom);
    setContentPolicyLockoutSecs(String(settings.content_policy_lockout_seconds));
    setKeyRotationOverlapSecs(String(settings.key_rotation_overlap_secs));
    setKeyRotationIntervalSecs(String(settings.key_rotation_interval_secs));
  }, [settingsQuery.data]);

  const saveMutation = useMutation({
    mutationFn: (body: UpdateAdminSettingsBody) => apiClient.updateAdminSettings(body),
    onSuccess: async (settings) => {
      setFormError(null);
      toast.success("Settings saved.");
      await queryClient.invalidateQueries({ queryKey: ["admin-settings"] });
      await queryClient.invalidateQueries({ queryKey: ["enrollment-settings"] });
      setEnrollmentAutoApprove(settings.enrollment_auto_approve);
      setProxyEnrollmentAutoApprove(settings.proxy_enrollment_auto_approve);
      setEnrollmentTokenTtlMinutes(String(settings.enrollment_token_ttl_minutes));
      setProxyEnrollmentTokenTtlMinutes(String(settings.proxy_enrollment_token_ttl_minutes));
    },
    onError: (error) => {
      setFormError(formatApiError(error, "Failed to save settings."));
    },
  });

  const rotateTaskMutation = useMutation({
    mutationFn: () => apiClient.rotateTaskSigning({}),
    onSuccess: async (result) => {
      toast.success(`Task signing rotated for ${result.agents} agent(s).`);
      await queryClient.invalidateQueries({ queryKey: ["admin-settings"] });
    },
    onError: (error) => {
      toast.error(formatApiError(error, "Failed to rotate task signing keys."));
    },
  });

  const rotateCredentialMutation = useMutation({
    mutationFn: () => apiClient.requestCredentialRotation({}),
    onSuccess: async (result) => {
      toast.success(`Identity rotation requested for ${result.agents} agent(s).`);
      await queryClient.invalidateQueries({ queryKey: ["admin-settings"] });
    },
    onError: (error) => {
      toast.error(formatApiError(error, "Failed to request credential rotation."));
    },
  });

  if (sessionLoading) {
    return <LoadingState />;
  }

  if (session?.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }

  if (settingsQuery.isLoading) {
    return <LoadingState />;
  }

  if (settingsQuery.error) {
    return <ErrorState message="Failed to load settings." />;
  }

  const settings = settingsQuery.data;
  const busy =
    saveMutation.isPending ||
    rotateTaskMutation.isPending ||
    rotateCredentialMutation.isPending;

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);

    const body: UpdateAdminSettingsBody = {
      release_signing_public_key_b64: releasePublicKey.trim(),
      release_key_continuity_sig_b64: releaseKeyContinuitySig.trim() || undefined,
      enrollment_auto_approve: enrollmentAutoApprove,
      proxy_enrollment_auto_approve: proxyEnrollmentAutoApprove,
      enrollment_token_ttl_minutes: Number(enrollmentTokenTtlMinutes),
      proxy_enrollment_token_ttl_minutes: Number(proxyEnrollmentTokenTtlMinutes),
      authz_tags_include_auto: authzTagsAuto,
      authz_tags_include_operator: authzTagsOperator,
      authz_tags_include_agent_custom: authzTagsAgentCustom,
      content_policy_lockout_seconds: Number(contentPolicyLockoutSecs),
      key_rotation_overlap_secs: Number(keyRotationOverlapSecs),
      key_rotation_interval_secs: Number(keyRotationIntervalSecs),
    };

    saveMutation.mutate(body);
  }

  return (
    <section>
      <PageHeader
        title="Settings"
        subtitle="Integration tokens and server configuration stored in the database (included in backup)."
      />

      <FeatureRepositorySettings />

      <form className="card stack" onSubmit={onSubmit}>
        <h2>Release signing</h2>
        <p className="muted">
          Public key used to verify feature-repo and agent package signatures. Saving a different key
          starts a dual-key grace period for rotation.
        </p>

        <label>
          Release signing public key (base64)
          <textarea
            rows={3}
            value={releasePublicKey}
            disabled={busy}
            placeholder="Ed25519 public key used to verify signed release artifacts"
            onChange={(event) => setReleasePublicKey(event.target.value)}
          />
        </label>
        <label>
          Release key continuity signature (base64)
          <textarea
            rows={2}
            value={releaseKeyContinuitySig}
            disabled={busy}
            placeholder="Required when rotating: Ed25519 sig by the previous private key over continuity_v1\\nold\\nnew"
            onChange={(event) => setReleaseKeyContinuitySig(event.target.value)}
          />
        </label>
        <p className="muted">
          Produce offline with the previous release private key. Empty when setting the first key or
          leaving the current key unchanged.
        </p>
        {settings?.release_signing_public_key_previous_b64 ? (
          <p className="muted">
            Previous release key active until{" "}
            {settings.release_signing_key_overlap_until ?? "unknown"}.
          </p>
        ) : null}

        <h2>Key rotation</h2>
        <p className="muted">
          Dual-key overlap for identity, task signing, and release keys. Cron interval 0 disables
          scheduled rotation (admin buttons still work).
        </p>

        <label>
          Overlap window (seconds)
          <input
            type="number"
            min={60}
            step={60}
            value={keyRotationOverlapSecs}
            disabled={busy}
            onChange={(event) => setKeyRotationOverlapSecs(event.target.value)}
          />
        </label>

        <label>
          Scheduled rotation interval (seconds)
          <input
            type="number"
            min={0}
            step={60}
            value={keyRotationIntervalSecs}
            disabled={busy}
            onChange={(event) => setKeyRotationIntervalSecs(event.target.value)}
          />
        </label>
        <p className="muted">
          Last task-signing rotation: {settings?.task_signing_last_rotated_at ?? "never"}. Last
          identity rotation request: {settings?.credential_rotation_last_requested_at ?? "never"}.
        </p>

        <div className="actions">
          <button
            type="button"
            disabled={busy}
            onClick={() => rotateTaskMutation.mutate()}
          >
            {rotateTaskMutation.isPending ? "Rotating…" : "Rotate task signing (all)"}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => rotateCredentialMutation.mutate()}
          >
            {rotateCredentialMutation.isPending
              ? "Requesting…"
              : "Request agent identity rotation (all)"}
          </button>
        </div>

        <h2>Enrollment</h2>
        <label>
          <input
            type="checkbox"
            checked={enrollmentAutoApprove}
            disabled={busy}
            onChange={(event) => setEnrollmentAutoApprove(event.target.checked)}
          />
          Auto-approve new agents
        </label>
        <p className="muted">
          When enabled, agents enrolled with a valid token are activated immediately without manual
          approval.
        </p>
        <label>
          Agent enrollment token TTL (minutes)
          <input
            type="number"
            min={60}
            max={43200}
            step={1}
            value={enrollmentTokenTtlMinutes}
            disabled={busy}
            onChange={(event) => setEnrollmentTokenTtlMinutes(event.target.value)}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={proxyEnrollmentAutoApprove}
            disabled={busy}
            onChange={(event) => setProxyEnrollmentAutoApprove(event.target.checked)}
          />
          Auto-approve new proxies
        </label>
        <p className="muted">
          When enabled, Propylaea proxies enrolled with a valid token are activated immediately.
        </p>
        <label>
          Proxy enrollment token TTL (minutes)
          <input
            type="number"
            min={60}
            max={43200}
            step={1}
            value={proxyEnrollmentTokenTtlMinutes}
            disabled={busy}
            onChange={(event) => setProxyEnrollmentTokenTtlMinutes(event.target.value)}
          />
        </label>
        <p className="muted">
          One-time enrollment tokens expire after this duration (60 minutes to 30 days). Applies to
          newly created tokens only.
        </p>

        <h2>AI machine authorization tags</h2>
        <p className="muted">
          Choose which tag sources participate in AI machine_tags filters. Safe defaults: auto and
          operator on; agent custom off.
        </p>
        <label>
          <input
            type="checkbox"
            checked={authzTagsAuto}
            disabled={busy}
            onChange={(event) => setAuthzTagsAuto(event.target.checked)}
          />
          Include automatic agent tags (reserved namespaces: os, arch, distro, virt, init, gui,
          display)
        </label>
        <label>
          <input
            type="checkbox"
            checked={authzTagsOperator}
            disabled={busy}
            onChange={(event) => setAuthzTagsOperator(event.target.checked)}
          />
          Include operator tags
        </label>
        <label>
          <input
            type="checkbox"
            checked={authzTagsAgentCustom}
            disabled={busy}
            onChange={(event) => setAuthzTagsAgentCustom(event.target.checked)}
          />
          Include agent custom tags (non-reserved namespaces reported by the agent)
        </label>

        <h2>Content policy lockout</h2>
        <label>
          Unlock timer (seconds)
          <input
            type="number"
            min={60}
            value={contentPolicyLockoutSecs}
            disabled={busy}
            onChange={(event) => setContentPolicyLockoutSecs(event.target.value)}
          />
        </label>
        <p className="muted">
          After a second illicit script/payload attempt, the AI identity is locked for this duration.
          The AI never sees the timer value.
        </p>

        {formError ? <p className="error">{formError}</p> : null}

        <div className="actions">
          <button type="submit" disabled={busy}>
            {busy && saveMutation.isPending ? "Saving…" : "Save settings"}
          </button>
        </div>
      </form>
    </section>
  );
}
