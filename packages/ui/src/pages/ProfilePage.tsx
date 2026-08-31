// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiClient } from "../api/client.js";
import { ErrorState, PageHeader } from "../components/Layout.js";
import { ValidationChecklist } from "../components/ValidationChecklist.js";
import { useToast } from "../components/ToastProvider.js";
import { useSession } from "../hooks/useSession.js";
import { getApiErrorMessage } from "../utils/apiErrorMessage.js";
import {
  firstPasswordValidationError,
  isPasswordValid,
  passwordValidationRules,
} from "../utils/authValidation.js";

export function ProfilePage() {
  const { session } = useSession();
  const toast = useToast();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const passwordRules = passwordValidationRules(newPassword);
  const canSubmit = currentPassword.length > 0 && isPasswordValid(newPassword);

  const mutation = useMutation({
    mutationFn: () =>
      apiClient.changePassword(currentPassword || undefined, newPassword),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      toast.success("Password updated.");
      setError(null);
    },
    onError: (err) => {
      setError(getApiErrorMessage(err, "Password change failed"));
    },
  });

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const passwordError = firstPasswordValidationError(newPassword);
    if (passwordError) {
      setError(passwordError);
      return;
    }
    setError(null);
    mutation.mutate();
  }

  return (
    <section>
      <PageHeader title="Profile & Security" subtitle="Password and account details." />
      <dl className="details">
        <div>
          <dt>Login</dt>
          <dd>{session?.login ?? "—"}</dd>
        </div>
        <div>
          <dt>Role</dt>
          <dd>{session?.role ?? "—"}</dd>
        </div>
      </dl>

      <h2>Change password</h2>
      <form onSubmit={onSubmit} className="stack">
        <label>
          Current password
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        <label>
          New password
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            autoComplete="new-password"
          />
          <ValidationChecklist rules={passwordRules} visible={newPassword.length > 0} />
        </label>
        {error ? <ErrorState message={error} /> : null}
        <button type="submit" disabled={mutation.isPending || !canSubmit}>
          {mutation.isPending ? "Saving…" : "Change password"}
        </button>
      </form>
      <p className="muted">WebAuthn passkeys are registered during onboarding.</p>
    </section>
  );
}
