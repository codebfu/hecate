// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { startRegistration } from "@simplewebauthn/browser";
import { Navigate, useNavigate } from "react-router-dom";
import { apiClient, normalizeRegistrationOptions } from "../api/client.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { ValidationChecklist } from "../components/ValidationChecklist.js";
import { useSession } from "../hooks/useSession.js";
import { getApiErrorMessage } from "../utils/apiErrorMessage.js";
import {
  firstPasswordValidationError,
  isPasswordValid,
  passwordValidationRules,
} from "../utils/authValidation.js";

export function OnboardingPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { session, isLoading } = useSession();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passkeyName, setPasskeyName] = useState("Primary passkey");
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);
  const [passwordUpdated, setPasswordUpdated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (isLoading) {
    return <LoadingState />;
  }

  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!session.onboarding_required) {
    return <Navigate to="/dashboard" replace />;
  }

  const needsPasswordChange = Boolean(session.must_change_password) && !passwordUpdated;
  const passwordRules = passwordValidationRules(newPassword);
  const canUpdatePassword =
    currentPassword.length > 0 && isPasswordValid(newPassword);

  async function onPasswordSubmit(event: FormEvent) {
    event.preventDefault();
    const passwordError = firstPasswordValidationError(newPassword);
    if (passwordError) {
      setError(passwordError);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await apiClient.onboardingPassword(currentPassword, newPassword);
      setPasswordUpdated(true);
      await queryClient.invalidateQueries({ queryKey: ["session"] });
    } catch (err) {
      setError(getApiErrorMessage(err, "Password update failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function onRegisterPasskey() {
    setSubmitting(true);
    setError(null);
    try {
      const options = normalizeRegistrationOptions(await apiClient.webauthnRegisterOptions());
      const credential = await startRegistration({ optionsJSON: options });
      await apiClient.webauthnRegisterVerify(
        credential as unknown as Record<string, unknown>,
        passkeyName.trim() || undefined,
      );
      setPasskeyRegistered(true);
    } catch (err) {
      setError(getApiErrorMessage(err, "Passkey registration failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function onComplete() {
    setSubmitting(true);
    setError(null);
    try {
      await apiClient.completeOnboarding();
      await queryClient.invalidateQueries({ queryKey: ["session"] });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(getApiErrorMessage(err, "Could not complete onboarding"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="auth-card onboarding-card">
      <PageHeader
        title="Finish setup"
        subtitle="Register a passkey for sign-in, then enter the console."
      />

      {needsPasswordChange ? (
        <form onSubmit={onPasswordSubmit} className="stack onboarding-step">
          <h2>Step 1 — Set a new password</h2>
          <label>
            Current password
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
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
          <button type="submit" disabled={submitting || !canUpdatePassword}>
            {submitting ? "Saving…" : "Update password"}
          </button>
        </form>
      ) : null}

      <div className={`stack onboarding-step${needsPasswordChange ? "" : " onboarding-step-first"}`}>
        <h2>{needsPasswordChange ? "Step 2" : "Step 1"} — Register a passkey</h2>
        <p className="muted">
          Use your device biometrics, security key, or platform authenticator.
        </p>
        <label>
          Passkey label
          <input
            value={passkeyName}
            onChange={(e) => setPasskeyName(e.target.value)}
            disabled={passkeyRegistered || submitting}
          />
        </label>
        <button type="button" onClick={onRegisterPasskey} disabled={submitting || passkeyRegistered}>
          {passkeyRegistered ? "Passkey registered" : submitting ? "Waiting for device…" : "Register passkey"}
        </button>
      </div>

      <div className="stack onboarding-step">
        <h2>{needsPasswordChange ? "Step 3" : "Step 2"} — Complete setup</h2>
        <button type="button" onClick={onComplete} disabled={submitting || !passkeyRegistered}>
          {submitting ? "Finishing…" : "Enter Hecate"}
        </button>
      </div>

      {error ? <ErrorState message={error} /> : null}
    </section>
  );
}
