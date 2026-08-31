// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { completeWebAuthnSignIn } from "../auth/webauthnSignIn.js";
import { apiClient } from "../api/client.js";
import { setCsrfToken } from "../csrf.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { useSession } from "../hooks/useSession.js";
import { getApiErrorMessage } from "../utils/apiErrorMessage.js";

type LoginStep = "password" | "webauthn";

function needsWebAuthnStep(session: {
  authenticated?: boolean;
  onboarding_required?: boolean;
  auth_stage?: string;
}) {
  return Boolean(session.authenticated && !session.onboarding_required && session.auth_stage !== "full");
}

export function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { session, isLoading: sessionLoading } = useSession();

  const [step, setStep] = useState<LoginStep>("password");
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (session && needsWebAuthnStep(session)) {
      setStep("webauthn");
    }
  }, [session]);

  async function finishSignIn() {
    await queryClient.invalidateQueries({ queryKey: ["session"] });
    await queryClient.invalidateQueries({ queryKey: ["auth-status"] });
    navigate("/dashboard", { replace: true });
  }

  async function runWebAuthnSignIn() {
    setSubmitting(true);
    setError(null);
    try {
      await completeWebAuthnSignIn();
      await finishSignIn();
    } catch (err) {
      setError(getApiErrorMessage(err, "Passkey verification failed"));
    } finally {
      setSubmitting(false);
    }
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const loginSession = await apiClient.login(login, password);
      if (loginSession.csrf_token) {
        setCsrfToken(loginSession.csrf_token);
      }

      if (loginSession.onboarding_required) {
        await queryClient.invalidateQueries({ queryKey: ["session"] });
        await queryClient.invalidateQueries({ queryKey: ["auth-status"] });
        navigate("/onboarding");
        return;
      }

      if (loginSession.auth_stage !== "full") {
        setStep("webauthn");
        await runWebAuthnSignIn();
        return;
      }

      await finishSignIn();
    } catch (err) {
      setError(getApiErrorMessage(err, "Login failed"));
    } finally {
      setSubmitting(false);
    }
  }

  if (sessionLoading) {
    return <LoadingState />;
  }

  if (step === "webauthn") {
    return (
      <section className="auth-card">
        <PageHeader
          title="Verify with passkey"
          subtitle="Use your security key or device authenticator to finish signing in."
        />
        <div className="stack">
          <p className="muted">
            {submitting
              ? "Waiting for your passkey…"
              : "Your browser should prompt for your passkey. If it does not, use the button below."}
          </p>
          {error ? <ErrorState message={error} /> : null}
          <button type="button" onClick={() => void runWebAuthnSignIn()} disabled={submitting}>
            {submitting ? "Verifying…" : "Use passkey"}
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="auth-card">
      <PageHeader title="Sign in" subtitle="Password first, then WebAuthn when onboarding is complete." />
      <form onSubmit={onSubmit} className="stack">
        <label>
          Login
          <input value={login} onChange={(e) => setLogin(e.target.value)} required autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </label>
        {error ? <ErrorState message={error} /> : null}
        <button type="submit" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </section>
  );
}
