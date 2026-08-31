// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { apiClient } from "../api/client.js";
import { setCsrfToken } from "../csrf.js";
import { ErrorState, PageHeader } from "../components/Layout.js";
import { ValidationChecklist } from "../components/ValidationChecklist.js";
import { getApiErrorMessage } from "../utils/apiErrorMessage.js";
import {
  firstLoginValidationError,
  firstPasswordValidationError,
  isLoginValid,
  isPasswordValid,
  loginValidationRules,
  passwordValidationRules,
} from "../utils/authValidation.js";

export function BootstrapPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const loginRules = loginValidationRules(login);
  const passwordRules = passwordValidationRules(password);
  const canSubmit = isLoginValid(login) && isPasswordValid(password);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const loginError = firstLoginValidationError(login);
    if (loginError) {
      setError(loginError);
      return;
    }
    const passwordError = firstPasswordValidationError(password);
    if (passwordError) {
      setError(passwordError);
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const session = await apiClient.bootstrap(login, password);
      if (session.csrf_token) {
        setCsrfToken(session.csrf_token);
      }
      await queryClient.invalidateQueries({ queryKey: ["session"] });
      await queryClient.invalidateQueries({ queryKey: ["auth-status"] });
      navigate("/onboarding");
    } catch (err) {
      setError(getApiErrorMessage(err, "Bootstrap failed"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="auth-card">
      <PageHeader
        title="Initial setup"
        subtitle="Create the first administrator account. Available only when no operators exist."
      />
      <form onSubmit={onSubmit} className="stack">
        <label>
          Login
          <input
            value={login}
            onChange={(e) => setLogin(e.target.value)}
            required
            autoComplete="username"
          />
          <ValidationChecklist
            rules={loginRules}
            visible={login.length > 0}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="new-password"
          />
          <ValidationChecklist
            rules={passwordRules}
            visible={password.length > 0}
          />
        </label>
        {error ? <ErrorState message={error} /> : null}
        <button type="submit" disabled={submitting || !canSubmit}>
          {submitting ? "Creating…" : "Create admin"}
        </button>
      </form>
    </section>
  );
}
