// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate, useSearchParams } from "react-router-dom";
import { apiClient } from "../api/client.js";
import { LIST_REFETCH_MS } from "../queries/refetch.js";
import { ErrorState, LoadingState, PageHeader } from "../components/Layout.js";
import { ValidationChecklist } from "../components/ValidationChecklist.js";
import { useToast } from "../components/ToastProvider.js";
import { useSession } from "../hooks/useSession.js";
import { getApiErrorMessage } from "../utils/apiErrorMessage.js";
import {
  firstLoginValidationError,
  firstPasswordValidationError,
  isLoginValid,
  isPasswordValid,
  loginValidationRules,
  passwordValidationRules,
} from "../utils/authValidation.js";

export function UsersPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { session, isLoading: sessionLoading } = useSession();
  const [searchParams] = useSearchParams();
  const highlightedRowRef = useRef<HTMLTableRowElement | null>(null);
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"admin" | "operator">("operator");
  const [formError, setFormError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["operators"],
    queryFn: () => apiClient.listOperators(),
    enabled: session?.role === "admin",
    refetchInterval: LIST_REFETCH_MS,
  });

  const createMutation = useMutation({
    mutationFn: () => apiClient.createOperator(login, password, role),
    onSuccess: async () => {
      setLogin("");
      setPassword("");
      setRole("operator");
      setFormError(null);
      toast.success("User created.");
      await queryClient.invalidateQueries({ queryKey: ["operators"] });
    },
    onError: (err) => {
      setFormError(getApiErrorMessage(err, "Failed to create user."));
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: { role?: "admin" | "operator"; active?: boolean };
    }) => apiClient.updateOperator(id, patch),
    onSuccess: async () => {
      toast.success("User updated.");
      await queryClient.invalidateQueries({ queryKey: ["operators"] });
    },
    onError: (err) => {
      toast.error(getApiErrorMessage(err, "Failed to update user."));
    },
  });

  const selectedOperatorId = searchParams.get("operator");
  const selectedLogin = searchParams.get("login");
  const operatorCount = query.data?.length ?? 0;

  useEffect(() => {
    highlightedRowRef.current?.scrollIntoView({ block: "center" });
  }, [selectedOperatorId, selectedLogin, operatorCount]);

  if (sessionLoading) {
    return <LoadingState />;
  }

  if (session?.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }

  if (query.isLoading) {
    return <LoadingState />;
  }

  if (query.error) {
    return <ErrorState message="Failed to load operators." />;
  }

  const operators = query.data ?? [];
  const busy = createMutation.isPending || updateMutation.isPending;
  const loginRules = loginValidationRules(login);
  const passwordRules = passwordValidationRules(password);
  const canCreate = isLoginValid(login) && isPasswordValid(password);

  function isHighlighted(operator: { id: string; login: string }) {
    if (selectedOperatorId) {
      return operator.id === selectedOperatorId;
    }
    if (selectedLogin) {
      return operator.login === selectedLogin;
    }
    return false;
  }

  function onCreateSubmit(event: FormEvent) {
    event.preventDefault();
    const loginError = firstLoginValidationError(login);
    if (loginError) {
      setFormError(loginError);
      return;
    }
    const passwordError = firstPasswordValidationError(password);
    if (passwordError) {
      setFormError(passwordError);
      return;
    }
    setFormError(null);
    createMutation.mutate();
  }

  function onRoleChange(operatorId: string, nextRole: "admin" | "operator", currentRole: string) {
    if (nextRole === currentRole) {
      return;
    }
    setFormError(null);
    updateMutation.mutate({ id: operatorId, patch: { role: nextRole } });
  }

  function onDelete(operatorId: string, operatorLogin: string) {
    if (!window.confirm(`Disable user "${operatorLogin}"? They will no longer be able to sign in.`)) {
      return;
    }
    updateMutation.mutate({ id: operatorId, patch: { active: false } });
  }

  return (
    <section>
      <PageHeader title="Users" subtitle="Admin-only operator account management." />

      <form onSubmit={onCreateSubmit} className="stack user-form">
        <h2 className="section-title">Add user</h2>
        <div className="user-form-grid">
          <label>
            Login
            <input
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              required
              autoComplete="off"
              disabled={busy}
            />
            <ValidationChecklist rules={loginRules} visible={login.length > 0} />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              disabled={busy}
            />
            <ValidationChecklist rules={passwordRules} visible={password.length > 0} />
          </label>
          <label>
            Role
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as "admin" | "operator")}
              disabled={busy}
            >
              <option value="operator">operator</option>
              <option value="admin">admin</option>
            </select>
          </label>
        </div>
        {formError ? <ErrorState message={formError} /> : null}
        <div className="actions">
          <button type="submit" disabled={busy || !canCreate}>
            {createMutation.isPending ? "Creating…" : "Add user"}
          </button>
        </div>
      </form>

      <table className="data-table">
        <thead>
          <tr>
            <th>Login</th>
            <th>Role</th>
            <th>Active</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {operators.map((operator) => {
            const isSelf = operator.login === session.login;
            const canManage = operator.active && !isSelf;

            return (
              <tr
                key={operator.id}
                ref={isHighlighted(operator) ? highlightedRowRef : undefined}
                className={isHighlighted(operator) ? "row-highlight" : undefined}
              >
                <td>
                  {operator.login}
                  {isSelf ? <span className="muted"> (you)</span> : null}
                </td>
                <td>
                  {canManage ? (
                    <select
                      value={operator.role}
                      onChange={(e) =>
                        onRoleChange(operator.id, e.target.value as "admin" | "operator", operator.role)
                      }
                      disabled={busy}
                    >
                      <option value="operator">operator</option>
                      <option value="admin">admin</option>
                    </select>
                  ) : (
                    operator.role
                  )}
                </td>
                <td>{operator.active ? "yes" : "no"}</td>
                <td>
                  {canManage ? (
                    <button
                      type="button"
                      className="button-danger"
                      onClick={() => onDelete(operator.id, operator.login)}
                      disabled={busy}
                    >
                      Delete
                    </button>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
