// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useQueryClient } from "@tanstack/react-query";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { apiClient } from "../api/client.js";
import { setCsrfToken } from "../csrf.js";
import { useSession } from "../hooks/useSession.js";

export function AppLayout() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { session } = useSession();
  const isAdmin = session?.role === "admin";
  const profileLabel =
    session?.login && session.role ? `${session.login} (${session.role})` : "Profile";

  async function onLogout() {
    try {
      await apiClient.logout();
    } finally {
      setCsrfToken(undefined);
      await queryClient.clear();
      navigate("/login");
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link to="/" className="brand">
          <img src="/favicon.svg" alt="" width={24} height={24} className="brand-icon" />
          Hecate
        </Link>
        <nav className="app-nav">
          <NavLink to="/dashboard" end>
            Dashboard
          </NavLink>
          <NavLink to="/machines">Machines</NavLink>
          <NavLink to="/proxies">Proxies</NavLink>
          <NavLink to="/action-queue" end>
            Action queue
          </NavLink>
          {isAdmin ? (
            <NavLink to="/permission-requests" end>
              Permission requests
            </NavLink>
          ) : null}
          {isAdmin ? (
            <NavLink to="/permissions" end>
              Permissions
            </NavLink>
          ) : null}
          <NavLink to="/ai-identities" end>
            AI Identities
          </NavLink>
          <NavLink to="/audit" end>
            Audit
          </NavLink>
          <NavLink to="/backup" end>
            Backup / Restore
          </NavLink>
          {isAdmin ? (
            <NavLink to="/settings" end>
              Settings
            </NavLink>
          ) : null}
          {isAdmin ? (
            <NavLink to="/users" end>
              Users
            </NavLink>
          ) : null}
          <NavLink to="/profile" end>
            {profileLabel}
          </NavLink>
          <button type="button" onClick={onLogout}>
            Sign out
          </button>
        </nav>
      </header>
      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
}

export function PageHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <header className="page-header">
      <h1>{title}</h1>
      {subtitle ? <p>{subtitle}</p> : null}
    </header>
  );
}

export function LoadingState() {
  return <p className="muted">Loading…</p>;
}

export function ErrorState({ message }: { message: string }) {
  return <p className="error">{message}</p>;
}
