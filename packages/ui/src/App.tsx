// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AppLayout, ErrorState, LoadingState } from "./components/Layout.js";
import { useAuthStatus } from "./hooks/useAuthStatus.js";
import { useSession } from "./hooks/useSession.js";
import { AiIdentitiesPage } from "./pages/AiIdentitiesPage.js";
import { AuditPage } from "./pages/AuditPage.js";
import { BackupRestorePage } from "./pages/BackupRestorePage.js";
import { BootstrapPage } from "./pages/BootstrapPage.js";
import { DashboardPage } from "./pages/DashboardPage.js";
import { LoginPage } from "./pages/LoginPage.js";
import { ActionQueuePage } from "./pages/ActionQueuePage.js";
import { PermissionRequestsPage } from "./pages/PermissionRequestsPage.js";
import { PermissionsPage } from "./pages/PermissionsPage.js";
import { MachinesPage } from "./pages/MachinesPage.js";
import { ProxiesPage } from "./pages/ProxiesPage.js";
import { OnboardingPage } from "./pages/OnboardingPage.js";
import { ProfilePage } from "./pages/ProfilePage.js";
import { SettingsPage } from "./pages/SettingsPage.js";
import { UsersPage } from "./pages/UsersPage.js";
function needsWebAuthn(
  session:
    | { authenticated?: boolean; onboarding_required?: boolean; auth_stage?: string }
    | undefined,
) {
  return Boolean(session?.authenticated && !session.onboarding_required && session.auth_stage !== "full");
}

function authStatusErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Cannot load auth status";
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { session, isLoading: sessionLoading } = useSession();
  const { status, isLoading: statusLoading, error: statusError } = useAuthStatus();

  if (statusLoading) {
    return <LoadingState />;
  }

  if (statusError || !status) {
    return <ErrorState message={authStatusErrorMessage(statusError)} />;
  }

  if (status.bootstrap_required) {
    return <Navigate to="/bootstrap" replace />;
  }

  if (sessionLoading) {
    return <LoadingState />;
  }

  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }

  if (session.onboarding_required) {
    return <Navigate to="/onboarding" replace />;
  }

  if (needsWebAuthn(session)) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function PublicOnly({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { session, isLoading: sessionLoading } = useSession();
  const { status, isLoading: statusLoading, error: statusError } = useAuthStatus();

  if (statusLoading) {
    return <LoadingState />;
  }

  if (statusError || !status) {
    return <ErrorState message={authStatusErrorMessage(statusError)} />;
  }

  if (status.bootstrap_required && location.pathname !== "/bootstrap") {
    return <Navigate to="/bootstrap" replace />;
  }

  if (!status.bootstrap_required && location.pathname === "/bootstrap") {
    return <Navigate to="/login" replace />;
  }

  if (sessionLoading) {
    return <LoadingState />;
  }

  if (session?.authenticated && !session.onboarding_required) {
    if (needsWebAuthn(session) && location.pathname === "/login") {
      return <>{children}</>;
    }
    if (needsWebAuthn(session)) {
      return <Navigate to="/login" replace />;
    }
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

function AuthEntryRedirect() {
  const { session, isLoading: sessionLoading } = useSession();
  const { status, isLoading: statusLoading, error: statusError } = useAuthStatus();

  if (statusLoading) {
    return <LoadingState />;
  }

  if (statusError || !status) {
    return <ErrorState message={authStatusErrorMessage(statusError)} />;
  }

  if (status.bootstrap_required) {
    return <Navigate to="/bootstrap" replace />;
  }

  if (sessionLoading) {
    return <LoadingState />;
  }

  if (session?.authenticated) {
    if (session.onboarding_required) {
      return <Navigate to="/onboarding" replace />;
    }
    if (needsWebAuthn(session)) {
      return <Navigate to="/login" replace />;
    }
    return <Navigate to="/dashboard" replace />;
  }

  return <Navigate to="/login" replace />;
}

function RequireOnboarding({ children }: { children: ReactNode }) {
  const { session, isLoading: sessionLoading } = useSession();
  const { status, isLoading: statusLoading } = useAuthStatus();

  if (statusLoading || sessionLoading) {
    return <LoadingState />;
  }

  if (status?.bootstrap_required) {
    return <Navigate to="/bootstrap" replace />;
  }

  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!session.onboarding_required) {
    if (needsWebAuthn(session)) {
      return <Navigate to="/login" replace />;
    }
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/bootstrap" element={<PublicOnly><BootstrapPage /></PublicOnly>} />
        <Route path="/login" element={<PublicOnly><LoginPage /></PublicOnly>} />
        <Route path="/webauthn" element={<Navigate to="/login" replace />} />
        <Route path="/onboarding" element={<RequireOnboarding><OnboardingPage /></RequireOnboarding>} />

        <Route
          element={
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          }
        >
          <Route index element={<AuthEntryRedirect />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/machines" element={<MachinesPage />} />
          <Route path="/machines/:machineId" element={<MachinesPage />} />
          <Route path="/proxies" element={<ProxiesPage />} />
          <Route path="/proxies/:proxyId" element={<ProxiesPage />} />
          <Route path="/action-queue" element={<ActionQueuePage />} />
          <Route path="/permission-requests" element={<PermissionRequestsPage />} />
          <Route path="/permissions" element={<PermissionsPage />} />
          <Route path="/ai-identities" element={<AiIdentitiesPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/backup" element={<BackupRestorePage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Route>

        <Route path="*" element={<AuthEntryRedirect />} />
      </Routes>
    </BrowserRouter>
  );
}
