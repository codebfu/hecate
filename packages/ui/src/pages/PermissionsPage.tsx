// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { Link, useSearchParams } from "react-router-dom";
import { ErrorState, PageHeader } from "../components/Layout.js";
import { useSession } from "../hooks/useSession.js";
import { FleetScopesTab } from "../components/fleet/FleetScopesTab.js";
import { CapabilityProfilesTab } from "../components/capability/CapabilityProfilesTab.js";
import { AccessGrantsTab } from "../components/grants/AccessGrantsTab.js";

type PermissionsTab = "fleet-scopes" | "capability-profiles" | "access-grants";

const TABS: { id: PermissionsTab; label: string }[] = [
  { id: "fleet-scopes", label: "Fleet Scopes" },
  { id: "capability-profiles", label: "Capability Profiles" },
  { id: "access-grants", label: "Access Grants" },
];

function parseTab(value: string | null): PermissionsTab {
  if (value === "capability-profiles" || value === "access-grants") {
    return value;
  }
  return "fleet-scopes";
}

export function PermissionsPage() {
  const { session } = useSession();
  const isAdmin = session?.role === "admin";
  const [searchParams] = useSearchParams();
  const tab = parseTab(searchParams.get("tab"));

  if (!isAdmin) {
    return <ErrorState message="Admin access required." />;
  }

  return (
    <section className="permissions-page">
      <PageHeader
        title="Permissions"
        subtitle="Manage reusable fleet scopes, capability profiles, and access grants."
      />

      <nav className="permissions-tab-bar" aria-label="Permissions sections">
        {TABS.map((entry) => (
          <Link
            key={entry.id}
            to={`/permissions?tab=${entry.id}`}
            className={tab === entry.id ? "permissions-tab permissions-tab--active" : "permissions-tab"}
          >
            {entry.label}
          </Link>
        ))}
      </nav>

      {tab === "fleet-scopes" ? <FleetScopesTab /> : null}
      {tab === "capability-profiles" ? <CapabilityProfilesTab /> : null}
      {tab === "access-grants" ? <AccessGrantsTab /> : null}
    </section>
  );
}
