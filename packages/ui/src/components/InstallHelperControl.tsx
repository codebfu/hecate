// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useState } from "react";
import type { AgentUpdateStatus, MachineSummary } from "../api/client.js";

export function helperComponentLabel(component: string): string {
  if (component === "desktop") {
    return "desktop helper";
  }
  if (component === "proxmox") {
    return "proxmox helper";
  }
  return component;
}

export function helperComponentShortLabel(component: string): string {
  if (component === "desktop") {
    return "desktop";
  }
  if (component === "proxmox") {
    return "proxmox";
  }
  return component;
}

export type PresentHelper = {
  component: string;
  shortLabel: string;
  tooltip: string;
};

function helperTooltip(
  component: string,
  version: string | null | undefined,
  status: AgentUpdateStatus | undefined,
  latest: string | null | undefined,
  isAdmin: boolean,
): string {
  const label = helperComponentLabel(component);
  if (status === "update_pending" && !version?.trim()) {
    return `${label} · installing…`;
  }
  const current = version?.trim() || "unknown";
  if (
    isAdmin &&
    latest &&
    (status === "outdated" || status === "update_pending" || status === "blocked_busy")
  ) {
    return `${label} ${current} → ${latest}`;
  }
  return `${label} ${current}`;
}

export function presentHelpers(machine: MachineSummary, isAdmin: boolean): PresentHelper[] {
  const items: PresentHelper[] = [];
  const desktopPendingInstall =
    machine.desktop_update_status === "update_pending" && !machine.desktop_version?.trim();
  if (desktopPendingInstall || machine.desktop_version?.trim()) {
    items.push({
      component: "desktop",
      shortLabel: helperComponentShortLabel("desktop"),
      tooltip: helperTooltip(
        "desktop",
        machine.desktop_version,
        machine.desktop_update_status,
        machine.latest_desktop_version,
        isAdmin,
      ),
    });
  }
  const proxmoxPendingInstall =
    machine.proxmox_update_status === "update_pending" && !machine.proxmox_version?.trim();
  if (proxmoxPendingInstall || machine.proxmox_version?.trim()) {
    items.push({
      component: "proxmox",
      shortLabel: helperComponentShortLabel("proxmox"),
      tooltip: helperTooltip(
        "proxmox",
        machine.proxmox_version,
        machine.proxmox_update_status,
        machine.latest_proxmox_version,
        isAdmin,
      ),
    });
  }
  return items;
}

export function HelpersSummary({
  machine,
  isAdmin,
}: {
  machine: MachineSummary;
  isAdmin: boolean;
}) {
  const items = presentHelpers(machine, isAdmin);
  if (items.length === 0) {
    return <span className="muted">—</span>;
  }
  return (
    <span className="helper-list">
      {items.map((item, index) => (
        <span key={item.component}>
          {index > 0 ? ", " : null}
          <span className="helper-list-item" title={item.tooltip}>
            {item.shortLabel}
          </span>
        </span>
      ))}
    </span>
  );
}

export function InstallHelperControl({
  machine,
  disabled,
  disabledTitle,
  pending,
  onInstall,
  showEmptyMessage = false,
}: {
  machine: MachineSummary;
  disabled: boolean;
  disabledTitle?: string;
  pending: boolean;
  onInstall: (machineId: string, component: string) => void;
  showEmptyMessage?: boolean;
}) {
  const helpers = machine.installable_helpers ?? [];
  const [component, setComponent] = useState(helpers[0]?.component ?? "");

  useEffect(() => {
    const next = machine.installable_helpers ?? [];
    if (next.length === 0) {
      setComponent("");
      return;
    }
    setComponent((current) =>
      next.some((helper) => helper.component === current) ? current : next[0]!.component,
    );
  }, [machine.installable_helpers]);

  if (helpers.length === 0) {
    if (!showEmptyMessage) {
      return null;
    }
    return <span className="muted">No helper available for this OS/arch</span>;
  }

  return (
    <div className="install-helper-control">
      <select
        aria-label="Helper to install"
        value={component}
        disabled={disabled || pending}
        title={disabledTitle}
        onChange={(event) => setComponent(event.target.value)}
      >
        {helpers.map((helper) => (
          <option key={helper.component} value={helper.component}>
            {helperComponentLabel(helper.component)} v{helper.version}
          </option>
        ))}
      </select>
      <button
        type="button"
        disabled={disabled || pending || !component}
        title={disabledTitle}
        onClick={() => onInstall(machine.id, component)}
      >
        Install
      </button>
    </div>
  );
}
