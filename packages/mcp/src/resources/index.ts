// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { HecateApiClient } from "../client.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESOURCES_ROOT = path.resolve(__dirname, "../../resources");

export interface StaticResourceDefinition {
  uri: string;
  name: string;
  description: string;
  relativePath: string;
  mimeType: string;
}

export const STATIC_RESOURCES: StaticResourceDefinition[] = [
  {
    uri: "hecate://skill/overview",
    name: "Hecate Overview",
    description: "Overview of Hecate fleet management, pull-only agents, and AI identity role.",
    relativePath: "skills/overview.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/authz-model",
    name: "Authz Model",
    description: "Granular authorization: Fleet Scope, Capability Profile, Access Grant, Grant Assignment.",
    relativePath: "skills/authz-model.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/grant-discovery",
    name: "Grant Discovery",
    description: "Workflow to discover catalog grants and request new assignments.",
    relativePath: "skills/grant-discovery.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/async-workflow",
    name: "Async Command Workflow",
    description: "Recommended workflow: execute_command (async) then pull get_command.",
    relativePath: "skills/async-workflow.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/fleet-discovery",
    name: "Fleet Discovery",
    description: "How to choose a machine via list_machines and get_machine.",
    relativePath: "skills/fleet-discovery.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/shell-run-usage",
    name: "shell.run Usage",
    description: "How to build a valid shell.run call with explicit argv, cwd, and elevated flag.",
    relativePath: "skills/shell-run-usage.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/elevated-execution",
    name: "Elevated Execution",
    description: "How to run root/admin commands with elevated=true (OS-dependent sudo/admin).",
    relativePath: "skills/elevated-execution.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/system-reboot",
    name: "system.reboot",
    description: "Reboot a machine and wait for agent offline → online before treating the command as complete.",
    relativePath: "skills/system-reboot.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/file-commands",
    name: "File Commands",
    description: "Workflows for file.pull, file.push, remote.download, and local file/folder manipulation.",
    relativePath: "skills/file-commands.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/desktop-commands",
    name: "Desktop Commands",
    description: "Computer-use: screenshot, mouse/keyboard, clipboard, multi-monitor, and desktop sessions.",
    relativePath: "skills/desktop-commands.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/proxmox-console",
    name: "Proxmox VM Console",
    description: "Last-resort Proxmox VM console discovery, frame, input, and session workflow.",
    relativePath: "skills/proxmox-console.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/approval-flow",
    name: "Approval Flow",
    description: "What to do when a command is pending_approval or expired.",
    relativePath: "skills/approval-flow.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/permission-requests",
    name: "Permission Requests",
    description: "How to request permanent permission changes and review pending requests.",
    relativePath: "skills/permission-requests.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://skill/feature-repository",
    name: "Feature Repository Management",
    description: "Manage signed feature sources, catalogue installs, upgrades, and pins.",
    relativePath: "skills/feature-repository.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://rule/security",
    name: "Security Rule",
    description: "Deny-by-default, no permission bypass, no secrets in params.",
    relativePath: "rules/security.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://rule/authz-admin",
    name: "Authz Admin Rule",
    description: "Security rules for admin.authz.* assignment and entity mutations.",
    relativePath: "rules/authz-admin.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://rule/shell-run",
    name: "shell.run Rule",
    description: "Strict prohibitions: no shell metacharacters, explicit argv only.",
    relativePath: "rules/shell-run.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://rule/proxmox-console",
    name: "Proxmox Console Rule",
    description: "Prefer structured administration; restrict VM console use to display, boot, and recovery.",
    relativePath: "rules/proxmox-console.md",
    mimeType: "text/markdown",
  },
  {
    uri: "hecate://rule/async-default",
    name: "Async Default Rule",
    description: "Prefer async execution; use wait=true only when necessary with bounded timeout.",
    relativePath: "rules/async-default.md",
    mimeType: "text/markdown",
  },
];

export const DYNAMIC_PERMISSIONS_RESOURCE = {
  uri: "hecate://context/permissions",
  name: "Current AI Permissions",
  description:
    "Live identity, resolved grant assignments, effective summary, capabilities, and admin command allowlist.",
  mimeType: "application/json",
};

export const DYNAMIC_AUTHZ_CATALOG_RESOURCE = {
  uri: "hecate://context/authz-catalog",
  name: "Self-Service Authz Catalog",
  description:
    "S12-filtered catalog of assignable fleet scopes, capability profiles, and access grants for the authenticated identity.",
  mimeType: "application/json",
};

export const DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE = {
  uri: "hecate://context/effective-rights",
  name: "Effective Rights (Self)",
  description: "Computed effective rights matrix for the authenticated identity only.",
  mimeType: "application/json",
};

export function registerResources(server: McpServer, client: HecateApiClient): void {
  for (const resource of STATIC_RESOURCES) {
    server.registerResource(
      resource.name,
      resource.uri,
      {
        description: resource.description,
        mimeType: resource.mimeType,
      },
      async (uri) => {
        const text = await readStaticResource(resource.relativePath);
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: resource.mimeType,
              text,
            },
          ],
        };
      },
    );
  }

  server.registerResource(
    DYNAMIC_PERMISSIONS_RESOURCE.name,
    DYNAMIC_PERMISSIONS_RESOURCE.uri,
    {
      description: DYNAMIC_PERMISSIONS_RESOURCE.description,
      mimeType: DYNAMIC_PERMISSIONS_RESOURCE.mimeType,
    },
    async (uri) => {
      const context = await client.getAiContext();
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: DYNAMIC_PERMISSIONS_RESOURCE.mimeType,
            text: JSON.stringify(context, null, 2),
          },
        ],
      };
    },
  );

  server.registerResource(
    DYNAMIC_AUTHZ_CATALOG_RESOURCE.name,
    DYNAMIC_AUTHZ_CATALOG_RESOURCE.uri,
    {
      description: DYNAMIC_AUTHZ_CATALOG_RESOURCE.description,
      mimeType: DYNAMIC_AUTHZ_CATALOG_RESOURCE.mimeType,
    },
    async (uri) => {
      const catalog = await client.getSelfServiceAuthzCatalog();
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: DYNAMIC_AUTHZ_CATALOG_RESOURCE.mimeType,
            text: JSON.stringify(catalog, null, 2),
          },
        ],
      };
    },
  );

  server.registerResource(
    DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.name,
    DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.uri,
    {
      description: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.description,
      mimeType: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.mimeType,
    },
    async (uri) => {
      const report = await client.getSelfEffectiveRights();
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.mimeType,
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    },
  );
}

export function listAllResourceDefinitions() {
  return [
    ...STATIC_RESOURCES.map(({ uri, name, description, mimeType }) => ({
      uri,
      name,
      description,
      mimeType,
    })),
    {
      uri: DYNAMIC_PERMISSIONS_RESOURCE.uri,
      name: DYNAMIC_PERMISSIONS_RESOURCE.name,
      description: DYNAMIC_PERMISSIONS_RESOURCE.description,
      mimeType: DYNAMIC_PERMISSIONS_RESOURCE.mimeType,
    },
    {
      uri: DYNAMIC_AUTHZ_CATALOG_RESOURCE.uri,
      name: DYNAMIC_AUTHZ_CATALOG_RESOURCE.name,
      description: DYNAMIC_AUTHZ_CATALOG_RESOURCE.description,
      mimeType: DYNAMIC_AUTHZ_CATALOG_RESOURCE.mimeType,
    },
    {
      uri: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.uri,
      name: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.name,
      description: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.description,
      mimeType: DYNAMIC_EFFECTIVE_RIGHTS_RESOURCE.mimeType,
    },
  ];
}

export async function readStaticResource(relativePath: string): Promise<string> {
  const fullPath = path.join(RESOURCES_ROOT, relativePath);
  return readFile(fullPath, "utf8");
}

export function resolveResourcePath(relativePath: string): string {
  return path.join(RESOURCES_ROOT, relativePath);
}
