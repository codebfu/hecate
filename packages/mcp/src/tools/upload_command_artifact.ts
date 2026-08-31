// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HecateApiClient } from "../client.js";
import { findToolSpec } from "./specs.js";

export const uploadCommandArtifactInputSchema = z.object({
  content_base64: z.string().min(1),
  sha256: z.string().length(64).optional(),
  filename: z.string().min(1).default("upload.bin"),
});

export function registerUploadCommandArtifactTool(server: McpServer, client: HecateApiClient) {
  const spec = findToolSpec("upload_command_artifact")!;

  server.registerTool(
    spec.name,
    {
      description: `Upload a file to the Hecate server before enqueueing file.push or desktop.clipboard.set (image).

Workflow (file.push):
1. upload_command_artifact → receive artifact_id and sha256
2. execute_command with command_name=file.push and params { dest_path, artifact_id, sha256, mode? }

Workflow (clipboard image):
1. upload_command_artifact → receive artifact_id and sha256
2. execute_command with command_name=desktop.clipboard.set and params { artifact_id, sha256, format: "image/png" }

Files are staged on the server; the agent pulls them on the next dispatch.`,
      inputSchema: uploadCommandArtifactInputSchema,
      annotations: spec.annotations,
    },
    async ({ content_base64, sha256, filename }) => {
      const content = Buffer.from(content_base64, "base64");
      const stored = await client.uploadCommandArtifact(content, filename, sha256);
      return {
        content: [{ type: "text", text: JSON.stringify(stored, null, 2) }],
      };
    },
  );

  return spec;
}
