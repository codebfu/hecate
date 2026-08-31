// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it, vi } from "vitest";
import { HecateApiClient } from "./client.js";

describe("HecateApiClient", () => {
  it("sends X-Internal-Token and X-AI-API-Key", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ machines: [] }),
    );

    const client = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "internal-secret",
      apiKey: "oak_test_key",
      fetchImpl,
    });

    await client.listMachines();

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/internal/machines");
    expect(init.method).toBe("GET");
    expect(init.headers).toMatchObject({
      "X-AI-API-Key": "oak_test_key",
      "X-Internal-Token": "internal-secret",
    });
  });

  it("builds wait query for getCommand", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        command_id: "00000000-0000-4000-8000-000000000001",
        machine_id: "00000000-0000-4000-8000-000000000002",
        command_name: "system.info",
        status: "completed",
      }),
    );

    const client = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "token",
      apiKey: "key",
      fetchImpl,
    });

    await client.getCommand("00000000-0000-4000-8000-000000000001", true, 60);

    const [url] = fetchImpl.mock.calls[0] as [string];
    expect(url).toContain("wait=1");
    expect(url).toContain("wait_timeout_secs=60");
  });

  it("parses listCommands wrapped and raw array responses", async () => {
    const wrapped = vi.fn(async () =>
      Response.json({
        commands: [
          {
            command_id: "00000000-0000-4000-8000-000000000001",
            machine_id: "00000000-0000-4000-8000-000000000002",
            command_name: "system.info",
            status: "completed",
            result: null,
          },
        ],
      }),
    );
    const wrappedClient = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "token",
      apiKey: "key",
      fetchImpl: wrapped,
    });
    await expect(wrappedClient.listCommands({ limit: 10 })).resolves.toHaveLength(1);

    const raw = vi.fn(async () =>
      Response.json([
        {
          command_id: "00000000-0000-4000-8000-000000000001",
          machine_id: "00000000-0000-4000-8000-000000000002",
          command_name: "system.info",
          status: "queued",
          result: null,
        },
      ]),
    );
    const rawClient = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "token",
      apiKey: "key",
      fetchImpl: raw,
    });
    await expect(rawClient.listCommands()).resolves.toHaveLength(1);
  });

  it("includes API error message in HecateApiError", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ error: "bad_request", message: "artifact not found or already linked" }, { status: 400 }),
    );
    const client = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "token",
      apiKey: "key",
      fetchImpl,
    });

    await expect(
      client.executeCommand({
        machine_id: "00000000-0000-4000-8000-000000000002",
        command_name: "file.push",
        params: {},
      }),
    ).rejects.toThrow(/artifact not found or already linked/);
  });

  it("uploads command artifacts with binary body", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        artifact_id: "00000000-0000-4000-8000-000000000010",
        sha256: "abc",
        size_bytes: 5,
        original_name: "test.bin",
      }, { status: 201 }),
    );

    const client = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "token",
      apiKey: "key",
      fetchImpl,
    });

    await client.uploadCommandArtifact(Buffer.from("hello"), "test.bin", "abc");

    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://api.test/internal/command-artifacts");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-Filename": "test.bin",
      "X-SHA256": "abc",
    });
  });

  it("downloads command artifacts as base64", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(Buffer.from("hello"), {
        status: 200,
        headers: { "x-sha256": "deadbeef" },
      }),
    );

    const client = new HecateApiClient({
      baseUrl: "http://api.test",
      internalToken: "token",
      apiKey: "key",
      fetchImpl,
    });

    const artifact = await client.downloadCommandArtifact(
      "00000000-0000-4000-8000-000000000001",
    );

    expect(artifact.content_base64).toBe(Buffer.from("hello").toString("base64"));
    expect(artifact.sha256).toBe("deadbeef");
    expect(artifact.size_bytes).toBe(5);
  });
});
