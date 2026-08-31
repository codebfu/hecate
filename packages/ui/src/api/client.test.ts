// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client.js";

describe("ApiClient", () => {
  it("calls /api/v1 by default", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ hecate_version: "0.1.0", schema_version: 1, backup_format_version_current: 1, api_version: "v1" }),
    );

    const client = new ApiClient({ fetchImpl });
    await client.getSystemVersion();

    const [url] = fetchImpl.mock.calls[0]! as [string, RequestInit?];
    expect(url).toBe("/api/v1/system/version");
  });

  it("sends credentials include", async () => {
    const fetchImpl = vi.fn(async () => Response.json({ authenticated: false }));

    const client = new ApiClient({ fetchImpl });
    await client.getSession();

    const [, init] = fetchImpl.mock.calls[0]! as [string, RequestInit];
    expect(init.credentials).toBe("include");
  });

  it("uses global fetch when no custom impl is provided", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        bootstrap_required: true,
        authenticated: false,
        onboarding_required: false,
        role: null,
      }),
    );
    vi.stubGlobal("fetch", fetchImpl);

    const client = new ApiClient();
    await client.getAuthStatus();

    expect(fetchImpl).toHaveBeenCalledOnce();
    vi.unstubAllGlobals();
  });

  it("requests machine agent update", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        id: "m1",
        hostname: "host",
        os: "linux",
        arch: "x86_64",
        tags: [],
        status: "online",
        agent_update_status: "update_pending",
      }),
    );

    const client = new ApiClient({ fetchImpl });
    await client.requestMachineAgentUpdate("m1");

    const [url, init] = fetchImpl.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/machines/m1/update-agent");
    expect(init.method).toBe("POST");
  });

  it("requests machine helper install", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({
        id: "m1",
        hostname: "host",
        os: "linux",
        arch: "x86_64",
        tags: [],
        status: "online",
        installable_helpers: [],
      }),
    );

    const client = new ApiClient({ fetchImpl });
    await client.requestMachineHelperInstall("m1", "proxmox");

    const [url, init] = fetchImpl.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("/api/v1/admin/machines/m1/install-helper");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ component: "proxmox" });
  });

  it("requests server update", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json({ ok: true, update_requested: true, fleet_busy: false, can_apply: true }),
    );

    const client = new ApiClient({ fetchImpl });
    await client.requestServerUpdate();

    const [url] = fetchImpl.mock.calls[0]! as [string, RequestInit?];
    expect(url).toBe("/api/v1/admin/system/update");
  });

  it("surfaces API error messages from JSON bodies", async () => {
    const fetchImpl = vi.fn(async () =>
      Response.json(
        { error: "bad_request", message: "password too short" },
        { status: 400 },
      ),
    );

    const client = new ApiClient({ fetchImpl });

    await expect(client.bootstrap("admin", "short")).rejects.toMatchObject({
      message: "Password must be at least 12 characters.",
      status: 400,
    });
  });
});
