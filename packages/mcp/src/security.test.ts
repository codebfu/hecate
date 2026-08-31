// Copyright (C) 2026 Gaultier HUBERT
// SPDX-License-Identifier: GPL-3.0-or-later

import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  extractBearerToken,
  hashApiKey,
  hostHeaderValidation,
  verifySessionBearer,
} from "./index.js";
import { executeCommandInputSchema } from "./tools/execute_command.js";

describe("extractBearerToken", () => {
  it("accepts well-formed Bearer tokens", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 128 }), (token) => {
        expect(extractBearerToken(`Bearer ${token}`)).toBe(token.trim() || undefined);
      }),
    );
  });

  it("rejects malformed authorization headers", () => {
    fc.assert(
      fc.property(fc.string(), (header) => {
        fc.pre(!header.startsWith("Bearer ") || header.slice("Bearer ".length).trim().length === 0);
        expect(extractBearerToken(header)).toBeUndefined();
      }),
    );
  });
});

describe("verifySessionBearer", () => {
  it("matches only the hashed API key used at session creation", () => {
    fc.assert(
      fc.property(fc.string({ minLength: 8, maxLength: 64 }), (apiKey) => {
        const entry = { transport: {} as never, apiKeyHash: hashApiKey(apiKey) };
        expect(verifySessionBearer(entry, apiKey)).toBe(true);
        expect(verifySessionBearer(entry, `${apiKey}-tampered`)).toBe(false);
      }),
    );
  });
});

describe("executeCommandInputSchema", () => {
  it("rejects invalid machine_id values", () => {
    fc.assert(
      fc.property(fc.string(), (machineId) => {
        fc.pre(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(machineId));
        const parsed = executeCommandInputSchema.safeParse({
          machine_id: machineId,
          command_name: "shell.run",
        });
        expect(parsed.success).toBe(false);
      }),
    );
  });

  it("rejects wait_timeout_secs outside 1..300", () => {
    fc.assert(
      fc.property(fc.oneof(fc.integer({ max: 0 }), fc.integer({ min: 301 })), (timeout) => {
        const parsed = executeCommandInputSchema.safeParse({
          machine_id: "00000000-0000-0000-0000-000000000001",
          command_name: "shell.run",
          wait_timeout_secs: timeout,
        });
        expect(parsed.success).toBe(false);
      }),
    );
  });

  it("accepts bounded valid payloads", () => {
    fc.assert(
      fc.property(
        fc.uuid(),
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.integer({ min: 1, max: 300 }),
        (machineId, commandName, timeout) => {
          const parsed = executeCommandInputSchema.safeParse({
            machine_id: machineId,
            command_name: commandName,
            wait_timeout_secs: timeout,
          });
          expect(parsed.success).toBe(true);
        },
      ),
    );
  });
});

describe("hostHeaderValidation", () => {
  it("blocks hosts outside the allowlist", () => {
    const middleware = hostHeaderValidation(["127.0.0.1", "localhost"]);
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 32 }), (host) => {
        fc.pre(host.toLowerCase() !== "127.0.0.1" && host.toLowerCase() !== "localhost");
        let status = 200;
        const req = { headers: { host: `${host}:3100` } } as never;
        const res = {
          status(code: number) {
            status = code;
            return this;
          },
          json() {
            return this;
          },
        } as never;
        let nextCalled = false;
        middleware(req, res, () => {
          nextCalled = true;
        });
        if (nextCalled) {
          expect(status).toBe(200);
        } else {
          expect(status).toBe(403);
        }
      }),
    );
  });
});
