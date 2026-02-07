import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  AuthContext,
  GeneratedMetadataClient,
  MediaApiSdk,
  RequestMetadata,
} from "./index";

describe("MediaApiSdk", () => {
  let calls: Array<{ method: string; metadata: RequestMetadata; request: unknown }>;
  let client: GeneratedMetadataClient;

  beforeEach(() => {
    calls = [];

    const record = (method: string) => (request: unknown, metadata: RequestMetadata) => {
      calls.push({ method, metadata, request });
      return Promise.resolve({ method, ok: true });
    };

    client = {
      createMetadata: vi.fn(record("createMetadata")),
      getMetadata: vi.fn(record("getMetadata")),
      listMetadata: vi.fn(record("listMetadata")),
      updateMetadata: vi.fn(record("updateMetadata")),
      deleteMetadata: vi.fn(record("deleteMetadata")),
    };
  });

  function expectAuthHeaders(metadata: RequestMetadata, auth: AuthContext) {
    expect(metadata.Authorization).toBe(`Bearer ${auth.accessToken}`);

    if (auth.csrfToken) {
      expect(metadata["X-CSRF-Token"]).toBe(auth.csrfToken);
    } else {
      expect(metadata["X-CSRF-Token"]).toBeUndefined();
    }
  }

  it("sends authorization and csrf metadata when csrf token is present", async () => {
    const auth: AuthContext = { accessToken: "token-1", csrfToken: "csrf-1" };
    const sdk = new MediaApiSdk(client, auth);

    await sdk.createMetadata({ id: "request-1" });

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("createMetadata");
    expectAuthHeaders(calls[0].metadata, auth);
  });

  it("omits csrf header when token is absent", async () => {
    const auth: AuthContext = { accessToken: "token-2" };
    const sdk = new MediaApiSdk(client, auth);

    await sdk.getMetadata({ id: "request-2" });

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("getMetadata");
    expectAuthHeaders(calls[0].metadata, auth);
  });

  it("delegates all sdk operations to generated client with shared metadata policy", async () => {
    const auth: AuthContext = { accessToken: "token-3", csrfToken: "csrf-3" };
    const sdk = new MediaApiSdk(client, auth);

    await sdk.createMetadata({ payload: "create" });
    await sdk.getMetadata({ payload: "get" });
    await sdk.listMetadata({ payload: "list" });
    await sdk.updateMetadata({ payload: "update" });
    await sdk.deleteMetadata({ payload: "delete" });

    expect(calls.map((call) => call.method)).toEqual([
      "createMetadata",
      "getMetadata",
      "listMetadata",
      "updateMetadata",
      "deleteMetadata",
    ]);

    for (const call of calls) {
      expectAuthHeaders(call.metadata, auth);
    }
  });
});
