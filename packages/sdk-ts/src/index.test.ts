import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  AuthContext,
  CreateMetadataRequest,
  CreateMetadataResponse,
  DeleteMetadataRequest,
  DeleteMetadataResponse,
  GetMetadataRequest,
  GetMetadataResponse,
  GeneratedMetadataClient,
  ListMetadataRequest,
  ListMetadataResponse,
  MediaApiSdk,
  RequestMetadata,
  UpdateMetadataRequest,
  UpdateMetadataResponse,
} from "./index";

describe("MediaApiSdk", () => {
  type AnySdkRequest =
    | CreateMetadataRequest
    | GetMetadataRequest
    | ListMetadataRequest
    | UpdateMetadataRequest
    | DeleteMetadataRequest;

  let calls: Array<{ method: string; metadata: RequestMetadata; request: AnySdkRequest }>;
  let client: GeneratedMetadataClient;

  beforeEach(() => {
    calls = [];

    const record =
      <TRequest extends AnySdkRequest, TResponse>(
        method: string,
        response: TResponse
      ) =>
      (request: TRequest, metadata: RequestMetadata) => {
        calls.push({ method, metadata, request });
        return Promise.resolve(response);
      };

    client = {
      createMetadata: vi.fn(
        record<CreateMetadataRequest, CreateMetadataResponse>(
          "createMetadata",
          {} as CreateMetadataResponse
        )
      ),
      getMetadata: vi.fn(
        record<GetMetadataRequest, GetMetadataResponse>(
          "getMetadata",
          {} as GetMetadataResponse
        )
      ),
      listMetadata: vi.fn(
        record<ListMetadataRequest, ListMetadataResponse>(
          "listMetadata",
          {} as ListMetadataResponse
        )
      ),
      updateMetadata: vi.fn(
        record<UpdateMetadataRequest, UpdateMetadataResponse>(
          "updateMetadata",
          {} as UpdateMetadataResponse
        )
      ),
      deleteMetadata: vi.fn(
        record<DeleteMetadataRequest, DeleteMetadataResponse>(
          "deleteMetadata",
          {} as DeleteMetadataResponse
        )
      ),
    };
  });

  function expectAuthHeaders(metadata: RequestMetadata, auth: AuthContext) {
    expect(metadata.authorization).toBe(`Bearer ${auth.accessToken}`);

    if (auth.csrfToken) {
      expect(metadata["x-csrf-token"]).toBe(auth.csrfToken);
    } else {
      expect(metadata["x-csrf-token"]).toBeUndefined();
    }
  }

  it("sends authorization and csrf metadata when csrf token is present", async () => {
    const auth: AuthContext = { accessToken: "token-1", csrfToken: "csrf-1" };
    const sdk = new MediaApiSdk(client, auth);

    await sdk.createMetadata({ title: "request-1" } as CreateMetadataRequest);

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("createMetadata");
    expectAuthHeaders(calls[0].metadata, auth);
  });

  it("omits csrf header when token is absent", async () => {
    const auth: AuthContext = { accessToken: "token-2" };
    const sdk = new MediaApiSdk(client, auth);

    await sdk.getMetadata({ id: "request-2" } as GetMetadataRequest);

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("getMetadata");
    expectAuthHeaders(calls[0].metadata, auth);
  });

  it("delegates all sdk operations to generated client with shared metadata policy", async () => {
    const auth: AuthContext = { accessToken: "token-3", csrfToken: "csrf-3" };
    const sdk = new MediaApiSdk(client, auth);

    await sdk.createMetadata({ title: "create" } as CreateMetadataRequest);
    await sdk.getMetadata({ id: "get" } as GetMetadataRequest);
    await sdk.listMetadata({ pageSize: 1 } as ListMetadataRequest);
    await sdk.updateMetadata({ id: "update" } as UpdateMetadataRequest);
    await sdk.deleteMetadata({ id: "delete" } as DeleteMetadataRequest);

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
