export type RequestMetadata = Record<string, string>;

export interface AuthContext {
  accessToken: string;
  csrfToken?: string;
}

export interface GeneratedMetadataClient {
  createMetadata(request: unknown, metadata: RequestMetadata): Promise<unknown>;
  getMetadata(request: unknown, metadata: RequestMetadata): Promise<unknown>;
  listMetadata(request: unknown, metadata: RequestMetadata): Promise<unknown>;
  updateMetadata(request: unknown, metadata: RequestMetadata): Promise<unknown>;
  deleteMetadata(request: unknown, metadata: RequestMetadata): Promise<unknown>;
}

export class MediaApiSdk {
  constructor(
    private readonly client: GeneratedMetadataClient,
    private readonly auth: AuthContext
  ) {}

  private metadata(): RequestMetadata {
    const headers: RequestMetadata = {
      authorization: `Bearer ${this.auth.accessToken}`,
    };

    if (this.auth.csrfToken) {
      headers["x-csrf-token"] = this.auth.csrfToken;
    }

    return headers;
  }

  createMetadata(request: unknown): Promise<unknown> {
    return this.client.createMetadata(request, this.metadata());
  }

  getMetadata(request: unknown): Promise<unknown> {
    return this.client.getMetadata(request, this.metadata());
  }

  listMetadata(request: unknown): Promise<unknown> {
    return this.client.listMetadata(request, this.metadata());
  }

  updateMetadata(request: unknown): Promise<unknown> {
    return this.client.updateMetadata(request, this.metadata());
  }

  deleteMetadata(request: unknown): Promise<unknown> {
    return this.client.deleteMetadata(request, this.metadata());
  }
}
