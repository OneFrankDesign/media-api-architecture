import type {
  CreateMetadataRequest,
  CreateMetadataResponse,
  DeleteMetadataRequest,
  DeleteMetadataResponse,
  GetMetadataRequest,
  GetMetadataResponse,
  ListMetadataRequest,
  ListMetadataResponse,
  Thumbnail,
  UpdateMetadataRequest,
  UpdateMetadataResponse,
  VideoMetadata,
  VideoResolution,
  VideoStats,
} from "./gen/api/v1/metadata_pb";
export { MetadataSortField, MetadataStatus } from "./gen/api/v1/metadata_pb";

export type RequestMetadata = Record<string, string>;

export interface AuthContext {
  accessToken: string;
  csrfToken?: string;
}

export interface GeneratedMetadataClient {
  createMetadata(
    request: CreateMetadataRequest,
    metadata: RequestMetadata
  ): Promise<CreateMetadataResponse>;
  getMetadata(request: GetMetadataRequest, metadata: RequestMetadata): Promise<GetMetadataResponse>;
  listMetadata(
    request: ListMetadataRequest,
    metadata: RequestMetadata
  ): Promise<ListMetadataResponse>;
  updateMetadata(
    request: UpdateMetadataRequest,
    metadata: RequestMetadata
  ): Promise<UpdateMetadataResponse>;
  deleteMetadata(
    request: DeleteMetadataRequest,
    metadata: RequestMetadata
  ): Promise<DeleteMetadataResponse>;
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

  createMetadata(request: CreateMetadataRequest): Promise<CreateMetadataResponse> {
    return this.client.createMetadata(request, this.metadata());
  }

  getMetadata(request: GetMetadataRequest): Promise<GetMetadataResponse> {
    return this.client.getMetadata(request, this.metadata());
  }

  listMetadata(request: ListMetadataRequest): Promise<ListMetadataResponse> {
    return this.client.listMetadata(request, this.metadata());
  }

  updateMetadata(request: UpdateMetadataRequest): Promise<UpdateMetadataResponse> {
    return this.client.updateMetadata(request, this.metadata());
  }

  deleteMetadata(request: DeleteMetadataRequest): Promise<DeleteMetadataResponse> {
    return this.client.deleteMetadata(request, this.metadata());
  }
}

export type {
  CreateMetadataRequest,
  CreateMetadataResponse,
  DeleteMetadataRequest,
  DeleteMetadataResponse,
  GetMetadataRequest,
  GetMetadataResponse,
  ListMetadataRequest,
  ListMetadataResponse,
  Thumbnail,
  UpdateMetadataRequest,
  UpdateMetadataResponse,
  VideoMetadata,
  VideoResolution,
  VideoStats,
};
